"""
DESFire EV1/EV2 transit terminal kernel — implements the full fare-payment flow.

DESFire transit payment steps (in order):
  1.  ISO SELECT  — selects the DESFire MIFARE ISO wrapper (optional but good practice)
  2.  GET_VERSION — reads HW/SW/UID across 3 frames (91AF → 91AF → 9100)
  3.  GET_APPLICATION_IDs — confirms transit app exists on card
  4.  SELECT_APPLICATION — selects the transit AID (e.g. 4D4258)
  5.  AUTHENTICATE_AES  — 3-pass mutual auth with terminal key
      5a. Terminal sends CMD_AUTH_AES(keyNo=0x01) → card returns E(RndB)
      5b. Terminal decrypts RndB, generates RndA, sends E(RndA || rotate(RndB))
      5c. Card returns E(rotate(RndA)) — terminal verifies
  6.  GET_FILE_IDs — list files in selected app
  7.  GET_FILE_SETTINGS(FILE_BALANCE) — read lower/upper limits and current value
  8.  GET_VALUE(FILE_BALANCE) — read current balance in centavos
  9.  DEBIT_VALUE(FILE_BALANCE, amount) — stage the debit (not yet committed)
  10. COMMIT_TRANSACTION — atomically apply the debit to the card

All steps are logged; caller retrieves the full trace via get_log().
"""

import os
import struct
from dataclasses import dataclass, field
from typing import Optional

try:
    from Crypto.Cipher import AES
    _CRYPTO = True
except ImportError:
    _CRYPTO = False

from .desfire_sim import (
    TRANSIT_AID, FILE_BALANCE, FILE_TXLOG,
    CMD_GET_VERSION, CMD_ADDITIONAL_FRAME, CMD_GET_APP_IDS,
    CMD_SELECT_APP, CMD_AUTH_AES, CMD_GET_FILE_IDS,
    CMD_GET_FILE_SETTINGS, CMD_GET_VALUE, CMD_DEBIT_VALUE,
    CMD_COMMIT_TX, CMD_ABORT_TX,
    STS_OK, STS_MORE, STS_AUTH_ERROR, STS_INSUFFICIENT, STS_PERMISSION,
    _rotate_left, _aes_cbc_enc, _aes_cbc_dec,
)

# Metro CDMX terminal ID and BUS transit type
TERMINAL_ID   = "BUS-MX-001"
BUS_FARE_CENT = 1100   # $11.00 MXN in centavos

DESFIRE_ISO_AID = bytes.fromhex("D27600002545500100")

# Standard DESFire-style terminal key (same as DESFireCard.TERMINAL_KEY)
TERMINAL_KEY = bytes.fromhex("00112233445566778899AABBCCDDEEFF")


def _send(conn, apdu: list[int]) -> tuple[bytes, int, int]:
    data, sw1, sw2 = conn.transmit(apdu)
    return bytes(data), sw1, sw2


def _desfire(ins: int, data: bytes = b"") -> list[int]:
    """Build a DESFire native APDU (CLA=0x90)."""
    apdu = [0x90, ins, 0x00, 0x00]
    if data:
        apdu += [len(data)] + list(data)
    apdu += [0x00]
    return apdu


@dataclass
class PaymentResult:
    approved: bool
    uid: str = ""
    balance_before: int = 0
    balance_after: int = 0
    amount_centavos: int = 0
    session_key: str = ""
    rnd_a: str = ""
    rnd_b: str = ""
    hw_version: str = ""
    sw_version: str = ""
    error: str = ""
    steps: list[dict] = field(default_factory=list)

    @property
    def amount_mxn(self) -> str:
        return f"${self.amount_centavos/100:.2f} MXN"

    @property
    def balance_before_mxn(self) -> str:
        return f"${self.balance_before/100:.2f} MXN"

    @property
    def balance_after_mxn(self) -> str:
        return f"${self.balance_after/100:.2f} MXN"


class DESFireTransitTerminal:
    """
    DESFire transit terminal kernel — mirrors what a real Metrobús validator does.

    Pass any connection object that implements transmit(apdu: list[int])
    returning (data: list[int], sw1: int, sw2: int).
    """

    def __init__(self, amount_centavos: int = BUS_FARE_CENT, debug: bool = False):
        self.amount = amount_centavos
        self.debug  = debug
        self._steps: list[dict] = []   # APDU trace for this transaction

    # ── Public ────────────────────────────────────────────────────────────────

    def run(self, conn) -> PaymentResult:
        self._steps = []
        result = PaymentResult(approved=False, amount_centavos=self.amount)
        try:
            self._execute(conn, result)
        except Exception as exc:
            result.approved = False
            result.error    = str(exc)
        result.steps = self._steps
        return result

    def get_log(self) -> list[dict]:
        return self._steps

    # ── Main flow ─────────────────────────────────────────────────────────────

    def _execute(self, conn, result: PaymentResult):

        # ── Step 1: ISO SELECT DESFire wrapper ───────────────────────────────
        iso_sel = [0x00, 0xA4, 0x04, 0x00, len(DESFIRE_ISO_AID)] + list(DESFIRE_ISO_AID) + [0x00]
        d, sw1, sw2 = _send(conn, iso_sel)
        self._log("ISO SELECT APPLICATION",
                  bytes(iso_sel), d + bytes([sw1, sw2]),
                  f"Selecciona wrapper ISO DESFire AID={DESFIRE_ISO_AID.hex().upper()}")
        # Some cards may return 6A82 if they don't support ISO wrapper — continue anyway

        # ── Step 2: GET_VERSION (3 frames) ───────────────────────────────────
        d, sw1, sw2 = _send(conn, _desfire(CMD_GET_VERSION))
        self._log("GET_VERSION [frame 1 — HW info]",
                  bytes(_desfire(CMD_GET_VERSION)), d + bytes([sw1, sw2]),
                  "HW: vendor/type/subtype/major/minor/storage/protocol")
        if sw1 == 0x91 and sw2 == STS_MORE:
            hw_raw = d
            result.hw_version = d.hex().upper()
            d2, sw1, sw2 = _send(conn, _desfire(CMD_ADDITIONAL_FRAME))
            self._log("ADDITIONAL_FRAME [frame 2 — SW info]",
                      bytes(_desfire(CMD_ADDITIONAL_FRAME)), d2 + bytes([sw1, sw2]),
                      "SW: vendor/type/subtype/major/minor/storage/protocol")
            result.sw_version = d2.hex().upper()
            if sw1 == 0x91 and sw2 == STS_MORE:
                d3, sw1, sw2 = _send(conn, _desfire(CMD_ADDITIONAL_FRAME))
                self._log("ADDITIONAL_FRAME [frame 3 — UID + batch]",
                          bytes(_desfire(CMD_ADDITIONAL_FRAME)), d3 + bytes([sw1, sw2]),
                          "UID (7 bytes) + batch number (5 bytes)")
                if len(d3) >= 7:
                    result.uid = d3[:7].hex().upper()

        # ── Step 3: GET_APPLICATION_IDs ──────────────────────────────────────
        d, sw1, sw2 = _send(conn, _desfire(CMD_GET_APP_IDS))
        aids_hex = d.hex().upper()
        self._log("GET_APPLICATION_IDs",
                  bytes(_desfire(CMD_GET_APP_IDS)), d + bytes([sw1, sw2]),
                  f"Apps en la tarjeta: {' '.join(aids_hex[i:i+6] for i in range(0, len(aids_hex), 6))}")
        if TRANSIT_AID not in [d[i:i+3] for i in range(0, len(d), 3)]:
            result.error = "Transit AID not found on card"
            return

        # ── Step 4: SELECT_APPLICATION ───────────────────────────────────────
        d, sw1, sw2 = _send(conn, _desfire(CMD_SELECT_APP, TRANSIT_AID))
        self._log("SELECT_APPLICATION",
                  bytes(_desfire(CMD_SELECT_APP, TRANSIT_AID)), d + bytes([sw1, sw2]),
                  f"Selecciona app de cobro AID={TRANSIT_AID.hex().upper()} (MetroBus)")
        if not (sw1 == 0x91 and sw2 == STS_OK):
            result.error = f"SELECT_APPLICATION failed: {sw1:02X}{sw2:02X}"
            return

        # ── Step 5a: AUTHENTICATE_AES — step 1 ───────────────────────────────
        key_no = bytes([0x01])
        d, sw1, sw2 = _send(conn, _desfire(CMD_AUTH_AES, key_no))
        self._log("AUTHENTICATE_AES (step 1)",
                  bytes(_desfire(CMD_AUTH_AES, key_no)), d + bytes([sw1, sw2]),
                  "Terminal solicita auth con key#01; carta responde E_key(RndB, IV=0)")
        if not (sw1 == 0x91 and sw2 == STS_MORE):
            result.error = f"AUTH step 1 failed: {sw1:02X}{sw2:02X}"
            return
        enc_rnd_b = d   # 16 bytes: AES-CBC(key, IV=0, RndB)

        # ── Step 5b: Terminal decrypts RndB, generates RndA ──────────────────
        # DESFire EV1 IV chaining:
        #   decrypt step1 with IV=0  → RndB
        #   encrypt step2 with IV=enc_rnd_b (last block of step1)
        rnd_b         = _aes_cbc_dec(TERMINAL_KEY, bytes(16), enc_rnd_b)
        rnd_a         = os.urandom(16)
        plaintext     = rnd_a + _rotate_left(rnd_b)
        iv_step2      = enc_rnd_b          # chain IV = ciphertext from card's step 1
        enc_response  = _aes_cbc_enc(TERMINAL_KEY, iv_step2, plaintext)

        result.rnd_a = rnd_a.hex().upper()
        result.rnd_b = rnd_b.hex().upper()

        d, sw1, sw2 = _send(conn, _desfire(CMD_ADDITIONAL_FRAME, enc_response))
        self._log("ADDITIONAL_FRAME (step 2 — respuesta terminal)",
                  bytes(_desfire(CMD_ADDITIONAL_FRAME, enc_response)),
                  d + bytes([sw1, sw2]),
                  "Terminal envía E(RndA || rotate(RndB), IV=enc_rnd_b); "
                  "carta verifica y retorna E(rotate(RndA))")
        if not (sw1 == 0x91 and sw2 == STS_OK):
            result.error = f"AUTH step 2 failed: {sw1:02X}{sw2:02X}"
            return

        # ── Step 5c: Verify card's E(RndA') ──────────────────────────────────
        # Card encrypted RndA' with IV = last 16 bytes of enc_response (step2 block 2)
        enc_rnd_a_prime       = d
        iv_step3              = enc_response[16:32]
        rnd_a_prime_decrypted = _aes_cbc_dec(TERMINAL_KEY, iv_step3, enc_rnd_a_prime)
        expected              = _rotate_left(rnd_a)
        if rnd_a_prime_decrypted != expected:
            result.error = "Card RndA' verification failed — authentication rejected"
            return

        # Derive session key (DESFire EV1 AES formula)
        session_key = rnd_a[:4] + rnd_b[:4] + rnd_a[12:16] + rnd_b[12:16]
        result.session_key = session_key.hex().upper()
        self._add_note("AUTH OK — Session key derivado",
                       f"SesKey = RndA[0:4]+RndB[0:4]+RndA[12:16]+RndB[12:16] = {result.session_key}")

        # ── Step 6: GET_FILE_IDs ──────────────────────────────────────────────
        d, sw1, sw2 = _send(conn, _desfire(CMD_GET_FILE_IDS))
        self._log("GET_FILE_IDs",
                  bytes(_desfire(CMD_GET_FILE_IDS)), d + bytes([sw1, sw2]),
                  f"Archivos: {list(d)}")

        # ── Step 7: GET_FILE_SETTINGS(FILE_BALANCE) ───────────────────────────
        d, sw1, sw2 = _send(conn, _desfire(CMD_GET_FILE_SETTINGS, bytes([FILE_BALANCE])))
        self._log("GET_FILE_SETTINGS (Value File 0x01)",
                  bytes(_desfire(CMD_GET_FILE_SETTINGS, bytes([FILE_BALANCE]))),
                  d + bytes([sw1, sw2]),
                  "Tipo=Value, CommMode=AES, límites inferior/superior, saldo actual")
        if sw1 == 0x91 and sw2 == STS_OK and len(d) >= 17:
            lower = struct.unpack("<i", d[4:8])[0]
            upper = struct.unpack("<i", d[8:12])[0]
            cur   = struct.unpack("<i", d[12:16])[0]
            self._add_note("File settings decodificados",
                           f"Límite inferior={lower}, superior={upper}, "
                           f"saldo actual={cur} centavos (${cur/100:.2f} MXN)")

        # ── Step 8: GET_VALUE ─────────────────────────────────────────────────
        d, sw1, sw2 = _send(conn, _desfire(CMD_GET_VALUE, bytes([FILE_BALANCE])))
        self._log("GET_VALUE (File 0x01 — saldo)",
                  bytes(_desfire(CMD_GET_VALUE, bytes([FILE_BALANCE]))),
                  d + bytes([sw1, sw2]),
                  "Saldo actual en centavos (signed 32-bit little-endian)")
        if not (sw1 == 0x91 and sw2 == STS_OK and len(d) >= 4):
            result.error = f"GET_VALUE failed: {sw1:02X}{sw2:02X}"
            return
        balance_before = struct.unpack("<i", d[:4])[0]
        result.balance_before = balance_before
        self._add_note("Saldo decodificado",
                       f"{balance_before} centavos = ${balance_before/100:.2f} MXN")

        if balance_before < self.amount:
            result.error = (
                f"Saldo insuficiente: ${balance_before/100:.2f} MXN < "
                f"${self.amount/100:.2f} MXN tarifa"
            )
            # Send ABORT so the card discards any pending state
            _send(conn, _desfire(CMD_ABORT_TX))
            return

        # ── Step 9: DEBIT_VALUE ───────────────────────────────────────────────
        debit_data = bytes([FILE_BALANCE]) + struct.pack("<I", self.amount)
        d, sw1, sw2 = _send(conn, _desfire(CMD_DEBIT_VALUE, debit_data))
        self._log("DEBIT_VALUE (File 0x01)",
                  bytes(_desfire(CMD_DEBIT_VALUE, debit_data)),
                  d + bytes([sw1, sw2]),
                  f"Débito={self.amount} centavos (${self.amount/100:.2f} MXN) — "
                  "aún NO aplicado, pendiente COMMIT")
        if not (sw1 == 0x91 and sw2 == STS_OK):
            code_map = {
                STS_INSUFFICIENT: "Saldo insuficiente",
                STS_PERMISSION:   "Permiso denegado (sin autenticación?)",
                STS_AUTH_ERROR:   "Error de autenticación",
            }
            reason = code_map.get(sw2, f"Error {sw1:02X}{sw2:02X}")
            result.error = f"DEBIT_VALUE failed: {reason}"
            _send(conn, _desfire(CMD_ABORT_TX))
            return
        response_mac = d.hex().upper() if d else "(none)"
        self._add_note("DEBIT_VALUE response MAC", response_mac)

        # ── Step 10: COMMIT_TRANSACTION ───────────────────────────────────────
        d, sw1, sw2 = _send(conn, _desfire(CMD_COMMIT_TX))
        self._log("COMMIT_TRANSACTION",
                  bytes(_desfire(CMD_COMMIT_TX)), d + bytes([sw1, sw2]),
                  "Aplica el débito de forma atómica — transacción finalizada")
        if not (sw1 == 0x91 and sw2 == STS_OK):
            result.error = f"COMMIT failed: {sw1:02X}{sw2:02X}"
            return

        result.approved      = True
        result.balance_after = balance_before - self.amount

    # ── Logging helpers ───────────────────────────────────────────────────────

    def _log(self, label: str, cmd: bytes, resp: bytes, note: str = ""):
        cmd_hex  = " ".join(f"{b:02X}" for b in cmd)
        resp_hex = " ".join(f"{b:02X}" for b in resp)
        sw1, sw2 = (resp[-2], resp[-1]) if len(resp) >= 2 else (0, 0)
        self._steps.append({
            "type":     "apdu",
            "step":     len(self._steps) + 1,
            "label":    label,
            "command":  cmd_hex,
            "response": resp_hex,
            "sw":       f"{sw1:02X}{sw2:02X}",
            "ok":       (sw1 == 0x91 and sw2 in (STS_OK, STS_MORE))
                        or (sw1 == 0x90 and sw2 == 0x00),
            "note":     note,
        })

    def _add_note(self, label: str, text: str):
        self._steps.append({
            "type":  "note",
            "step":  len(self._steps) + 1,
            "label": label,
            "note":  text,
        })
