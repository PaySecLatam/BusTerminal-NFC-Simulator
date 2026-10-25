"""
DESFire EV1/EV2 card simulator — native DESFire protocol over ISO 14443-4.

Transit cards (Metrobús, Metro CDMX) use this protocol, NOT standard EMV.
Card stores balance in a Value File (FILE_BALANCE) and logs trips in a
Linear Record File (FILE_TXLOG). Mutual AES authentication is mandatory
before any debit operation.

DESFire native frame format:
  CLA=0x90 INS P1=00 P2=00 [Lc data] [Le=00]
Response:
  [data bytes] 0x91 <status>
"""

import os
import struct
import time
from dataclasses import dataclass, field
from typing import Optional

try:
    from Crypto.Cipher import AES
    from Crypto.Hash import CMAC as _CMAC
    _CRYPTO = True
except ImportError:
    _CRYPTO = False

# ── Application IDs (3 bytes each, DESFire native) ───────────────────────────
TRANSIT_AID = bytes([0x4D, 0x42, 0x58])   # "MBX" — demo MetroBus app
MASTER_AID  = bytes([0x00, 0x00, 0x00])   # Card master application

# ── File numbers inside the transit app ──────────────────────────────────────
FILE_BALANCE = 0x01   # Value file  — balance in centavos (signed 32-bit LE)
FILE_TXLOG   = 0x02   # Record file — last 10 trip records

# ── DESFire EV1 instruction bytes (CLA always 0x90) ──────────────────────────
CMD_GET_VERSION       = 0x60
CMD_GET_APP_IDS       = 0x6A
CMD_SELECT_APP        = 0x5A
CMD_AUTH_AES          = 0xAA   # step-1: terminal initiates auth
CMD_ADDITIONAL_FRAME  = 0xAF   # step-2 continuation / next response frame
CMD_GET_FILE_IDS      = 0x6F
CMD_GET_FILE_SETTINGS = 0xF5
CMD_GET_VALUE         = 0x6C
CMD_DEBIT_VALUE       = 0xDC
CMD_COMMIT_TX         = 0xC7
CMD_ABORT_TX          = 0xA7
CMD_READ_RECORDS      = 0xBB

# ── DESFire status codes (low byte of 0x91XX) ────────────────────────────────
STS_OK                = 0x00
STS_MORE              = 0xAF   # more frames follow (multi-frame responses)
STS_AUTH_ERROR        = 0xAE
STS_PERMISSION        = 0x9D
STS_APP_NOT_FOUND     = 0xA0
STS_FILE_NOT_FOUND    = 0xF0
STS_NO_CHANGE         = 0x0C
STS_INSUFFICIENT      = 0x40   # also "no such key" — NXP reuses the code
STS_ILLEGAL_CMD       = 0x6E
STS_LEN_ERROR         = 0x7E
STS_INTEGRITY_ERROR   = 0x1E


def _sw(code: int) -> bytes:
    return bytes([0x91, code])


def _aes_cbc_enc(key: bytes, iv: bytes, data: bytes) -> bytes:
    if _CRYPTO:
        return AES.new(key, AES.MODE_CBC, iv=iv).encrypt(data)
    return data  # no-op fallback (install pycryptodome for real crypto)


def _aes_cbc_dec(key: bytes, iv: bytes, data: bytes) -> bytes:
    if _CRYPTO:
        return AES.new(key, AES.MODE_CBC, iv=iv).decrypt(data)
    return data


def _cmac(key: bytes, data: bytes) -> bytes:
    """AES-CMAC (RFC 4493) — used for DESFire response integrity MACs."""
    if _CRYPTO:
        obj = _CMAC.new(key, ciphermod=AES)
        obj.update(data)
        return obj.digest()
    return bytes(16)


def _rotate_left(b: bytes) -> bytes:
    return b[1:] + b[:1]


@dataclass
class TripRecord:
    amount_centavos: int
    balance_after: int
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "amount_centavos": self.amount_centavos,
            "amount_mxn": f"${self.amount_centavos/100:.2f}",
            "balance_after": self.balance_after,
            "balance_after_mxn": f"${self.balance_after/100:.2f}",
            "timestamp": self.timestamp,
        }


class DESFireCard:
    """
    Software simulation of a NXP DESFire EV1 transit card.

    A real Metrobús card contains:
    - Master Application (AID 000000) — card-level management
    - Transit Application (AID 4D4258) — fare payment
        └─ File 01: Value file (balance in centavos)
        └─ File 02: Linear Record file (last 10 trips)

    Authentication flow (3-pass AES-128 mutual auth):
      1. Terminal → Card:  CMD_AUTH_AES(keyNo)
         Card → Terminal:  E_key(RndB) + 91AF
      2. Terminal → Card:  CMD_ADDITIONAL_FRAME(E_key(RndA || rotate(RndB)))
         Card → Terminal:  E_key(rotate(RndA)) + 9100
      Session key = RndA[0:4] + RndB[0:4] + RndA[12:16] + RndB[12:16]

    Key #01 in transit app = shared terminal authentication key.
    """

    # Shared terminal key (key #01) — would be derived from master key in prod
    TERMINAL_KEY = bytes.fromhex("00112233445566778899AABBCCDDEEFF")
    MASTER_KEY   = bytes(16)   # default blank-card master key (all zeros)

    def __init__(
        self,
        uid_hex: str,
        balance_centavos: int = 50000,
        card_label: str = "",
    ):
        if len(uid_hex) != 14:
            raise ValueError("UID must be exactly 7 bytes (14 hex chars)")
        self.uid           = bytes.fromhex(uid_hex)
        self.uid_hex       = uid_hex.upper()
        self.balance       = balance_centavos
        self.card_label    = card_label or f"CARD-{uid_hex[-6:].upper()}"
        self.trip_log: list[TripRecord] = []

        self._reset_state()

    def _reset_state(self):
        """Reset session state (card re-tapped / connection lost)."""
        self._selected_app: Optional[bytes] = None
        self._authenticated = False
        self._auth_state: Optional[str] = None  # None | "pending" | "done"
        self._rnd_b: Optional[bytes] = None
        self._rnd_a: Optional[bytes] = None
        self._session_key: Optional[bytes] = None
        self._session_iv  = bytes(16)
        self._pending     = False
        self._pending_amt = 0
        self._ver_step    = 0   # multi-frame GET_VERSION cursor

    # ── Public interface ──────────────────────────────────────────────────────

    def reset(self):
        self._reset_state()

    def process_apdu(self, apdu: bytes) -> bytes:
        """Accept raw APDU bytes, return raw response bytes."""
        return self._dispatch(apdu)

    @property
    def balance_mxn(self) -> float:
        return self.balance / 100.0

    def to_dict(self) -> dict:
        return {
            "uid": self.uid_hex,
            "label": self.card_label,
            "balance_centavos": self.balance,
            "balance_mxn": f"${self.balance_mxn:.2f}",
            "trips": len(self.trip_log),
            "last_trips": [t.to_dict() for t in self.trip_log[-5:]],
        }

    # ── Dispatcher ────────────────────────────────────────────────────────────

    def _dispatch(self, apdu: bytes) -> bytes:
        if len(apdu) < 4:
            return _sw(STS_LEN_ERROR)

        cla, ins = apdu[0], apdu[1]
        lc   = apdu[4] if len(apdu) > 4 else 0
        data = apdu[5:5 + lc] if lc else b""

        # ISO SELECT (CLA=00 INS=A4) — used to select DESFire MIFARE AID
        if cla == 0x00 and ins == 0xA4:
            return self._iso_select(apdu[2], apdu[3], data)

        # DESFire native (CLA must be 0x90)
        if cla != 0x90:
            return bytes([0x6E, 0x00])

        # Multi-frame continuation (same INS as step-2 auth)
        if ins == CMD_ADDITIONAL_FRAME:
            return self._continuation(data)

        table = {
            CMD_GET_VERSION:       self._get_version,
            CMD_GET_APP_IDS:       self._get_app_ids,
            CMD_SELECT_APP:        self._select_app,
            CMD_AUTH_AES:          self._auth_step1,
            CMD_GET_FILE_IDS:      self._get_file_ids,
            CMD_GET_FILE_SETTINGS: self._get_file_settings,
            CMD_GET_VALUE:         self._get_value,
            CMD_DEBIT_VALUE:       self._debit_value,
            CMD_COMMIT_TX:         self._commit,
            CMD_ABORT_TX:          self._abort,
            CMD_READ_RECORDS:      self._read_records,
        }
        fn = table.get(ins)
        if fn is None:
            return _sw(STS_ILLEGAL_CMD)
        return fn(data)

    # ── ISO SELECT ────────────────────────────────────────────────────────────

    def _iso_select(self, p1: int, p2: int, data: bytes) -> bytes:
        if p1 != 0x04:
            return bytes([0x6A, 0x86])
        # DESFire MIFARE/ISO wrapper AIDs
        desfire_aids = {
            bytes.fromhex("D27600002545500100"),
            bytes.fromhex("D276000085010100"),
            bytes.fromhex("D2760000850101"),
        }
        if data in desfire_aids:
            self._selected_app = MASTER_AID
            df_name = bytes.fromhex("D276000085010100")
            fci = (
                bytes([0x6F]) + bytes([len(df_name) + 4]) +
                bytes([0x84, len(df_name)]) + df_name +
                bytes([0xA5, 0x00])
            )
            return fci + bytes([0x90, 0x00])
        # PPSE — DESFire transit cards don't respond to this
        if data == b"2PAY.SYS.DDF01":
            return bytes([0x6A, 0x82])
        return bytes([0x6A, 0x82])

    # ── GET_VERSION (3 frames) ────────────────────────────────────────────────

    def _get_version(self, _: bytes) -> bytes:
        hw = bytes([
            0x04,   # Vendor: NXP Semiconductors
            0x01,   # HW Type: DESFire
            0x01,   # HW Subtype: EV1
            0x01,   # Major version
            0x00,   # Minor version
            0x1A,   # Storage size code: 8 KB
            0x05,   # ISO 14443-2/3 protocol
        ])
        self._ver_step = 1
        return hw + _sw(STS_MORE)

    def _continuation(self, data: bytes) -> bytes:
        if self._auth_state == "pending":
            return self._auth_step2(data)
        if self._ver_step == 1:
            sw_info = bytes([0x04, 0x01, 0x01, 0x04, 0x00, 0x1A, 0x05])
            self._ver_step = 2
            return sw_info + _sw(STS_MORE)
        if self._ver_step == 2:
            # UID (7) + batch no (5)
            payload = self.uid + bytes([0xAB, 0xCD, 0x00, 0x01, 0x02])
            self._ver_step = 0
            return payload + _sw(STS_OK)
        return _sw(STS_ILLEGAL_CMD)

    # ── Application management ────────────────────────────────────────────────

    def _get_app_ids(self, _: bytes) -> bytes:
        return TRANSIT_AID + _sw(STS_OK)

    def _select_app(self, data: bytes) -> bytes:
        if len(data) < 3:
            return _sw(STS_LEN_ERROR)
        aid = data[:3]
        if aid in (TRANSIT_AID, MASTER_AID):
            self._selected_app = aid
            # Reset auth state on app change
            self._authenticated = False
            self._auth_state    = None
            self._session_key   = None
            return _sw(STS_OK)
        return _sw(STS_APP_NOT_FOUND)

    # ── AES Mutual Authentication ─────────────────────────────────────────────

    def _auth_step1(self, data: bytes) -> bytes:
        """Card generates RndB, returns E_key(RndB, IV=0), saves enc_rnd_b for IV chain."""
        # key_no = data[0] if data else 0x00
        self._rnd_b = os.urandom(16)
        # IV=0 for first frame
        enc = _aes_cbc_enc(self.TERMINAL_KEY, bytes(16), self._rnd_b)
        self._enc_rnd_b = enc   # save for IV chaining in step 2
        self._auth_state = "pending"
        return enc + _sw(STS_MORE)

    def _auth_step2(self, data: bytes) -> bytes:
        """
        Verify terminal's E(RndA||RndB') and return E(RndA') to complete auth.

        DESFire EV1 IV chaining:
          - step 2 decrypt uses IV = enc_rnd_b (last frame sent by card)
          - step 3 encrypt uses IV = last 16 bytes of step 2 ciphertext received
        """
        if len(data) < 32:
            self._auth_state = None
            return _sw(STS_AUTH_ERROR)
        # Decrypt with IV = enc_rnd_b (the 16 bytes we sent in step 1)
        iv_step2 = self._enc_rnd_b
        dec       = _aes_cbc_dec(self.TERMINAL_KEY, iv_step2, data[:32])
        rnd_a     = dec[:16]
        rnd_b_rot = dec[16:32]
        if rnd_b_rot != _rotate_left(self._rnd_b):
            self._auth_state = None
            return _sw(STS_AUTH_ERROR)
        self._rnd_a = rnd_a
        # DESFire EV1 AES session key: RndA[0:4]+RndB[0:4]+RndA[12:16]+RndB[12:16]
        self._session_key = (
            rnd_a[:4] + self._rnd_b[:4] +
            rnd_a[12:16] + self._rnd_b[12:16]
        )
        self._session_iv = bytes(16)
        # Step 3: encrypt rotate(RndA) with auth key, IV = last 16 bytes of ciphertext received
        iv_step3 = data[16:32]   # last block of terminal's ciphertext
        enc_rnd_a_prime = _aes_cbc_enc(self.TERMINAL_KEY, iv_step3, _rotate_left(rnd_a))
        self._authenticated = True
        self._auth_state    = "done"
        return enc_rnd_a_prime + _sw(STS_OK)

    # ── File commands ─────────────────────────────────────────────────────────

    def _get_file_ids(self, _: bytes) -> bytes:
        if self._selected_app != TRANSIT_AID:
            return _sw(STS_PERMISSION)
        return bytes([FILE_BALANCE, FILE_TXLOG]) + _sw(STS_OK)

    def _get_file_settings(self, data: bytes) -> bytes:
        fn = data[0] if data else 0xFF
        if fn == FILE_BALANCE:
            lower = struct.pack("<i", 0)
            upper = struct.pack("<i", 2_000_000)  # 20 000 MXN max
            val   = struct.pack("<i", self.balance)
            return bytes([
                0x02,         # File type: Value
                0x03,         # CommMode: AES enciphered
                0x11, 0x1F,   # Access: Read=key1, Write=key1, RW=key1, CAR=free
            ]) + lower + upper + val + bytes([0x00]) + _sw(STS_OK)
        if fn == FILE_TXLOG:
            n = min(len(self.trip_log), 10)
            return bytes([
                0x01,              # File type: Linear Record
                0x03,              # CommMode: AES enciphered
                0xEE, 0xEE,        # Access: all free (demo)
                0x1C, 0x00, 0x00,  # Record size: 28 bytes
                0x0A, 0x00, 0x00,  # Max records: 10
                n,    0x00, 0x00,  # Current record count
            ]) + _sw(STS_OK)
        return _sw(STS_FILE_NOT_FOUND)

    def _get_value(self, data: bytes) -> bytes:
        fn = data[0] if data else 0xFF
        if fn != FILE_BALANCE:
            return _sw(STS_FILE_NOT_FOUND)
        if not self._authenticated:
            return _sw(STS_PERMISSION)
        return struct.pack("<i", self.balance) + _sw(STS_OK)

    def _debit_value(self, data: bytes) -> bytes:
        """DEBIT_VALUE: FileNo(1) | Amount LE-4 | [terminal-MAC 8]."""
        if not self._authenticated:
            return _sw(STS_PERMISSION)
        if len(data) < 5:
            return _sw(STS_LEN_ERROR)
        fn     = data[0]
        amount = struct.unpack("<I", data[1:5])[0]
        if fn != FILE_BALANCE:
            return _sw(STS_FILE_NOT_FOUND)
        if amount > self.balance:
            return _sw(STS_INSUFFICIENT)
        self._pending     = True
        self._pending_amt = amount
        # Compute 8-byte CMAC over INS + command data as response MAC
        mac_input = bytes([CMD_DEBIT_VALUE]) + data[:5]
        mac = _cmac(self._session_key or bytes(16), mac_input)[:8]
        return mac + _sw(STS_OK)

    def _commit(self, _: bytes) -> bytes:
        if not self._pending:
            return _sw(STS_NO_CHANGE)
        self.balance -= self._pending_amt
        self.trip_log.append(TripRecord(self._pending_amt, self.balance))
        self._pending     = False
        self._pending_amt = 0
        return _sw(STS_OK)

    def _abort(self, _: bytes) -> bytes:
        self._pending     = False
        self._pending_amt = 0
        return _sw(STS_OK)

    def _read_records(self, data: bytes) -> bytes:
        fn = data[0] if data else 0xFF
        if fn != FILE_TXLOG:
            return _sw(STS_FILE_NOT_FOUND)
        if not self.trip_log:
            return _sw(STS_NO_CHANGE)
        records = b""
        for tr in self.trip_log[-10:]:
            # 28-byte record: amount(4) + balance(4) + timestamp(4) + padding(16)
            records += (
                struct.pack("<i", tr.amount_centavos) +
                struct.pack("<i", tr.balance_after) +
                struct.pack("<I", int(tr.timestamp)) +
                bytes(16)
            )
        return records + _sw(STS_OK)
