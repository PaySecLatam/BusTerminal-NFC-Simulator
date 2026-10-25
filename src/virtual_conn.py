"""
Virtual PC/SC connection — routes APDUs to a DESFireCard simulator.

Implements the same interface as pyscard's CardConnection so it can be
dropped in anywhere a real connection object is expected.

Usage:
    card = DESFireCard("04A1B2C3D4E5F6", balance_centavos=15000)
    conn = VirtualConnection(card)
    # conn.transmit(apdu) behaves exactly like a real pyscard connection
"""

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from .desfire_sim import DESFireCard


class ApduEntry:
    """One APDU exchange recorded in the session log."""
    def __init__(
        self,
        direction: str,
        label: str,
        cmd_bytes: bytes,
        resp_bytes: bytes,
        sw1: int,
        sw2: int,
    ):
        self.direction  = direction
        self.label      = label
        self.cmd_bytes  = cmd_bytes
        self.resp_bytes = resp_bytes
        self.sw1        = sw1
        self.sw2        = sw2

    def to_dict(self) -> dict:
        cmd_hex  = " ".join(f"{b:02X}" for b in self.cmd_bytes)
        resp_hex = " ".join(f"{b:02X}" for b in self.resp_bytes)
        return {
            "direction": self.direction,
            "label":     self.label,
            "command":   cmd_hex,
            "response":  resp_hex,
            "sw":        f"{self.sw1:02X}{self.sw2:02X}",
            "sw_ok":     (self.sw1 == 0x90 and self.sw2 == 0x00)
                         or (self.sw1 == 0x91 and self.sw2 == 0x00)
                         or (self.sw1 == 0x91 and self.sw2 == 0xAF),
        }


_APDU_NAMES: dict[tuple, str] = {
    # (CLA, INS)
    (0x00, 0xA4): "ISO SELECT APPLICATION",
    (0x00, 0xC0): "GET RESPONSE",
    (0x90, 0x60): "GET_VERSION",
    (0x90, 0x6A): "GET_APPLICATION_IDs",
    (0x90, 0x5A): "SELECT_APPLICATION",
    (0x90, 0xAA): "AUTHENTICATE_AES (step 1 — send key no.)",
    (0x90, 0xAF): "ADDITIONAL_FRAME (step 2 or next frame)",
    (0x90, 0x6F): "GET_FILE_IDs",
    (0x90, 0xF5): "GET_FILE_SETTINGS",
    (0x90, 0x6C): "GET_VALUE",
    (0x90, 0xDC): "DEBIT_VALUE",
    (0x90, 0xC7): "COMMIT_TRANSACTION",
    (0x90, 0xA7): "ABORT_TRANSACTION",
    (0x90, 0xBB): "READ_RECORDS",
}


def _label(apdu: list[int]) -> str:
    if len(apdu) < 2:
        return "UNKNOWN"
    return _APDU_NAMES.get((apdu[0], apdu[1]), f"CMD {apdu[0]:02X} {apdu[1]:02X}")


class VirtualConnection:
    """
    Fake pyscard CardConnection that routes APDUs to a DESFireCard instance.

    The `transmit` method signature matches pyscard exactly:
        data, sw1, sw2 = conn.transmit([0x90, 0xAA, 0x00, 0x00, ...])
    """

    def __init__(self, card: "DESFireCard"):
        self._card = card
        self._log: list[ApduEntry] = []
        self._card.reset()

    # ── pyscard-compatible interface ─────────────────────────────────────────

    def transmit(self, apdu: list[int]) -> tuple[list[int], int, int]:
        raw     = bytes(apdu)
        label   = _label(apdu)
        resp    = self._card.process_apdu(raw)

        # Last 2 bytes of DESFire response are the status word
        if len(resp) >= 2:
            data_part = resp[:-2]
            sw1, sw2  = resp[-2], resp[-1]
        else:
            data_part = b""
            sw1, sw2  = 0x6F, 0x00

        self._log.append(ApduEntry(
            direction  = ">>",
            label      = label,
            cmd_bytes  = raw,
            resp_bytes = resp,
            sw1        = sw1,
            sw2        = sw2,
        ))

        return list(data_part), sw1, sw2

    def connect(self):
        self._card.reset()
        self._log.clear()

    def disconnect(self):
        pass

    def getATR(self) -> list[int]:
        # Synthetic ATR for DESFire EV1 over ISO 14443-4
        return list(bytes.fromhex(
            "3B8180018080"          # minimal ISO 14443-4 ATR
        ))

    # ── Log access ───────────────────────────────────────────────────────────

    def get_log(self) -> list[ApduEntry]:
        return list(self._log)

    def get_log_dicts(self) -> list[dict]:
        return [e.to_dict() for e in self._log]
