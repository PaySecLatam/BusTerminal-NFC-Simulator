"""EMV APDU command builders and response parser."""

from dataclasses import dataclass
from typing import Optional


SW_DESCRIPTIONS = {
    0x9000: "Success",
    0x6100: "Response bytes available",
    0x6200: "Warning: no info",
    0x6281: "Warning: returned data may be corrupted",
    0x6282: "Warning: EOF reached",
    0x6283: "Warning: selected file invalidated",
    0x6284: "Warning: FCI not formatted per ISO7816",
    0x6300: "Warning: auth failed",
    0x6381: "Warning: file filled up",
    0x6700: "Error: wrong length",
    0x6800: "Error: function not supported",
    0x6881: "Error: logical channel not supported",
    0x6882: "Error: secure messaging not supported",
    0x6900: "Error: command not allowed",
    0x6981: "Error: command incompatible with file structure",
    0x6982: "Error: security status not satisfied",
    0x6983: "Error: authentication method blocked",
    0x6984: "Error: referenced data invalidated",
    0x6985: "Error: conditions not satisfied",
    0x6986: "Error: command not allowed (no EF selected)",
    0x6987: "Error: expected SM data objects missing",
    0x6988: "Error: SM data objects incorrect",
    0x6A00: "Error: wrong parameter(s) P1/P2",
    0x6A80: "Error: incorrect parameters in data field",
    0x6A81: "Error: function not supported",
    0x6A82: "Error: file not found",
    0x6A83: "Error: record not found",
    0x6A84: "Error: not enough memory",
    0x6A85: "Error: Lc inconsistent with TLV structure",
    0x6A86: "Error: incorrect P1/P2",
    0x6A87: "Error: Lc inconsistent with P1/P2",
    0x6A88: "Error: referenced data not found",
    0x6B00: "Error: wrong parameter(s) P1/P2",
    0x6C00: "Error: wrong Le length",
    0x6D00: "Error: instruction code not supported",
    0x6E00: "Error: class not supported",
    0x6F00: "Error: no precise diagnosis",
}

PPSE = b"2PAY.SYS.DDF01"  # Contactless PPSE


@dataclass
class APDUResponse:
    data: bytes
    sw1: int
    sw2: int

    @property
    def sw(self) -> int:
        return (self.sw1 << 8) | self.sw2

    @property
    def success(self) -> bool:
        return self.sw == 0x9000 or self.sw1 == 0x61

    @property
    def sw_str(self) -> str:
        key = (self.sw1 << 8) | (self.sw2 & 0xFF00 if self.sw2 != self.sw2 else 0)
        desc = SW_DESCRIPTIONS.get(self.sw)
        if not desc:
            desc = SW_DESCRIPTIONS.get((self.sw1 << 8), "Unknown")
        return f"{self.sw1:02X}{self.sw2:02X} - {desc or 'Unknown'}"

    @property
    def full_hex(self) -> str:
        return self.data.hex().upper() + f" {self.sw1:02X}{self.sw2:02X}"


def _send(connection, apdu: list[int]) -> APDUResponse:
    data, sw1, sw2 = connection.transmit(apdu)
    resp = APDUResponse(data=bytes(data), sw1=sw1, sw2=sw2)
    if sw1 == 0x61:
        get_response = [0x00, 0xC0, 0x00, 0x00, sw2]
        data2, sw1b, sw2b = connection.transmit(get_response)
        resp = APDUResponse(data=bytes(data2), sw1=sw1b, sw2=sw2b)
    return resp


def select_ppse(connection) -> APDUResponse:
    apdu = [0x00, 0xA4, 0x04, 0x00, len(PPSE)] + list(PPSE) + [0x00]
    return _send(connection, apdu)


def select_aid(connection, aid: bytes) -> APDUResponse:
    apdu = [0x00, 0xA4, 0x04, 0x00, len(aid)] + list(aid) + [0x00]
    return _send(connection, apdu)


def get_processing_options(connection, pdol_data: bytes) -> APDUResponse:
    data_field = [0x83, len(pdol_data)] + list(pdol_data)
    apdu = [0x80, 0xA8, 0x00, 0x00, len(data_field)] + data_field + [0x00]
    return _send(connection, apdu)


def read_record(connection, record_number: int, sfi: int) -> APDUResponse:
    p2 = (sfi << 3) | 0x04
    apdu = [0x00, 0xB2, record_number, p2, 0x00]
    return _send(connection, apdu)


def generate_ac(connection, ref_ctrl: int, cdol_data: bytes) -> APDUResponse:
    """ref_ctrl P1 bits b8b7: 0x00=AAC (decline), 0x40=TC (offline approve), 0x80=ARQC (request online)"""
    apdu = [0x80, 0xAE, ref_ctrl, 0x00, len(cdol_data)] + list(cdol_data) + [0x00]
    return _send(connection, apdu)


def compute_cryptographic_checksum(connection, un: bytes, amount: bytes) -> APDUResponse:
    """Visa payWave COMPUTE CRYPTOGRAPHIC CHECKSUM command."""
    data = list(un) + list(amount)
    apdu = [0x80, 0x2A, 0x8E, 0x80, len(data)] + data + [0x00]
    return _send(connection, apdu)


def get_data(connection, tag: int) -> APDUResponse:
    p1 = (tag >> 8) & 0xFF
    p2 = tag & 0xFF
    apdu = [0x80, 0xCA, p1, p2, 0x00]
    return _send(connection, apdu)


def internal_authenticate(connection, ddol_data: bytes) -> APDUResponse:
    apdu = [0x00, 0x88, 0x00, 0x00, len(ddol_data)] + list(ddol_data) + [0x00]
    return _send(connection, apdu)


def verify_pin(connection, pin: str) -> APDUResponse:
    pin_block = _build_plaintext_pin_block(pin)
    apdu = [0x00, 0x20, 0x00, 0x80, len(pin_block)] + list(pin_block)
    return _send(connection, apdu)


def _build_plaintext_pin_block(pin: str) -> bytes:
    pin_len = len(pin)
    block = f"2{pin_len:X}" + pin + "F" * (14 - pin_len)
    return bytes.fromhex(block)
