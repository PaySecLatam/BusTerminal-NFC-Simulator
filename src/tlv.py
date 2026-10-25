"""BER-TLV parser for EMV data structures."""

from dataclasses import dataclass, field
from typing import Optional


EMV_TAGS = {
    0x6F: "FCI Template",
    0x70: "Record Template",
    0x77: "Response Message Template Format 2",
    0x80: "Response Message Template Format 1",
    0x84: "Dedicated File Name (AID)",
    0x87: "Application Priority Indicator",
    0x88: "Short File Identifier (SFI)",
    0x8C: "CDOL1",
    0x8D: "CDOL2",
    0x8E: "Cardholder Verification Method (CVM) List",
    0x8F: "Certification Authority Public Key Index",
    0x90: "Issuer Public Key Certificate",
    0x92: "Issuer Public Key Remainder",
    0x93: "Signed Static Application Data",
    0x94: "Application File Locator (AFL)",
    0xA5: "FCI Proprietary Template",
    0xBF0C: "FCI Issuer Discretionary Data",
    0x4F: "Application Identifier (AID)",
    0x50: "Application Label",
    0x57: "Track 2 Equivalent Data",
    0x5A: "Application Primary Account Number (PAN)",
    0x5F20: "Cardholder Name",
    0x5F24: "Application Expiration Date",
    0x5F25: "Application Effective Date",
    0x5F28: "Issuer Country Code",
    0x5F2A: "Transaction Currency Code",
    0x5F2D: "Language Preference",
    0x5F30: "Service Code",
    0x5F34: "Application PAN Sequence Number",
    0x61: "Application Template",
    0x6F: "FCI Template",
    0x82: "Application Interchange Profile (AIP)",
    0x9A: "Transaction Date",
    0x9C: "Transaction Type",
    0x9F02: "Amount Authorized",
    0x9F03: "Amount Other",
    0x9F05: "Application Discretionary Data",
    0x9F07: "Application Usage Control",
    0x9F08: "Application Version Number",
    0x9F0B: "Cardholder Name Extended",
    0x9F0D: "Issuer Action Code - Default",
    0x9F0E: "Issuer Action Code - Denial",
    0x9F0F: "Issuer Action Code - Online",
    0x9F10: "Issuer Application Data",
    0x9F11: "Issuer Code Table Index",
    0x9F12: "Application Preferred Name",
    0x9F13: "Last Online ATC Register",
    0x9F14: "Lower Consecutive Offline Limit",
    0x9F17: "PIN Try Counter",
    0x9F1A: "Terminal Country Code",
    0x9F1F: "Track 1 Discretionary Data",
    0x9F20: "Track 2 Discretionary Data",
    0x9F21: "Transaction Time",
    0x9F23: "Upper Consecutive Offline Limit",
    0x9F26: "Application Cryptogram (ARQC/TC/AAC)",
    0x9F27: "Cryptogram Information Data (CID)",
    0x9F2D: "ICC PIN Encipherment Public Key Certificate",
    0x9F32: "Issuer Public Key Exponent",
    0x9F34: "Cardholder Verification Method (CVM) Results",
    0x9F35: "Terminal Type",
    0x9F36: "Application Transaction Counter (ATC)",
    0x9F37: "Unpredictable Number",
    0x9F38: "Processing Options Data Object List (PDOL)",
    0x9F42: "Application Currency Code",
    0x9F44: "Application Currency Exponent",
    0x9F45: "Data Authentication Code",
    0x9F46: "ICC Public Key Certificate",
    0x9F47: "ICC Public Key Exponent",
    0x9F48: "ICC Public Key Remainder",
    0x9F49: "Dynamic Data Authentication Data Object List (DDOL)",
    0x9F4A: "Static Data Authentication Tag List",
    0x9F4B: "Signed Dynamic Application Data",
    0x9F4C: "ICC Dynamic Number",
    0x9F51: "Application Currency Code",
    0x9F52: "Application Default Action",
    0x9F53: "Consecutive Transaction Limit (International)",
    0x9F54: "Cumulative Total Transaction Amount Limit",
    0x9F55: "Geographic Indicator",
    0x9F56: "Issuer Authentication Indicator",
    0x9F57: "Issuer Country Code",
    0x9F58: "Lower Consecutive Offline Limit (International)",
    0x9F59: "Upper Consecutive Offline Limit (International)",
    0x9F5C: "Cumulative Total Transaction Amount Upper Limit",
    0x9F6C: "Mag-stripe Application Version Number (Card)",
    0x9F6D: "Mag-stripe Application Version Number (Reader)",
    0x9F6E: "Third Party Data",
    0x9F72: "Consecutive Transaction Limit (International - Currency)",
    0x9F73: "Currency Conversion Factor",
    0x9F74: "VLP Issuer Authorization Code",
    0x9F75: "Cumulative Total Transaction Amount Limit - Dual Currency",
    0x9F76: "Secondary Application Currency Code",
    0x9F77: "VLP Funds Limit",
    0x9F78: "VLP Single Transaction Limit",
    0x9F79: "VLP Available Funds",
    0xFF01: "Maestro/Mastercard Transit Data",
}

CONSTRUCTED_TAGS = {
    0x6F, 0x70, 0x77, 0xA5, 0x61, 0xBF0C,
}

CURRENCY_CODES = {
    "0484": "MXN", "0840": "USD", "0978": "EUR", "0826": "GBP",
    "0986": "BRL", "0032": "ARS", "0152": "CLP", "0170": "COP",
    "0604": "PEN", "0858": "UYU",
}

KNOWN_AIDS = {
    bytes.fromhex("A0000000031010"): ("Visa Credit/Debit", "VISA"),
    bytes.fromhex("A0000000032010"): ("Visa Electron", "VE"),
    bytes.fromhex("A0000000033010"): ("Visa Interlink", "VI"),
    bytes.fromhex("A0000000038010"): ("Visa Plus", "VP"),
    bytes.fromhex("A0000000041010"): ("Mastercard Credit/Debit", "MC"),
    bytes.fromhex("A0000000043060"): ("Maestro", "MAESTRO"),
    bytes.fromhex("A0000000050001"): ("Mastercard Maestro UK", "MAESTRO-UK"),
    bytes.fromhex("A0000000651010"): ("JCB", "JCB"),
    bytes.fromhex("A000000025010801"): ("American Express", "AMEX"),
    bytes.fromhex("A0000003241010"): ("Discover", "DISCOVER"),
    bytes.fromhex("A000000333010101"): ("China Union Pay Credit", "CUP"),
    bytes.fromhex("A000000333010102"): ("China Union Pay Debit", "CUP"),
    bytes.fromhex("A0000004766C"): ("Google Pay", "GPAY"),
    bytes.fromhex("A000000620"): ("Interac", "INTERAC"),
    bytes.fromhex("A000000840"): ("Humo", "HUMO"),
    bytes.fromhex("D27600002545500100"): ("MIFARE DESFire", "MIFARE"),
}


@dataclass
class TLV:
    tag: int
    length: int
    value: bytes
    children: list = field(default_factory=list)

    @property
    def tag_name(self) -> str:
        return EMV_TAGS.get(self.tag, f"Unknown Tag [{self.tag:04X}]")

    @property
    def tag_hex(self) -> str:
        if self.tag > 0xFF:
            return f"{self.tag:04X}"
        return f"{self.tag:02X}"

    @property
    def value_hex(self) -> str:
        return self.value.hex().upper()

    def is_constructed(self) -> bool:
        return bool(self.tag & 0x20) or self.tag in CONSTRUCTED_TAGS

    def find(self, tag: int) -> Optional["TLV"]:
        if self.tag == tag:
            return self
        for child in self.children:
            result = child.find(tag)
            if result:
                return result
        return None

    def find_all(self, tag: int) -> list:
        results = []
        if self.tag == tag:
            results.append(self)
        for child in self.children:
            results.extend(child.find_all(tag))
        return results


def _read_tag(data: bytes, offset: int) -> tuple[int, int]:
    b = data[offset]
    if (b & 0x1F) == 0x1F:
        tag = b
        offset += 1
        while True:
            b = data[offset]
            tag = (tag << 8) | b
            offset += 1
            if not (b & 0x80):
                break
    else:
        tag = b
        offset += 1
    return tag, offset


def _read_length(data: bytes, offset: int) -> tuple[int, int]:
    b = data[offset]
    offset += 1
    if b & 0x80:
        num_bytes = b & 0x7F
        length = 0
        for _ in range(num_bytes):
            length = (length << 8) | data[offset]
            offset += 1
    else:
        length = b
    return length, offset


def parse_tlv(data: bytes) -> list[TLV]:
    results = []
    offset = 0
    while offset < len(data):
        if data[offset] == 0x00 or data[offset] == 0xFF:
            offset += 1
            continue
        try:
            tag, offset = _read_tag(data, offset)
            length, offset = _read_length(data, offset)
            value = data[offset:offset + length]
            offset += length
            node = TLV(tag=tag, length=length, value=value)
            if node.is_constructed():
                node.children = parse_tlv(value)
            results.append(node)
        except (IndexError, ValueError):
            break
    return results


def find_tag(data: bytes, tag: int) -> Optional[bytes]:
    nodes = parse_tlv(data)
    for node in nodes:
        result = node.find(tag)
        if result:
            return result.value
    return None


def parse_dol(dol_bytes: bytes) -> list[tuple[int, int]]:
    """Parse a Data Object List (PDOL, CDOL) into (tag, length) pairs."""
    entries = []
    offset = 0
    while offset < len(dol_bytes):
        if dol_bytes[offset] in (0x00, 0xFF):
            offset += 1
            continue
        try:
            tag, offset = _read_tag(dol_bytes, offset)
            length = dol_bytes[offset]
            offset += 1
            entries.append((tag, length))
        except IndexError:
            break
    return entries


def build_dol_data(dol_entries: list[tuple[int, int]], terminal_data: dict) -> bytes:
    """Build DOL data from terminal data dict, padding missing fields with zeros."""
    result = b""
    for tag, length in dol_entries:
        value = terminal_data.get(tag, bytes(length))
        if len(value) < length:
            value = value.ljust(length, b"\x00")
        result += value[:length]
    return result


def format_pan(pan_bytes: bytes) -> str:
    pan = pan_bytes.hex().upper().rstrip("F")
    return " ".join(pan[i:i+4] for i in range(0, len(pan), 4))


def format_date(date_bytes: bytes) -> str:
    d = date_bytes.hex()
    if len(d) == 6:
        return f"20{d[0:2]}/{d[2:4]}/{d[4:6]}"
    return date_bytes.hex().upper()


def decode_aip(aip: bytes) -> list[str]:
    caps = []
    b1, b2 = aip[0], aip[1]
    if b1 & 0x40: caps.append("SDA")
    if b1 & 0x20: caps.append("DDA")
    if b1 & 0x10: caps.append("Cardholder Verification")
    if b1 & 0x08: caps.append("Terminal Risk Management")
    if b1 & 0x04: caps.append("Issuer Authentication")
    if b1 & 0x01: caps.append("CDA")
    if b2 & 0x20: caps.append("EMV Mode")
    if b2 & 0x40: caps.append("Mag-stripe Mode")
    return caps


def decode_cid(cid_byte: int) -> str:
    ac_type = (cid_byte >> 6) & 0x03
    return {0: "AAC (Declined)", 1: "TC (Approved Offline)", 2: "ARQC (Online Auth Required)", 3: "Reserved"}[ac_type]
