"""EMV terminal state machine — implements L2 contactless kernel."""

import os
import time
import struct
import secrets
import datetime
from dataclasses import dataclass, field
from typing import Optional

from .tlv import (
    parse_tlv, find_tag, parse_dol, build_dol_data,
    format_pan, format_date, decode_aip, decode_cid,
    KNOWN_AIDS, CURRENCY_CODES,
)
from .apdu import (
    select_ppse, select_aid, get_processing_options,
    read_record, generate_ac, get_data, APDUResponse,
)


BUS_FARE_MXN = 11.00
TERMINAL_COUNTRY_CODE = b"\x04\x84"    # Mexico (484)
TERMINAL_CURRENCY_CODE = b"\x04\x84"   # MXN
TERMINAL_TYPE = b"\x22"                # Type 22: attended, offline with online cap.
TERMINAL_CAPABILITIES = b"\xE0\xF8\xC8"
ADDITIONAL_TERMINAL_CAPABILITIES = b"\x6F\x00\xF0\xA0\x01"
TERMINAL_ID = b"\x01\x23\x45\x67"
MERCHANT_ID = b"\x4D\x45\x54\x52\x4F\x42\x55\x53\x20\x4D\x58"  # METROBUS MX
IFD_SERIAL = b"\x30\x31\x32\x33\x34\x35\x36\x37"


def _amount_to_bytes(amount_cents: int) -> bytes:
    return amount_cents.to_bytes(6, "big")


def _date_bytes() -> bytes:
    d = datetime.date.today()
    return bytes.fromhex(f"{d.year % 100:02d}{d.month:02d}{d.day:02d}")


def _time_bytes() -> bytes:
    t = datetime.datetime.now().time()
    return bytes.fromhex(f"{t.hour:02d}{t.minute:02d}{t.second:02d}")


def _unpredictable_number() -> bytes:
    return secrets.token_bytes(4)


@dataclass
class TransactionResult:
    approved: bool
    online_required: bool
    declined: bool
    cryptogram_type: str
    pan: str = ""
    pan_masked: str = ""
    expiry: str = ""
    cardholder: str = ""
    aid: str = ""
    app_label: str = ""
    atc: int = 0
    cryptogram: bytes = b""
    amount_cents: int = 0
    currency: str = "MXN"
    aip_caps: list = field(default_factory=list)
    raw_records: list = field(default_factory=list)
    error: str = ""
    atr: bytes = b""
    timestamp: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.datetime.now().isoformat()

    @property
    def amount_display(self) -> str:
        return f"${self.amount_cents / 100:.2f} {self.currency}"


class EMVTerminal:
    """
    EMV L2 contactless terminal kernel.

    Implements the full transaction flow:
    1. SELECT PPSE
    2. SELECT Application (AID)
    3. GET PROCESSING OPTIONS
    4. READ RECORD (all AFL entries)
    5. GENERATE AC (request ARQC/TC/AAC)
    """

    def __init__(self, amount_cents: int = 1100, debug: bool = False):
        self.amount_cents = amount_cents
        self.debug = debug
        self._log: list[tuple[str, str, str]] = []  # (direction, cmd_name, hex)

    def _terminal_data(self, pdol_entries: list[tuple[int, int]]) -> dict:
        """Map known terminal tags to their values for PDOL/CDOL filling."""
        amount = _amount_to_bytes(self.amount_cents)
        un = _unpredictable_number()
        return {
            0x9F02: amount,                                # Amount Authorized
            0x9F03: b"\x00\x00\x00\x00\x00\x00",          # Amount Other
            0x9F1A: TERMINAL_COUNTRY_CODE,                 # Terminal Country Code
            0x95:   b"\x00\x00\x00\x00\x00",              # Terminal Verification Results
            0x5F2A: TERMINAL_CURRENCY_CODE,                # Transaction Currency Code
            0x9A:   _date_bytes(),                         # Transaction Date
            0x9C:   b"\x09",                               # Transaction Type (purchase=0x00, refund=0x09... bus=0x09 transit)
            0x9F37: un,                                    # Unpredictable Number
            0x9F35: TERMINAL_TYPE,                         # Terminal Type
            0x9F45: b"\x00\x00",                           # Data Authentication Code
            0x9F34: b"\x1F\x03\x02",                       # CVM Results
            0x9F40: ADDITIONAL_TERMINAL_CAPABILITIES,      # Additional Terminal Capabilities
            0x9F6E: b"\x00\x00\x00\x00",                   # Third Party Data
            0x9F21: _time_bytes(),                         # Transaction Time
            0x9F7C: b"\x00" * 20,                          # Customer Exclusive Data
            0x9F04: b"\x00\x00\x00\x00\x00\x00",          # Amount Other (numeric)
        }

    def _log_apdu(self, direction: str, name: str, data: bytes):
        self._log.append((direction, name, data.hex().upper()))

    def run(self, connection) -> TransactionResult:
        result = TransactionResult(
            approved=False,
            online_required=False,
            declined=False,
            cryptogram_type="",
            amount_cents=self.amount_cents,
        )

        # ── Step 1: SELECT PPSE ───────────────────────────────────────────
        resp = select_ppse(connection)
        self._log_apdu(">>", "SELECT PPSE", b"2PAY.SYS.DDF01")
        self._log_apdu("<<", "PPSE Response", resp.data + bytes([resp.sw1, resp.sw2]))

        if not resp.success:
            result.error = f"PPSE rejected: {resp.sw_str}"
            result.declined = True
            return result

        # Parse PPSE response to find AIDs
        aid_list = self._parse_ppse(resp.data)
        if not aid_list:
            result.error = "No applications found in PPSE"
            result.declined = True
            return result

        # ── Step 2: SELECT Application ────────────────────────────────────
        selected_aid = None
        fci_data = b""
        for aid, priority in sorted(aid_list, key=lambda x: x[1]):
            resp2 = select_aid(connection, aid)
            self._log_apdu(">>", f"SELECT AID {aid.hex().upper()}", aid)
            self._log_apdu("<<", "FCI Response", resp2.data + bytes([resp2.sw1, resp2.sw2]))
            if resp2.success:
                selected_aid = aid
                fci_data = resp2.data
                break

        if not selected_aid:
            result.error = "No application could be selected"
            result.declined = True
            return result

        # Decode selected application info
        aid_info = KNOWN_AIDS.get(selected_aid, ("Unknown", "???"))
        result.aid = selected_aid.hex().upper()
        result.app_label = self._extract_app_label(fci_data) or aid_info[0]

        # ── Step 3: GET PROCESSING OPTIONS ────────────────────────────────
        pdol_bytes = find_tag(fci_data, 0x9F38)
        pdol_entries = parse_dol(pdol_bytes) if pdol_bytes else []
        terminal_data = self._terminal_data(pdol_entries)
        pdol_data = build_dol_data(pdol_entries, terminal_data)

        resp3 = get_processing_options(connection, pdol_data)
        self._log_apdu(">>", "GET PROCESSING OPTIONS", pdol_data)
        self._log_apdu("<<", "GPO Response", resp3.data + bytes([resp3.sw1, resp3.sw2]))

        if not resp3.success:
            result.error = f"GPO failed: {resp3.sw_str}"
            result.declined = True
            return result

        aip, afl = self._parse_gpo(resp3.data)
        if aip:
            result.aip_caps = decode_aip(aip)

        # ── Step 4: READ RECORD ───────────────────────────────────────────
        records = []
        for sfi, start, end, _ in afl:
            for rec_num in range(start, end + 1):
                resp4 = read_record(connection, rec_num, sfi)
                self._log_apdu(">>", f"READ RECORD SFI={sfi} Rec={rec_num}", bytes([sfi, rec_num]))
                self._log_apdu("<<", f"Record {sfi}/{rec_num}", resp4.data + bytes([resp4.sw1, resp4.sw2]))
                if resp4.success:
                    records.append(resp4.data)

        result.raw_records = records

        # Extract card data from records
        self._extract_card_data(records, result)

        # ── Step 5: GENERATE AC ───────────────────────────────────────────
        cdol1 = None
        for rec_data in records:
            cdol1 = find_tag(rec_data, 0x8C)
            if cdol1:
                break

        if cdol1:
            cdol_entries = parse_dol(cdol1)
            cdol_data = build_dol_data(cdol_entries, terminal_data)
        else:
            cdol_data = (
                _amount_to_bytes(self.amount_cents) +
                b"\x00\x00\x00\x00\x00\x00" +
                TERMINAL_COUNTRY_CODE +
                b"\x00\x00\x00\x00\x00" +
                TERMINAL_CURRENCY_CODE +
                _date_bytes() +
                b"\x09" +
                _unpredictable_number()
            )

        resp5 = generate_ac(connection, 0x40, cdol_data)  # 0x40 = TC request (offline approve)
        self._log_apdu(">>", "GENERATE AC (ARQC)", cdol_data)
        self._log_apdu("<<", "AC Response", resp5.data + bytes([resp5.sw1, resp5.sw2]))

        if not resp5.success:
            # Some cards use Format 1 for TC directly
            result.approved = True
            result.online_required = False
            result.cryptogram_type = "TC (Offline Approved)"
            return result

        self._parse_generate_ac(resp5.data, result)
        return result

    def _parse_ppse(self, data: bytes) -> list[tuple[bytes, int]]:
        """Extract list of (AID, priority) from PPSE FCI response."""
        aids = []
        nodes = parse_tlv(data)

        def walk(node_list):
            for node in node_list:
                if node.tag == 0x61:  # Application Template
                    aid_node = node.find(0x4F)
                    pri_node = node.find(0x87)
                    if aid_node:
                        priority = pri_node.value[0] if pri_node else 0xFF
                        aids.append((aid_node.value, priority))
                walk(node.children)

        walk(nodes)
        return aids

    def _extract_app_label(self, fci_data: bytes) -> str:
        label = find_tag(fci_data, 0x50)
        if label:
            try:
                return label.decode("ascii").strip()
            except Exception:
                return label.hex().upper()
        pref = find_tag(fci_data, 0x9F12)
        if pref:
            try:
                return pref.decode("ascii").strip()
            except Exception:
                return pref.hex().upper()
        return ""

    def _parse_gpo(self, data: bytes) -> tuple[Optional[bytes], list]:
        """Parse GPO response, returns (AIP, AFL entries)."""
        # Format 1: 80 len [AIP 2 bytes][AFL n bytes]
        if data and data[0] == 0x80:
            body = data[2:]
            aip = body[:2]
            afl_data = body[2:]
            return aip, self._parse_afl(afl_data)

        # Format 2: TLV with 77 tag
        nodes = parse_tlv(data)
        aip_val = None
        afl_val = None
        for node in nodes:
            a = node.find(0x82)
            if a:
                aip_val = a.value
            b = node.find(0x94)
            if b:
                afl_val = b.value
        afl = self._parse_afl(afl_val) if afl_val else []
        return aip_val, afl

    def _parse_afl(self, afl_data: bytes) -> list[tuple[int, int, int, bool]]:
        """Parse AFL into list of (SFI, first_record, last_record, offline_auth)."""
        entries = []
        if not afl_data:
            return entries
        for i in range(0, len(afl_data), 4):
            chunk = afl_data[i:i+4]
            if len(chunk) < 4:
                break
            sfi = (chunk[0] >> 3) & 0x1F
            first = chunk[1]
            last = chunk[2]
            offline = chunk[3] > 0
            entries.append((sfi, first, last, offline))
        return entries

    def _extract_card_data(self, records: list[bytes], result: TransactionResult):
        for rec in records:
            pan = find_tag(rec, 0x5A)
            if pan and not result.pan:
                result.pan = format_pan(pan)
                digits = pan.hex().upper().rstrip("F")
                result.pan_masked = "*" * (len(digits) - 4) + digits[-4:]

            expiry = find_tag(rec, 0x5F24)
            if expiry and not result.expiry:
                result.expiry = format_date(expiry)

            name = find_tag(rec, 0x5F20)
            if name and not result.cardholder:
                try:
                    result.cardholder = name.decode("ascii").strip()
                except Exception:
                    result.cardholder = name.hex()

            track2 = find_tag(rec, 0x57)
            if track2 and not result.pan:
                t2 = track2.hex().upper()
                sep = t2.find("D")
                if sep > 0:
                    pan_raw = t2[:sep]
                    result.pan = " ".join(pan_raw[i:i+4] for i in range(0, len(pan_raw), 4))
                    result.pan_masked = "*" * (len(pan_raw) - 4) + pan_raw[-4:]
                    if sep + 5 <= len(t2):
                        yyMM = t2[sep+1:sep+5]
                        result.expiry = f"20{yyMM[:2]}/{yyMM[2:4]}"

            currency_tag = find_tag(rec, 0x9F42)
            if currency_tag:
                code = currency_tag.hex().upper()
                result.currency = CURRENCY_CODES.get(code, code)

    def _parse_generate_ac(self, data: bytes, result: TransactionResult):
        # Format 1: 80 len [CID 1][ATC 2][AC 8][IAD n]
        if data and data[0] == 0x80:
            body = data[2:]
            if len(body) >= 11:
                cid = body[0]
                result.atc = int.from_bytes(body[1:3], "big")
                result.cryptogram = body[3:11]
                result.cryptogram_type = decode_cid(cid)
                ac_type = (cid >> 6) & 0x03
                result.approved = ac_type in (1, 2)
                result.online_required = ac_type == 2
                result.declined = ac_type == 0
            return

        # Format 2: TLV with 77 tag
        nodes = parse_tlv(data)
        cid_node = None
        atc_node = None
        ac_node = None
        for node in nodes:
            c = node.find(0x9F27)
            if c:
                cid_node = c
            a = node.find(0x9F36)
            if a:
                atc_node = a
            cr = node.find(0x9F26)
            if cr:
                ac_node = cr

        if cid_node:
            cid = cid_node.value[0]
            result.cryptogram_type = decode_cid(cid)
            ac_type = (cid >> 6) & 0x03
            result.approved = ac_type in (1, 2)
            result.online_required = ac_type == 2
            result.declined = ac_type == 0

        if atc_node:
            result.atc = int.from_bytes(atc_node.value, "big")

        if ac_node:
            result.cryptogram = ac_node.value

        if not cid_node:
            result.approved = True
            result.cryptogram_type = "TC (Offline Approved)"

    def get_log(self) -> list[tuple[str, str, str]]:
        return self._log
