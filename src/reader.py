"""NFC reader detection and card connection management via PC/SC."""

import time
import threading
from typing import Callable, Optional
from smartcard.System import readers
from smartcard.CardMonitoring import CardMonitor, CardObserver
from smartcard.ReaderMonitoring import ReaderMonitor, ReaderObserver
from smartcard.CardType import AnyCardType
from smartcard.CardRequest import CardRequest
from smartcard.util import toHexString


class NFCReaderObserver(ReaderObserver):
    def __init__(self, on_added: Callable, on_removed: Callable):
        self.on_added = on_added
        self.on_removed = on_removed

    def update(self, observable, actions):
        added, removed = actions
        for reader in added:
            self.on_added(reader)
        for reader in removed:
            self.on_removed(reader)


class CardEventObserver(CardObserver):
    def __init__(self, on_inserted: Callable, on_removed: Callable):
        self.on_inserted = on_inserted
        self.on_removed = on_removed

    def update(self, observable, actions):
        added, removed = actions
        for card in added:
            self.on_inserted(card)
        for card in removed:
            self.on_removed(card)


def get_available_readers() -> list:
    try:
        return readers()
    except Exception:
        return []


def atr_to_card_type(atr: list) -> str:
    """Best-effort identification from ATR."""
    if not atr:
        return "Unknown"
    atr_hex = bytes(atr).hex().upper()

    # ── NFC / contactless cards ───────────────────────────────────────────────
    # DESFire EV1/EV2 — PC/SC wrapper ATR
    if atr_hex.startswith("3B8180018080"):
        return "NFC ISO 14443-A (DESFire / MIFARE)"
    if "04" in atr_hex[:6] and atr_hex.startswith("3B"):
        # Short ATR with historical bytes starting with 0x04 = NXP NFC
        pass

    if atr_hex.startswith("3B8F8001804F0CA0000003064"):
        return "MIFARE Classic 1K"
    if atr_hex.startswith("3B8F8001804F0CA0000003"):
        return "MIFARE (NFC ISO 14443-A)"
    if atr_hex.startswith("3B8F80018031"):
        return "MIFARE DESFire (ISO 14443-A)"

    # PC/SC contactless wrapper (T=CL):  3B 8x 80 01 ...
    if atr_hex.startswith("3B8") and "8001" in atr_hex:
        return "NFC Contactless ISO 14443"

    if "A000000003" in atr_hex:
        return "Visa EMV Contactless"
    if "A000000004" in atr_hex:
        return "Mastercard EMV Contactless"

    # ── Contact cards ─────────────────────────────────────────────────────────
    if len(atr) >= 1:
        if atr[0] == 0x3B:
            return "ISO 7816 Contact"
        if atr[0] == 0x3F:
            return "ISO 7816 Inverse Convention"

    return "Desconocido"


def connect_card(reader) -> Optional[object]:
    try:
        conn = reader.createConnection()
        conn.connect()
        return conn
    except Exception:
        try:
            from smartcard.scard import SCARD_PROTOCOL_T0, SCARD_PROTOCOL_T1
            conn = reader.createConnection()
            conn.connect(protocol=SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1)
            return conn
        except Exception:
            return None


def wait_for_card(reader, timeout: int = 30) -> Optional[object]:
    """Block until a card is presented to the reader or timeout."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        conn = connect_card(reader)
        if conn:
            return conn
        time.sleep(0.2)
    return None


def get_atr(connection) -> bytes:
    try:
        return bytes(connection.getATR())
    except Exception:
        return b""


def is_nfc_reader(reader_name: str) -> bool:
    nfc_keywords = [
        "contactless", "nfc", "acr122", "acr1252", "acr1255",
        "acr1281", "scm", "identiv", "omnikey", "hid", "cherry",
        "gemalto", "acs", "feitian", "rfid", "proximity",
        "acr1222", "acr101", "acr100",
    ]
    name_lower = reader_name.lower()
    return any(kw in name_lower for kw in nfc_keywords)


class ReaderManager:
    def __init__(self):
        self._reader_monitor: Optional[ReaderMonitor] = None
        self._card_monitor: Optional[CardMonitor] = None
        self._reader_observer: Optional[NFCReaderObserver] = None
        self._card_observer: Optional[CardEventObserver] = None
        self._lock = threading.Lock()

    def start_reader_monitoring(
        self,
        on_added: Callable[[object], None],
        on_removed: Callable[[object], None],
    ) -> None:
        self._reader_observer = NFCReaderObserver(on_added, on_removed)
        self._reader_monitor = ReaderMonitor()
        self._reader_monitor.addObserver(self._reader_observer)

    def start_card_monitoring(
        self,
        on_inserted: Callable[[object], None],
        on_removed: Callable[[object], None],
    ) -> None:
        self._card_observer = CardEventObserver(on_inserted, on_removed)
        self._card_monitor = CardMonitor()
        self._card_monitor.addObserver(self._card_observer)

    def stop(self) -> None:
        if self._reader_monitor and self._reader_observer:
            try:
                self._reader_monitor.deleteObserver(self._reader_observer)
            except Exception:
                pass
        if self._card_monitor and self._card_observer:
            try:
                self._card_monitor.deleteObserver(self._card_observer)
            except Exception:
                pass
