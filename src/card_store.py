"""
Persistent card registry — links real card UIDs to backend balances.

Cards are stored in data/cards.json. The balance (GTC) lives here,
not on the physical card — we only use the card UID as the identifier.

GTC = Global Transit Credit  (1 GTC = $1.00 MXN in this demo)
"""

import json
import os
import datetime
from typing import Optional

_DB_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "data", "cards.json",
)

INITIAL_GTC = 50   # default credit on enrollment


def _load() -> dict:
    if not os.path.exists(_DB_PATH):
        return {}
    with open(_DB_PATH, "r") as f:
        return json.load(f)


def _save(db: dict):
    os.makedirs(os.path.dirname(_DB_PATH), exist_ok=True)
    with open(_DB_PATH, "w") as f:
        json.dump(db, f, indent=2, ensure_ascii=False)


# ── Public API ────────────────────────────────────────────────────────────────

def get(uid: str) -> Optional[dict]:
    return _load().get(uid.upper())


def all_cards() -> list[dict]:
    return list(_load().values())


def enroll(uid: str, card_info: dict, gtc: int = INITIAL_GTC) -> dict:
    """Register a new card with initial GTC balance. Raises ValueError if exists."""
    db  = _load()
    key = uid.upper()
    if key in db:
        raise ValueError(f"Card {uid} already registered")
    record = {
        "uid":            key,
        "registered_at":  datetime.datetime.now().isoformat(),
        "balance_gtc":    gtc,
        "trips":          0,
        "last_tap":       None,
        "card_type":      card_info.get("card_type", "Unknown"),
        "hw_version":     card_info.get("hw_version", ""),
        "atr":            card_info.get("atr", ""),
        "label":          card_info.get("label", f"Card {key[-6:]}"),
    }
    db[key] = record
    _save(db)
    return record


def debit(uid: str, amount_gtc: int) -> dict:
    """Debit amount_gtc from card balance. Returns updated record."""
    db  = _load()
    key = uid.upper()
    if key not in db:
        raise KeyError(f"Card {uid} not registered")
    rec = db[key]
    if rec["balance_gtc"] < amount_gtc:
        raise ValueError(
            f"Insufficient balance: {rec['balance_gtc']} GTC < {amount_gtc} GTC"
        )
    rec["balance_gtc"] -= amount_gtc
    rec["trips"]        += 1
    rec["last_tap"]     = datetime.datetime.now().isoformat()
    db[key] = rec
    _save(db)
    return rec


def reload(uid: str, amount_gtc: int) -> dict:
    """Add GTC to existing card."""
    db  = _load()
    key = uid.upper()
    if key not in db:
        raise KeyError(f"Card {uid} not registered")
    db[key]["balance_gtc"] += amount_gtc
    _save(db)
    return db[key]
