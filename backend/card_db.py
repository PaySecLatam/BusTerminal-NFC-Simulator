"""
In-memory card database seeded with demo DESFire transit cards.

Cards persist in memory for the lifetime of the backend process.
Balance changes from /simulate/tap are committed to the in-memory state,
so successive calls reflect the correct remaining balance.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.desfire_sim import DESFireCard

# Pre-seeded demo cards — UIDs are 7 bytes (14 hex chars)
_SEED_CARDS = [
    {"uid": "04A1B2C3D4E501", "balance": 15000, "label": "Pasajero 001 — Cargada"},
    {"uid": "04B2C3D4E5F602", "balance":  1000, "label": "Pasajero 002 — Saldo bajo"},
    {"uid": "04C3D4E5F6A703", "balance":    500, "label": "Pasajero 003 — Saldo insuficiente"},
    {"uid": "04D4E5F6A7B804", "balance": 50000, "label": "Pasajero 004 — Premium"},
    {"uid": "04E5F6A7B8C905", "balance":  2200, "label": "Pasajero 005 — Exacto para 2 viajes"},
]

# Singleton card store: uid → DESFireCard
_cards: dict[str, DESFireCard] = {}


def _seed():
    for entry in _SEED_CARDS:
        card = DESFireCard(
            uid_hex=entry["uid"],
            balance_centavos=entry["balance"],
            card_label=entry["label"],
        )
        _cards[entry["uid"].upper()] = card


_seed()


def get_all() -> list[dict]:
    return [c.to_dict() for c in _cards.values()]


def get_card(uid: str) -> DESFireCard | None:
    return _cards.get(uid.upper())


def add_card(uid: str, balance_centavos: int, label: str = "") -> DESFireCard:
    if uid.upper() in _cards:
        raise ValueError(f"Card {uid} already exists")
    card = DESFireCard(uid_hex=uid, balance_centavos=balance_centavos, card_label=label)
    _cards[uid.upper()] = card
    return card


def reload_balance(uid: str, amount_centavos: int) -> DESFireCard:
    card = get_card(uid)
    if not card:
        raise KeyError(f"Card {uid} not found")
    card.balance += amount_centavos
    return card
