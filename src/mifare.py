"""MIFARE Classic 1K — constantes, APDUs y encode/decode de datos de tránsito."""

import struct
import datetime
from typing import Optional

# ── Bloques y constantes ──────────────────────────────────────────────────────

BLOCK_CARD_META = 4    # sector 1 bloque 0 — metadatos tarjeta
BLOCK_NAME      = 5    # sector 1 bloque 1 — nombre titular
BLOCK_ID        = 6    # sector 1 bloque 2 — CURP / nacimiento
BLOCK_BALANCE   = 8    # sector 2 bloque 0 — value block (saldo en centavos)
BLOCK_TXN       = 9    # sector 2 bloque 1 — info última transacción
BLOCK_STATS     = 10   # sector 2 bloque 2 — estadísticas acumuladas

KEY_DEFAULT = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]
KEY_A       = 0x60
KEY_B       = 0x61

SYSTEM_ID   = b"MBMX"
CARD_TYPES  = {
    0x01: "Estándar",
    0x02: "Estudiante",
    0x03: "Tercera Edad",
    0x04: "Personas con Discapacidad",
}

# Marcador en ATR que identifica familia MIFARE Classic (histórico NXP)
MIFARE_ATR_MARKER = "A000000306"


# ── Constructores de APDU PC/SC para MIFARE ───────────────────────────────────

def apdu_load_key(key: list, slot: int = 0) -> list:
    """FF 82 — carga clave en ranura del lector."""
    return [0xFF, 0x82, 0x00, slot, 0x06] + key


def apdu_authenticate(block: int, key_type: int = KEY_A, slot: int = 0) -> list:
    """FF 86 — autentica el sector al que pertenece `block`."""
    return [0xFF, 0x86, 0x00, 0x00, 0x05, 0x01, 0x00, block, key_type, slot]


def apdu_read_block(block: int) -> list:
    """FF B0 — lee 16 bytes del bloque."""
    return [0xFF, 0xB0, 0x00, block, 0x10]


def apdu_write_block(block: int, data: bytes) -> list:
    """FF D6 — escribe 16 bytes en el bloque."""
    if len(data) != 16:
        raise ValueError(f"MIFARE block must be 16 bytes, got {len(data)}")
    return [0xFF, 0xD6, 0x00, block, 0x10] + list(data)


# ── Value Block estándar MIFARE (monedero electrónico) ────────────────────────

def encode_value_block(value: int, block_addr: int) -> bytes:
    """
    Formato MIFARE value block — 16 bytes:
      [0-3]  value    (int32 LE)
      [4-7]  ~value   (uint32 LE, complemento a bits)
      [8-11] value    (copia de redundancia)
      [12]   addr     (número de bloque)
      [13]   ~addr
      [14]   addr     (copia)
      [15]   ~addr    (copia)

    Ejemplo: 5000 centavos en bloque 8
      88 13 00 00  77 EC FF FF  88 13 00 00  08 F7 08 F7
    """
    v  = struct.pack("<i", value)
    nv = struct.pack("<I", (~value) & 0xFFFFFFFF)
    a  = block_addr & 0xFF
    na = (~a) & 0xFF
    return v + nv + v + bytes([a, na, a, na])


def decode_value_block(data: bytes) -> Optional[int]:
    """
    Verifica integridad y retorna el valor (centavos).
    Retorna None si el bloque está en blanco o corrupto.
    """
    if not data or len(data) < 12:
        return None
    v1 = struct.unpack_from("<i", data, 0)[0]
    nv = struct.unpack_from("<I", data, 4)[0]
    v2 = struct.unpack_from("<i", data, 8)[0]
    if v1 != v2 or ((~v1) & 0xFFFFFFFF) != nv:
        return None
    return v1


# ── Bloque 4: metadatos de tarjeta ────────────────────────────────────────────

def encode_card_meta(card_id: int, card_type: int,
                     issue: tuple, expiry: tuple) -> bytes:
    """
    16 bytes:
      [0-3]   Número de tarjeta (uint32 BE)
      [4]     Tipo (01=Estándar, 02=Estudiante…)
      [5]     Motivo emisión (00=Nueva)
      [6-7]   Fecha emisión BCD (YY MM)
      [8-9]   Fecha vencimiento BCD (YY MM)
      [10-13] ID sistema (b"MBMX")
      [14-15] Checksum suma bytes 0-13 mod 65536 (uint16 BE)
    """
    buf = bytearray(16)
    struct.pack_into(">I", buf, 0, card_id)
    buf[4] = card_type
    buf[5] = 0x00
    buf[6] = issue[0] % 100
    buf[7] = issue[1]
    buf[8] = expiry[0] % 100
    buf[9] = expiry[1]
    buf[10:14] = SYSTEM_ID
    struct.pack_into(">H", buf, 14, sum(buf[:14]) & 0xFFFF)
    return bytes(buf)


def decode_card_meta(data: bytes) -> dict:
    card_id   = struct.unpack_from(">I", data, 0)[0]
    card_type = data[4]
    iy, im    = data[6], data[7]
    ey, em    = data[8], data[9]
    sys_id    = data[10:14].decode("ascii", errors="replace")
    stored    = struct.unpack_from(">H", data, 14)[0]
    return {
        "card_id":   card_id,
        "card_type": card_type,
        "issue":     f"20{iy:02d}/{im:02d}",
        "expiry":    f"20{ey:02d}/{em:02d}",
        "system":    sys_id,
        "chk_ok":    stored == (sum(data[:14]) & 0xFFFF),
    }


# ── Bloque 5: nombre del titular ──────────────────────────────────────────────

def encode_name(name: str) -> bytes:
    """16 bytes ASCII, relleno con espacios (0x20)."""
    return name.encode("ascii", errors="replace")[:16].ljust(16, b"\x20")


def decode_name(data: bytes) -> str:
    return data.rstrip(b"\x20\x00").decode("ascii", errors="replace")


# ── Bloque 6: CURP + fecha de nacimiento ──────────────────────────────────────

def encode_id_block(curp: str, birth_date: str) -> bytes:
    """
    16 bytes:
      [0-11]  CURP primeros 12 chars (ASCII)
      [12-13] Año de nacimiento (uint16 BE)
      [14]    Mes
      [15]    Día
    """
    buf = bytearray(16)
    curp_b = curp.upper().encode("ascii", errors="replace")[:12]
    buf[:len(curp_b)] = curp_b
    try:
        bd = datetime.date.fromisoformat(birth_date)
        struct.pack_into(">H", buf, 12, bd.year)
        buf[14] = bd.month
        buf[15] = bd.day
    except Exception:
        pass
    return bytes(buf)


def decode_id_block(data: bytes) -> dict:
    curp  = data[:12].rstrip(b"\x00 ").decode("ascii", errors="replace")
    year  = struct.unpack_from(">H", data, 12)[0]
    month = data[14]
    day   = data[15]
    return {
        "curp":  curp,
        "birth": f"{year:04d}-{month:02d}-{day:02d}" if year else "—",
    }


# ── Bloque 9: información de última transacción ───────────────────────────────

def encode_txn_block(trip_count: int, last_charge_cents: int,
                     last_debit_cents: int = 0,
                     timestamp: Optional[int] = None) -> bytes:
    """
    16 bytes:
      [0-3]   Contador de viajes (uint32 BE)
      [4-7]   Monto última recarga en centavos (uint32 BE)
      [8-11]  Timestamp última recarga (uint32 BE, Unix)
      [12-13] Monto último débito en centavos (uint16 BE)
      [14-15] Reservado
    """
    ts  = timestamp or int(datetime.datetime.now().timestamp())
    buf = bytearray(16)
    struct.pack_into(">I", buf, 0, trip_count)
    struct.pack_into(">I", buf, 4, last_charge_cents)
    struct.pack_into(">I", buf, 8, ts)
    struct.pack_into(">H", buf, 12, last_debit_cents)
    return bytes(buf)


def decode_txn_block(data: bytes) -> dict:
    trips       = struct.unpack_from(">I", data, 0)[0]
    last_charge = struct.unpack_from(">I", data, 4)[0]
    ts          = struct.unpack_from(">I", data, 8)[0]
    last_debit  = struct.unpack_from(">H", data, 12)[0]
    try:
        dt = datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M") if ts else "—"
    except Exception:
        dt = "—"
    return {
        "trips":       trips,
        "last_charge": last_charge,
        "last_date":   dt,
        "last_debit":  last_debit,
    }


# ── Bloque 10: estadísticas acumuladas ────────────────────────────────────────

def encode_stats_block(total_charged_cents: int, total_trips: int) -> bytes:
    buf = bytearray(16)
    struct.pack_into(">I", buf, 0, total_charged_cents)
    struct.pack_into(">I", buf, 4, total_trips)
    return bytes(buf)


def decode_stats_block(data: bytes) -> dict:
    return {
        "total_charged": struct.unpack_from(">I", data, 0)[0],
        "total_trips":   struct.unpack_from(">I", data, 4)[0],
    }
