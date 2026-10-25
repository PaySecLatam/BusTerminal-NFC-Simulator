#!/usr/bin/env python3
"""
MIFARE Classic 1K — escritura y lectura de tarjeta de tránsito.

Layout de sectores:
  Sector 1 (bloques 4-6): Datos del titular
    Bloque 4  — Metadatos de tarjeta (ID, tipo, fechas, sistema "MBMX")
    Bloque 5  — Nombre del titular   (16 bytes ASCII)
    Bloque 6  — CURP + fecha de nacimiento
  Sector 2 (bloques 8-10): Saldo y transacciones
    Bloque 8  — VALUE BLOCK estándar MIFARE (saldo en centavos, int32 LE)
    Bloque 9  — Info última recarga (viajes, monto, timestamp)
    Bloque 10 — Estadísticas (total acumulado, rutas)

Value Block MIFARE (16 bytes):
  [0-3]   value      (int32 little-endian)
  [4-7]   ~value     (complemento a bits, uint32 LE)
  [8-11]  value      (copia de redundancia)
  [12]    addr       (número de bloque)
  [13]    ~addr
  [14]    addr       (copia)
  [15]    ~addr      (copia)

Ejemplo — $50.00 MXN = 5000 centavos en bloque 8:
  88 13 00 00  77 EC FF FF  88 13 00 00  08 F7 08 F7

Uso:
  python3 mifare_rw.py                          # leer tarjeta
  python3 mifare_rw.py --write                  # escribir datos ficticios default
  python3 mifare_rw.py --write --name "Ana García" --curp GAAA900101 --balance 5000
  python3 mifare_rw.py --reload 2000            # sumar $20.00 al saldo existente
"""

import sys
import struct
import datetime
import argparse
import random
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.text import Text
from rich import box
from rich.table import Table

from smartcard.System import readers

console = Console()

# ── Constantes ────────────────────────────────────────────────────────────────

KEY_DEFAULT = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]
KEY_A  = 0x60
KEY_B  = 0x61

# Bloques usados (sector N → bloques N*4 .. N*4+2, trailer en N*4+3)
BLOCK_CARD_META = 4   # sector 1, bloque 0 — metadatos tarjeta
BLOCK_NAME      = 5   # sector 1, bloque 1 — nombre titular
BLOCK_ID        = 6   # sector 1, bloque 2 — CURP / nacimiento

BLOCK_BALANCE   = 8   # sector 2, bloque 0 — VALUE BLOCK saldo
BLOCK_TXN       = 9   # sector 2, bloque 1 — info última transacción
BLOCK_STATS     = 10  # sector 2, bloque 2 — estadísticas acumuladas

SYSTEM_ID = b"MBMX"  # identificador del sistema "MetroBus MéXico"

CARD_TYPES = {
    0x01: "Estándar",
    0x02: "Estudiante",
    0x03: "Tercera Edad",
    0x04: "Personas con Discapacidad",
}


# ── PC/SC helpers ─────────────────────────────────────────────────────────────

def _tx(conn, apdu: list, label: str = "") -> tuple:
    data, sw1, sw2 = conn.transmit(apdu)
    ok  = (sw1 == 0x90 and sw2 == 0x00)
    col = "green" if ok else "red"
    cmd = " ".join(f"{b:02X}" for b in apdu)
    rsp = " ".join(f"{b:02X}" for b in data)
    console.print(
        f"  [dim]{label or 'APDU':30s}[/dim]  "
        f"[dim]{cmd}[/dim]  "
        f"[bold {col}]SW {sw1:02X}{sw2:02X}[/bold {col}]"
        + (f"  [dim cyan]{rsp}[/dim cyan]" if data else "")
    )
    return bytes(data), sw1, sw2


def load_key(conn, key: list, slot: int = 0) -> bool:
    _, sw1, sw2 = _tx(conn, [0xFF, 0x82, 0x00, slot, 0x06] + key,
                       f"LOAD KEY slot {slot}")
    return sw1 == 0x90 and sw2 == 0x00


def authenticate(conn, block: int, key_type: int = KEY_A, slot: int = 0) -> bool:
    kname = "A" if key_type == KEY_A else "B"
    _, sw1, sw2 = _tx(conn,
                       [0xFF, 0x86, 0x00, 0x00, 0x05, 0x01, 0x00, block, key_type, slot],
                       f"AUTHENTICATE blq {block:02d} Key{kname}")
    return sw1 == 0x90 and sw2 == 0x00


def read_block(conn, block: int) -> Optional[bytes]:
    data, sw1, sw2 = _tx(conn, [0xFF, 0xB0, 0x00, block, 0x10],
                          f"READ BINARY  blq {block:02d}")
    return data if (sw1 == 0x90 and sw2 == 0x00) else None


def write_block(conn, block: int, data: bytes) -> bool:
    if len(data) != 16:
        raise ValueError(f"write_block necesita exactamente 16 bytes, recibió {len(data)}")
    _, sw1, sw2 = _tx(conn, [0xFF, 0xD6, 0x00, block, 0x10] + list(data),
                       f"UPDATE BINARY blq {block:02d}")
    return sw1 == 0x90 and sw2 == 0x00


# ── Codificación de bloques ───────────────────────────────────────────────────

def encode_card_meta(card_id: int, card_type: int,
                     issue: tuple, expiry: tuple) -> bytes:
    """
    Bloque 4 — 16 bytes:
      [0-3]   Número de tarjeta (uint32 BE)
      [4]     Tipo de tarjeta   (01=Estándar, 02=Estudiante…)
      [5]     Motivo de emisión (00=Nueva, 01=Reposición)
      [6-7]   Fecha emisión BCD (YY MM)
      [8-9]   Fecha vencimiento BCD (YY MM)
      [10-13] ID del sistema ("MBMX")
      [14-15] Checksum simple (suma bytes 0-13 mod 65536, BE)
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
    chk = sum(buf[:14]) & 0xFFFF
    struct.pack_into(">H", buf, 14, chk)
    return bytes(buf)


def decode_card_meta(data: bytes) -> dict:
    card_id    = struct.unpack_from(">I", data, 0)[0]
    card_type  = data[4]
    issue_yy   = data[6]; issue_mm = data[7]
    expiry_yy  = data[8]; expiry_mm = data[9]
    sys_id     = data[10:14].decode("ascii", errors="replace")
    stored_chk = struct.unpack_from(">H", data, 14)[0]
    calc_chk   = sum(data[:14]) & 0xFFFF
    return {
        "card_id":   card_id,
        "card_type": card_type,
        "issue":     f"20{issue_yy:02d}/{issue_mm:02d}",
        "expiry":    f"20{expiry_yy:02d}/{expiry_mm:02d}",
        "system":    sys_id,
        "chk_ok":    stored_chk == calc_chk,
    }


def encode_name(name: str) -> bytes:
    """Bloque 5 — 16 bytes ASCII, relleno con espacios (0x20)."""
    return name.encode("ascii", errors="replace")[:16].ljust(16, b"\x20")


def decode_name(data: bytes) -> str:
    return data.rstrip(b"\x20\x00").decode("ascii", errors="replace")


def encode_id_block(curp: str, birth_date: str) -> bytes:
    """
    Bloque 6 — 16 bytes:
      [0-11]  CURP primeros 12 chars (ASCII)
      [12-13] Año de nacimiento (uint16 BE)
      [14]    Mes de nacimiento
      [15]    Día de nacimiento
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
    birth = f"{year:04d}-{month:02d}-{day:02d}" if year else "—"
    return {"curp": curp, "birth": birth}


# ── Value Block (formato estándar MIFARE Classic) ─────────────────────────────

def encode_value_block(value: int, block_addr: int) -> bytes:
    """
    Codifica un entero como MIFARE value block de 16 bytes.

    El value block garantiza integridad mediante triple redundancia:
      bytes 0-3:  value    (int32 LE)
      bytes 4-7:  ~value   (complemento a bits, uint32 LE)
      bytes 8-11: value    (copia)
      byte  12:   addr     (número de bloque)
      byte  13:   ~addr
      byte  14:   addr     (copia)
      byte  15:   ~addr    (copia)
    """
    v  = struct.pack("<i", value)
    nv = struct.pack("<I", (~value) & 0xFFFFFFFF)
    a  = block_addr & 0xFF
    na = (~a) & 0xFF
    return v + nv + v + bytes([a, na, a, na])


def decode_value_block(data: bytes) -> Optional[int]:
    """
    Verifica integridad del value block y devuelve el valor.
    Retorna None si el bloque está corrupto o en blanco.
    """
    if len(data) < 12:
        return None
    v1 = struct.unpack_from("<i", data, 0)[0]
    nv = struct.unpack_from("<I", data, 4)[0]
    v2 = struct.unpack_from("<i", data, 8)[0]
    if v1 != v2:
        return None
    if ((~v1) & 0xFFFFFFFF) != nv:
        return None
    return v1


def encode_txn_block(trip_count: int, last_charge_cents: int,
                     last_debit_cents: int = 0,
                     timestamp: Optional[int] = None) -> bytes:
    """
    Bloque 9 — 16 bytes:
      [0-3]   Contador de viajes (uint32 BE)
      [4-7]   Monto última recarga en centavos (uint32 BE)
      [8-11]  Timestamp última recarga (uint32 BE, Unix epoch)
      [12-13] Monto último débito en centavos (uint16 BE)
      [14-15] Reservado
    """
    ts = timestamp or int(datetime.datetime.now().timestamp())
    buf = bytearray(16)
    struct.pack_into(">I", buf, 0, trip_count)
    struct.pack_into(">I", buf, 4, last_charge_cents)
    struct.pack_into(">I", buf, 8, ts)
    struct.pack_into(">H", buf, 12, last_debit_cents)
    return bytes(buf)


def decode_txn_block(data: bytes) -> dict:
    trips        = struct.unpack_from(">I", data, 0)[0]
    last_charge  = struct.unpack_from(">I", data, 4)[0]
    ts           = struct.unpack_from(">I", data, 8)[0]
    last_debit   = struct.unpack_from(">H", data, 12)[0]
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


def encode_stats_block(total_charged_cents: int, total_trips: int) -> bytes:
    """
    Bloque 10 — 16 bytes:
      [0-3]   Total recargado históricamente (uint32 BE centavos)
      [4-7]   Total viajes históricos (uint32 BE)
      [8-15]  Reservado
    """
    buf = bytearray(16)
    struct.pack_into(">I", buf, 0, total_charged_cents)
    struct.pack_into(">I", buf, 4, total_trips)
    return bytes(buf)


def decode_stats_block(data: bytes) -> dict:
    total_charged = struct.unpack_from(">I", data, 0)[0]
    total_trips   = struct.unpack_from(">I", data, 4)[0]
    return {"total_charged": total_charged, "total_trips": total_trips}


# ── Operaciones de alto nivel ─────────────────────────────────────────────────

def write_card(conn, name: str, curp: str, birth: str,
               card_id: int, card_type: int, balance_cents: int) -> bool:
    console.print(Rule("[cyan]Escritura de datos en tarjeta[/cyan]"))
    console.print()

    today  = datetime.date.today()
    expiry = (today.year + 2, today.month)

    if not load_key(conn, KEY_DEFAULT, slot=0):
        console.print("[red]Error cargando clave — ¿tarjeta en el lector?[/red]")
        return False

    # ── Sector 1 ──────────────────────────────────────────────────────────────
    console.print("\n  [cyan bold]Sector 1 — Datos del titular[/cyan bold]")
    if not authenticate(conn, BLOCK_CARD_META, KEY_A, slot=0):
        console.print("[red]  Auth sector 1 fallida[/red]")
        return False

    ok_meta  = write_block(conn, BLOCK_CARD_META,
                            encode_card_meta(card_id, card_type,
                                             (today.year, today.month), expiry))
    ok_name  = write_block(conn, BLOCK_NAME, encode_name(name))
    ok_id    = write_block(conn, BLOCK_ID, encode_id_block(curp, birth))

    # ── Sector 2 ──────────────────────────────────────────────────────────────
    console.print("\n  [cyan bold]Sector 2 — Saldo (value block)[/cyan bold]")
    if not authenticate(conn, BLOCK_BALANCE, KEY_A, slot=0):
        console.print("[red]  Auth sector 2 fallida[/red]")
        return False

    ok_bal   = write_block(conn, BLOCK_BALANCE,
                            encode_value_block(balance_cents, BLOCK_BALANCE))
    ok_txn   = write_block(conn, BLOCK_TXN,
                            encode_txn_block(trip_count=0,
                                             last_charge_cents=balance_cents,
                                             last_debit_cents=0))
    ok_stats = write_block(conn, BLOCK_STATS,
                            encode_stats_block(total_charged_cents=balance_cents,
                                               total_trips=0))

    all_ok = all([ok_meta, ok_name, ok_id, ok_bal, ok_txn, ok_stats])
    console.print()
    if all_ok:
        console.print("  [green bold]✓  Escritura completada correctamente[/green bold]")
    else:
        console.print("  [red]✗  Algunos bloques no se pudieron escribir[/red]")
    return all_ok


def reload_card(conn, add_cents: int) -> bool:
    """Lee el saldo actual, suma add_cents y escribe el nuevo saldo."""
    console.print(Rule("[cyan]Recarga de saldo[/cyan]"))
    console.print()

    if not load_key(conn, KEY_DEFAULT, slot=0):
        return False

    if not authenticate(conn, BLOCK_BALANCE, KEY_A, slot=0):
        console.print("[red]Auth sector 2 fallida[/red]")
        return False

    b8 = read_block(conn, BLOCK_BALANCE)
    b9 = read_block(conn, BLOCK_TXN)
    b10 = read_block(conn, BLOCK_STATS)
    if b8 is None:
        console.print("[red]Error leyendo saldo actual[/red]")
        return False

    current = decode_value_block(b8)
    if current is None:
        console.print("[yellow]Value block no inicializado — se asume saldo 0[/yellow]")
        current = 0

    txn   = decode_txn_block(b9)   if b9  else {}
    stats = decode_stats_block(b10) if b10 else {}

    new_balance = current + add_cents
    trips       = txn.get("trips", 0)
    prev_total  = stats.get("total_charged", 0)

    console.print(f"  Saldo anterior: [white]${current/100:.2f} MXN[/white]  ({current} centavos)")
    console.print(f"  Recarga:        [green]+${add_cents/100:.2f} MXN[/green]  ({add_cents} centavos)")
    console.print(f"  Saldo nuevo:    [green bold]${new_balance/100:.2f} MXN[/green bold]  ({new_balance} centavos)")
    console.print()

    ok_bal   = write_block(conn, BLOCK_BALANCE,
                            encode_value_block(new_balance, BLOCK_BALANCE))
    ok_txn   = write_block(conn, BLOCK_TXN,
                            encode_txn_block(trip_count=trips,
                                             last_charge_cents=add_cents,
                                             last_debit_cents=0))
    ok_stats = write_block(conn, BLOCK_STATS,
                            encode_stats_block(total_charged_cents=prev_total + add_cents,
                                               total_trips=trips))
    all_ok = all([ok_bal, ok_txn, ok_stats])
    if all_ok:
        console.print("  [green bold]✓  Recarga completada[/green bold]")
    return all_ok


def read_card(conn) -> Optional[dict]:
    console.print(Rule("[cyan]Lectura de tarjeta[/cyan]"))
    console.print()

    if not load_key(conn, KEY_DEFAULT, slot=0):
        console.print("[red]Error cargando clave[/red]")
        return None

    # Sector 1
    console.print("  [cyan bold]Sector 1 — Datos del titular[/cyan bold]")
    if not authenticate(conn, BLOCK_CARD_META, KEY_A, 0):
        console.print("[red]  Auth sector 1 fallida[/red]")
        return None
    b4 = read_block(conn, BLOCK_CARD_META)
    b5 = read_block(conn, BLOCK_NAME)
    b6 = read_block(conn, BLOCK_ID)

    # Sector 2
    console.print("\n  [cyan bold]Sector 2 — Saldo[/cyan bold]")
    if not authenticate(conn, BLOCK_BALANCE, KEY_A, 0):
        console.print("[red]  Auth sector 2 fallida[/red]")
        return None
    b8  = read_block(conn, BLOCK_BALANCE)
    b9  = read_block(conn, BLOCK_TXN)
    b10 = read_block(conn, BLOCK_STATS)

    if not all([b4, b5, b6, b8, b9, b10]):
        console.print("[red]Error leyendo uno o más bloques[/red]")
        return None

    meta  = decode_card_meta(b4)
    id_d  = decode_id_block(b6)
    txn   = decode_txn_block(b9)
    stats = decode_stats_block(b10)
    bal   = decode_value_block(b8)

    return {
        **meta,
        "name":          decode_name(b5),
        **id_d,
        "balance_cents": bal,
        **txn,
        **{f"stat_{k}": v for k, v in stats.items()},
        "_raw": {
            "bloque_04 (meta)":    b4.hex().upper(),
            "bloque_05 (nombre)":  b5.hex().upper(),
            "bloque_06 (id/curp)": b6.hex().upper(),
            "bloque_08 (saldo)":   b8.hex().upper(),
            "bloque_09 (txn)":     b9.hex().upper(),
            "bloque_10 (stats)":   b10.hex().upper(),
        },
    }


# ── Display ───────────────────────────────────────────────────────────────────

def display_card(uid_hex: str, data: dict):
    bal_cents = data.get("balance_cents") or 0
    is_valid_vb = data.get("balance_cents") is not None

    content = Text()
    content.append("\n  TARJETA DE TRÁNSITO — MIFARE Classic 1K\n\n", style="bold cyan")

    # Metadatos
    chk_icon = "✓" if data.get("chk_ok") else "⚠"
    content.append("  Núm. tarjeta:  ", style="dim")
    content.append(f"{data.get('card_id', 0):,}  [{chk_icon} checksum]\n", style="bold white")
    content.append("  UID del chip:  ", style="dim")
    content.append(f"{uid_hex}\n", style="cyan")
    content.append("  Tipo:          ", style="dim")
    content.append(f"{CARD_TYPES.get(data.get('card_type', 0), 'Desconocido')}\n", style="white")
    content.append("  Sistema:       ", style="dim")
    content.append(f"{data.get('system', '—')}\n", style="white")
    content.append("  Emisión:       ", style="dim")
    content.append(f"{data.get('issue', '—')}\n", style="white")
    content.append("  Vencimiento:   ", style="dim")
    content.append(f"{data.get('expiry', '—')}\n", style="white")

    # Titular
    content.append("\n  ── Titular ─────────────────────────\n", style="dim")
    content.append("  Nombre:        ", style="dim")
    content.append(f"{data.get('name', '—')}\n", style="bold white")
    content.append("  CURP:          ", style="dim")
    content.append(f"{data.get('curp', '—')}\n", style="white")
    content.append("  Nacimiento:    ", style="dim")
    content.append(f"{data.get('birth', '—')}\n", style="white")

    # Saldo
    content.append("\n  ── Saldo (sector 2, value block) ───\n", style="dim")
    if is_valid_vb:
        content.append("  Saldo actual:  ", style="dim")
        content.append(f"${bal_cents/100:.2f} MXN", style="bold green")
        content.append(f"  ({bal_cents} centavos)\n", style="dim")
    else:
        content.append("  Saldo actual:  ", style="dim")
        content.append("— (value block no inicializado)\n", style="yellow")

    content.append("  Viajes:        ", style="dim")
    content.append(f"{data.get('trips', 0)}\n", style="white")
    content.append("  Última recarga:", style="dim")
    content.append(f" ${(data.get('last_charge', 0))/100:.2f} MXN"
                   f"  el {data.get('last_date', '—')}\n", style="white")

    total_c = data.get("stat_total_charged", 0)
    content.append("  Total recargado:", style="dim")
    content.append(f" ${total_c/100:.2f} MXN histórico\n", style="dim white")

    console.print(Panel(content, border_style="cyan",
                         title="[bold]DATOS DE TARJETA[/bold]", padding=(0, 1)))

    # Hex dump con anotaciones
    console.print()
    console.print(Rule("[dim]Volcado hexadecimal de bloques[/dim]", style="dim"))
    raw = data.get("_raw", {})
    for label, hex_data in raw.items():
        formatted = " ".join(hex_data[i:i+2] for i in range(0, len(hex_data), 2))
        console.print(f"  [dim]{label}[/dim]")
        console.print(f"  [cyan]{formatted}[/cyan]")

        # Anotar el value block
        if "saldo" in label and is_valid_vb:
            v_hex = hex_data[0:8]
            nv_hex = hex_data[8:16]
            v2_hex = hex_data[16:24]
            addr   = hex_data[24:26]
            console.print(
                f"  [dim]  → value={v_hex}  ~value={nv_hex}  "
                f"redundancia={v2_hex}  addr={addr}[/dim]"
            )
            console.print(
                f"  [dim]  → {int(v_hex, 16)} centavos = "
                f"${int(v_hex, 16)/100:.2f} MXN[/dim]"
            )
        console.print()


# ── main ─────────────────────────────────────────────────────────────────────

def get_reader_conn():
    available = readers()
    if not available:
        console.print("[red]No se detectó lector PC/SC.[/red]")
        sys.exit(1)
    reader = available[0]
    console.print(f"  [green]✓[/green] Lector: [bold]{reader}[/bold]")
    conn = reader.createConnection()
    conn.connect()
    return conn


def get_uid(conn) -> str:
    data, sw1, sw2 = conn.transmit([0xFF, 0xCA, 0x00, 0x00, 0x00])
    if sw1 == 0x90 and sw2 == 0x00:
        return " ".join(f"{b:02X}" for b in data)
    return "—"


def main():
    parser = argparse.ArgumentParser(
        description="MIFARE Classic 1K — escritura/lectura de tarjeta de tránsito",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--write",   action="store_true",
                        help="Escribir datos en la tarjeta")
    parser.add_argument("--reload",  type=int, metavar="CENTAVOS",
                        help="Sumar centavos al saldo existente (ej. 2000 = +$20.00)")
    parser.add_argument("--name",    default="María García López",
                        help="Nombre del titular")
    parser.add_argument("--curp",    default="GALM901231MDFRZR08",
                        help="CURP (18 chars)")
    parser.add_argument("--birth",   default="1990-12-31",
                        help="Fecha de nacimiento YYYY-MM-DD")
    parser.add_argument("--balance", type=int, default=5000,
                        help="Saldo inicial en centavos (5000 = $50.00 MXN)")
    parser.add_argument("--type",    type=int, default=1,
                        choices=[1, 2, 3, 4],
                        help="Tipo: 1=Estándar 2=Estudiante 3=Tercera Edad 4=Discapacidad")
    args = parser.parse_args()

    console.print()
    console.print(Panel(
        "  [bold cyan]MIFARE Classic 1K — Terminal de R/W[/bold cyan]\n"
        "  [dim]Formato tarjeta de tránsito — MetroBus MX (demo)[/dim]",
        border_style="cyan", padding=(0, 1),
    ))
    console.print()

    console.print("  Conectando al lector...")
    conn = get_reader_conn()

    console.print("  Leyendo UID de la tarjeta...")
    uid = get_uid(conn)
    console.print(f"  [cyan]UID:[/cyan] {uid}")
    console.print()

    if args.write:
        card_id = random.randint(100_000, 999_999)
        console.print(Panel(
            f"  Nombre:  [white]{args.name}[/white]\n"
            f"  CURP:    [white]{args.curp}[/white]\n"
            f"  Nac.:    [white]{args.birth}[/white]\n"
            f"  Tipo:    [white]{CARD_TYPES.get(args.type, '?')}[/white]\n"
            f"  Núm.:    [white]{card_id:,}[/white]\n"
            f"  Saldo:   [green bold]${args.balance/100:.2f} MXN[/green bold]  "
            f"([dim]{args.balance} centavos[/dim])\n"
            f"\n"
            f"  [dim]Value block bloque 8:[/dim]\n"
            f"  [cyan]{encode_value_block(args.balance, BLOCK_BALANCE).hex(' ').upper()}[/cyan]",
            border_style="yellow", title="[yellow]DATOS A ESCRIBIR[/yellow]", padding=(0, 1),
        ))
        console.print()
        ok = write_card(conn,
                        name=args.name, curp=args.curp, birth=args.birth,
                        card_id=card_id, card_type=args.type,
                        balance_cents=args.balance)
        if not ok:
            conn.disconnect()
            sys.exit(1)
        console.print()

    elif args.reload is not None:
        ok = reload_card(conn, args.reload)
        if not ok:
            conn.disconnect()
            sys.exit(1)
        console.print()

    # Siempre leer y mostrar al final
    data = read_card(conn)
    if data:
        console.print()
        display_card(uid, data)

    conn.disconnect()


if __name__ == "__main__":
    main()
