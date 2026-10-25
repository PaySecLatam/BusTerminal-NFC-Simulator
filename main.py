#!/usr/bin/env python3

import sys
import time
import signal
import threading
import datetime
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.live import Live
from rich.columns import Columns
from rich.rule import Rule
from rich.prompt import Prompt
from rich import box

from src.reader import (
    get_available_readers, wait_for_card, get_atr,
    atr_to_card_type, is_nfc_reader, ReaderManager,
)
from src.terminal import EMVTerminal, TransactionResult, BUS_FARE_MXN
from src.desfire_sim import DESFireCard
from src.desfire_terminal import DESFireTransitTerminal, BUS_FARE_CENT
from src.virtual_conn import VirtualConnection
from src import card_store
from src.mifare import (
    KEY_DEFAULT, KEY_A, CARD_TYPES as MIFARE_CARD_TYPES,
    BLOCK_CARD_META, BLOCK_NAME, BLOCK_ID,
    BLOCK_BALANCE, BLOCK_TXN, BLOCK_STATS,
    MIFARE_ATR_MARKER,
    apdu_load_key, apdu_authenticate, apdu_read_block, apdu_write_block,
    decode_card_meta, decode_name, decode_id_block,
    decode_value_block, encode_value_block,
    decode_txn_block, encode_txn_block,
    decode_stats_block, encode_stats_block,
)

FARE_GTC = 1

console = Console()

BANNER = """
███████╗███╗   ███╗██╗   ██╗    ████████╗███████╗██████╗ ███╗   ███╗██╗███╗   ██╗ █████╗ ██╗
██╔════╝████╗ ████║██║   ██║    ╚══██╔══╝██╔════╝██╔══██╗████╗ ████║██║████╗  ██║██╔══██╗██║
█████╗  ██╔████╔██║╚██╗ ██╔╝       ██║   █████╗  ██████╔╝██╔████╔██║██║██╔██╗ ██║███████║██║
██╔══╝  ██║╚██╔╝██║ ╚████╔╝        ██║   ██╔══╝  ██╔══██╗██║╚██╔╝██║██║██║╚██╗██║██╔══██║██║
███████╗██║ ╚═╝ ██║  ╚██╔╝         ██║   ███████╗██║  ██║██║ ╚═╝ ██║██║██║ ╚████║██║  ██║███████╗
╚══════╝╚═╝     ╚═╝   ╚═╝          ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝
"""

TRANSACTION_LOG: list[TransactionResult] = []
_shutdown = threading.Event()


def header_panel() -> Panel:
    now = datetime.datetime.now().strftime("%Y-%m-%d  %H:%M:%S")
    content = Text()
    content.append("  TERMINAL BUS EMV\n", style="bold cyan")
    content.append(f"  METROBUS Ciudad de México\n", style="white")
    content.append(f"  Terminal ID: BUS-2024-MX-001\n", style="dim")
    content.append(f"  {now}\n", style="dim")
    content.append(f"\n  TARIFA: ", style="white")
    content.append(f"{FARE_GTC} GTC / viaje", style="bold green")
    return Panel(content, border_style="cyan", title="[bold]EMV BUS TERMINAL[/bold]", padding=(0, 1))


def reader_panel(reader_name: str, status: str = "LISTO") -> Panel:
    color = "green" if status == "LISTO" else "yellow" if status == "ESPERANDO" else "red"
    content = Text()
    content.append(f"  Lector: ", style="dim")
    content.append(f"{reader_name}\n", style="bold white")
    content.append(f"  Estado: ", style="dim")
    content.append(f"{status}", style=f"bold {color}")
    return Panel(content, border_style=color, title="NFC READER", padding=(0, 1))


def waiting_animation(reader_name: str, stop_event: threading.Event):
    frames = ["◜", "◠", "◝", "◞", "◡", "◟"]
    idx = 0
    with Live(console=console, refresh_per_second=8) as live:
        while not stop_event.is_set():
            spin = frames[idx % len(frames)]
            text = Text()
            text.append(f"\n  {spin} ", style="cyan bold")
            text.append("Acerque su tarjeta al lector...\n\n", style="white bold")
            text.append(f"  Lector: {reader_name}\n", style="dim")
            text.append(f"  Tarifa: {FARE_GTC} GTC / viaje\n", style="green")
            live.update(Panel(text, border_style="cyan", title="[cyan]ESPERANDO TARJETA[/cyan]", padding=(0, 2)))
            time.sleep(0.12)
            idx += 1


SIM_CARDS = [
    {"uid": "04A1B2C3D4E501", "balance": 15000, "label": "Pasajero 001 — Cargada ($150.00)"},
    {"uid": "04B2C3D4E5F602", "balance":  1000, "label": "Pasajero 002 — Saldo bajo ($10.00)"},
    {"uid": "04C3D4E5F6A703", "balance":   500, "label": "Pasajero 003 — Saldo insuficiente ($5.00)"},
    {"uid": "04D4E5F6A7B804", "balance": 50000, "label": "Pasajero 004 — Premium ($500.00)"},
    {"uid": "04E5F6A7B8C905", "balance":  2200, "label": "Pasajero 005 — Exacto 2 viajes ($22.00)"},
]
_sim_card_objects: dict[str, DESFireCard] = {
    c["uid"]: DESFireCard(c["uid"], c["balance"], c["label"])
    for c in SIM_CARDS
}


def print_apdu_log(log_entries: list[tuple[str, str, str]], show: bool = False):
    if not show:
        return
    console.print()
    console.print(Rule("[dim]APDU Transaction Log[/dim]", style="dim"))
    for direction, name, hex_data in log_entries:
        color = "cyan" if direction == ">>" else "green"
        arrow = "→" if direction == ">>" else "←"
        console.print(f"  [bold {color}]{arrow}[/bold {color}] [white]{name}[/white]")
        if hex_data:
            formatted = " ".join(hex_data[i:i+2] for i in range(0, len(hex_data), 2))
            console.print(f"    [dim]{formatted}[/dim]")


def print_desfire_apdu_trace(steps: list[dict]):
    console.print()
    console.print(Rule("[dim]Traza APDU DESFire — Protocolo Nativo (CLA=0x90)[/dim]", style="dim"))
    for s in steps:
        if s.get("type") == "note":
            console.print(
                f"  [yellow]ℹ[/yellow]  [yellow]{s['label']}[/yellow]"
                f"  [dim]{s.get('note', '')}[/dim]"
            )
            continue
        ok       = s.get("ok", False)
        sw       = s.get("sw", "????")
        sc       = "green" if ok else "red"
        cmd_hex  = s.get("command", "")
        resp_hex = s.get("response", "")
        console.print(
            f"\n  [bold cyan]→[/bold cyan] [white bold]Step {s['step']}:[/white bold] "
            f"[white]{s['label']}[/white]"
        )
        console.print(f"    [cyan]CMD :[/cyan] [dim]{cmd_hex}[/dim]")
        console.print(f"    [green]RESP:[/green] [dim]{resp_hex}[/dim]")
        console.print(f"    [bold {sc}]SW  : {sw}[/bold {sc}]", end="")
        if s.get("note"):
            console.print(f"  [dim]{s['note']}[/dim]")
        else:
            console.print()


def display_desfire_result(result, card: DESFireCard, show_apdu: bool = False):
    approved = result.approved
    col      = "green" if approved else "red"
    status   = "✓  APROBADO" if approved else "✗  RECHAZADO"

    content = Text()
    content.append(f"\n  {status}\n\n", style=f"bold {col}")
    content.append("  Protocolo:   ", style="dim")
    content.append("DESFire EV1 (CLA=0x90)\n", style="white")
    content.append("  UID:         ", style="dim")
    content.append(f"{card.uid_hex}\n", style="bold cyan")
    content.append("  Tarjeta:     ", style="dim")
    content.append(f"{card.card_label}\n", style="white")
    content.append("  AID (App):   ", style="dim")
    content.append("4D 42 58  (MetroBus MX)\n", style="dim white")
    content.append("  Monto:       ", style="dim")
    content.append(f"{result.amount_mxn}\n", style="bold green")
    content.append("  Saldo antes: ", style="dim")
    content.append(f"{result.balance_before_mxn}\n", style="white")
    content.append("  Saldo nuevo: ", style="dim")
    content.append(f"{result.balance_after_mxn}\n", style=f"bold {col}")

    if result.session_key:
        content.append("\n  Session Key: ", style="dim")
        content.append(
            " ".join(result.session_key[i:i+2] for i in range(0, len(result.session_key), 2)) + "\n",
            style="dim cyan",
        )
        content.append("  RndA:        ", style="dim")
        content.append(
            " ".join(result.rnd_a[i:i+2] for i in range(0, len(result.rnd_a), 2)) + "\n",
            style="dim",
        )
        content.append("  RndB:        ", style="dim")
        content.append(
            " ".join(result.rnd_b[i:i+2] for i in range(0, len(result.rnd_b), 2)) + "\n",
            style="dim",
        )

    if result.error:
        content.append(f"\n  Error:       ", style="dim red")
        content.append(f"{result.error}\n", style="red")

    content.append(f"\n  {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n", style="dim")

    console.print(Panel(
        content,
        border_style=col,
        title=f"[bold {col}]RESULTADO TRANSACCIÓN DESFire[/bold {col}]",
        padding=(0, 1),
    ))

    if show_apdu:
        print_desfire_apdu_trace(result.steps)

    console.print()
    console.print(Rule(style="dim"))


def display_transaction_result(result: TransactionResult, atr: bytes, show_apdu: bool = False):
    console.print()

    if result.approved and not result.declined:
        status_text  = "✓  APROBADO"
        status_color = "green"
        border_color = "green"
        if result.online_required:
            status_text  = "⟳  AUTORIZACIÓN ONLINE"
            status_color = "yellow"
            border_color = "yellow"
    else:
        status_text  = "✗  RECHAZADO"
        status_color = "red"
        border_color = "red"

    content = Text()
    content.append(f"\n  {status_text}\n\n", style=f"bold {status_color}")

    if result.pan:
        content.append(f"  PAN:       ", style="dim")
        content.append(f"{result.pan_masked or result.pan}\n", style="bold white")
    if result.expiry:
        content.append(f"  Vence:     ", style="dim")
        content.append(f"{result.expiry}\n", style="white")
    if result.cardholder:
        content.append(f"  Titular:   ", style="dim")
        content.append(f"{result.cardholder}\n", style="white")
    if result.app_label:
        content.append(f"  App:       ", style="dim")
        content.append(f"{result.app_label}\n", style="white")
    if result.aid:
        content.append(f"  AID:       ", style="dim")
        content.append(f"{result.aid}\n", style="dim white")

    content.append(f"\n  Monto:     ", style="dim")
    content.append(f"{result.amount_display}\n", style="bold green")
    content.append(f"  Tipo:      ", style="dim")
    content.append(f"{result.cryptogram_type}\n", style="white")

    if result.atc:
        content.append(f"  ATC:       ", style="dim")
        content.append(f"{result.atc:04X}\n", style="dim white")

    if result.cryptogram:
        content.append(f"  Criptograma: ", style="dim")
        content.append(f"{result.cryptogram.hex().upper()}\n", style="dim cyan")

    if atr:
        content.append(f"  ATR:       ", style="dim")
        content.append(f"{atr.hex().upper()}\n", style="dim")

    if result.aip_caps:
        content.append(f"\n  Capacidades: ", style="dim")
        content.append(f"{', '.join(result.aip_caps)}\n", style="dim white")

    if result.error:
        content.append(f"\n  Error:     ", style="dim red")
        content.append(f"{result.error}\n", style="red")

    content.append(f"\n  {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n", style="dim")

    console.print(Panel(
        content,
        border_style=border_color,
        title=f"[bold {status_color}]RESULTADO TRANSACCIÓN[/bold {status_color}]",
        padding=(0, 1),
    ))

    if show_apdu:
        print_apdu_log(result.__dict__.get("_log", []), show=True)

    console.print()
    console.print(Rule(style="dim"))


def display_session_summary():
    if not TRANSACTION_LOG:
        return
    console.print()
    total       = sum(1 for r in TRANSACTION_LOG if r.approved and not getattr(r, "declined", False))
    declined    = sum(1 for r in TRANSACTION_LOG if getattr(r, "declined", not r.approved))
    online_auth = sum(1 for r in TRANSACTION_LOG if getattr(r, "online_required", False))
    revenue_gtc = total * FARE_GTC

    table = Table(title="Resumen de Sesión", box=box.ROUNDED, border_style="cyan")
    table.add_column("Métrica", style="dim")
    table.add_column("Valor", style="bold white")

    table.add_row("Transacciones totales", str(len(TRANSACTION_LOG)))
    table.add_row("Aprobadas", f"[green]{total}[/green]")
    table.add_row("Rechazadas", f"[red]{declined}[/red]")
    table.add_row("Autorización online", f"[yellow]{online_auth}[/yellow]")
    table.add_row("Recaudación", f"[green bold]{revenue_gtc} GTC[/green bold]")

    console.print(table)


def select_virtual_card() -> Optional[DESFireCard]:
    console.print()
    table = Table(
        title="[cyan]Tarjetas Simuladas[/cyan]",
        box=box.ROUNDED,
        border_style="cyan",
        show_lines=True,
    )
    table.add_column("#",       style="dim", width=3)
    table.add_column("UID",     style="cyan")
    table.add_column("Saldo",   style="bold green")
    table.add_column("Etiqueta")

    cards = list(_sim_card_objects.values())
    for i, card in enumerate(cards):
        bal_col = "green" if card.balance >= BUS_FARE_CENT else "red"
        table.add_row(
            str(i),
            " ".join(card.uid_hex[j:j+2] for j in range(0, len(card.uid_hex), 2)),
            f"[{bal_col}]${card.balance/100:.2f} MXN[/{bal_col}]",
            card.card_label,
        )

    console.print(table)
    try:
        choice = int(Prompt.ask(
            "\n  [cyan]Selecciona tarjeta (número)[/cyan]",
            default="0",
        ))
        return cards[choice]
    except (ValueError, IndexError):
        return cards[0]


def run_virtual_transaction(card: DESFireCard, show_apdu: bool = False):
    conn     = VirtualConnection(card)
    terminal = DESFireTransitTerminal(amount_centavos=BUS_FARE_CENT, debug=True)

    console.print()
    console.print(Panel(
        f"  [cyan]UID:[/cyan]       {card.uid_hex}\n"
        f"  [cyan]Tarjeta:[/cyan]   {card.card_label}\n"
        f"  [cyan]Saldo:[/cyan]     ${card.balance/100:.2f} MXN\n"
        f"  [cyan]Protocolo:[/cyan] DESFire EV1 — CLA=0x90",
        border_style="cyan",
        title="[cyan]TARJETA VIRTUAL DETECTADA[/cyan]",
        padding=(0, 1),
    ))
    console.print("\n  [dim]Ejecutando protocolo DESFire...[/dim]")

    result = terminal.run(conn)
    TRANSACTION_LOG.append(result)

    display_desfire_result(result, card, show_apdu=show_apdu)
    return result


_SW_CARD_STATES: dict[int, tuple[str, str]] = {
    0x6983: ("PIN BLOQUEADO",           "Se excedió el número de intentos de PIN. El titular debe contactar a su banco."),
    0x6984: ("TARJETA BLOQUEADA",       "Datos de referencia invalidados por el emisor."),
    0x6985: ("CONDICIONES NO CUMPLIDAS","Tarjeta posiblemente vencida o bloqueada por el emisor."),
    0x6283: ("TARJETA DESACTIVADA",     "El emisor desactivó esta tarjeta."),
    0x6982: ("ACCESO DENEGADO",         "Estado de seguridad insuficiente — puede requerir PIN físico."),
    0x6300: ("AUTENTICACIÓN FALLIDA",   "La tarjeta rechazó la autenticación criptográfica."),
    0x6A82: ("APLICACIÓN NO HALLADA",   "No se encontró aplicación de pago en la tarjeta."),
    0x6700: ("LONGITUD INCORRECTA",     "El chip rechazó un comando por longitud inesperada."),
    0x6900: ("COMANDO NO PERMITIDO",    "La tarjeta no permite esta operación en el estado actual."),
}


def _infer_card_state(entries: list[dict], emv_result) -> tuple[str, str]:
    if emv_result.expiry:
        try:
            parts = emv_result.expiry.split("/")
            if len(parts) == 2:
                year  = int(parts[0]) if len(parts[0]) == 4 else int("20" + parts[1])
                month = int(parts[1]) if len(parts[0]) == 4 else int(parts[0])
                if datetime.date(year, month, 1) < datetime.date.today().replace(day=1):
                    return ("TARJETA VENCIDA", f"Venció en {emv_result.expiry}. El titular debe renovarla.")
        except Exception:
            pass

    for entry in reversed(entries):
        if entry.get("type") != "apdu" or entry.get("ok"):
            continue
        sw_str = entry.get("sw", "")
        if sw_str == "????":
            return (
                "SIN RESPUESTA DEL CHIP",
                f"La tarjeta no respondió a «{entry['label']}». "
                "Puede estar bloqueada o el campo fue interrumpido.",
            )
        if len(sw_str) == 4:
            try:
                sw = int(sw_str, 16)
                if sw in _SW_CARD_STATES:
                    return _SW_CARD_STATES[sw]
                if sw_str.startswith("69"):
                    return ("OPERACIÓN BLOQUEADA", f"Condición de seguridad no cumplida (SW {sw_str}).")
            except ValueError:
                pass

    return ("RECHAZADA", emv_result.error or "El chip rechazó la transacción.")


_EMV_NOTES: dict[tuple, str] = {
    (0x00, 0xA4): "SELECT",
    (0x00, 0xC0): "GET RESPONSE — recupera datos del buffer de la tarjeta",
    (0x80, 0xA8): "GET PROCESSING OPTIONS — obtiene AIP (capacidades) y AFL (mapa de registros)",
    (0x00, 0xB2): "READ RECORD — lee registro del chip (PAN, vencimiento, nombre, criptograma info)",
    (0x80, 0xAE): "GENERATE AC — solicita criptograma de autenticación (TC/ARQC/AAC)",
    (0x80, 0xCA): "GET DATA — recupera dato específico del chip",
    (0x00, 0x88): "INTERNAL AUTHENTICATE — autenticación dinámica de datos (DDA)",
    (0x00, 0x20): "VERIFY PIN",
    (0x80, 0x2A): "COMPUTE CRYPTOGRAPHIC CHECKSUM (Visa payWave)",
}


def _emv_label(apdu: list[int]) -> str:
    if len(apdu) < 2:
        return "APDU"
    cla, ins = apdu[0], apdu[1]
    if ins == 0xA4 and len(apdu) > 5:
        lc  = apdu[4]
        aid = bytes(apdu[5:5 + lc])
        if aid == b"2PAY.SYS.DDF01":
            return "SELECT PPSE  (2PAY.SYS.DDF01) — directorio de pagos contactless"
        from src.tlv import KNOWN_AIDS
        name = KNOWN_AIDS.get(aid, (aid.hex().upper(),))[0]
        return f"SELECT AID  {aid.hex().upper()}  ({name})"
    if ins == 0xB2:
        sfi = (apdu[3] >> 3) & 0x1F
        rec = apdu[2]
        return f"READ RECORD  SFI={sfi}  Rec={rec}"
    if ins == 0xAE:
        ref_map = {0x00: "AAC (declinar)", 0x40: "TC (aprobar offline)", 0x80: "ARQC (autorizar online)"}
        return f"GENERATE AC  →  {ref_map.get(apdu[2], f'P1={apdu[2]:02X}')}"
    if ins == 0xA8:
        return "GET PROCESSING OPTIONS (GPO)"
    if ins == 0xC0:
        return "GET RESPONSE"
    return _EMV_NOTES.get((cla, ins), f"APDU CLA={cla:02X} INS={ins:02X}")


class _TracingConnection:
    def __init__(self, real_conn, trace: "_LiveTrace", label_fn=None):
        self._conn  = real_conn
        self._trace = trace
        self._label = label_fn or _emv_label

    def transmit(self, apdu: list[int]) -> tuple[list[int], int, int]:
        label   = self._label(apdu)
        cmd_hex = " ".join(f"{b:02X}" for b in apdu)
        n       = self._trace._next()
        try:
            data, sw1, sw2 = self._conn.transmit(apdu)
        except Exception as exc:
            self._trace.entries.append({
                "type": "apdu", "step": n, "label": label,
                "command": cmd_hex, "response": "",
                "sw": "????", "ok": False, "note": f"EXCEPCIÓN: {exc}",
            })
            if self._trace.show:
                console.print(f"  [dim]{n:02d}[/dim]  [red]→[/red] [white]{label}[/white]")
                console.print(f"       [dim]CMD :[/dim] [cyan]{cmd_hex}[/cyan]")
                console.print(f"       [red bold]EXCEPCIÓN: {exc}[/red bold]\n")
            raise

        resp_hex = " ".join(f"{b:02X}" for b in data) + f" {sw1:02X} {sw2:02X}"
        ok       = (sw1 == 0x90 and sw2 == 0x00) or sw1 == 0x61
        sw_col   = "green" if ok else "yellow" if sw1 in (0x62, 0x63) else "red"
        self._trace.entries.append({
            "type": "apdu", "step": n, "label": label,
            "command": cmd_hex, "response": resp_hex,
            "sw": f"{sw1:02X}{sw2:02X}", "ok": ok, "note": "",
        })
        if self._trace.show:
            console.print(f"  [dim]{n:02d}[/dim]  [cyan]→[/cyan] [white]{label}[/white]")
            console.print(f"       [dim]CMD :[/dim] [cyan]{cmd_hex}[/cyan]")
            console.print(f"       [dim]RESP:[/dim] [green]{resp_hex}[/green]")
            console.print(f"       [dim]SW  :[/dim] [bold {sw_col}]{sw1:02X} {sw2:02X}[/bold {sw_col}]")
            console.print()
        return data, sw1, sw2

    def getATR(self) -> list[int]:
        return self._conn.getATR()

    def disconnect(self):
        return self._conn.disconnect()


class _LiveTrace:
    def __init__(self, show: bool = True):
        self.show    = show
        self.entries: list[dict] = []
        self._step   = 0

    def _next(self) -> int:
        self._step += 1
        return self._step

    def _tx(self, connection, apdu: list[int], label: str, note: str = "") -> tuple[bytes, int, int]:
        data, sw1, sw2 = connection.transmit(apdu)
        cmd_hex  = " ".join(f"{b:02X}" for b in apdu)
        resp_hex = " ".join(f"{b:02X}" for b in data) + f" {sw1:02X} {sw2:02X}"
        ok       = (sw1 == 0x90 and sw2 == 0x00) or (sw1 == 0x91 and sw2 in (0x00, 0xAF))
        sw_col   = "green" if ok else "red"
        n        = self._next()
        entry    = {
            "type": "apdu", "step": n, "label": label,
            "command": cmd_hex, "response": resp_hex,
            "sw": f"{sw1:02X}{sw2:02X}", "ok": ok, "note": note,
        }
        self.entries.append(entry)
        if self.show:
            console.print(f"  [dim]{n:02d}[/dim]  [cyan]→[/cyan] [white]{label}[/white]")
            console.print(f"       [dim]CMD :[/dim] [cyan]{cmd_hex}[/cyan]")
            console.print(f"       [dim]RESP:[/dim] [green]{resp_hex}[/green]")
            console.print(
                f"       [dim]SW  :[/dim] [bold {sw_col}]{sw1:02X} {sw2:02X}[/bold {sw_col}]"
                + (f"  [dim]{note}[/dim]" if note else "")
            )
            console.print()
        return bytes(data), sw1, sw2

    def note(self, label: str, text: str):
        n = self._next()
        self.entries.append({"type": "note", "step": n, "label": label, "note": text})
        if self.show:
            console.print(
                f"  [dim]{n:02d}[/dim]  [yellow]ℹ[/yellow]  "
                f"[yellow]{label}[/yellow]  [dim]{text}[/dim]\n"
            )


def run_transaction(connection, reader_name: str, show_apdu: bool = True,
                    enroll_mode: bool = False):
    atr       = get_atr(connection)
    card_type = atr_to_card_type(list(atr))
    atr_hex   = atr.hex().upper()

    console.print()
    console.print(Rule("[dim]Iniciando comunicación con tarjeta[/dim]", style="dim"))

    trace = _LiveTrace(show=show_apdu)

    trace.note("ATR", f"{atr_hex}  →  {card_type}")

    uid_data, sw1, sw2 = trace._tx(
        connection,
        [0xFF, 0xCA, 0x00, 0x00, 0x00],
        "GET UID  (FF CA 00 00 00)",
        "PC/SC pseudo-APDU — devuelve UID del chip sin autenticación",
    )
    uid = uid_data.hex().upper() if sw1 == 0x90 and sw2 == 0x00 else ""

    if not uid:
        console.print(Panel(
            "  [red]No se pudo leer el UID.[/red]\n"
            "  [dim]Mantén la tarjeta sobre el lector.[/dim]",
            border_style="red", title="ERROR",
        ))
        return

    uid_fmt = " ".join(uid[i:i+2] for i in range(0, len(uid), 2))

    _DESFIRE_ATR_PREFIXES = ("3B818001", "3B8F80018031", "3B8080018080")

    is_emv_card = False
    is_mifare   = False

    if atr_hex.upper().startswith(_DESFIRE_ATR_PREFIXES):
        pass
    elif MIFARE_ATR_MARKER in atr_hex.upper():
        is_mifare = True
    else:
        ppse      = b"2PAY.SYS.DDF01"
        _ppse_cmd = [0x00, 0xA4, 0x04, 0x00, len(ppse)] + list(ppse) + [0x00]
        try:
            _d, _s1, _s2 = connection.transmit(_ppse_cmd)
            sw_ok        = (_s1 == 0x90 and _s2 == 0x00) or _s1 == 0x61
            is_emv_card  = sw_ok and (0xBF in _d or 0x61 in _d)
        except Exception:
            is_emv_card = False

    hw_version     = ""
    card_type_disp = card_type

    if not is_emv_card and not is_mifare:
        hw_raw, sw1, sw2 = trace._tx(
            connection,
            [0x90, 0x60, 0x00, 0x00, 0x00],
            "GET_VERSION  (90 60 00 00 00)",
            "DESFire: versión HW — vendor/tipo/subtipo/major/minor/storage/proto",
        )
        if sw1 == 0x91 and sw2 == 0xAF:
            hw_version = hw_raw.hex().upper()
            vendor_map = {0x04: "NXP Semiconductors"}
            type_map   = {0x01: "DESFire"}
            sub_map    = {0x01: "EV1", 0x02: "EV2", 0x03: "EV3"}
            if len(hw_raw) >= 3:
                v  = vendor_map.get(hw_raw[0], f"0x{hw_raw[0]:02X}")
                ht = type_map.get(hw_raw[1],   f"0x{hw_raw[1]:02X}")
                sb = sub_map.get(hw_raw[2],    f"0x{hw_raw[2]:02X}")
                card_type_disp = f"{v} — {ht} {sb}"

            sw_raw, sw1, sw2 = trace._tx(
                connection, [0x90, 0xAF, 0x00, 0x00, 0x00],
                "ADDITIONAL_FRAME  (90 AF)", "DESFire: versión SW",
            )
            if sw1 == 0x91 and sw2 == 0xAF:
                uid3, sw1, sw2 = trace._tx(
                    connection, [0x90, 0xAF, 0x00, 0x00, 0x00],
                    "ADDITIONAL_FRAME  (90 AF)", "DESFire: UID (7 bytes) + lote",
                )
                if sw1 == 0x91 and sw2 == 0x00 and len(uid3) >= 7:
                    uid_from_card = uid3[:7].hex().upper()
                    trace.note(
                        "UID confirmado por GET_VERSION",
                        f"{' '.join(uid_from_card[i:i+2] for i in range(0, 14, 2))}"
                        f"  {'✓ coincide' if uid_from_card == uid else '⚠ difiere de FF CA'}",
                    )

        apps_raw, sw1, sw2 = trace._tx(
            connection, [0x90, 0x6A, 0x00, 0x00, 0x00],
            "GET_APPLICATION_IDs  (90 6A)", "DESFire: lista de AIDs (3 bytes c/u)",
        )
        if sw1 == 0x91 and sw2 == 0x00 and apps_raw:
            aids = [apps_raw[i:i+3].hex().upper() for i in range(0, len(apps_raw), 3)]
            trace.note("Aplicaciones encontradas", "  ".join(aids))

    if is_emv_card:
        proto_disp = "EMV Contactless  (ISO 14443-4)"
    elif is_mifare:
        proto_disp = "MIFARE Classic 1K  (ISO 14443-A)"
    else:
        proto_disp = "DESFire EV1  (CLA=0x90)"

    console.print(Panel(
        f"  [cyan]UID:[/cyan]      {uid_fmt}\n"
        f"  [cyan]ATR:[/cyan]      [dim]{atr_hex}[/dim]\n"
        f"  [cyan]Chip:[/cyan]     {card_type_disp}\n"
        f"  [cyan]Protocolo:[/cyan] {proto_disp}",
        border_style="cyan",
        title="[cyan]TARJETA DETECTADA[/cyan]",
        padding=(0, 1),
    ))

    if enroll_mode:
        existing = card_store.get(uid)
        if existing:
            trace.note(
                "DB lookup",
                f"Tarjeta ya registrada — saldo={existing['balance_gtc']} GTC  viajes={existing['trips']}",
            )
            console.print(Panel(
                f"  [yellow]Esta tarjeta ya está registrada.[/yellow]\n"
                f"  UID:    {uid}\n"
                f"  Saldo:  [bold]{existing['balance_gtc']} GTC[/bold]\n"
                f"  Viajes: {existing['trips']}",
                border_style="yellow", title="YA REGISTRADA",
            ))
        else:
            label = Prompt.ask(
                "  [cyan]Etiqueta para la tarjeta[/cyan]",
                default=f"Pasajero {uid[-4:]}",
            )
            record = card_store.enroll(uid, {
                "card_type":  card_type_disp,
                "hw_version": hw_version,
                "atr":        atr_hex,
                "label":      label,
            }, gtc=card_store.INITIAL_GTC)
            trace.note(
                "DB ENROLL",
                f"UID={uid}  label={label}  saldo_inicial={record['balance_gtc']} GTC  "
                f"→  data/cards.json actualizado",
            )
            console.print(Panel(
                f"  [green bold]✓  TARJETA REGISTRADA[/green bold]\n\n"
                f"  UID:    {uid}\n"
                f"  Label:  {label}\n"
                f"  Saldo:  [bold green]{record['balance_gtc']} GTC[/bold green]",
                border_style="green", title="[green]REGISTRO EXITOSO[/green]",
                padding=(0, 1),
            ))
        console.print(Rule(style="dim"))
        return

    approved   = False
    error      = ""
    extra_info = {}

    if is_mifare:
        trace.note("Protocolo detectado", "MIFARE Classic 1K  (ISO 14443-A)")
        console.print(
            "  [dim]Protocolo: [bold cyan]MIFARE Classic 1K[/bold cyan]"
            " — leyendo sectores con clave A...[/dim]\n"
        )
        fare_cents = FARE_GTC * 100

        trace._tx(connection, apdu_load_key(KEY_DEFAULT, 0),
                  "LOAD KEY  slot 0  (FF FF FF FF FF FF)",
                  "Clave A por defecto — tarjeta en blanco o sistema MBMX")

        _, as1, as2 = trace._tx(connection,
                                 apdu_authenticate(BLOCK_CARD_META, KEY_A, 0),
                                 f"AUTHENTICATE  sector 1  blq {BLOCK_CARD_META}  Key A",
                                 "Autentica sector 1 (bloques 4-6) — datos del titular")
        auth_s1 = (as1 == 0x90 and as2 == 0x00)

        b4, *_ = trace._tx(connection, apdu_read_block(BLOCK_CARD_META),
                            f"READ BINARY  blq {BLOCK_CARD_META:02d} — metadatos tarjeta")
        b5, *_ = trace._tx(connection, apdu_read_block(BLOCK_NAME),
                            f"READ BINARY  blq {BLOCK_NAME:02d} — nombre titular")
        b6, *_ = trace._tx(connection, apdu_read_block(BLOCK_ID),
                            f"READ BINARY  blq {BLOCK_ID:02d} — CURP / nacimiento")

        mf_meta = decode_card_meta(b4) if len(b4) == 16 else {}
        mf_name = decode_name(b5)      if len(b5) == 16 else "—"
        mf_id   = decode_id_block(b6)  if len(b6) == 16 else {"curp": "—", "birth": "—"}

        if mf_meta:
            trace.note(
                "Datos del titular",
                f"Nombre: {mf_name}  "
                f"ID: {mf_meta.get('card_id', 0):,}  "
                f"Tipo: {MIFARE_CARD_TYPES.get(mf_meta.get('card_type', 1), '?')}  "
                f"Vence: {mf_meta.get('expiry', '—')}",
            )

        _, as1, as2 = trace._tx(connection,
                                 apdu_authenticate(BLOCK_BALANCE, KEY_A, 0),
                                 f"AUTHENTICATE  sector 2  blq {BLOCK_BALANCE}  Key A",
                                 "Autentica sector 2 (bloques 8-10) — saldo")
        auth_s2 = (as1 == 0x90 and as2 == 0x00)

        b8,  *_ = trace._tx(connection, apdu_read_block(BLOCK_BALANCE),
                             f"READ BINARY  blq {BLOCK_BALANCE:02d} — value block (saldo)")
        b9,  *_ = trace._tx(connection, apdu_read_block(BLOCK_TXN),
                             f"READ BINARY  blq {BLOCK_TXN:02d} — info transacciones")
        b10, *_ = trace._tx(connection, apdu_read_block(BLOCK_STATS),
                             f"READ BINARY  blq {BLOCK_STATS:02d} — estadísticas")

        balance_cents = decode_value_block(b8)  if len(b8)  == 16 else None
        txn_info      = decode_txn_block(b9)    if len(b9)  == 16 else {}
        stats_info    = decode_stats_block(b10) if len(b10) == 16 else {}

        balance_gtc = balance_cents // 100 if balance_cents is not None else None

        if balance_cents is not None:
            vb_hex = b8.hex().upper()
            trace.note(
                "Value block decodificado",
                f"{' '.join(vb_hex[i:i+2] for i in range(0,8,2))} (LE) = "
                f"{balance_cents} centavos = {balance_gtc} GTC",
            )
        else:
            trace.note("Value block", "no inicializado o corrupto")

        mf_new_balance_gtc = None
        if balance_cents is None:
            error = "Tarjeta sin datos — inicializar con: python3 mifare_rw.py --write"
            trace.note("ERROR", error)
        elif balance_cents < fare_cents:
            error = (
                f"Saldo insuficiente: {balance_gtc} GTC disponibles, "
                f"se requiere {FARE_GTC} GTC"
            )
            trace.note("Saldo insuficiente", error)
        else:
            new_bal_cents      = balance_cents - fare_cents
            mf_new_balance_gtc = new_bal_cents // 100
            new_trips          = txn_info.get("trips", 0) + 1

            new_vb = encode_value_block(new_bal_cents, BLOCK_BALANCE)
            _, ws1, ws2 = trace._tx(
                connection, apdu_write_block(BLOCK_BALANCE, new_vb),
                f"UPDATE BINARY  blq {BLOCK_BALANCE:02d} — nuevo saldo",
                f"{balance_gtc} → {mf_new_balance_gtc} GTC  "
                f"({balance_cents} → {new_bal_cents} centavos)",
            )

            new_txn = encode_txn_block(
                trip_count        = new_trips,
                last_charge_cents = txn_info.get("last_charge", 0),
                last_debit_cents  = fare_cents,
            )
            trace._tx(connection, apdu_write_block(BLOCK_TXN, new_txn),
                      f"UPDATE BINARY  blq {BLOCK_TXN:02d} — contador viajes",
                      f"viajes: {txn_info.get('trips',0)} → {new_trips}")

            new_stats = encode_stats_block(
                total_charged_cents = stats_info.get("total_charged", 0),
                total_trips         = stats_info.get("total_trips", 0) + 1,
            )
            trace._tx(connection, apdu_write_block(BLOCK_STATS, new_stats),
                      f"UPDATE BINARY  blq {BLOCK_STATS:02d} — estadísticas acumuladas")

            approved = (ws1 == 0x90 and ws2 == 0x00)
            if not approved:
                error = "Error escribiendo nuevo saldo — ¿tarjeta retirada?"
            else:
                trace.note(
                    "COBRO OK",
                    f"Débito: {FARE_GTC} GTC  |  Saldo nuevo: {mf_new_balance_gtc} GTC  "
                    f"|  Viajes: {new_trips}",
                )

        extra_info = {
            "proto":          "MIFARE Classic 1K  (ISO 14443-A)",
            "mf_card_id":     f"{mf_meta.get('card_id', 0):,}",
            "mf_card_type":   MIFARE_CARD_TYPES.get(mf_meta.get("card_type", 1), "—"),
            "mf_name":        mf_name,
            "mf_curp":        mf_id.get("curp", "—"),
            "mf_birth":       mf_id.get("birth", "—"),
            "mf_expiry":      mf_meta.get("expiry", "—"),
            "mf_system":      mf_meta.get("system", "—"),
            "mf_auth_s1":     "✓" if auth_s1 else "✗",
            "mf_auth_s2":     "✓" if auth_s2 else "✗",
            "mf_bal_before":  balance_gtc if balance_gtc is not None else "—",
            "mf_bal_after":   mf_new_balance_gtc if mf_new_balance_gtc is not None else "—",
            "mf_trips":       txn_info.get("trips", 0) + (1 if approved else 0),
            "mf_last_charge": f"${txn_info.get('last_charge', 0)/100:.2f} MXN",
            "mf_last_date":   txn_info.get("last_date", "—"),
        }

    elif is_emv_card:
        trace.note("Protocolo detectado", "EMV Contactless L2  (ISO 14443-4)")
        console.print("  [dim]Protocolo: [bold cyan]EMV Contactless[/bold cyan] — ejecutando kernel L2...[/dim]\n")

        tracing_conn = _TracingConnection(connection, trace)
        terminal     = EMVTerminal(amount_cents=FARE_GTC * 100, debug=False)
        try:
            emv_result = terminal.run(tracing_conn)
        except Exception as exc:
            emv_result = TransactionResult(
                approved=False, online_required=False, declined=True,
                cryptogram_type="Error", error=str(exc),
                amount_cents=FARE_GTC * 100,
            )

        if emv_result.pan:
            trace.note(
                "PAN decodificado del chip",
                f"{emv_result.pan_masked or emv_result.pan}  "
                f"vence: {emv_result.expiry}  titular: {emv_result.cardholder or '—'}",
            )
        if emv_result.cryptogram:
            trace.note(
                f"Criptograma  [{emv_result.cryptogram_type}]",
                f"{emv_result.cryptogram.hex().upper()}  ATC={emv_result.atc:04X}",
            )
        if emv_result.aip_caps:
            trace.note("Capacidades AIP", "  ".join(emv_result.aip_caps))

        approved         = emv_result.approved and not emv_result.declined
        card_state_title = ""
        card_state_desc  = ""
        if not approved:
            card_state_title, card_state_desc = _infer_card_state(trace.entries, emv_result)
            error = f"{card_state_title} — {card_state_desc}"
            trace.note(f"Estado tarjeta: {card_state_title}", card_state_desc)

        extra_info = {
            "pan":              emv_result.pan_masked or emv_result.pan or "—",
            "expiry":           emv_result.expiry or "—",
            "cardholder":       emv_result.cardholder or "—",
            "aid":              emv_result.aid or "—",
            "app_label":        emv_result.app_label or "—",
            "cryptogram":       emv_result.cryptogram.hex().upper() if emv_result.cryptogram else "—",
            "crypt_type":       emv_result.cryptogram_type,
            "atc":              f"{emv_result.atc:04X}",
            "card_state_title": card_state_title,
            "card_state_desc":  card_state_desc,
            "proto":            "EMV Contactless L2",
        }

    else:
        record = card_store.get(uid)
        if not record:
            console.print(Panel(
                f"  [yellow]Tarjeta no registrada.[/yellow]\n"
                f"  UID: {uid}\n\n"
                f"  Usa [bold]--enroll[/bold] para registrarla con {card_store.INITIAL_GTC} GTC.",
                border_style="yellow", title="TARJETA DESCONOCIDA",
            ))
            console.print(Rule(style="dim"))
            return

        balance_before = record["balance_gtc"]
        trace.note(
            "DB lookup",
            f"label={record['label']}  saldo={balance_before} GTC  viajes={record['trips']}",
        )

        trace.note("Protocolo detectado", "DESFire EV1 nativo  (CLA=0x90)")
        console.print("  [dim]Protocolo: [bold cyan]DESFire EV1[/bold cyan] — ejecutando flujo nativo...[/dim]\n")

        import os, struct
        from src.desfire_terminal import TERMINAL_KEY
        from src.desfire_sim import (
            TRANSIT_AID, _aes_cbc_enc, _aes_cbc_dec, _rotate_left,
        )

        session_key = b""
        auth_ok     = False

        _, sw1, sw2 = trace._tx(
            connection,
            [0x90, 0x5A, 0x00, 0x00, 0x03] + list(TRANSIT_AID) + [0x00],
            f"SELECT_APPLICATION  (90 5A) — AID {TRANSIT_AID.hex().upper()}",
            "Selecciona app de cobro en la tarjeta",
        )

        auth1_raw, sw1, sw2 = trace._tx(
            connection,
            [0x90, 0xAA, 0x00, 0x00, 0x01, 0x01, 0x00],
            "AUTHENTICATE_AES step 1  (90 AA — key #01)",
            "Terminal solicita auth; tarjeta responde E_key(RndB)  →  SW 91AF",
        )
        if sw1 == 0x91 and sw2 == 0xAF and len(auth1_raw) == 16:
            enc_rnd_b = auth1_raw
            rnd_b     = _aes_cbc_dec(TERMINAL_KEY, bytes(16), enc_rnd_b)
            rnd_a     = os.urandom(16)
            enc_resp  = _aes_cbc_enc(TERMINAL_KEY, enc_rnd_b, rnd_a + _rotate_left(rnd_b))
            trace.note(
                "Terminal calcula respuesta auth",
                f"RndB={rnd_b.hex().upper()}  RndA={rnd_a.hex().upper()}",
            )
            auth2_raw, sw1, sw2 = trace._tx(
                connection,
                [0x90, 0xAF, 0x00, 0x00, 0x20] + list(enc_resp) + [0x00],
                "AUTHENTICATE_AES step 2  (90 AF — E(RndA||rot(RndB)))",
                "Tarjeta verifica y responde E(rot(RndA))  →  SW 9100",
            )
            if sw1 == 0x91 and sw2 == 0x00 and len(auth2_raw) == 16:
                rnd_a_dec = _aes_cbc_dec(TERMINAL_KEY, enc_resp[16:32], auth2_raw)
                if rnd_a_dec == _rotate_left(rnd_a):
                    session_key = rnd_a[:4] + rnd_b[:4] + rnd_a[12:16] + rnd_b[12:16]
                    auth_ok = True
                    trace.note("AUTH MUTUA OK — Session key", session_key.hex().upper())
                else:
                    trace.note("AUTH FALLIDA", "rot(RndA) no coincide")
        else:
            trace.note(
                "AUTH no disponible",
                f"SW={sw1:02X}{sw2:02X} — clave distinta o sin app DESFire",
            )

        files_raw, sw1, sw2 = trace._tx(
            connection, [0x90, 0x6F, 0x00, 0x00, 0x00],
            "GET_FILE_IDs  (90 6F)", "Lista archivos en la app",
        )

        fs_raw, sw1, sw2 = trace._tx(
            connection, [0x90, 0xF5, 0x00, 0x00, 0x01, 0x01, 0x00],
            "GET_FILE_SETTINGS  (90 F5 — file 0x01)",
            "Tipo=Value, CommMode, límites, saldo actual",
        )
        if sw1 == 0x91 and sw2 == 0x00 and len(fs_raw) >= 16:
            cur = struct.unpack("<i", fs_raw[12:16])[0]
            trace.note("Saldo en chip", f"{cur} centavos = ${cur/100:.2f} MXN")

        val_raw, sw1, sw2 = trace._tx(
            connection, [0x90, 0x6C, 0x00, 0x00, 0x01, 0x01, 0x00],
            "GET_VALUE  (90 6C — file 0x01)",
            "Saldo actual — signed 32-bit little-endian",
        )
        if sw1 == 0x91 and sw2 == 0x00 and len(val_raw) >= 4:
            chip_bal = struct.unpack("<i", val_raw[:4])[0]
            trace.note("GET_VALUE decodificado", f"{chip_bal} centavos = ${chip_bal/100:.2f}")

        fare_cents = FARE_GTC * 100
        mac_raw, sw1, sw2 = trace._tx(
            connection,
            [0x90, 0xDC, 0x00, 0x00, 0x05, 0x01]
            + list(struct.pack("<I", fare_cents)) + [0x00],
            f"DEBIT_VALUE  (90 DC — file 0x01 | {fare_cents} centavos)",
            f"Débita ${fare_cents/100:.2f} MXN — pendiente COMMIT",
        )
        if sw1 == 0x91 and sw2 == 0x00 and mac_raw:
            trace.note("MAC respuesta DEBIT_VALUE", f"{mac_raw.hex().upper()}  (AES-CMAC)")

        _, sw1, sw2 = trace._tx(
            connection, [0x90, 0xC7, 0x00, 0x00, 0x00],
            "COMMIT_TRANSACTION  (90 C7)",
            "Aplica débito atómicamente en el chip  →  SW 9100",
        )
        trace.note(
            "COMMIT " + ("OK ✓" if (sw1 == 0x91 and sw2 == 0x00) else "FALLÓ"),
            f"SW={sw1:02X}{sw2:02X}",
        )

        extra_info = {
            "proto":          "DESFire EV1  (CLA=0x90)",
            "auth":           "✓ AES mutua OK" if auth_ok else "✗ sin auth / clave incorrecta",
            "session_key":    session_key.hex().upper() if session_key else "",
            "label":          record["label"],
            "balance_before": balance_before,
        }
        try:
            updated  = card_store.debit(uid, FARE_GTC)
            approved = True
            extra_info["balance_after"] = updated["balance_gtc"]
            extra_info["trips"]         = updated["trips"]
            trace.note(
                "DB DEBIT",
                f"−{FARE_GTC} GTC  →  saldo nuevo: {updated['balance_gtc']} GTC",
            )
        except ValueError as e:
            error = str(e)
            trace.note("DB DEBIT RECHAZADO", error)

    col         = "green" if approved else "red"
    panel_title = (
        f"[bold green]✓  COBRO REALIZADO[/bold green]"
        if approved
        else f"[bold red]✗  TRANSACCIÓN RECHAZADA[/bold red]"
    )

    content = Text()
    if approved:
        content.append("\n  ✓  COBRO REALIZADO\n\n", style="bold green")
    else:
        state_title = extra_info.get("card_state_title") or "RECHAZADA"
        content.append(f"\n  ✗  {state_title}\n\n", style="bold red")
        state_desc = extra_info.get("card_state_desc")
        if state_desc:
            content.append(f"  {state_desc}\n\n", style="yellow")

    content.append("  UID:          ", style="dim"); content.append(f"{uid}\n", style="bold cyan")
    content.append("  Chip:         ", style="dim"); content.append(f"{card_type_disp}\n", style="white")
    content.append("  Protocolo:    ", style="dim"); content.append(f"{extra_info.get('proto','—')}\n", style="white")

    if is_emv_card:
        if extra_info["pan"] != "—":
            content.append("  PAN:          ", style="dim"); content.append(f"{extra_info['pan']}\n", style="white")
        content.append("  Vence:        ", style="dim")
        exp_col = "red bold" if extra_info.get("card_state_title") == "TARJETA VENCIDA" else "white"
        content.append(f"{extra_info['expiry']}\n", style=exp_col)
        if extra_info["cardholder"] != "—":
            content.append("  Titular:      ", style="dim"); content.append(f"{extra_info['cardholder']}\n", style="white")
        if extra_info["aid"] != "—":
            content.append("  App / AID:    ", style="dim"); content.append(f"{extra_info['app_label']}  {extra_info['aid']}\n", style="dim white")
        if approved:
            content.append("  Criptograma:  ", style="dim"); content.append(f"{extra_info['crypt_type']}\n", style="white")
            content.append("  AC:           ", style="dim"); content.append(f"{extra_info['cryptogram']}  (ATC={extra_info['atc']})\n", style="dim cyan")
    elif is_mifare:
        content.append("  Titular:      ", style="dim"); content.append(f"{extra_info.get('mf_name', '—')}\n", style="bold white")
        if extra_info.get("mf_curp") and extra_info["mf_curp"] != "—":
            content.append("  CURP:         ", style="dim"); content.append(f"{extra_info['mf_curp']}\n", style="white")
        if extra_info.get("mf_birth") and extra_info["mf_birth"] not in ("—", "0000-00-00"):
            content.append("  Nacimiento:   ", style="dim"); content.append(f"{extra_info['mf_birth']}\n", style="white")
        content.append("  No. tarjeta:  ", style="dim"); content.append(f"{extra_info.get('mf_card_id', '—')}\n", style="white")
        content.append("  Tipo:         ", style="dim"); content.append(f"{extra_info.get('mf_card_type', '—')}\n", style="white")
        content.append("  Vence:        ", style="dim"); content.append(f"{extra_info.get('mf_expiry', '—')}\n", style="white")
        content.append("  Sistema:      ", style="dim"); content.append(f"{extra_info.get('mf_system', '—')}\n", style="dim white")
        s1_col = "green" if extra_info.get("mf_auth_s1") == "✓" else "red"
        s2_col = "green" if extra_info.get("mf_auth_s2") == "✓" else "red"
        content.append("  Auth sector 1:", style="dim"); content.append(f" {extra_info.get('mf_auth_s1','✗')}\n", style=s1_col)
        content.append("  Auth sector 2:", style="dim"); content.append(f" {extra_info.get('mf_auth_s2','✗')}\n", style=s2_col)
        content.append("\n  Cobro:        ", style="dim"); content.append(f"{FARE_GTC} GTC\n", style="bold green")
        bal_before = extra_info.get("mf_bal_before")
        content.append("  Saldo antes:  ", style="dim")
        content.append(f"{bal_before} GTC\n" if bal_before != "—" else "— GTC\n", style="white")
        content.append("  Saldo nuevo:  ", style="dim")
        bal_after = extra_info.get("mf_bal_after")
        content.append(
            f"{bal_after} GTC\n" if approved and bal_after != "—" else "— GTC\n",
            style=f"bold {col}",
        )
        if approved:
            content.append("  Viajes total: ", style="dim"); content.append(f"{extra_info.get('mf_trips', '—')}\n", style="white")
            if extra_info.get("mf_last_charge") and extra_info["mf_last_charge"] != "$0.00 MXN":
                content.append("  Últ. recarga: ", style="dim"); content.append(f"{extra_info['mf_last_charge']}\n", style="dim white")
    else:
        content.append("  Tarjeta:      ", style="dim"); content.append(f"{extra_info['label']}\n", style="white")
        auth_col = "green" if extra_info["auth"].startswith("✓") else "yellow"
        content.append("  Auth DESFire: ", style="dim"); content.append(f"{extra_info['auth']}\n", style=auth_col)
        if extra_info.get("session_key"):
            sk = extra_info["session_key"]
            content.append("  Session Key:  ", style="dim")
            content.append(" ".join(sk[i:i+2] for i in range(0, len(sk), 2)) + "\n", style="dim cyan")
        content.append("\n  Cobro:        ", style="dim"); content.append(f"{FARE_GTC} GTC\n", style="bold green")
        content.append("  Saldo antes:  ", style="dim"); content.append(f"{extra_info['balance_before']} GTC\n", style="white")
        content.append("  Saldo nuevo:  ", style="dim")
        content.append(
            f"{extra_info.get('balance_after', '—')} GTC\n" if approved else "— GTC\n",
            style=f"bold {col}",
        )
        if approved:
            content.append("  Viajes total: ", style="dim"); content.append(f"{extra_info['trips']}\n", style="white")

    content.append(f"\n  {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n", style="dim")

    console.print(Panel(
        content, border_style=col,
        title=panel_title,
        padding=(0, 1),
    ))
    console.print(Rule(style="dim"))

    class _R:
        pass
    r = _R()
    r.approved        = approved
    r.declined        = not approved
    r.online_required = False
    TRANSACTION_LOG.append(r)


def select_reader() -> Optional[object]:
    available = get_available_readers()
    if not available:
        return None

    nfc_readers = [r for r in available if is_nfc_reader(str(r))]
    if nfc_readers:
        return nfc_readers[0]

    if len(available) == 1:
        return available[0]

    console.print("\n[bold]Lectores disponibles:[/bold]")
    for i, r in enumerate(available):
        console.print(f"  [{i}] {r}")
    try:
        choice = int(Prompt.ask("Selecciona lector", default="0"))
        return available[choice]
    except (ValueError, IndexError):
        return available[0]


def main():
    show_apdu   = "--no-apdu" not in sys.argv
    continuous  = "--once" not in sys.argv
    sim_mode    = "--sim" in sys.argv
    enroll_mode = "--enroll" in sys.argv

    console.print(BANNER, style="cyan bold")
    console.print(Panel(
        "  [bold white]Terminal de Cobro DESFire / EMV / MIFARE — Microbús[/bold white]\n"
        "  [dim]--enroll      Registrar tarjeta con 50 GTC iniciales[/dim]\n"
        "  [dim]--once        Una transacción y salir[/dim]\n"
        "  [dim]--no-apdu     Ocultar traza APDU (por defecto se muestra)[/dim]\n"
        "  [dim]--sim         Modo virtual (sin lector NFC)[/dim]",
        border_style="cyan",
        padding=(0, 1),
    ))

    def handle_sigint(sig, frame):
        console.print("\n\n  [yellow]Cerrando terminal...[/yellow]")
        _shutdown.set()
        display_session_summary()
        sys.exit(0)

    signal.signal(signal.SIGINT, handle_sigint)

    if sim_mode:
        console.print(Panel(
            "  [yellow bold]MODO SIMULACIÓN[/yellow bold]\n"
            "  [dim]Protocolo DESFire EV1 nativo — sin lector NFC requerido[/dim]\n"
            "  [dim]Tarjetas pre-cargadas con diferentes saldos[/dim]",
            border_style="yellow",
            padding=(0, 1),
        ))
        console.print(header_panel())

        try:
            while not _shutdown.is_set():
                card = select_virtual_card()
                if not card:
                    break

                console.print(
                    "\n  [dim]Simulando tap NFC... "
                    "(autenticación AES mutua 3-pass)[/dim]"
                )
                run_virtual_transaction(card, show_apdu=show_apdu)

                if not continuous:
                    break

                console.print("\n  [dim]Siguiente pasajero — Ctrl+C para salir[/dim]")
                time.sleep(1)

        except KeyboardInterrupt:
            pass
        finally:
            console.print()
            display_session_summary()
        return

    console.print("\n  [dim]Buscando lector NFC...[/dim]")
    reader = None

    for attempt in range(30):
        reader = select_reader()
        if reader:
            break
        if attempt == 0:
            console.print(
                "  [yellow]No se detectó lector. "
                "Esperando... (o usa --sim para modo virtual)[/yellow]"
            )
        time.sleep(1)

    if not reader:
        console.print("[red bold]ERROR:[/red bold] No se encontró ningún lector PC/SC.")
        console.print(
            "[dim]Conecta un lector NFC (ACR122U, ACR1252U, etc.) "
            "o ejecuta con [bold]--sim[/bold] para modo virtual.[/dim]"
        )
        sys.exit(1)

    reader_name = str(reader)
    console.print(f"\n  [green]✓[/green] Lector detectado: [bold]{reader_name}[/bold]")

    if enroll_mode:
        console.print(Panel(
            "  [yellow bold]MODO REGISTRO[/yellow bold]\n"
            "  [dim]Acerca una tarjeta para registrarla con 50 GTC iniciales[/dim]",
            border_style="yellow", padding=(0, 1),
        ))
    else:
        cards_count = len(card_store.all_cards())
        console.print(Panel(
            "  [cyan bold]MODO COBRO[/cyan bold]\n"
            f"  [dim]Tarjetas registradas: {cards_count}[/dim]\n"
            "  [dim]Acerca tarjeta registrada para cobrar 1 GTC[/dim]",
            border_style="cyan", padding=(0, 1),
        ))

    console.print(header_panel())

    try:
        while not _shutdown.is_set():
            stop_anim   = threading.Event()
            anim_thread = threading.Thread(
                target=waiting_animation,
                args=(reader_name, stop_anim),
                daemon=True,
            )
            anim_thread.start()

            connection = None
            while not connection and not _shutdown.is_set():
                connection = wait_for_card(reader, timeout=5)

            stop_anim.set()
            anim_thread.join(timeout=1)

            if _shutdown.is_set():
                break

            if connection:
                run_transaction(
                    connection,
                    reader_name,
                    show_apdu=show_apdu,
                    enroll_mode=enroll_mode,
                )
                try:
                    connection.disconnect()
                except Exception:
                    pass

                if not continuous:
                    break

                console.print(
                    "\n  [dim]Esperando siguiente pasajero... (Ctrl+C para salir)[/dim]"
                )
                time.sleep(2)

    except KeyboardInterrupt:
        pass
    finally:
        console.print()
        display_session_summary()


if __name__ == "__main__":
    main()
