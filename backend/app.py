"""
FastAPI backend — DESFire transit payment simulator.

Endpoints:
  GET  /cards                        — list all simulated cards with balance
  GET  /cards/{uid}                  — card detail + trip history
  POST /cards                        — add a new card
  POST /cards/{uid}/reload           — reload balance (add centavos)
  POST /simulate/tap/{uid}           — simulate a card tap (full APDU trace)
  GET  /transactions                 — history of all simulated transactions
  WS   /ws                           — real-time tap events (JSON)

Run with:
  uvicorn backend.app:app --reload --port 8000
"""

import sys
import os
import json
import asyncio
import datetime
from typing import AsyncGenerator

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from backend.card_db import get_all, get_card, add_card, reload_balance
from src.desfire_terminal import DESFireTransitTerminal, BUS_FARE_CENT
from src.virtual_conn import VirtualConnection

app = FastAPI(
    title="DESFire Transit Simulator",
    description="Simulador de terminal de cobro DESFire EV1 para microbús / Metrobús",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Global transaction log ────────────────────────────────────────────────────
_transaction_log: list[dict] = []

# ── Active WebSocket connections ──────────────────────────────────────────────
_ws_clients: list[WebSocket] = []


async def _broadcast(event: dict):
    dead = []
    for ws in _ws_clients:
        try:
            await ws.send_text(json.dumps(event))
        except Exception:
            dead.append(ws)
    for ws in dead:
        _ws_clients.remove(ws)


# ── Pydantic models ───────────────────────────────────────────────────────────

class NewCardRequest(BaseModel):
    uid: str                       # 14 hex chars (7 bytes)
    balance_centavos: int = 10000
    label: str = ""


class ReloadRequest(BaseModel):
    amount_centavos: int


class TapRequest(BaseModel):
    amount_centavos: int = BUS_FARE_CENT


# ── Routes ────────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse, include_in_schema=False)
async def root():
    return _ui_html()


@app.get("/cards", summary="List all simulated cards")
async def list_cards():
    return {"cards": get_all()}


@app.get("/cards/{uid}", summary="Get card detail + trip history")
async def card_detail(uid: str):
    card = get_card(uid)
    if not card:
        raise HTTPException(404, f"Card {uid} not found")
    return card.to_dict()


@app.post("/cards", summary="Add a new simulated card")
async def create_card(body: NewCardRequest):
    if len(body.uid.replace(" ", "")) != 14:
        raise HTTPException(400, "UID must be 14 hex chars (7 bytes)")
    try:
        card = add_card(body.uid, body.balance_centavos, body.label)
    except ValueError as e:
        raise HTTPException(409, str(e))
    return {"status": "created", "card": card.to_dict()}


@app.post("/cards/{uid}/reload", summary="Reload card balance")
async def reload_card(uid: str, body: ReloadRequest):
    try:
        card = reload_balance(uid, body.amount_centavos)
    except KeyError as e:
        raise HTTPException(404, str(e))
    return {"status": "reloaded", "card": card.to_dict()}


@app.post("/simulate/tap/{uid}", summary="Simulate card tap — returns full APDU trace")
async def simulate_tap(uid: str, body: TapRequest = None):
    card = get_card(uid)
    if not card:
        raise HTTPException(404, f"Card {uid} not found")

    amount = (body.amount_centavos if body else BUS_FARE_CENT)

    # Run full DESFire payment flow via virtual connection
    conn     = VirtualConnection(card)
    terminal = DESFireTransitTerminal(amount_centavos=amount, debug=True)
    result   = terminal.run(conn)

    tx = {
        "id":              len(_transaction_log) + 1,
        "timestamp":       datetime.datetime.now().isoformat(),
        "uid":             card.uid_hex,
        "card_label":      card.card_label,
        "amount_centavos": amount,
        "amount_mxn":      f"${amount/100:.2f} MXN",
        "approved":        result.approved,
        "error":           result.error,
        "balance_before":  result.balance_before,
        "balance_after":   result.balance_after,
        "balance_before_mxn": result.balance_before_mxn,
        "balance_after_mxn":  result.balance_after_mxn,
        "session_key":     result.session_key,
        "rnd_a":           result.rnd_a,
        "rnd_b":           result.rnd_b,
        "hw_version":      result.hw_version,
        "sw_version":      result.sw_version,
        "uid_from_card":   result.uid,
        "apdu_trace":      result.steps,
        "apdu_raw_log":    conn.get_log_dicts(),
    }
    _transaction_log.append(tx)

    # Notify WebSocket clients
    await _broadcast({"event": "tap", "transaction": tx})

    return tx


@app.get("/transactions", summary="Full history of simulated transactions")
async def transactions():
    return {"count": len(_transaction_log), "transactions": _transaction_log}


@app.get("/transactions/{tx_id}", summary="Single transaction detail")
async def transaction_detail(tx_id: int):
    for tx in _transaction_log:
        if tx["id"] == tx_id:
            return tx
    raise HTTPException(404, f"Transaction {tx_id} not found")


# ── WebSocket ─────────────────────────────────────────────────────────────────

@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket):
    await ws.accept()
    _ws_clients.append(ws)
    try:
        while True:
            await ws.receive_text()  # keep alive
    except WebSocketDisconnect:
        if ws in _ws_clients:
            _ws_clients.remove(ws)


# ── Embedded UI ───────────────────────────────────────────────────────────────

def _ui_html() -> str:
    return """<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<title>DESFire Transit Simulator</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: #0d1117; color: #c9d1d9; font-family: 'Courier New', monospace; }
  header { background: #161b22; border-bottom: 1px solid #30363d; padding: 16px 24px; }
  header h1 { color: #58a6ff; font-size: 1.2rem; }
  header p  { color: #8b949e; font-size: 0.8rem; margin-top: 4px; }
  .layout { display: grid; grid-template-columns: 320px 1fr; gap: 0; min-height: calc(100vh - 56px); }
  .sidebar { background: #161b22; border-right: 1px solid #30363d; padding: 16px; overflow-y: auto; }
  .main    { padding: 16px; overflow-y: auto; }
  .card-item {
    background: #0d1117; border: 1px solid #30363d; border-radius: 6px;
    padding: 12px; margin-bottom: 8px; cursor: pointer; transition: border-color .2s;
  }
  .card-item:hover { border-color: #58a6ff; }
  .card-uid   { color: #58a6ff; font-size: 0.75rem; letter-spacing: .05em; }
  .card-label { color: #c9d1d9; font-size: 0.85rem; margin: 4px 0; }
  .card-bal   { color: #3fb950; font-size: 1rem; font-weight: bold; }
  .card-bal.low { color: #f85149; }
  .btn {
    display: inline-block; padding: 8px 14px; border-radius: 6px; border: none;
    font-family: monospace; font-size: 0.85rem; cursor: pointer; margin: 4px 2px;
  }
  .btn-blue  { background: #1f6feb; color: white; }
  .btn-green { background: #238636; color: white; }
  .btn-red   { background: #da3633; color: white; }
  .btn:hover { opacity: 0.85; }
  section { margin-bottom: 24px; }
  section h2 { color: #8b949e; font-size: 0.75rem; text-transform: uppercase;
               letter-spacing: .08em; border-bottom: 1px solid #30363d;
               padding-bottom: 8px; margin-bottom: 12px; }
  .apdu-table { width: 100%; border-collapse: collapse; font-size: 0.75rem; }
  .apdu-table th { background: #161b22; color: #8b949e; padding: 6px 10px;
                   text-align: left; font-weight: 600; }
  .apdu-table td { padding: 6px 10px; border-top: 1px solid #21262d;
                   vertical-align: top; word-break: break-all; }
  .apdu-table tr.ok   td:first-child { border-left: 3px solid #3fb950; }
  .apdu-table tr.err  td:first-child { border-left: 3px solid #f85149; }
  .apdu-table tr.note td { color: #d29922; font-style: italic; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 12px;
           font-size: 0.7rem; font-weight: bold; }
  .badge-ok  { background: #0d4429; color: #3fb950; }
  .badge-err { background: #490202; color: #f85149; }
  .badge-pend{ background: #1c2128; color: #8b949e; }
  .mono { font-family: monospace; font-size: 0.75rem; color: #8b949e; }
  .result-box { background: #0d1117; border: 1px solid #30363d; border-radius: 6px;
                padding: 16px; margin-bottom: 12px; }
  .result-box.approved { border-color: #238636; }
  .result-box.declined { border-color: #da3633; }
  #log { color: #3fb950; font-size: 0.75rem; background: #0d1117;
         border: 1px solid #30363d; border-radius: 6px; padding: 12px;
         height: 120px; overflow-y: auto; }
  input[type=text], input[type=number] {
    background: #0d1117; border: 1px solid #30363d; color: #c9d1d9;
    border-radius: 6px; padding: 6px 10px; font-family: monospace;
    font-size: 0.85rem; width: 100%; margin: 4px 0 8px;
  }
</style>
</head>
<body>
<header>
  <h1>&#9654; DESFire EV1 Transit Simulator — MetroBus CDMX</h1>
  <p>Simulador de terminal de cobro con protocolo nativo DESFire. Muestra traza APDU completa.</p>
</header>
<div class="layout">
  <!-- Sidebar: card list -->
  <aside class="sidebar">
    <section>
      <h2>Tarjetas Simuladas</h2>
      <div id="card-list">Cargando...</div>
    </section>
    <section>
      <h2>Agregar Tarjeta</h2>
      <label>UID (14 hex)</label>
      <input id="new-uid" type="text" placeholder="04AABBCCDDEEFF" maxlength="14">
      <label>Saldo inicial (centavos)</label>
      <input id="new-bal" type="number" value="15000">
      <label>Etiqueta</label>
      <input id="new-label" type="text" placeholder="Nombre del pasajero">
      <button class="btn btn-green" onclick="addCard()">Crear tarjeta</button>
    </section>
    <section>
      <h2>WebSocket Live</h2>
      <div id="log">Conectando...</div>
    </section>
  </aside>

  <!-- Main panel: transaction result + APDU trace -->
  <main class="main">
    <section>
      <h2>Resultado de Transacción</h2>
      <div id="result">
        <p style="color:#8b949e">Haz click en una tarjeta para simular un cobro.</p>
      </div>
    </section>
    <section>
      <h2>Traza APDU Completa</h2>
      <div id="trace">
        <p style="color:#8b949e">La traza aparecerá aquí después de un tap.</p>
      </div>
    </section>
  </main>
</div>

<script>
const API = '';

async function loadCards() {
  const r = await fetch(API + '/cards');
  const j = await r.json();
  const el = document.getElementById('card-list');
  el.innerHTML = '';
  j.cards.forEach(c => {
    const bal = c.balance_centavos;
    const low = bal < 1100;
    el.innerHTML += \`
      <div class="card-item" onclick="tap('\${c.uid}')">
        <div class="card-uid">\${c.uid}</div>
        <div class="card-label">\${c.label}</div>
        <div class="card-bal \${low ? 'low' : ''}">
          \${c.balance_mxn} \${low ? '⚠ saldo bajo' : ''}
        </div>
        <div style="margin-top:6px">
          <button class="btn btn-blue" onclick="event.stopPropagation();tap('\${c.uid}')">
            &#9654; Cobrar $11.00
          </button>
        </div>
      </div>\`;
  });
}

async function tap(uid) {
  document.getElementById('result').innerHTML = '<p style="color:#8b949e">Procesando...</p>';
  document.getElementById('trace').innerHTML  = '';
  const r = await fetch(API + '/simulate/tap/' + uid, {method:'POST',
    headers:{'Content-Type':'application/json'}, body:'{}'});
  const tx = await r.json();
  renderResult(tx);
  loadCards();
}

async function addCard() {
  const uid   = document.getElementById('new-uid').value.trim();
  const bal   = parseInt(document.getElementById('new-bal').value);
  const label = document.getElementById('new-label').value.trim();
  const r = await fetch(API + '/cards', {
    method:'POST',
    headers:{'Content-Type':'application/json'},
    body: JSON.stringify({uid, balance_centavos: bal, label}),
  });
  if (r.ok) { loadCards(); }
  else { alert((await r.json()).detail); }
}

function renderResult(tx) {
  const cls = tx.approved ? 'approved' : 'declined';
  const badge = tx.approved
    ? '<span class="badge badge-ok">APROBADO</span>'
    : '<span class="badge badge-err">RECHAZADO</span>';
  document.getElementById('result').innerHTML = \`
    <div class="result-box \${cls}">
      \${badge}
      <table style="margin-top:12px;font-size:0.85rem;line-height:1.8">
        <tr><td style="color:#8b949e;padding-right:16px">UID</td><td>\${tx.uid}</td></tr>
        <tr><td style="color:#8b949e">Tarjeta</td><td>\${tx.card_label}</td></tr>
        <tr><td style="color:#8b949e">Monto</td><td>\${tx.amount_mxn}</td></tr>
        <tr><td style="color:#8b949e">Saldo anterior</td><td>\${tx.balance_before_mxn}</td></tr>
        <tr><td style="color:#8b949e">Saldo nuevo</td>
            <td style="color:\${tx.approved?'#3fb950':'#f85149'}">\${tx.balance_after_mxn}</td></tr>
        \${tx.error ? '<tr><td style=\\"color:#f85149\\">Error</td><td style=\\"color:#f85149\\">' + tx.error + '</td></tr>' : ''}
        \${tx.session_key ? '<tr><td style=\\"color:#8b949e\\">Session Key</td><td class=\\"mono\\">' + tx.session_key + '</td></tr>' : ''}
        \${tx.rnd_a ? '<tr><td style=\\"color:#8b949e\\">RndA</td><td class=\\"mono\\">' + tx.rnd_a + '</td></tr>' : ''}
        \${tx.rnd_b ? '<tr><td style=\\"color:#8b949e\\">RndB</td><td class=\\"mono\\">' + tx.rnd_b + '</td></tr>' : ''}
      </table>
    </div>\`;
  renderTrace(tx.apdu_trace);
}

function renderTrace(steps) {
  if (!steps || !steps.length) return;
  let html = '<table class="apdu-table"><thead><tr>' +
    '<th>#</th><th>Comando / Nota</th><th>APDU Enviado</th>' +
    '<th>Respuesta Carta</th><th>SW</th><th>Descripción</th>' +
    '</tr></thead><tbody>';
  steps.forEach(s => {
    if (s.type === 'note') {
      html += \`<tr class="note">
        <td>\${s.step}</td>
        <td colspan="4" style="color:#d29922">&#8505; \${s.label}</td>
        <td>\${s.note}</td>
      </tr>\`;
    } else {
      const cls = s.ok ? 'ok' : 'err';
      const sw_color = s.ok ? '#3fb950' : '#f85149';
      html += \`<tr class="\${cls}">
        <td>\${s.step}</td>
        <td>\${s.label}</td>
        <td class="mono">\${s.command}</td>
        <td class="mono">\${s.response || '-'}</td>
        <td style="color:\${sw_color};font-weight:bold">\${s.sw}</td>
        <td style="color:#8b949e">\${s.note || ''}</td>
      </tr>\`;
    }
  });
  html += '</tbody></table>';
  document.getElementById('trace').innerHTML = html;
}

// WebSocket live feed
const ws = new WebSocket('ws://' + location.host + '/ws');
const logEl = document.getElementById('log');
ws.onopen  = () => { logEl.innerHTML = '[WS] Conectado &#10003;\\n'; };
ws.onclose = () => { logEl.innerHTML += '[WS] Desconectado\\n'; };
ws.onmessage = e => {
  const ev = JSON.parse(e.data);
  if (ev.event === 'tap') {
    const t = ev.transaction;
    const status = t.approved ? 'APROBADO' : 'RECHAZADO';
    logEl.innerHTML += \`[\${new Date().toLocaleTimeString()}] \${status} \${t.uid} \${t.amount_mxn}\\n\`;
    logEl.scrollTop = logEl.scrollHeight;
  }
};

loadCards();
</script>
</body>
</html>"""
