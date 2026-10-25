# BusTerminal-NFC-Simulator

Simulador de terminal de cobro contactless para transporte público. Habla los tres protocolos que se encuentran en tarjetas de tránsito reales: DESFire EV1 nativo, EMV Contactless (Visa/Mastercard) y MIFARE Classic 1K. Muestra la traza APDU completa paso a paso en la terminal, en tiempo real.

El proyecto surgió como herramienta de investigación para entender cómo funcionan las terminales de cobro en transporte público, desde el handshake inicial hasta el commit de la transacción en el chip.

---

## Cómo funciona

Cuando se acerca una tarjeta al lector NFC, el sistema detecta automáticamente qué protocolo usa y ejecuta el flujo correspondiente:

**DESFire EV1** — protocolo común en tarjetas de tránsito modernas. El flujo completo toma 10 pasos: GET_VERSION × 3 frames, GET_APPLICATION_IDs, SELECT_APPLICATION, autenticación AES mutua en 2 pasos (3-pass challenge-response), GET_FILE_IDs, GET_FILE_SETTINGS, GET_VALUE, DEBIT_VALUE y COMMIT_TRANSACTION. La autenticación genera una session key efímera derivada de RndA y RndB. El saldo vive en un Value File (archivo 0x01) en el chip.

**EMV Contactless** — para tarjetas bancarias con chip NFC (Visa payWave, Mastercard Contactless, AMEX). Ejecuta el kernel L2: SELECT PPSE, SELECT AID, GET PROCESSING OPTIONS, READ RECORD y GENERATE AC. El chip devuelve un criptograma (TC para aprobación offline, ARQC para autorización online, AAC para declinar). La terminal interpreta el Application Interchange Profile para saber qué capacidades tiene la tarjeta.

**MIFARE Classic 1K** — protocolo más antiguo, presente en sistemas de tránsito de primera generación. El saldo vive directamente en un value block del sector 2 de la tarjeta. El flujo carga la clave en el lector, autentica cada sector con Key A, lee los bloques de metadatos (nombre, ID, tipo de tarjeta), lee el saldo, lo descuenta y escribe el nuevo valor. No requiere conectividad al backend.

Cuando la tarjeta es DESFire y ya está registrada en la base de datos local (`data/cards.json`), el saldo GTC también se descuenta en la base para mantener sincronía. Si la tarjeta DESFire no está registrada, el sistema la rechaza y pide registrarla primero con `--enroll`.

---

## Requisitos

- Python 3.10 o superior
- Driver PC/SC instalado en el sistema operativo:
  - macOS: incluido en el sistema (no requiere instalación adicional)
  - Linux: instalar `pcscd` y `libpcsclite-dev`
  - Windows: instala el driver del fabricante del lector
- Un lector NFC compatible con PC/SC: ACR122U, ACR1252U, SCL3711, o cualquier lector que cumpla ISO 14443

Dependencias Python:

```
pyscard>=2.0.0
rich>=13.0.0
pycryptodome>=3.19.0
fastapi>=0.110.0
uvicorn[standard]>=0.27.0
```

Instalar:

```bash
pip install -r requirements.txt
```

---

## Uso

### Terminal CLI

```bash
# Modo normal — espera tarjetas en bucle, muestra traza APDU
python3 main.py

# Modo virtual — no requiere lector NFC, usa tarjetas simuladas preconfiguradas
python3 main.py --sim

# Registrar una tarjeta DESFire en la base de datos local (50 GTC iniciales)
python3 main.py --enroll

# Procesar una sola tarjeta y salir
python3 main.py --once

# Ocultar la traza APDU (por defecto siempre se muestra)
python3 main.py --no-apdu
```

### Backend REST + UI web

```bash
uvicorn backend.app:app --reload --port 8000
```

Abre `http://localhost:8000` para ver la interfaz web. Desde ahí puedes ver las tarjetas simuladas, disparar cobros, recargar saldo y monitorear transacciones en tiempo real via WebSocket.

Endpoints disponibles:

| Método | Ruta | Descripción |
|--------|------|-------------|
| GET | `/cards` | Lista todas las tarjetas |
| GET | `/cards/{uid}` | Detalle de una tarjeta |
| POST | `/cards` | Crear tarjeta simulada |
| POST | `/cards/{uid}/reload` | Recargar saldo |
| POST | `/simulate/tap/{uid}` | Simular un cobro (devuelve traza APDU completa) |
| GET | `/transactions` | Historial de todas las transacciones |
| WS | `/ws` | Feed de eventos en tiempo real |

### Herramienta MIFARE

```bash
# Leer una tarjeta MIFARE Classic conectada al lector
python3 mifare_rw.py --read

# Inicializar/escribir datos en una tarjeta MIFARE virgen
python3 mifare_rw.py --write
```

---

## Estructura del proyecto

```
BusTerminal-NFC-Simulator/
├── main.py                  — Punto de entrada, CLI de la terminal
├── mifare_rw.py             — Lectura/escritura de tarjetas MIFARE Classic
├── requirements.txt
├── data/
│   └── cards.json           — Base de datos persistente de tarjetas registradas
├── backend/
│   ├── app.py               — FastAPI: rutas REST, WebSocket, UI web embebida
│   └── card_db.py           — Store en memoria para el backend
└── src/
    ├── desfire_sim.py        — Simulador de tarjeta DESFire EV1 (protocolo completo)
    ├── desfire_terminal.py   — Kernel de cobro DESFire (10 pasos del protocolo)
    ├── terminal.py           — Kernel EMV L2 contactless
    ├── mifare.py             — Constantes y helpers para MIFARE Classic 1K
    ├── reader.py             — Abstracción del lector PC/SC
    ├── virtual_conn.py       — Conexión virtual para modo simulación
    ├── card_store.py         — Persistencia JSON de tarjetas y saldos GTC
    ├── apdu.py               — Utilidades para construir y parsear APDUs
    └── tlv.py                — Parser TLV (Tag-Length-Value) para datos EMV
```

---

## Modo simulación

El modo `--sim` no requiere hardware. Hay cinco tarjetas preconfiguradas con saldos variados para probar distintos escenarios: tarjeta con saldo suficiente, saldo bajo, saldo insuficiente, saldo premium y exactamente dos viajes disponibles. Los saldos persisten durante la sesión; si cobras varias veces a la misma tarjeta el saldo baja de forma acumulativa.

El simulador ejecuta el protocolo DESFire completo incluyendo la autenticación AES mutua, usando una clave de terminal hardcodeada (`00112233445566778899AABBCCDDEEFF`). En un despliegue real esta clave estaría en un HSM y sería diferente por aplicación.

---

## Notas de seguridad

Este proyecto es una herramienta de investigación y educación. La clave AES del terminal es pública a propósito. No está diseñado para usarse en producción. El protocolo DESFire real en producción usa claves diversificadas por tarjeta (CMAC con UID como dato de diversificación) y comunicación cifrada en el canal NFC.
