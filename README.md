# Collab LAN

Collab LAN is a self-hosted collaboration application for Assignment 1. A Python server relays private messages, broadcasts, and files between authenticated clients over raw TCP/UDP sockets. Use either the terminal client or a local browser interface backed by the same client core.

## Features and limits

- Persistent username/password accounts in SQLite, with secure PBKDF2-HMAC-SHA256 password hashes.
- Server-verified TLS for TCP authentication and control traffic; a new random Fernet key for every login session.
- Online user discovery, private chat, and broadcast chat.
- UDP file transfer with chunking, ACK/retry, ordering, progress events, SHA-256 verification, and completion receipts.
- Session expiry, UDP endpoint verification, replay protection, simplified application-level CUBIC data windows/pacing, bounded worker/transfer capacity, and shutdown cleanup.
- A local HTTP interface built with the standard library and client-side JavaScript. No Flask, Django, or WebSockets are used.

Files are limited to **25 MiB**. Each client allows two outgoing and two incoming transfers, with at most 50 MiB declared across active incoming files. Chat messages must fit both the 1,000-character limit and the 1,100-byte encrypted UDP datagram limit; long messages are not fragmented.

The server reads relayed content and encrypts it again with the recipient's key. This is **not end-to-end encryption**. There is no offline message storage, persistent chat history, automatic reconnect, file resume, password reset, email verification, OAuth, or admin role. Application-level CUBIC controls both UDP data hops; BBR is not implemented.

## Requirements

- **Python 3.10 or later**, including the standard-library `ssl` and `sqlite3` modules.
- Runtime packages from `requirements.txt`: `cryptography>=42,<47`. (Argon2 has been replaced by Python's built-in `hashlib.pbkdf2_hmac` to optimize dependencies).
- TCP and bidirectional UDP connectivity between clients and the server.
- A browser for the Web UI.

All clients and the server must run the same protocol version.

## Install from a clean checkout

Open a terminal in the repository root, the directory containing `requirements.txt` and `collab/`:

```bash
python3 --version
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

On Windows PowerShell, activate it with:

```powershell
.venv\Scripts\Activate.ps1
```

## Create TLS certificates

For a localhost demo, generate a local CA and server certificate once:

```bash
python -m collab.certgen --out certs --names localhost 127.0.0.1
```

It creates:

| File | Purpose |
| --- | --- |
| `certs/ca.crt` | Public CA certificate trusted by clients |
| `certs/ca.key` | Private CA signing key; keep on the server |
| `certs/server.crt` | Server identity certificate |
| `certs/server.key` | Private server key; keep on the server |

## Run a localhost demo

### 1. Start the server

In terminal 1:

```bash
python -m collab.server \
  --host 127.0.0.1 --tcp-port 9000 --udp-port 9001 \
  --cert certs/server.crt --key certs/server.key \
  --database accounts.sqlite3
```

### 2. Register and log in as Alice and Bob

In terminal 2:

```bash
python -m collab.client --name alice --ca certs/ca.crt --downloads downloads/alice
```

In terminal 3:

```bash
python -m collab.client --name bob --ca certs/ca.crt --downloads downloads/bob
```

Follow the interactive terminal menu to register (`2`) or log in (`1`).

### 3. Chat and send files

In Alice's terminal CLI:

```text
/users
/msg bob Hello Bob
/all Hello everyone
/file bob /absolute/path/to/sample.bin
/quit
```

## Use the Web UI

Run Alice and Bob's web backend in separate terminals:

```bash
# Alice
python -m collab.webui --name alice --ca certs/ca.crt \
  --web-port 8080 --downloads downloads/alice
```

```bash
# Bob
python -m collab.webui --name bob --ca certs/ca.crt \
  --web-port 8081 --downloads downloads/bob
```

Complete the terminal login menu first. Then open Alice's interface and Bob's interface in your browser.

## Configuration

| Option | Applies to | Default | Meaning |
| --- | --- | --- | --- |
| `--host` | Server | `127.0.0.1` | TCP/UDP bind address |
| `--tcp-port` | Server | `9000` | TCP control listener |
| `--udp-port` | Server | `9001` | UDP listener |
| `--cert` | Server | Required | PEM server certificate |
| `--key` | Server | Required | PEM server private key |
| `--database` | Server | `accounts.sqlite3` | SQLite account database |
| `--name` | CLI / Web | Optional | Prefilled username |
| `--ca` | CLI / Web | Required | PEM CA trusted for the server certificate |
| `--downloads` | CLI / Web | `downloads` | Receive directory |
| `--web-port` | Web | `8080` | Local HTTP port |

## Multi-client and LAN verification

To verify an already-running server from another machine or script, run:

```bash
python scripts/verify_lan.py --host 127.0.0.1 --port 9000 --ca certs/ca.crt
```

## Repository layout

```text
collab/
  accounts.py          SQLite accounts and PBKDF2-HMAC password hashing
  certgen.py           Local CA and server certificate generator
  client/              Client lifecycle, terminal UI, chat, and file transfer
  server/              Server lifecycle, session control, routing, and file relay
  transport/           TLS, authentication, TCP/UDP framing, envelopes, and CUBIC
  shared/              Protocol validation, limits, concurrency, and cleanup helpers
  web/                 Local HTTP handlers, bounded runtime, and Web entry point
    static/            Browser HTML, CSS, and JavaScript
scripts/               Repeatable LAN/private-chat/broadcast/file verifier
tests/                 Unit, network, and integration tests
requirements.txt       Runtime dependency ranges
```