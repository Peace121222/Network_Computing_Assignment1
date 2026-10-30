# Collab LAN

Collab LAN is a self-hosted collaboration application for Assignment 1. A Python server relays private messages, broadcasts, and files between authenticated clients over raw TCP/UDP sockets. Use either the terminal client or a local browser interface backed by the same client core.

## Features and limits

- Persistent username/password accounts in SQLite, with Argon2id password hashes.
- Server-verified TLS for TCP authentication and control traffic; a new random Fernet key for every login session.
- Online user discovery, private chat, and broadcast chat.
- UDP file transfer with chunking, ACK/retry, ordering, progress events, SHA-256 verification, and completion receipts.
- Session expiry, UDP endpoint verification, replay protection, bounded worker/transfer capacity, and shutdown cleanup.
- A local HTTP interface built with the standard library and client-side JavaScript. No Flask, Django, or WebSockets are used.

Files are limited to **25 MiB**. Each client allows two outgoing and two incoming transfers, with at most 50 MiB declared across active incoming files. Chat messages must fit both the 1,000-character limit and the 1,100-byte encrypted UDP datagram limit; long messages are not fragmented.

The server reads relayed content and encrypts it again with the recipient's key. This is **not end-to-end encryption**. There is no offline message storage, persistent chat history, automatic reconnect, file resume, password reset, email verification, OAuth, or admin role. BBR/CUBIC congestion control is not implemented.

## Requirements

- **Python 3.10 or later**, including the standard-library `ssl` and `sqlite3` modules. Python 3.11.4 on macOS is the locally verified runtime; Python 3.10 syntax compatibility is checked by the test suite. Windows/Linux operation has not been verified here.
- Runtime packages from `requirements.txt`: `cryptography>=42,<47` and `argon2-cffi>=23.1,<26`.
- TCP and bidirectional UDP connectivity between clients and the server.
- A browser for the Web UI. Node.js is optional and used by one JavaScript regression test, not by the application.
- OpenSSL is optional for the certificate-fingerprint command below.

All clients and the server must run the same protocol version. Legacy nickname/shared-key clients are incompatible with account authentication.

## Install from a clean checkout

Open a terminal in the repository root, the directory containing `requirements.txt` and `collab/`:

```bash
python3 --version
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

Check that `python3 --version` reports at least 3.10 before creating the environment. On Windows PowerShell, activate it with:

```powershell
.venv\Scripts\Activate.ps1
```

Activate the environment and use the repository root as the working directory in every additional terminal. The project uses `pip` and `requirements.txt`; there is no package-install/build configuration or lockfile.

## Create TLS certificates

For a localhost demo, generate a local CA and server certificate once:

```bash
python -m collab.certgen --out certs --names localhost 127.0.0.1
```

The command prints:

```text
Created CA and server certificate. Share only ca.crt with clients.
```

It creates:

| File | Purpose |
| --- | --- |
| `certs/ca.crt` | Public CA certificate trusted by clients |
| `certs/ca.key` | Private CA signing key; keep on the server |
| `certs/server.crt` | Server identity certificate |
| `certs/server.key` | Private server key; keep on the server |

Private keys are created with mode `0600` on POSIX systems. The server certificate is valid for 90 days and the CA for 365 days, with a five-minute clock allowance at issuance. The generator refuses to overwrite existing output files; use a new directory when rotating certificates.

Client `--ca` explicitly selects the trusted CA. The server hostname/IP must match a certificate SAN; verification is not disabled. When distributing `ca.crt`, compare its fingerprint over a separate trusted channel:

```bash
openssl x509 -in certs/ca.crt -noout -sha256 -fingerprint
```

## Run a localhost demo

### 1. Start the server

In terminal 1:

```bash
python -m collab.server \
  --host 127.0.0.1 --tcp-port 9000 --udp-port 9001 \
  --cert certs/server.crt --key certs/server.key \
  --database accounts.sqlite3
```

Keep this process running. The server does not display a client login menu. The database is created automatically; its parent directory must already exist. Restart with the same database path to retain accounts.

### 2. Register and log in as Alice and Bob

In terminal 2:

```bash
python -m collab.client --name alice --ca certs/ca.crt --downloads downloads/alice
```

In terminal 3:

```bash
python -m collab.client --name bob --ca certs/ca.crt --downloads downloads/bob
```

Both clients display:

```text
1. Log in
2. Register
3. Exit
```

For a new account:

1. Choose `2`.
2. Press Enter at `Username [alice]:` or `Username [bob]:` to accept the prefilled name.
3. Enter and confirm a password. `getpass` hides both inputs.
4. After `Registration successful. Please log in.`, choose `1` and enter the same credentials.

For an existing account, choose `1` immediately. `--name` is optional and only prefills the prompt; it never bypasses authentication. Passwords are not accepted as CLI arguments.

Usernames contain 1–24 Unicode letters/digits/underscores, with at least one letter or digit. They are case-sensitive and remain reserved while offline. Passwords contain 8–128 characters and are not trimmed. Each account can have one active session.

### 3. Chat and send files

After successful login, the CLI prints its command list. In Alice's terminal:

```text
/users
/msg bob Hello Bob
/all Hello everyone
/file bob /absolute/path/to/sample.bin
/quit
```

The file command accepts paths containing spaces without shell-style quoting, because it reads the rest of the input line as the path. Relative paths resolve against the client process's working directory.

Received files are saved under `--downloads`, with a random filename prefix to prevent overwrites. A `file_complete` event means the receiver verified SHA-256 and saved the file. For example, inspect Bob's directory:

```bash
ls -lht downloads/bob
```

`/quit`, EOF, Ctrl+C, TCP loss, or heartbeat expiry ends the session. Log in manually to reconnect; each successful login receives a fresh key.

## Use the Web UI

Stop an account's CLI before using that account in a Web backend. Run Alice and Bob in separate terminals:

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

Complete the same terminal login menu. The backend opens its HTTP listener only after successful login and prints the website address. Open [Alice's interface](http://127.0.0.1:8080) and [Bob's interface](http://127.0.0.1:8081). Select a recipient to send chat or choose a file for upload.

For a third account, run `--name carol --web-port 8082 --downloads downloads/carol` with the same CA and register Carol in the terminal.

`python -m collab.web` is equivalent to `python -m collab.webui`. HTTP always binds to `127.0.0.1`; open it on the machine running that backend. Closing a browser tab does not log out. Use Ctrl+C in the backend terminal to stop its client session.

## Configuration

All paths are relative to the process working directory unless absolute. There is no `.env` loader or separate configuration file.

| Option | Applies to | Required / default | Meaning |
| --- | --- | --- | --- |
| `--host` | Server | `127.0.0.1` | TCP/UDP bind address; use `0.0.0.0` to listen on LAN interfaces |
| `--tcp-port` | Server | `9000` | TCP control listener |
| `--udp-port` | Server | `9001` | UDP listener, announced to clients after login |
| `--cert` | Server | Required | PEM server certificate |
| `--key` | Server | Required | PEM server private key |
| `--database` | Server | `accounts.sqlite3` | Persistent SQLite account database |
| `--name` | CLI / Web | Optional | Prefilled username |
| `--host` | CLI / Web | `127.0.0.1` | Server address |
| `--port` | CLI / Web | `9000` | Server TCP port |
| `--ca` | CLI / Web | Required | PEM CA trusted for the server certificate |
| `--server-name` | CLI / Web | Server host | Certificate DNS/IP identity to verify, independent of the connection address |
| `--downloads` | CLI / Web | `downloads` | Receive directory, created by the client |
| `--web-port` | Web | `8080` | Local HTTP port; use a different port for each backend on one machine |
| `--out` | `certgen` | `certs` | Certificate output directory |
| `--names` | `certgen` | `localhost 127.0.0.1` | One or more DNS/IP SAN values; the first is also the certificate common name |

Use `python -m collab.server --help`, `python -m collab.client --help`, `python -m collab.webui --help`, or `python -m collab.certgen --help` to inspect options.

`COLLAB_KEY` is retained only by legacy codec helpers (`get_key()` / `cipher()`) and `python -m collab.keygen`. The server and client entry points do not use it for login. Setting it cannot bypass account authentication.

### LAN example

Replace `192.168.1.10` with the server's actual LAN IP. Generate certificates containing that IP, using a new output directory:

```bash
python -m collab.certgen --out certs-lan --names localhost 127.0.0.1 192.168.1.10
python -m collab.server --host 0.0.0.0 \
  --cert certs-lan/server.crt --key certs-lan/server.key \
  --database accounts.sqlite3
```

Securely copy only `certs-lan/ca.crt` to each client, for example as `certs/ca.crt`, and compare fingerprints. On a client:

```bash
python -m collab.client --name alice --host 192.168.1.10 \
  --ca certs/ca.crt --downloads downloads/alice
```

Use Bob's name and directory on another client. For Web, use the Web commands above with `--host 192.168.1.10`. Permit server TCP 9000 and UDP 9001 through the firewall and allow bidirectional client UDP traffic. If the IP changes, issue a certificate with the new SAN.

## Protocol and resource ownership

Authentication JSON uses four-byte length-prefixed frames inside verified TLS: `register → registered/error` or `login → welcome/error`. A successful login returns an independent random token, public session ID, Fernet key, and server UDP port. Account storage contains only `id`, `username`, `password_hash`, and `created_at`; session keys are never stored in SQLite or printed.

Established TCP frames also use the ordered session envelope. UDP datagrams start with a 32-byte public session lookup hint, followed by an encrypted envelope bound to protocol version, session, direction, transport, and sequence number. UDP uses a 4,096-packet replay window; TCP requires the exact next sequence. Retries retain application IDs but use fresh envelope sequences. UDP endpoint challenge/response precedes application traffic.

The CLI owns terminal input/output; the reusable client owns sockets and workers; the local HTTP backend calls that same client core; the server owns accounts, active sessions, routing, and relay queues. Existing public imports remain available through `collab.client.Client`, `collab.server.Server`, `collab.common`, and `collab.webui`. `collab.client.core.main()` remains a compatibility entry point. Static Web resources intentionally load at import so the existing `PAGE` export and startup errors remain compatible.

Important defaults, defined in `collab/shared/limits.py` and the runtime constructors:

| Limit | Default |
| --- | --- |
| Server TCP connections, including unauthenticated connections | 64 |
| Server pending packets / per-recipient pending packets | 8,192 / 1,024 |
| Authentication frame / concurrent Argon2 jobs | 2,048 bytes / 4 |
| Authentication attempts per source IP | 10 per 60-second fixed window, including registration and successful login |
| Remembered authentication IPs | At most 4,096; expiring LRU state |
| Argon2id parameters | 19 MiB memory, 2 iterations, parallelism 1, random salt |
| TCP connection timeout / client login deadline / server login deadline | 5 / 5 / 4 seconds |
| Heartbeat interval / session expiry / expiry check interval | 2 / 10 / 0.5 seconds |
| UDP datagram / file chunk / send window | 1,100 bytes / 320 bytes / 6 packets |
| HTTP send workers / waiting send slots / concurrent uploads | 2 / 4 / 2 |
| HTTP handler workers / total admitted requests | 8 / 16 |

The client login deadline starts before TCP setup; the connection attempt also has its own timeout. Valid application UDP traffic from a verified endpoint extends heartbeat lifetime; path verification alone does not. Losing TCP also ends the session. Chat ACKs indicate application acceptance, not that a person read the message. File completion requires the receiver's verification/save receipt. HTTP 202 means a send job was accepted locally, not that delivery is complete; exhausted HTTP capacity returns 503.

Authentication limits are shared by clients behind the same source IP. SQLite is not encrypted at rest. Protect the database and private keys with filesystem permissions. Python releases session references during cleanup but does not guarantee key-memory zeroization. The replay window cannot identify a valid packet withheld before its first delivery. The Web UI consumes one local event queue; multiple tabs do not synchronize or restore chat history after refresh.

## Development and verification

The existing test runner is standard-library `unittest`. Run from the repository root with the environment activated:

```bash
# Full suite; uses temporary localhost TCP/UDP ports.
python -m unittest discover -s tests -q

# Focused authentication, handshake, and compatibility checks.
python -m unittest tests.test_accounts tests.test_handshake tests.test_refactoring -q

# Individual network or HTTP integration suites.
python -m unittest tests.test_integration tests.test_web_ui -q

# Syntax compilation and whitespace checks.
python -m compileall -q collab tests
git diff --check
```

Tests use disposable databases, certificates, account names, files, and OS-assigned localhost ports. Socket binding must be permitted in your environment. One JavaScript test is skipped if Node.js is absent. Some tests deliberately inject worker/disk/cleanup failures and print tracebacks even on success; use the final summary and process exit code to determine the result.

The existing formatting convention is Black, Python 3.10 target, 88 columns. Black is optional and is not installed by `requirements.txt`. If available in your Python 3.10+ environment, run:

```bash
python -m black --check --target-version py310 --line-length 88 collab tests
```

No lint or static type checker is configured, and Ruff, mypy, and Pyright are not part of the repository's development dependencies. Type annotations and the annotation-resolution/Python-3.10-grammar regression tests do not constitute a static type check. There is no checked-in CI workflow, packaging configuration, contributor guide, or license file; the repository owner still needs to choose and document a license before distribution under one.

## Troubleshooting

| Symptom | What to check |
| --- | --- |
| `No module named collab` | Run from the repository root with the correct virtual environment active. |
| Missing `cryptography` or `argon2` | Run `python -m pip install -r requirements.txt` in that environment. |
| Certificate files already exist | Reuse existing certificates or generate into a new directory; the generator will not overwrite them. |
| Certificate verification fails | Check `--ca`, certificate validity, system clock, and the DNS/IP SAN. For LAN, the certificate must include the address you use. |
| `Invalid username or password` | Check the case-sensitive username and password; register first if the account is new. |
| `User already connected` | Stop that account's existing client/backend or wait for its expired session to be removed. |
| `Too many authentication attempts; try later` | Wait for the 60-second source-IP window to expire. Users behind one NAT share the limit. |
| `Address already in use` | Stop the old listener or select unused TCP/UDP/Web ports. Each local Web backend needs a separate `--web-port`. |
| Login works but presence/file delivery fails | Check bidirectional UDP, the server UDP port, firewall rules, and heartbeat expiry. |
| Web page does not open | Finish terminal login first, keep the backend running, and open its printed localhost URL on that machine. |
| File was sent but is not complete | Wait for the completion event; look in the recipient's configured downloads directory for the prefixed filename. HTTP acceptance or chunk ACKs alone do not mean completion. |
| Cannot open/write the database | Ensure its parent exists, the path is writable, and another process is not holding a long SQLite write lock. |

## Repository layout

```text
collab/
  accounts.py          SQLite accounts, password policy, and authentication limiter
  certgen.py           Local CA and server certificate generator
  client/              Client lifecycle, terminal UI, chat, and file transfer
  server/              Server lifecycle, session control, routing, and file relay
  transport/           TLS contexts, authentication, TCP framing, UDP, and envelopes
  shared/              Protocol validation, limits, concurrency, and cleanup helpers
  web/                 Local HTTP handlers, bounded runtime, and Web entry point
    static/            Browser HTML, CSS, and JavaScript
  common.py            Compatibility exports for protocol/transport helpers
  keygen.py            Legacy Fernet-key utility; not used for account login
  webui.py             Compatibility Web entry point and exports
tests/                 Unit, network, browser-interface, and compatibility tests
docs/                  Existing report, report builder, and historical test output
requirements.txt       Runtime dependency ranges
```

Copy the complete `collab/web/static/` directory when copying the project. The generated PDF and saved test output in `docs/` predate the current authentication implementation; this README describes current usage. No claim of complete assignment-rubric compliance is made.
