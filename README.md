# Collab LAN — Assignment 1

A self-hosted LAN collaboration application built with Python TCP/UDP sockets and the `cryptography` library. It supports nickname login, online user lists, private and broadcast messaging, file transfers up to 25 MiB with SHA-256 verification, encrypted TCP/UDP traffic, and an HTTP interface using plain client-side JavaScript.

## 1. Requirements

- Python **3.10 or later**. The test suite has been verified on macOS with Python 3.12; Windows and Linux have not been verified directly.
- All server/client processes must use the **same source-code version** and the same `COLLAB_KEY`.
- Machines must be able to communicate over both TCP and UDP. Each browser accesses the HTTP backend on the machine running its client.
- Node.js is optional for one test that executes the interface's JavaScript. The application does not require Node.js to run.

Run the commands below from the project root directory.

## 2. Installation and Key Generation

Create a virtual environment:

```bash
python -m venv .venv
```

Activate it on macOS/Linux:

```bash
source .venv/bin/activate
```

Or on Windows PowerShell:

```powershell
.venv\Scripts\Activate.ps1
```

Install the dependency and generate a key:

```bash
python -m pip install -r requirements.txt
python -m collab.keygen
```

The last command prints a Fernet key. Copy this key for use by the server and every client; do not generate a different key for each terminal.

In **every terminal**, activate the virtual environment and set the key before starting the application.

macOS/Linux:

```bash
export COLLAB_KEY='PASTE_GENERATED_KEY'
```

Windows PowerShell:

```powershell
$env:COLLAB_KEY='PASTE_GENERATED_KEY'
```

Missing or malformed keys are rejected before opening a connection. Changing the key requires restarting the server and clients.

## 3. Running on Localhost with Three Terminals

After configuring the environment and key in all three terminals:

**Terminal 1 — server:**

```bash
python -m collab.server --host 127.0.0.1 --tcp-port 9000 --udp-port 9001
```

**Terminal 2 — Alice:**

```bash
python -m collab.webui --name alice --host 127.0.0.1 --port 9000 --web-port 8080 --downloads downloads/alice
```

**Terminal 3 — Bob:**

```bash
python -m collab.webui --name bob --host 127.0.0.1 --port 9000 --web-port 8081 --downloads downloads/bob
```

Open two browser tabs:

- Alice: <http://127.0.0.1:8080>
- Bob: <http://127.0.0.1:8081>

Select a nickname to send a private message or `Everyone` to broadcast. The interface displays messages, online users, connection status, and separate progress bars for each outgoing/incoming file. Received files are saved in the `--downloads` directory with a random prefix to prevent overwrites. A file is reported as received only after its hash has been verified and the file has been saved successfully.

You can use `python -m collab.web` instead of `python -m collab.webui` with the same arguments. Press Ctrl+C in the relevant terminal to stop a backend/client or the server. Closing a browser tab does not stop the client process.

## 4. Running the Command-Line Client

In a terminal with the virtual environment activated and the same key configured:

```bash
python -m collab.client --name carol --host 127.0.0.1 --port 9000 --downloads downloads/carol
```

Enter these commands in the client:

```text
/users
/msg alice Hello Alice
/all Hello everyone
/file alice ./sample.bin
/quit
```

File paths are relative to the client process's working directory. Nicknames contain 1–24 letters, digits, or underscores, with at least one letter or digit. They are case-sensitive and must not duplicate an active session's nickname. The client reports individual command errors and continues while its connection remains healthy. Use `/quit`, EOF, or Ctrl+C to exit.

## 5. Running Across LAN Machines

On the server machine:

```bash
python -m collab.server --host 0.0.0.0 --tcp-port 9000 --udp-port 9001
```

On each client machine, replace `SERVER_LAN_IP` with the server's actual LAN IP address:

```bash
python -m collab.webui --name alice --host SERVER_LAN_IP --port 9000 --web-port 8080 --downloads downloads/alice
```

Open <http://127.0.0.1:8080> on **that client machine**. When running multiple clients on one machine, use distinct nicknames and `--web-port` values. Allow TCP 9000 and UDP 9001 through the server machine's firewall. Bidirectional UDP communication is required for endpoint registration, data reception, and ACKs.

The HTTP backend binds only to `127.0.0.1`; its port does not need to be exposed to the LAN. Automated tests use localhost and do not replace checks of firewall configuration and connectivity between physical machines.

## 6. Protocol and Delivery Semantics

- **TCP:** the `hello → challenge → login → welcome/error` handshake, session management, large online-user snapshots, chat/file results, and control messages. Each frame contains a 4-byte length header and a Fernet-encrypted body.
- **UDP:** heartbeats, endpoint verification through challenge/response, presence, ACKs, and chat/file data. Encrypted datagrams are limited to **1,100 bytes**; file chunks contain **320 bytes**.
- Security envelopes bind the protocol version, session, direction, TCP/UDP channel, and sequence number. TCP requires the exact next sequence number; UDP uses a **4,096-packet** replay window. Retries retain their application-level ID and receive a new security sequence number.
- Heartbeats are sent every **2 seconds**. After **10 seconds without valid application UDP traffic from a verified endpoint**, the server closes the session even if TCP is still open. Expiry is checked every 0.5 seconds. Losing TCP also ends the session.
- TCP connection establishment allows up to 5 seconds. The complete handshake has a 5-second client deadline and a 4-second server deadline. There is no automatic reconnection.
- Chat succeeds when the recipient application has accepted the message into its buffer/queue, **not when a person has read it**. A broadcast succeeds only when all recipients selected at initial acceptance acknowledge it. Partial failures include detailed recipient results.
- A file transfer succeeds when all initial recipients confirm SHA-256 verification and successful saving. Chunk ACKs confirm individual hops; they do not confirm completion of the file.
- HTTP **202** means the task has entered the local client's send queue. Final results arrive through interface events.

## 7. Limits and Scope

- Files are limited to **25 MiB**. The sender reads files in blocks; the receiver writes chunks to a temporary file, verifies its hash, and renames it upon completion. Browser/HTTP uploads still buffer JSON/base64 data in memory.
- Each client supports up to **2 outgoing** and **2 incoming** file transfers concurrently. The total declared size of active incoming files cannot exceed **50 MiB**.
- The server defaults to **64 TCP connections**, **8,192 pending packets**, and **1,024 pending packets per recipient session**. Some capacity is reserved for chat so file traffic cannot occupy the entire queue.
- HTTP uses 2 send workers and 4 waiting slots, allows up to 2 uploads, and has 8 handler workers with capacity for 16 admitted connections. Exhausted task capacity returns HTTP 503.
- Chat is limited by both character count and ciphertext size; not every 1,000-character message fits in one datagram. Long messages are not fragmented.
- Reliability includes ACKs/retries, a send window, and chat ordering with a maximum 1-second gap wait per stream. **BBR/CUBIC is not implemented.** File resume, offline message storage, and automatic retransmission of an entire file are also not implemented. Chunks arriving before `file_start` are neither accepted nor ACKed.
- Fernet protects both TCP and UDP using a **shared group key**. Anyone who knows that key can decrypt and forge group traffic. Login authenticates nicknames/sessions within a trusted group; there are no passwords, database, TLS, per-user keys, or end-to-end encryption between clients.
- The replay window rejects previously observed packets and packets outside its window. It cannot identify every valid packet withheld before its first delivery.
- The interface serves one local user. There is no persistent history or event synchronization across multiple tabs; refreshing does not restore history already consumed from the backend.

## 8. Testing

Run the complete suite from the project root:

```bash
python -m unittest discover -s tests -v
```

The suite currently contains **237 tests** covering protocol validation, handshake deadlines and rollback, sessions/presence, 20 concurrent clients, chat retries and ordering, files/hashes/disk failures, worker failures and cleanup, security/replay/UDP endpoint verification, the HTTP interface, CLI compatibility, static-resource loading, and public annotation contracts.

Tests generate temporary keys, open localhost sockets on operating-system-assigned ports, and use temporary directories. One JavaScript test uses Node.js when it is available in `PATH`; otherwise, that test is skipped. Tests that intentionally simulate failures may print traceback logs even when the final result is `OK`; check the summary and exit code.

Run the integration or interface tests separately:

```bash
python -m unittest discover -s tests -p test_integration.py -v
python -m unittest discover -s tests -p test_web_ui.py -v
```

If Black is installed in the Python 3.10+ environment, check formatting without modifying files:

```bash
python -m black --check --target-version py310 --line-length 88 collab tests
```

Black is a development tool, not a runtime dependency.

### Verification with Multiple Terminals

1. Start the server and two clients as described in section 3 or 4. Confirm both nicknames appear in the online list.
2. Send private and broadcast messages. Check the recipients and contents.
3. Send a regular file and an empty file. Wait for successful saving and compare the original and received SHA-256 hashes.
4. Close one client. Confirm the remaining client's online list updates and messaging still works.
5. Try a duplicate nickname or send to an offline recipient. Confirm a clear error is reported and healthy sessions remain usable.
6. Stop the server. Confirm clients go offline and release resources. Restart and reconnect manually.

## 9. Project Structure

```text
collab/
  client/       # Socket core, cli.py, chat sender/inbox, and file transfers
  server/       # Server lifecycle, sessions, and chat/file routing
  transport/    # TCP framing, UDP codec, security envelopes, and handshake
  shared/       # Validators, constants, bounded executor, and common error handling
  web/          # HTTP handlers, bounded runtime, and CLI
    static/     # index.html, style.css, and app.js
  common.py     # Compatibility imports for protocol/transport
  keygen.py     # Fernet key generation
  webui.py      # Compatibility entry point for the web interface
tests/          # Automated test suite
docs/           # Existing PDF report and report-generation script
```

The client terminal interface lives in `collab.client.cli`; `collab.client.core.main()` remains a lazy forwarding entry point. Web handlers retain the `PAGE` HTML export, while CSS and JavaScript are served from a fixed static-resource allowlist. Static files are resolved relative to the package, so loading does not depend on the current working directory. Include the entire `collab/web/static/` directory when copying the project.

Public protocol/transport and client/server interfaces have type annotations compatible with Python 3.10+. Validators still accept untrusted values and return the validated message; annotations do not replace runtime validation. Lock documentation identifies caller-held locks, session checks, and cleanup ownership without changing the synchronization model.

Shared timing defaults are centralized in `collab/shared/limits.py`:

| Constant | Seconds | Purpose |
| --- | ---: | --- |
| `SHUTDOWN_TIMEOUT` | 3 | Common shutdown deadline |
| `CONTROL_TIMEOUT` | 0.5 | Server TCP control write deadline |
| `UDP_PATH_CHALLENGE_TIMEOUT` | 2 | Candidate endpoint challenge lifetime |
| `UDP_PATH_CHALLENGE_INTERVAL` | 0.5 | Minimum interval between new path challenges |
| `HTTP_REQUEST_TIMEOUT` | 2 | HTTP request socket timeout |
| `FILE_PROGRESS_INTERVAL` | 0.1 | Send/receive progress sampling interval |

`LOGOUT_TIMEOUT` remains separate from `CONTROL_TIMEOUT` because they serve different operations. These source-level defaults preserve existing behavior; they do not add CLI options or live reconfiguration.

Packages retain `__init__.py`/`__main__.py` so that `python -m collab.server`, `python -m collab.client`, and `python -m collab.web` continue to work.
