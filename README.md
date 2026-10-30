# Collab LAN — Assignment 1

A raw TCP/UDP socket collaboration application with persistent username/password accounts, online presence, private and broadcast chat, reliable file transfer with SHA-256 verification, and a local HTTP interface using client-side JavaScript.

## 1. Requirements and installation

Python **3.10+**; all clients and the server must run this same protocol version. The previous nickname/shared `COLLAB_KEY` login is incompatible and cannot authenticate to this server. `COLLAB_KEY` is ignored by the application entry points. Node.js is optional for one JavaScript test.

Run all commands from this repository:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

On Windows, activate with `.venv\Scripts\Activate.ps1`. New runtime dependency: `argon2-cffi`; TLS/SQLite use Python’s standard library, and certificate/session encryption uses `cryptography`.

## 2. Create and trust a local demo CA

For localhost:

```bash
python -m collab.certgen --out certs --names localhost 127.0.0.1
```

This creates `ca.crt`, `ca.key`, `server.crt`, `server.key`. Keep both private keys on the server and protect them; the generator creates them with mode 0600. It refuses to overwrite files. Certificates expire after 90 days (CA: 365 days); generate a new directory when rotating and distribute the new CA through a trusted channel.

Clients explicitly trust **only the public `ca.crt`** using `--ca`. Verify its fingerprint over a separate trusted channel before copying it to another machine:

```bash
openssl x509 -in certs/ca.crt -noout -sha256 -fingerprint
```

No verification bypass is provided. The connection hostname/IP must occur in the certificate SAN. `--server-name localhost` can select the verified DNS identity independently of `--host`; it still requires a trusted matching certificate.

## 3. Localhost demo: one server, two CLI users

Activate the virtual environment in every terminal. Terminal 1:

```bash
python -m collab.server --host 127.0.0.1 --tcp-port 9000 --udp-port 9001 --cert certs/server.crt --key certs/server.key --database accounts.sqlite3
```

Terminal 2:

```bash
python -m collab.client --name alice --host 127.0.0.1 --port 9000 --ca certs/ca.crt --downloads downloads/alice
```

Terminal 3:

```bash
python -m collab.client --name bob --host 127.0.0.1 --port 9000 --ca certs/ca.crt --downloads downloads/bob
```

In each client terminal choose **2. Register**, press Enter to accept the prefilled username, enter a password and confirm it (both hidden via `getpass`). After successful registration the menu returns; choose **1. Log in**, accept the username and enter the password. Choose **3. Exit** to exit. `--name` is optional and never bypasses authentication. Passwords have no command-line option.

Usernames contain 1–24 Unicode letters/digits/underscores with at least one letter/digit, following the existing validator. They are **case-sensitive** (`Alice` and `alice` differ) and remain reserved offline. Passwords must be 8–128 characters. Incorrect login uses a generic message; the server reports an existing active session only after verifying the password. One account has one active session.

After login:

```text
/users
/msg bob Hello Bob
/all Hello everyone
/file bob /absolute/path/to/file.bin
/quit
```

Paths are relative to the client working directory unless absolute. Received files use random prefixes in `--downloads`; files are announced complete only after hash verification and saving. `/quit`, EOF, Ctrl+C, TCP loss and heartbeat expiry terminate the session. There is no automatic reconnect. Restart the same server with the same `--database` to retain accounts; start a client again to log in with a new key.

## 4. Two Web UI backends

Stop the corresponding CLI sessions first (one session per account). Terminal 2:

```bash
python -m collab.webui --name alice --host 127.0.0.1 --port 9000 --ca certs/ca.crt --web-port 8080 --downloads downloads/alice
```

Terminal 3:

```bash
python -m collab.webui --name bob --host 127.0.0.1 --port 9000 --ca certs/ca.crt --web-port 8081 --downloads downloads/bob
```

Complete the same terminal login menu. Only after authentication succeeds does the backend open its local HTTP listener and print [Alice’s UI](http://127.0.0.1:8080) or [Bob’s UI](http://127.0.0.1:8081). No browser login form is added. `python -m collab.web` is an equivalent entry point. Browser tabs do not own the session; Ctrl+C in the backend terminal logs out. HTTP remains bound to `127.0.0.1` and should be opened on the client machine.

## 5. LAN configuration

Suppose the server’s LAN IP is `192.168.1.10`. Generate certificates containing that actual IP (use a new directory):

```bash
python -m collab.certgen --out certs-lan --names localhost 127.0.0.1 192.168.1.10
python -m collab.server --host 0.0.0.0 --tcp-port 9000 --udp-port 9001 --cert certs-lan/server.crt --key certs-lan/server.key --database accounts.sqlite3
```

Copy `certs-lan/ca.crt` securely to each client, for example as `certs/ca.crt`, and compare fingerprints. On each client:

```bash
python -m collab.client --name alice --host 192.168.1.10 --port 9000 --ca certs/ca.crt --downloads downloads/alice
# On the other client, change alice to bob and downloads/alice to downloads/bob.
```

For the Web UI use the commands from section 4 with `--host 192.168.1.10`. Open the printed localhost URL on each client’s own machine. Allow inbound TCP 9000 and UDP 9001 on the server and bidirectional UDP for clients. A changed IP requires a matching new certificate SAN. `--database` and `--downloads` are relative to the process working directory unless absolute; the database parent directory must already exist.

The Assignment 1 PDF requires login/state tracking, raw sockets, UDP file transfer, separation of UI/network logic and standard cryptographic libraries. This implementation uses `socket`/`ssl` and retains the custom UDP reliability protocol; it adds no Flask/Django/WebSockets. The PDF also mentions BBR/CUBIC, which this project does not implement; no claim of full rubric compliance is made. The existing generated report under `docs/` predates this authentication change; this README describes the current protocol.

Detailed exchange and behavioral test coverage: [authentication protocol](docs/authentication.md).

## 6. Protocol and Delivery Semantics

- **TCP:** TLS followed by `login → welcome/error` (or `register → registered/error`), session management, large online-user snapshots, chat/file results, and control messages. Each frame has a 4-byte length header. Authentication frames are JSON inside TLS; established frames also carry a Fernet session envelope.
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
- TLS verifies the server and protects the entire TCP connection. Every successful login receives a fresh random Fernet key, session ID and token over TLS. UDP includes a 32-byte public session lookup prefix; the encrypted envelope independently authenticates that context. The server decrypts Alice’s traffic and encrypts it under Bob’s key: **this is not end-to-end encryption**. Keys are never stored in SQLite or printed. Session references are released when sockets/workers finish; Python does not guarantee secure memory erasure.
- Passwords use Argon2id (19 MiB memory, 2 iterations, parallelism 1, random library-managed salts). Policy: 8–128 characters, no composition rule, no silent trimming. Use a unique passphrase. SQLite stores only id, case-sensitive unique username, password_hash and creation time. Protect the database and CA/server private keys with filesystem permissions; SQLite is not encrypted at rest.
- Authentication attempts (including registrations and successful attempts) are limited per source IP to 10 per 60-second window, with at most 4,096 remembered IPs. This is temporary and may affect users behind one NAT; it is not a distributed abuse defense. Unauthenticated sockets share the 64-connection cap and handshake deadline, accept at most 2,048 bytes per authentication frame, and share four Argon2 workers (about 76 MiB hashing memory). No email, password reset, OAuth or admin roles are provided.
- The replay window rejects previously observed packets and packets outside its window. It cannot identify every valid packet withheld before its first delivery.
- The interface serves one local user. There is no persistent history or event synchronization across multiple tabs; refreshing does not restore history already consumed from the backend.

## 8. Testing

Run the complete suite from the project root:

```bash
python -m unittest discover -s tests -v
```

The unittest suite covers protocol validation, handshake deadlines and rollback, sessions/presence, 20 concurrent clients, chat retries and ordering, files/hashes/disk failures, worker failures and cleanup, security/replay/UDP endpoint verification, the HTTP interface, CLI compatibility, static-resource loading, and public annotation contracts.

Tests generate temporary accounts, databases, CA certificates and session keys, open localhost sockets on operating-system-assigned ports, and use temporary directories. One JavaScript test uses Node.js when it is available in `PATH`; otherwise, that test is skipped. Tests that intentionally simulate failures may print traceback logs even when the final result is `OK`; check the summary and exit code.

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
  accounts.py   # SQLite accounts, Argon2id and bounded throttling
  certgen.py    # Local demo CA and server certificate generation
  webui.py      # Compatibility entry point for the web interface
tests/          # Automated test suite
docs/           # Existing PDF report and report-generation script
```

The client terminal interface lives in `collab.client.cli`; `collab.client.core.main()` remains a lazy forwarding entry point. Web handlers retain the `PAGE` HTML export, while CSS and JavaScript are served from a fixed static-resource allowlist. Static files are resolved relative to the package, so loading does not depend on the current working directory. Include the entire `collab/web/static/` directory when copying the project.

Python 3.10+ remains the minimum supported version. Validators still accept untrusted values and return the validated message; annotations do not replace runtime validation. Lock documentation identifies caller-held locks, session checks, and cleanup ownership without changing the synchronization model.

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
