# Collab LAN — Assignment 1

Self-hosted multi-user collaboration built with Python standard-library TCP/UDP sockets and the `cryptography` Fernet package. Supports login/presence, private and broadcast messaging, 25 MiB binary files with chunking and SHA-256, encrypted UDP frames, sliding-window client→server retransmission, server→recipient retries, and browser UI served on localhost.

## Prerequisites
Python 3.10+; Windows, macOS or Linux. Each client needs the same pre-shared encryption key. This is an **academic LAN prototype**, not production authentication or secure group key management.

## Quick start — 3 terminals

```bash
python -m venv .venv
# Linux/macOS: source .venv/bin/activate
# Windows PowerShell: .venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -m collab.keygen
```

Copy the generated key and set it in **every** terminal/process:

```bash
# Linux/macOS:
export COLLAB_KEY='PASTE_GENERATED_KEY'
# Windows PowerShell:
$env:COLLAB_KEY='PASTE_GENERATED_KEY'
```

Terminal 1:
```bash
python -m collab.server --host 127.0.0.1 --tcp-port 9000 --udp-port 9001
```

Terminal 2:
```bash
python -m collab.webui --name alice --web-port 8080
```

Terminal 3:
```bash
python -m collab.webui --name bob --web-port 8081
```

Open `http://127.0.0.1:8080` and `http://127.0.0.1:8081` in **two different browser tabs**. Send a private message from alice to bob, broadcast to everyone, and send a file. Received files appear in `downloads/` prefixed with a random ID. You can alternatively start terminal clients:

```bash
python -m collab.client --name carol
# commands: /users, /msg alice hi, /all hi everyone, /file alice ./photo.jpg, /quit
```

## Run on multiple physical computers
Run the server with `--host 0.0.0.0`. From each client computer run `python -m collab.webui --name USERNAME --host SERVER_LAN_IP --web-port 8080`. Open TCP 9000 and UDP 9001 in the server's host firewall. All machines must share the key, and routing must permit traffic. The browser UI binds *only* to 127.0.0.1, so remote browsers cannot directly access the UI on another machine.

## Automated tests
```bash
python -m unittest discover -s tests -v
```
Tests cover login/presence, unicast, broadcast, 125 KB binary file integrity, empty file, duplicate login and disconnection. Tests start an isolated localhost server and generate a temporary key.

## Additional manual tests
- Run 10–20 distinct users via CLI; observe `presence` updates and bidirectional messaging.
- Send PDFs, PNGs, ZIPs and empty files; compute SHA-256 of original and received copy.
- During transfer terminate the receiving client and observe server retries and eventual delivery expiry; reconnect and retry transfer.
- Disable UDP connectivity to test sender ACK timeout (up to roughly 3.75 seconds per retry stage).
- Inspect the UDP port using Wireshark: payloads should be Fernet ciphertext, not plaintext chat/file contents.
- Close client and reconnect with same username; try duplicate username while original is connected.

## Limitations and scope notes
- **Important rubric ambiguity:** project goal specifies application-layer streaming over UDP, but step 2 demands a TCP handshake, while techniques mention TCP file transfers. This implementation uses TCP for handshake/session and UDP for encrypted messages/file transfer, matching the explicit UDP file-transfer criterion.
- Login is nickname/session authentication, **not identity/password authentication**. A trusted shared key protects content and an unguessable per-session token authorizes UDP messages. There is no registration/password database, per-user key management or TLS.
- The application implements selective-retry application-level reliability rather than full TCP-style congestion algorithms (BBR/CUBIC). Sliding window is client→server; server→receiver has 12 retries with ACKs. A sender's success indicates **server receipt**, not guaranteed recipient delivery. There is no persistent offline message queue.
- File transfers max 25 MiB (memory buffering on both endpoints). File chunks must arrive after `file_start`; `file_end` is finalized when all chunks are present. No disk streaming/resume; extremely high packet reordering can cause a late start event to be missed.
- UDP encrypted traffic has significant overhead; packet chunk size is 320 bytes; delivery limited to registered, connected users.
- `webui` has minimal HTTP handling and is intended for localhost, not exposure to untrusted clients; avoid port forwarding the HTTP UI. For large files browser base64 upload incurs extra memory usage.
- Presence heartbeat is 2 seconds. A TCP disconnect removes the user; absent TCP disconnect with broken transport depends on OS TCP timeout.

## Package structure
- `collab/server.py` — TCP login and presence, UDP relay, ACK/retransmit.
- `collab/client.py` — socket client, reliable sliding-window sender, file checksum/reassembly, CLI.
- `collab/webui.py` — browser UI with JS polling and Python localhost HTTP bridge.
- `collab/common.py` — encrypted UDP and framed TCP wire format.
- `tests/test_integration.py` — integration tests.
- `docs/TECHNICAL_REPORT.pdf` — architecture, protocol, sequence, challenges and test plan.
