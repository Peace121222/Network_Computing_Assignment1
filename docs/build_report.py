"""Build the English technical report from current code constants and test evidence.

Run from the project root: python docs/build_report.py
Requires the application's dependencies plus reportlab. Test results are read from
--test-log; the generator does not silently rerun tests or invent a passing result.
"""

import argparse
import ast
from datetime import datetime, timezone
from html import escape
from pathlib import Path
import re
import sys

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import (
    Flowable,
    PageBreak,
    Paragraph,
    Preformatted,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from collab.shared import limits  # noqa: E402
from collab.transport.security import HEADER, REPLAY_WINDOW, VERSION  # noqa: E402

NAVY = colors.HexColor("#16314B")
BLUE = colors.HexColor("#216BA5")
MUTED = colors.HexColor("#536679")
PALE = colors.HexColor("#EFF5FA")
LINE = colors.HexColor("#D7E1EA")
WIDTH = A4[0] - 92


def evidence(path):
    """Require a completed successful run matching the current test inventory."""
    text = path.read_text()
    runs = re.findall(r"^Ran (\d+) tests? in ([\d.]+)s$", text, re.M)
    outcome = next(
        (line.strip() for line in reversed(text.splitlines()) if line.strip()), ""
    )
    if not runs or not re.fullmatch(r"OK(?: \(skipped=\d+\))?", outcome):
        raise ValueError("Test log must end with a successful unittest summary")
    inventory = {}
    for source in sorted((ROOT / "tests").glob("test_*.py")):
        tree = ast.parse(source.read_text(), filename=str(source))
        inventory[source.stem] = sum(
            isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name.startswith("test_")
            for node in ast.walk(tree)
        )
    count, seconds = runs[-1]
    if int(count) != sum(inventory.values()):
        raise ValueError("Test inventory changed; refresh the complete test log first")

    def field(name, default):
        match = re.search(r"^" + re.escape(name) + r": (.+)$", text, re.M)
        return match.group(1) if match else default

    recorded = field(
        "Recorded UTC",
        datetime.fromtimestamp(path.stat().st_mtime, timezone.utc).isoformat(
            timespec="seconds"
        ),
    )
    return dict(
        count=int(count),
        seconds=seconds,
        outcome=outcome,
        inventory=inventory,
        recorded=recorded,
        environment=field("Environment", "See the test log"),
    )


class Diagram(Flowable):
    def __init__(self, height):
        super().__init__()
        self.width, self.height = WIDTH, height

    def text(self, x, y, text, size=9, bold=False, color=NAVY):
        self.canv.setFillColor(color)
        self.canv.setFont("Helvetica-Bold" if bold else "Helvetica", size)
        self.canv.drawCentredString(x, y, text)

    def box(self, x, y, w, h, lines):
        self.canv.setFillColor(PALE)
        self.canv.setStrokeColor(LINE)
        self.canv.roundRect(x, y, w, h, 7, fill=1, stroke=1)
        for index, text in enumerate(lines):
            self.text(x + w / 2, y + h - 16 - index * 13, text, 8.5, index == 0)

    def arrow(self, x1, y1, x2, y2, color=BLUE):
        import math

        self.canv.setStrokeColor(color)
        self.canv.setFillColor(color)
        self.canv.setLineWidth(1)
        self.canv.line(x1, y1, x2, y2)
        angle = math.atan2(y2 - y1, x2 - x1)
        path = self.canv.beginPath()
        path.moveTo(x2, y2)
        for offset in (-0.45, 0.45):
            path.lineTo(
                x2 - 6 * math.cos(angle + offset), y2 - 6 * math.sin(angle + offset)
            )
        path.close()
        self.canv.drawPath(path, fill=1, stroke=0)


class Architecture(Diagram):
    def __init__(self):
        super().__init__(220)

    def draw(self):
        self.box(0, 145, 110, 52, ["Alice browser", "localhost :8080"])
        self.box(
            145,
            132,
            150,
            78,
            ["Alice local process", "web/ HTTP bridge", "client/ TCP + UDP"],
        )
        self.box(0, 25, 110, 52, ["Bob browser", "localhost :8081"])
        self.box(
            145,
            12,
            150,
            78,
            ["Bob local process", "web/ HTTP bridge", "client/ TCP + UDP"],
        )
        self.box(
            353,
            62,
            150,
            108,
            ["Relay server", "server/", "TCP :9000", "UDP :9001", "sessions + routing"],
        )
        for y in (170, 50):
            self.arrow(110, y, 145, y)
            self.text(127, y + 10, "HTTP", 7)
        self.arrow(295, 174, 353, 150)
        self.arrow(295, 151, 353, 128)
        self.arrow(295, 65, 353, 105)
        self.arrow(295, 42, 353, 82)
        self.text(320, 194, "TCP", 7.5)
        self.text(320, 124, "UDP", 7.5)
        self.text(320, 23, "TCP / UDP", 7)


class Sequence(Diagram):
    def __init__(self, actors, steps):
        self.actors, self.steps = actors, steps
        super().__init__(40 + 23 * len(steps))

    def draw(self):
        margin = 45 if len(self.actors) == 3 else 65
        xs = [
            margin + i * (WIDTH - 2 * margin) / (len(self.actors) - 1)
            for i in range(len(self.actors))
        ]
        for x, name in zip(xs, self.actors):
            self.text(x, self.height - 12, name, 9, True)
            self.canv.setStrokeColor(LINE)
            self.canv.setDash(2, 3)
            self.canv.line(x, 5, x, self.height - 21)
            self.canv.setDash()
        for index, (source, destination, label) in enumerate(self.steps):
            y = self.height - 39 - index * 23
            self.arrow(xs[source], y, xs[destination], y)
            self.text((xs[source] + xs[destination]) / 2, y + 5, label, 8)


class Envelope(Diagram):
    def __init__(self):
        super().__init__(56)

    def draw(self):
        widths = [68, 137, 75, 75, 148]
        x = 0
        for width, name, size in zip(
            widths,
            ["Version", "Context", "Direction", "Transport", "Sequence"],
            ["1 byte", "16 bytes", "1 byte", "1 byte", "8 bytes"],
        ):
            self.box(x, 6, width, 43, [name, size])
            x += width


class Report:
    def __init__(self):
        base = getSampleStyleSheet()
        self.styles = {
            "title": ParagraphStyle(
                "ReportTitle",
                parent=base["Title"],
                fontName="Helvetica-Bold",
                fontSize=27,
                leading=32,
                textColor=NAVY,
                alignment=0,
                spaceAfter=14,
            ),
            "h1": ParagraphStyle(
                "SectionTitle",
                parent=base["Heading1"],
                fontName="Helvetica-Bold",
                fontSize=19,
                leading=24,
                textColor=NAVY,
                spaceAfter=13,
            ),
            "h2": ParagraphStyle(
                "Subsection",
                parent=base["Heading2"],
                fontSize=11.5,
                leading=15,
                textColor=BLUE,
                spaceBefore=11,
                spaceAfter=6,
            ),
            "body": ParagraphStyle(
                "ReportBody",
                parent=base["BodyText"],
                fontSize=9.5,
                leading=13.7,
                textColor=NAVY,
                spaceAfter=7,
            ),
            "small": ParagraphStyle(
                "ReportSmall",
                parent=base["BodyText"],
                fontSize=8,
                leading=11,
                textColor=MUTED,
                spaceAfter=6,
            ),
            "cell": ParagraphStyle(
                "ReportCell",
                parent=base["BodyText"],
                fontSize=8.1,
                leading=11,
                textColor=NAVY,
            ),
            "th": ParagraphStyle(
                "ReportTableHeader",
                parent=base["BodyText"],
                fontName="Helvetica-Bold",
                fontSize=8.1,
                leading=11,
                textColor=colors.white,
            ),
            "code": ParagraphStyle(
                "ReportCode",
                fontName="Courier",
                fontSize=7.6,
                leading=11,
                textColor=NAVY,
                backColor=PALE,
                borderPadding=8,
                spaceBefore=5,
                spaceAfter=10,
            ),
        }
        self.story = []

    def p(self, text, style="body"):
        self.story.append(Paragraph(text, self.styles[style]))

    def h(self, text):
        self.p(text, "h2")

    def page(self, number, title):
        if self.story:
            self.story.append(PageBreak())
        self.p(f"COLLAB LAN / TECHNICAL REPORT / {number:02d}", "small")
        self.p(title, "h1")

    def code(self, text):
        self.story.append(Preformatted(text, self.styles["code"]))

    def table(self, headings, rows, widths):
        cells = [
            [Paragraph(escape(str(value)), self.styles["th"]) for value in headings]
        ]
        cells += [
            [Paragraph(str(value), self.styles["cell"]) for value in row]
            for row in rows
        ]
        table = Table(cells, colWidths=widths, repeatRows=1, hAlign="LEFT")
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), NAVY),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, PALE]),
                    ("LINEBELOW", (0, 0), (-1, 0), 0.6, NAVY),
                    ("LINEBELOW", (0, 1), (-1, -1), 0.35, LINE),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("LEFTPADDING", (0, 0), (-1, -1), 8),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                    ("TOPPADDING", (0, 0), (-1, -1), 6),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ]
            )
        )
        self.story.extend([table, Spacer(1, 6)])


def populate(report, result):
    r = report
    r.p("NETWORK APPLICATION DEVELOPMENT / ASSIGNMENT 1", "small")
    r.p("Technical Explanation<br/>Report", "title")
    r.p(
        "<b>Distributed and Streaming-based Client-Server Collaboration Application</b>"
    )
    r.p(
        f"Implementation: Collab LAN | Evidence recorded: {escape(result['recorded'])}",
        "small",
    )
    r.h("1. Objective and system architecture")
    r.p(
        "Collab LAN provides nickname login, live user discovery, private/broadcast chat, and reliable binary file transfer for a trusted LAN group. It uses Python raw TCP/UDP sockets, application-layer reliability, Fernet encryption, and a plain JavaScript browser interface. Core networking is separated from data processing and presentation."
    )
    r.story.append(Architecture())
    r.p(
        "Figure 1. Browsers talk only to their local HTTP bridge. Client processes communicate with the relay over encrypted TCP and UDP. Arrows identify connection paths; both transports exchange traffic in both directions. A CLI can replace the browser/HTTP bridge.",
        "small",
    )
    r.h("Transport responsibilities")
    r.p(
        "<b>TCP:</b> encrypted login, session control, large presence snapshots, and final chat/file results. <b>UDP:</b> encrypted heartbeat, path verification, presence, chat/file payloads, and per-hop ACK/retry. The relay sees application contents; this is not end-to-end encryption between clients."
    )
    r.p(
        f"<b>Verified snapshot:</b> {result['count']} tests completed with {escape(result['outcome'])}; includes 20 simultaneous clients. This is functional localhost evidence, not a WAN throughput or congestion-control benchmark."
    )

    r.page(2, "2. Modular implementation and concurrency")
    r.table(
        ["Package / entry point", "Responsibility"],
        [
            (
                "collab/client/",
                "core.py owns sockets and lifecycle; cli.py owns terminal commands and exit handling; chat_sender.py waits for delivery results; chat_inbox.py handles per-stream ordering; file_transfer.py streams and verifies files.",
            ),
            (
                "collab/server/",
                "core.py manages sessions, bounded connections and supervision; routing.py handles chat admission/retries; file_transfers.py tracks fixed recipient sessions and file results.",
            ),
            (
                "collab/transport/",
                "tcp.py provides persistent framing/deadlines; udp.py provides size-aware encoding; security.py owns authenticated envelopes/replay state; handshake.py binds login to fresh nonces.",
            ),
            (
                "collab/shared/",
                "protocol.py validates business messages; limits.py defines protocol defaults; concurrency.py provides bounded pools; resilience.py handles retry/backoff and independent cleanup.",
            ),
            (
                "collab/web/",
                "handlers.py serves JSON and fixed static routes; static/index.html, style.css and app.js contain the frontend; runtime.py bounds work; cli.py starts the interface.",
            ),
            (
                "Compatibility modules",
                "common.py re-exports shared APIs and shutdown/control defaults. webui.py retains PAGE and the web command; core.main() lazily forwards to client.cli. Package entry points preserve python -m commands.",
            ),
        ],
        [137, WIDTH - 137],
    )
    r.h("Worker ownership")
    r.p(
        "The server has five critical loops: accept, UDP receive, retransmission, session expiry, and presence. One supervisor coordinates fatal-worker shutdown. Each accepted connection has a tracked handler; each logged-in session has a TCP writer with bounded control/chat/file mailboxes. Sockets are registered before handlers start."
    )
    r.p(
        "A connected client has TCP receive, UDP receive, heartbeat, and file/disk workers. Slow writes and hashing run in the file worker rather than the UDP listener. HTTP adds two send workers plus four waiting slots, two upload slots, and eight handler workers with capacity for 16 admitted connections."
    )
    r.h("Lock and resource boundaries")
    r.p(
        "Registry locks protect short state changes. Encoding, network sends, disk I/O, and joins run outside the global server lock. UDP session gates are acquired in token order, with session identity checked again before sending. Startup gates prevent workers processing partially initialized sessions. Cleanup uses a shared 3-second deadline and retains unfinished resources for a later retry."
    )
    r.p(
        "Source: collab/server/core.py; collab/client/core.py; collab/web/runtime.py; collab/shared/concurrency.py.",
        "small",
    )

    r.page(3, "3. Application protocol specification")
    r.table(
        ["Message / transport", "Payload and purpose"],
        [
            (
                "hello / challenge (TCP)",
                "hello: client_nonce. challenge: client_nonce + server_nonce. Each nonce contains 32 random bytes encoded as 64 hex characters.",
            ),
            (
                "login / welcome (TCP)",
                "login: name and both nonces. welcome: token, udp_port, session and both nonces. The public session context differs from the secret authorization token.",
            ),
            (
                "error / logout / users (TCP)",
                "error carries a bounded message; logout ends the session. Server users responses carry names[] and nonnegative revision.",
            ),
            (
                "chat_status (TCP)",
                "id, state (delivered/failed/rejected), original recipients[], delivered[], failures[{name, reason}].",
            ),
            (
                "File control (TCP)",
                "file_status reports accepted/final results. file_receipt confirms recipient saving or failure; file_abort and file_cancel terminate transfer work.",
            ),
            (
                "heartbeat / presence (UDP)",
                "Client packets carry from + token. Server presence carries sorted names[] + revision; clients ignore older revisions.",
            ),
            (
                "path_challenge / response (UDP)",
                "A nonce proves that a new candidate endpoint can receive and answer an authenticated challenge before registration.",
            ),
            (
                "data/chat (UDP)",
                "id, from, to, kind, payload, meta. Forwarded metadata adds sender_session, original channel and per-recipient stream sequence.",
            ),
            (
                "data/file_start (UDP)",
                "meta: transfer, filename, size, count, sha256; forwarded packets also include sender_session.",
            ),
            (
                "data/file_chunk / end (UDP)",
                "chunk: transfer + index and base64 payload. end: transfer and empty payload. Receiver checks chunk length against declared file size.",
            ),
            (
                "ack (UDP)",
                "id identifies a hop-local packet. Client ACKs also carry from + token. Server-to-client payloads do not expose authorization tokens.",
            ),
        ],
        [145, WIDTH - 145],
    )
    r.h("Framing and validation")
    r.p(
        f"Business payloads are compact UTF-8 JSON objects. TCP carries a 4-byte big-endian ciphertext length followed by a Fernet token. Its JSON payload limit remains {limits.MAX_FRAME:,} bytes, with a separately computed ciphertext ceiling. UDP carries one Fernet token per datagram, at most {limits.UDP_MTU:,} bytes including encryption overhead; a raw file chunk is {limits.CHUNK} bytes."
    )
    r.p(
        "TCPReader preserves partial headers/bodies across timeout and reads only missing bytes. EOF mid-frame, invalid lengths, authentication failure or malformed JSON terminate that connection. UDP is authenticated and schema-checked before replay state, endpoint, liveness or application state can change. Invalid packets receive no ACK."
    )
    r.p(
        "Source: collab/shared/protocol.py; collab/transport/tcp.py; collab/transport/udp.py.",
        "small",
    )

    r.page(4, "4. Security Envelope and anti-replay window")
    r.p(
        f"The authenticated plaintext is a {HEADER.size}-byte binary header followed by compact JSON. Fernet encrypts and authenticates both together. The header is <b>inside</b> the Fernet token; it is not an unauthenticated routing prefix."
    )
    r.code(
        "wire TCP = uint32_be(token_length) || Fernet(header || JSON)\nwire UDP = Fernet(header || JSON)\nheader format = !B16sBBQ   (network byte order)"
    )
    r.story.append(Envelope())
    r.table(
        ["Field", "Validation / meaning"],
        [
            (
                "Version (1 byte)",
                f"Must equal {VERSION}; no downgrade to legacy plaintext or old UDP JSON framing.",
            ),
            (
                "Context (16 bytes)",
                "All-zero context during nonce-bound handshake; a new public session UUID after welcome. It is separate from the authorization token.",
            ),
            (
                "Direction (1 byte)",
                "1 = client-to-server; 2 = server-to-client. Reflected frames in the wrong direction are rejected.",
            ),
            (
                "Transport (1 byte)",
                "1 = TCP; 2 = UDP. A frame cannot be reused across transports.",
            ),
            (
                "Sequence (8 bytes)",
                "Unsigned integer from 1 to 2^64 - 1. Separate send/receive state per channel, direction and session. Exhaustion is an explicit error.",
            ),
        ],
        [130, WIDTH - 130],
    )
    r.h(f"Bounded UDP replay window: {REPLAY_WINDOW:,} sequence numbers")
    r.p(
        "The receiver keeps a highest sequence number and a 4,096-bit bitmap. A higher sequence shifts the bitmap, marks the new sequence and discards bits outside the window. A large jump clears the window before marking the newest packet. An older sequence is accepted only if it remains within the window and its bit is unset. Duplicate and out-of-window packets are dropped without ACK or liveness refresh."
    )
    r.code(
        "receive: 3 -> accept; 1 -> accept; 2 -> accept; 1 -> reject\nreceive: 4099 -> accept; 3 -> reject (distance = 4096)"
    )
    r.p(
        "For UDP, schema, session, direction and transport checks precede replay-state commitment. Each actual UDP retry uses a fresh security sequence while retaining the application ID, so application deduplication can ACK a legitimate retry without displaying it twice. TCP instead requires exactly the next sequence number. Counters are reset for every new session."
    )
    r.p(
        "<b>Trust boundary:</b> one COLLAB_KEY is shared by the group. Key holders can decrypt and forge group traffic; there is no per-user cryptographic identity, TLS or forward secrecy. Replay protection does not detect every valid packet withheld before first delivery. Fernet timestamps are not used as the main freshness check, avoiding a wall-clock synchronization dependency.",
        "small",
    )

    r.page(5, "5. Login, endpoint validation and presence")
    r.story.append(
        Sequence(
            ["Client", "Server"],
            [
                (0, 1, "TCP connect"),
                (0, 1, "hello(client_nonce) [encrypted]"),
                (1, 0, "challenge(client_nonce, server_nonce)"),
                (0, 1, "login(name, both nonces)"),
                (1, 0, "welcome(token, udp_port, session, both nonces)"),
                (0, 1, "UDP heartbeat from candidate endpoint"),
                (1, 0, "path_challenge(nonce)"),
                (0, 1, "path_response(nonce)"),
                (0, 1, "fresh heartbeat from verified endpoint"),
                (1, 0, "presence(names, revision)"),
            ],
        )
    )
    r.p(
        "Figure 2. All messages after TCP connect are protected. Fresh nonces bind a login/welcome exchange to this attempt; old login/welcome ciphertext cannot complete a new handshake. After welcome, both ends switch to the new session context and reset channel counters.",
        "small",
    )
    r.h("Deadlines and initialization")
    r.p(
        f"TCP establishment allows {limits.CONNECT_TIMEOUT} seconds; the complete client handshake has {limits.CLIENT_LOGIN_TIMEOUT} seconds, and the server has {limits.LOGIN_TIMEOUT} seconds from accept. These are monotonic total deadlines, so drip-fed bytes do not extend them. Username registration is atomic. Server ready is set only after welcome and writer startup; clients become connected after local UDP setup, first heartbeat send, and worker startup. Connected does not guarantee UDP reachability."
    )
    r.h("Path verification and session expiry")
    r.p(
        "A new UDP source address does not immediately replace the verified endpoint. One candidate per session holds a random challenge for 2 seconds; new challenges are rate-limited to one per 0.5 seconds. A matching response must come from that candidate before expiry. Path control alone never refreshes liveness; the old endpoint remains usable until replacement succeeds."
    )
    r.p(
        f"Valid business UDP activity refreshes last_seen. After {limits.SESSION_EXPIRY} seconds without it, expiry closes TCP and removes the session; checks run every {limits.SESSION_CHECK_INTERVAL} seconds. Logout/EOF/errors use the same session-identity-safe cleanup. Revision increases on online membership changes, not endpoint changes. Heartbeats recover presence; snapshots above the UDP ceiling use TCP users."
    )

    r.page(6, "6. Message and file-transfer lifecycles")
    r.h("Chat: hop ACK versus application acceptance")
    r.story.append(
        Sequence(
            ["Sender", "Relay", "Recipient"],
            [
                (0, 1, "data/chat(id)"),
                (1, 0, "ingress ACK"),
                (1, 2, "forwarded chat + stream sequence"),
                (2, 1, "ACK after buffer/event admission"),
                (1, 0, "TCP chat_status(final result)"),
            ],
        )
    )
    r.p(
        "The relay caches source-session + ID, normalized content and a fixed recipient-session set. Retries cannot add recipients or change content. A recipient ACK follows valid buffer/event admission; it does not imply a human has read the message. Streams buffer up to 64 messages, wait at most 1 second for a gap, then report the gap and advance without blocking other streams. Server delivery deadline: 5 seconds; sender confirmation deadline: 10 seconds."
    )
    r.h("Files: verified disk saving before final success")
    r.story.append(
        Sequence(
            ["Sender", "Relay", "Recipient"],
            [
                (0, 1, "file_start(size, count, SHA-256)"),
                (1, 2, "file_start + sender_session"),
                (0, 1, "file_chunk(index, base64) + retry"),
                (1, 0, "UDP ingress ACK"),
                (1, 2, "file_chunk(index, base64)"),
                (2, 1, "UDP ACK after queue admission"),
                (0, 1, "file_end"),
                (1, 2, "file_end"),
                (2, 1, "TCP file_receipt(saved or failed)"),
                (1, 0, "TCP file_status(final result)"),
            ],
        )
    )
    r.p(
        "Figure 3. ACKs exist on both UDP hops; the diagram groups repeated chunk/ACK exchanges. Sender hashing and reads are streamed. The recipient's file worker seeks/writes a temporary file by chunk index, verifies SHA-256 by streaming reads, and renames only if the local session still matches. Empty files are supported. file_complete is local receive success; file_sent follows successful final recipient receipts, not relay ingress."
    )
    r.p(
        "The source waits for all original recipients; partial failures include delivered/failed names. Pending packets retain source/destination session tokens internally and are removed on session end. The UI exposes separate send/receive progress with transfer identity; 100% chunk progress still waits for saving/recipient confirmation.",
        "small",
    )

    r.page(7, "7. Challenges and solutions")
    r.h("Keeping modular boundaries while preserving commands")
    r.p(
        "The initial single-file client/server layout mixed socket ownership, routing and UI concerns. Packages now separate transport/security, shared validation, client chat/file services, server routing and the HTTP bridge. Compatibility exports and package entry points retain existing imports and commands. Timing defaults are centralized in shared/limits.py. Public interfaces have Python 3.10+ annotations; caller-held-lock and cleanup invariants document the existing model. External CSS/JS preserve UI behavior, and a lazy core.main() wrapper avoids a CLI/core import cycle."
    )
    r.h("Timeouts without corrupting a byte stream")
    r.p(
        "A TCP timeout may occur after part of a header or body has arrived. Restarting an ad-hoc reader would lose framing. One persistent TCPReader retains those bytes and bounds each recv to missing data. Total monotonic handshake deadlines stop silent/drip clients. Post-login poll timeouts preserve state; malformed frames fail closed instead of attempting stream resynchronization."
    )
    r.h("Reliability without duplicate delivery or stale-session leakage")
    r.p(
        "Security counters and application IDs serve different purposes. Retries receive a new authenticated counter but keep their application ID. Routing caches pin original recipients and compare content; destination-session checks prevent retries reaching a new login under the same nickname. Chat ACK follows admission, while a file's final result requires verified saving. Bounded per-stream gap waiting avoids one conversation blocking another."
    )
    r.h("Disk and network work must not block shared workers")
    r.p(
        "The UDP listener retains valid chunks in a bounded queue; the file worker writes/hashes outside the state lock. Queue admission precedes ACK, so rejected work can retry. Per-session TCP writers bound slow-reader effects. Global pending limits reserve chat capacity, and batches prefer 96 chat / 32 file packets out of 128, with unused slots redistributed and rotation within groups."
    )
    r.h("Authenticated traffic still needs replay and path checks")
    r.p(
        "Encryption alone did not stop a captured heartbeat refreshing an active session or changing its endpoint. The authenticated context/direction/transport fields, bounded replay bitmap and endpoint challenge now make these separate checks explicit. Client UDP also verifies the actual server IP/advertised UDP port. These mechanisms protect against outsiders; possession of the group key still grants group-wide trust."
    )
    r.h("Cleanup must remain independent under failure")
    r.p(
        "Critical server workers report the first error to a supervisor rather than joining one another. Handler/writer errors close only their own session. Cleanup attempts socket shutdown, queued-work cancellation, temporary-file cleanup and joins even if another step fails, using one deadline. EINTR/EAGAIN retry and interruptible UDP backoff avoid busy loops; incomplete resources stay tracked and block unsafe restart."
    )

    r.page(8, "8. Test evidence and validation boundaries")
    r.p(
        f"<b>Recorded run:</b> {result['count']} tests in {result['seconds']} seconds; <b>{escape(result['outcome'])}</b>. Environment: {escape(result['environment'])}. Recorded UTC: {escape(result['recorded'])}."
    )
    r.code("python -m unittest discover -s tests -v")
    descriptions = {
        "test_protocol": "Framing, schema, sizes, Unicode and invalid payload rejection",
        "test_handshake": "Partial frames, total deadlines, initialization and rollback",
        "test_sessions": "Tokens, expiry, endpoint changes, presence and session isolation",
        "test_concurrency": "20 simultaneous clients, capacity, startup/shutdown and slow peers",
        "test_chat": "Fixed recipients, ACK loss, ordering, gaps, limits and delivery results",
        "test_files": "Streaming, SHA-256, empty files, partial failures, retries and cleanup",
        "test_resilience": "Worker failure supervision, CLI errors, subprocess death and deadlines",
        "test_security": "Encrypted envelopes, replay, wrong keys, nonce/path checks and rollback",
        "test_web_concurrency": "HTTP admission, upload ownership, cancellation and pool cleanup",
        "test_web_ui": "HTTP messages/presence/progress, static MIME/routes and JavaScript rendering",
        "test_refactoring": "CLI import/legacy entry, timing aliases, annotations and static loading",
        "test_integration": "Real encrypted sockets, unicast/broadcast, file hash and invalid UDP",
    }
    r.table(
        ["Test module", "Tests", "Evidence covered"],
        [
            (
                name.removeprefix("test_"),
                str(count),
                descriptions.get(name, "See test source"),
            )
            for name, count in result["inventory"].items()
        ],
        [105, 40, WIDTH - 145],
    )
    r.h("What these tests demonstrate")
    r.p(
        "The 20-client test uses barriers to race login, unicast/broadcast and close, comparing exact content and receiver counts. Socket localhost tests combine with fake clocks, Events, Barriers and injected errors for deterministic failure boundaries. The invalid-UDP integration case uses a valid security envelope and observes actual schema rejection, rather than passing only because a legacy envelope was rejected."
    )
    r.p(
        "Static-route tests verify exact resource bytes, MIME types and allowlisted paths. Import tests cover both CLI/core orders, loading from another working directory and clear failure when resources are missing. The JavaScript test requires Node.js and is explicitly skipped if unavailable; browser HTTP integration remains Python-based. Failure-injection cases intentionally log tracebacks, so the final unittest summary and exit code determine success. Test counts are checked against the current source inventory whenever this report is generated."
    )
    r.p(
        "The current evidence does not establish Windows/Linux execution, physical-LAN firewall behavior, WAN performance, or broad loss/latency benchmarks. A 20-client functional scenario is not a throughput claim. Detailed output: docs/test_results.txt.",
        "small",
    )

    r.page(9, "9. Limits, reproduction and submission")
    r.table(
        ["Default / boundary", "Current behavior"],
        [
            (
                "File and receive limits",
                "25 MiB/file; 320-byte chunks; two outgoing and two incoming files per client; 50 MiB total declared incoming size. File write queue: 256 jobs.",
            ),
            (
                "Server admission",
                "64 TCP connections including handshake; 8,192 pending packets total; 1,024 per recipient. Limits are configurable keyword-only constructor parameters.",
            ),
            (
                "Retry and resource bounds",
                "Client window: 6 packets; client attempts: 15; relay attempts: 12; retry interval: 250 ms. Chat/file result mailboxes and caches have explicit bounds.",
            ),
            (
                "File lifetime",
                "Default idle timeout: 30 seconds; total transfer deadline: 15 minutes. Incomplete transfers are cancelled and temporary resources are cleaned.",
            ),
            (
                "Remaining scope",
                "No BBR/CUBIC, persistent offline messages, automatic reconnect, resumable transfer, or per-user key isolation. Browser HTTP upload still buffers JSON/base64. UI history is not persistent or synchronized across tabs.",
            ),
        ],
        [145, WIDTH - 145],
    )
    r.h("Run the demo")
    r.p(
        "Create/activate a Python 3.10+ virtual environment, install requirements.txt, generate one key with python -m collab.keygen, and set COLLAB_KEY to that same key in every terminal. Full platform-specific setup is in README.md."
    )
    r.code(
        "# Terminal 1\npython -m collab.server --tcp-port 9000 --udp-port 9001\n# Terminal 2\npython -m collab.webui --name alice --web-port 8080\n# Terminal 3\npython -m collab.webui --name bob --web-port 8081"
    )
    r.p(
        "Open http://127.0.0.1:8080 and :8081. Demonstrate online users, private/broadcast chat, file progress and a verified saved file; then stop a client and server to show cleanup. For LAN use, bind the server to 0.0.0.0 and pass its LAN IP using client --host; allow server TCP 9000 and UDP 9001. HTTP remains local. Existing CLI: python -m collab.client --name carol."
    )
    r.h("Regenerate this report")
    r.code(
        "# ReportLab is a report-generation dependency only\npython -m pip install reportlab\npython -m unittest discover -s tests -v > docs/test_results.txt 2>&1\npython docs/build_report.py"
    )
    r.p(
        "The generator reads current protocol constants and the completed test log; it refuses an unsuccessful run or a mismatched test inventory. --test-log and --output accept alternate paths. Default output: docs/TECHNICAL_REPORT.pdf. No application sockets or test workers are started by the generator."
    )
    r.p(
        "<b>Transport interpretation:</b> the brief describes UDP streaming/file reassembly, a TCP handshake, and a techniques section mentioning TCP reliable transfer. This implementation uses encrypted TCP control plus encrypted UDP application data. The report records that design choice and the unimplemented congestion algorithms explicitly.",
        "small",
    )


def footer(canvas, doc):
    canvas.saveState()
    canvas.setStrokeColor(LINE)
    canvas.line(46, 39, A4[0] - 46, 39)
    canvas.setFillColor(MUTED)
    canvas.setFont("Helvetica", 7.5)
    canvas.drawString(46, 26, "Collab LAN | Assignment 1 | Technical explanation")
    canvas.drawRightString(A4[0] - 46, 26, f"Page {doc.page}")
    canvas.restoreState()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output", type=Path, default=Path(__file__).with_name("TECHNICAL_REPORT.pdf")
    )
    parser.add_argument(
        "--test-log", type=Path, default=Path(__file__).with_name("test_results.txt")
    )
    args = parser.parse_args()
    result = evidence(args.test_log)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    report = Report()
    populate(report, result)
    document = SimpleDocTemplate(
        str(args.output),
        pagesize=A4,
        rightMargin=46,
        leftMargin=46,
        topMargin=42,
        bottomMargin=53,
        title="Collab LAN - Technical Explanation Report",
        author="Collab LAN",
        subject="Modular architecture, protocol, security and test evidence",
    )
    document.build(report.story, onFirstPage=footer, onLaterPages=footer)
    print(args.output.resolve())


if __name__ == "__main__":
    main()
