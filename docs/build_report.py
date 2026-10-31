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
    """Read successful unittest evidence matching the current source test inventory.

    The log is read without rerunning tests. Test modules are parsed to count test_
    functions; missing metadata falls back to the log's modification time or a label.

    Args:
        path: Test log path, read as text.

    Returns:
        Report metadata containing count, duration, outcome, per-module inventory,
        recorded time, and environment description.

    Raises:
        ValueError: The log lacks a successful final summary or its count differs from
            the current test inventory.
        OSError: Reading the log or test sources fails.
    """
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
        source_snapshot=field("Source snapshot SHA256", "not recorded"),
    )


class Diagram(Flowable):
    """Provide shared drawing helpers for report flowables using PDF-point coordinates."""

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


class StateDiagram(Diagram):
    """Draw editable state transitions using the report's existing vector style."""

    def __init__(self, states, transitions, return_label, terminal_failure=False):
        self.states, self.transitions, self.return_label = (
            states,
            transitions,
            return_label,
        )
        self.terminal_failure = terminal_failure
        super().__init__(len(states) * 78 + 12)

    def draw(self):
        x, width = 95, 290
        positions = []
        for index, (name, detail) in enumerate(self.states):
            y = self.height - 58 - index * 78
            self.box(x, y, width, 43, [name, detail])
            positions.append(y)
            if index:
                self.arrow(x + width / 2, positions[index - 1], x + width / 2, y + 43)
                self.text(x + width / 2 + 80, y + 54, self.transitions[index - 1], 7)
        if self.terminal_failure:
            middle = (positions[0] + positions[-2]) / 2 + 20
            self.box(0, middle - 22, 73, 44, ["FAILED /", "CANCELLED"])
            for y in positions[:-1]:
                self.canv.line(95, y + 20, 82, y + 20)
            self.canv.line(82, positions[0] + 20, 82, positions[-2] + 20)
            self.arrow(82, middle, 73, middle)

        right = WIDTH - 15
        bottom = positions[-1] + 20
        top = positions[0] + 20
        self.canv.setStrokeColor(BLUE)
        self.canv.line(x + width, bottom, right, bottom)
        self.canv.line(right, bottom, right, top)
        self.arrow(right, top, x + width, top)
        self.canv.saveState()
        self.canv.translate(right - 5, (top + bottom) / 2)
        self.canv.rotate(90)
        self.text(0, 0, self.return_label, 7)
        self.canv.restoreState()


def populate(report, result):
    """Build the current account/TLS/CUBIC report from verified test evidence."""
    r = report
    r.p("NETWORK APPLICATION DEVELOPMENT / ASSIGNMENT 1", "small")
    r.p("Technical Explanation<br/>Report", "title")
    r.p(
        "<b>Distributed and Streaming-based Client-Server Collaboration Application</b>"
    )
    r.p(
        f"Evidence: {escape(result['recorded'])} | {result['count']} tests | {escape(result['outcome'])}",
        "small",
    )
    r.h("1. Objective and system architecture")
    r.p(
        "Collab LAN provides persistent username/password accounts, online discovery, private/broadcast chat, and reliable binary file transfer. Clients use raw TCP/UDP sockets; browsers use a local standard-library HTTP bridge. Network, application state, and user interface responsibilities remain separate."
    )
    r.story.append(Architecture())
    r.p(
        "Figure 1. Each browser communicates with its own loopback HTTP backend. Client processes connect to the relay using verified TLS/TCP control and encrypted UDP data. The server decrypts source content and encrypts it for the destination; this is not end-to-end encryption.",
        "small",
    )
    r.h("Transport interpretation")
    r.p(
        "The assignment's goal and file-transfer rubric require UDP streaming and reassembly; its technology overview also mentions TCP reliable transfer. This project uses TCP for TLS authentication/control/results and UDP for application payloads, discovery, and ACK/retry. Presence broadcast is server fan-out, not LAN broadcast autodiscovery. These interpretations remain instructor questions; no instructor approval is claimed."
    )

    r.page(2, "2. Architecture, concurrency, and resource ownership")
    r.table(
        ["Module", "Responsibility"],
        [
            (
                "client/",
                "Session lifecycle, terminal menu/commands, bounded chat ordering, outgoing confirmation and file/disk workers.",
            ),
            (
                "server/",
                "Account admission, session registry, per-session TCP writers, relay queues and recipient-confirmed file outcomes.",
            ),
            (
                "transport/",
                "TLS contexts, account handshake, TCP frames, encrypted UDP envelopes and path-local CUBIC controllers.",
            ),
            (
                "shared/",
                "Schemas, limits, bounded worker pools, retry/backoff and independent cleanup.",
            ),
            (
                "accounts.py / certgen.py",
                "Parameterized SQLite account operations, Argon2id hashes, bounded authentication policy, and a local CA/server certificate generator.",
            ),
            (
                "web/",
                "Loopback HTTP requests call the same client core; JavaScript renders online users, messages and per-transfer progress.",
            ),
        ],
        [135, WIDTH - 135],
    )
    r.h("Workers and locks")
    r.p(
        "Server workers accept TCP, receive UDP, schedule relay retries, expire sessions, and publish presence. An event-driven failure monitor owns fatal-worker cleanup without polling for lifecycle ownership; each session has a TCP handler and writer. Clients own TCP receive, UDP receive, heartbeat, and receive-disk workers. HTTP has two send workers/four waiting slots, two upload slots, and eight handlers/sixteen admitted connections."
    )
    r.p(
        "Registry locks protect short state changes. Session gates are acquired in token order; socket sends and joins occur outside the server registry lock. CUBIC state has its own lock and never sleeps or calls back into application locks. The receive worker owns temporary streams; socket/file cleanup retains unfinished resources for a later close within a shared shutdown deadline. HTTP workers use a single FIFO queue; pending jobs are cancelled at stop and their cleanup is attempted once, with failures reported rather than retried."
    )
    r.h("Production configuration and scaling")
    r.p(
        "Defaults remain 64 TCP connections, 8,192 pending packets, and 1,024 pending packets per recipient. Authentication permits ten attempts per source IP per 60 seconds. The 20-user same-IP demonstration explicitly starts the production Server with auth_limit=60 (CLI --auth-limit 60), covering twenty registrations plus twenty logins without a test-subclass override. The default security policy is tested separately and is not silently disabled."
    )

    r.page(3, "3. Application protocol specification")
    r.table(
        ["Message / transport", "Fields and purpose"],
        [
            (
                "register / registered (TLS TCP)",
                "Request: name, password. Success: type=registered, then connection closes. Registration returns to the terminal menu; it does not create an online session.",
            ),
            (
                "login / welcome (TLS TCP)",
                "Request: name, password. Welcome: token, session, key, udp_port. Keys and identifiers are freshly random; credentials are not command-line arguments.",
            ),
            (
                "error / logout / users (TCP)",
                "Bounded error message; logout ends the session. Users carries names[] and revision. Established controls also use an ordered session envelope inside TLS.",
            ),
            (
                "chat_status / file controls (TCP)",
                "Final recipients, delivered names and failure reasons. file_receipt confirms successful save/hash verification; abort/cancel retire outstanding work.",
            ),
            (
                "heartbeat / presence (UDP)",
                "Client from+token; server names[]+revision. Verified application activity refreshes liveness; older presence revisions are ignored.",
            ),
            (
                "path_challenge / path_response (UDP)",
                "A fresh nonce and initial endpoint must match before application data is accepted. The verified address stays fixed until a new login. Path checks alone do not extend heartbeat life.",
            ),
            (
                "data/chat (UDP)",
                "id, from, to, kind, payload, meta. Relay metadata includes sender_session, original channel and stream sequence.",
            ),
            (
                "file_start / chunk / end (UDP)",
                "Start: transfer, filename, size, count, sha256. Chunk: transfer/index/base64 bytes. End: transfer and empty payload. Forwarded packets include sender_session.",
            ),
            (
                "ack (UDP)",
                "Hop-local application ID; client ACKs include from+token. New ACKs release congestion flight and update the sending hop's controller.",
            ),
        ],
        [145, WIDTH - 145],
    )
    r.h("Framing and size checks")
    r.p(
        f"JSON is compact UTF-8. TCP uses a four-byte big-endian length; authentication JSON is protected by TLS and capped at 2,048 bytes. Established JSON is capped at {limits.MAX_FRAME:,} bytes before envelope encoding. UDP includes a 32-byte public context lookup prefix plus a Fernet token and is limited to {limits.UDP_MTU} bytes. File chunks are {limits.CHUNK} raw bytes. Chat and file preflight now use the same session-framed size calculation as the relay, preventing the previously accepted oversized boundary case."
    )

    r.page(4, "4. Account security and authenticated envelopes")
    r.p(
        "Clients load an explicit CA and verify the server DNS/IP SAN before sending credentials. TLS 1.2 or later protects the entire TCP connection; there is no insecure bypass. SQLite stores id, unique case-sensitive username, Argon2id password_hash, and created_at. Policy: 8-128 password characters, random library-managed salts, 19 MiB memory, two iterations and parallelism one. Four hashing jobs and bounded login frames/deadlines limit unauthenticated work."
    )
    r.p(
        "A valid password is checked before the server reports an already-online account. Username reservation is atomic. Each login receives a random Fernet key, public session context and separate authorization token. The key is not derived from the password/hash and is never stored in SQLite or printed. Legacy shared-key helpers and compatibility entry points have been removed; authentication uses only the account/TLS flow."
    )
    r.code(
        "auth TCP = TLS(uint32_be(length) || JSON)\ncontrol TCP = TLS(uint32_be(length) || Fernet(header || JSON))\nUDP = public_context_hex[32] || Fernet(header || JSON)\nheader = !B16sBBQ"
    )
    r.story.append(Envelope())
    r.p(
        f"Figure 2. The {HEADER.size}-byte encrypted header binds version {VERSION}, 16-byte session context, direction, TCP/UDP transport, and sequence. The outer UDP prefix is only a cipher lookup hint; the inner context must still authenticate.",
        "small",
    )
    r.h("Replay, endpoint and cleanup boundaries")
    r.p(
        f"TCP requires the next sequence. UDP uses a {REPLAY_WINDOW:,}-packet replay bitmap. Every actual retry retains its application ID but uses a fresh security sequence, allowing legitimate deduplication without accepting replayed frames. UDP schemas and session credentials are checked before endpoint/liveness updates. A challenge response proves initial endpoint reachability; changing the verified UDP address requires a new login. Authentication uses fixed per-IP windows; expired entries are pruned on the next attempt without an LRU cache. Logout, TCP loss, heartbeat expiry, and interrupts retire session references; Python cannot promise physical key-memory erasure. TLS plus a trusted CA prevents an old welcome from authenticating a new TLS connection."
    )

    r.page(5, "5. Authentication and data lifecycles")
    r.story.append(
        Sequence(
            ["Client", "Server"],
            [
                (0, 1, "TCP + verified TLS handshake"),
                (0, 1, "register(name,password) [optional new account]"),
                (1, 0, "registered; close; return to terminal menu"),
                (0, 1, "new verified TLS + login(name,password)"),
                (1, 0, "welcome(token,session,key,udp_port)"),
                (0, 1, "UDP heartbeat from candidate endpoint"),
                (1, 0, "path_challenge(nonce)"),
                (0, 1, "path_response(nonce), then fresh heartbeat"),
                (1, 0, "presence(names,revision)"),
            ],
        )
    )
    r.p(
        "Figure 3. Registration and login are separate TLS connections. Passwords are entered only in the terminal. The Web HTTP listener opens only after successful login. Client connected status follows local UDP setup and worker startup; it does not itself prove path reachability.",
        "small",
    )
    r.h("Chat and file sequence")
    r.story.append(
        Sequence(
            ["Sender", "Relay", "Recipient"],
            [
                (0, 1, "data/chat or file_start/chunk/end + ID"),
                (1, 0, "ingress ACK after bounded admission"),
                (1, 2, "CUBIC-admitted, per-recipient encrypted data"),
                (2, 1, "ACK after buffer/job admission"),
                (2, 1, "file_receipt after SHA-256 + saving"),
                (1, 0, "final chat_status / file_status"),
            ],
        )
    )
    r.p(
        "Figure 4. Each UDP data hop has independent congestion state. Hop ACKs indicate admission, not a human read or saved file. Final file success requires verification/save receipts from the original recipients. Sender and recipient sessions are pinned so a replacement login cannot inherit old work.",
        "small",
    )

    r.page(6, "6. Explicit state-transition diagrams")
    r.h("Client lifecycle")
    r.story.append(
        StateDiagram(
            [
                ("DISCONNECTED", "initial state; menu or cleaned resources"),
                ("CONNECTING", "verified TLS, login, UDP setup, workers"),
                ("CONNECTED", "chat/file work; heartbeat and receive loops"),
            ],
            ["connect(password)", "welcome + local startup"],
            "logout / failure / expiry -> cleanup",
        )
    )
    r.p(
        "Figure 5. Actual Client.status values are disconnected, connecting and connected. Startup failure also returns from connecting to disconnected. TLS/authentication are internal connecting stages; cleanup has no separately published closing status.",
        "small",
    )
    r.h("Server lifecycle")
    r.story.append(
        StateDiagram(
            [
                ("STOPPED", "no active listeners/workers"),
                ("STARTING", "database, TCP/UDP bind, worker gate"),
                ("RUNNING", "accept, relay, presence, expiry"),
                ("STOPPING", "signal, close sessions, join, retry cleanup"),
            ],
            ["start()", "startup succeeds", "close() / fatal worker"],
            "cleanup succeeds; failed startup also rolls back",
        )
    )
    r.p(
        "Figure 6. Incomplete cleanup retains stopping status and blocks unsafe restart. These diagrams document the current implementation; they do not claim historical creation before the original code.",
        "small",
    )

    r.page(7, "7. File transaction states and CUBIC")
    r.story.append(
        StateDiagram(
            [
                ("RECEIVING", "file_start admitted; temporary receive state"),
                ("WRITING", "bounded chunk jobs; indexed disk writes"),
                ("VERIFYING", "file_end + every chunk written; SHA-256"),
                ("SAVED / RECEIPT", "rename, file_complete, final TCP receipt"),
            ],
            ["chunk admission", "all data + end", "size/hash match"],
            "new transaction requires file_start",
            terminal_failure=True,
        )
    )
    r.p(
        "Figure 7. Conceptual receive states are represented by existing ended/finalizing/cancelled flags and job records, not new enum values. Unknown transfers are not ACKed. Duplicate chunks are fingerprint-checked. An active-session failure queues a failed receipt; session cancellation cleans up owned work.",
        "small",
    )
    r.h("Application-level CUBIC on both UDP hops")
    r.p(
        "Each client session and each server destination session owns a bounded CUBIC controller shared by concurrent application data sends. It uses C=0.4 and beta=0.7, Reno slow start, a cubic epoch with Reno-friendly growth, and fast convergence. Three later ACKs mark a missing flight for fast retransmission; timeout restarts cwnd at one and increases the bounded RTO. First-send RTT samples update smoothed RTT/variation; retransmissions do not supply RTT samples (Karn's rule)."
    )
    r.p(
        "A token bucket limits the average send budget using cwnd/RTT with at most one window per burst. Heartbeats, ACKs and path controls bypass the data window so congestion cannot deadlock control traffic. Client application batches still cap each call at six packets; the independent server relay window can grow up to 128. This is an application-datagram adaptation of CUBIC, not a claim of complete TCP/QUIC conformance: ECN, HyStart++, TCP SACK recovery and spurious-loss undo are absent."
    )
    r.p(
        "Algorithm reference: RFC 9438, sections 4.2-4.10. https://www.rfc-editor.org/rfc/rfc9438.html. Source: collab/transport/congestion.py.",
        "small",
    )

    r.page(8, "8. Challenges and solutions")
    for title, text in [
        (
            "Confidential credentials without losing raw sockets",
            "The former group-key nickname exchange could not establish individual identity. TLS now authenticates the server before credential transfer; SQLite and Argon2id preserve accounts without retaining plaintext passwords. Per-session keys isolate relay envelopes while retaining existing replay/path checks.",
        ),
        (
            "Reliable transfer without blocking unrelated streams",
            "One persistent TCP reader preserves fragmented frames across timeouts. UDP data admission and receive-disk work are separate; indexed temporary-file writes handle reordered chunks. Per-chat-stream gap handling bounds waiting without freezing other conversations. Slow-disk and dropped-ACK regression tests check those boundaries, rather than claiming all head-of-line delay disappears.",
        ),
        (
            "Real congestion feedback rather than a fixed retry loop",
            "CUBIC state tracks flight, ACKs, loss, RTT, RTO and pacing for both data hops. Window reservation precedes sends; rejected admission consumes neither a retry attempt nor another queue slot. A persistent 3:1 scheduling phase lets files progress even when a small shared destination window limits a batch.",
        ),
        (
            "Size accounting must include the actual wire format",
            "The old preflight measured an unprefixed token and could accept a 511-character chat whose relay frame was 1,112 bytes. Preflight now includes the public session prefix and forwarded metadata, matching the 1,100-byte wire ceiling before admission.",
        ),
        (
            "A scalable demo must declare its authentication budget",
            "Twenty users on one source IP require forty registration/login requests. A documented --auth-limit 60 setting enables that demonstration; default ten-per-minute behavior remains separately verified. Production scale tests use the real Client and Server classes, not relaxed fixture subclasses.",
        ),
        (
            "Cleanup is independent of another cleanup failure",
            "Session identities pin outstanding work; cancellation releases congestion flight. Supervisors signal before joining. Socket shutdown, worker pools, file cleanup and joins share bounded deadlines. Failed sockets/files can be retried on a later close; worker job cleanup runs once and reports failure. No automatic reconnect silently recreates credentials or keys.",
        ),
    ]:
        r.h(title)
        r.p(text)

    r.page(9, "9. Test evidence and verification boundaries")
    r.p(
        f"Recorded run: <b>{result['count']} tests</b> in {escape(result['seconds'])} seconds; <b>{escape(result['outcome'])}</b>. Environment: {escape(result['environment'])}. Recorded UTC: {escape(result['recorded'])}."
    )
    r.code("python -m unittest discover -s tests -v")
    r.p(
        "Test-run source snapshot SHA-256: " + escape(result["source_snapshot"]),
        "small",
    )
    r.table(
        ["Test module", "Count", "Evidence"],
        [
            (
                name.removeprefix("test_"),
                count,
                {
                    "test_congestion": "Deterministic window/RTT/loss/idle behavior and framing regression.",
                    "test_production_scale": "Real TLS accounts and 20 clients under explicit production configuration.",
                    "test_authentication": "Persistence, password policy, races, TLS trust, fixed rate windows, framing and terminal flow.",
                    "test_concurrency": "Bounded pools, 20 clients, scheduler fairness, slow workers and cleanup.",
                    "test_files": "Chunks, hashes, receipts, reordering, loss, disk failure and streamed source limits.",
                    "test_chat": "Broadcast/private results, ordering, missing ACKs and concurrent files.",
                    "test_handshake": "Partial frames, deadlines, silent peers and startup rollback.",
                    "test_integration": "Real encrypted TCP/UDP private/broadcast and binary/empty files.",
                    "test_security": "Session/channel binding, replay windows, path verification and stale packets.",
                    "test_sessions": "Presence, expiry, disconnect/relogin and endpoint lifecycle.",
                    "test_web": "HTTP/static routes, progress, JavaScript rendering, bounded admission and cancellation.",
                    "test_web_concurrency": "Upload/send admission, cancellation and local HTTP cleanup.",
                    "test_protocol": "Wire schemas, invalid payloads, Unicode and boundary sizes.",
                    "test_refactoring": "Entry points, CLI flags, certificate generation and source grammar.",
                    "test_resilience": "Killed processes, worker exceptions, deadlines and cleanup retries.",
                }.get(name, "Behavioral regression tests."),
            )
            for name, count in sorted(result["inventory"].items())
        ],
        [104, 48, WIDTH - 152],
    )
    r.p(
        "Localhost regression tests use OS-assigned ports, temporary databases/certificates/files, fake clocks and controlled loss/error injection. They do not establish WAN fairness or throughput. Historical terminal/LAN-interface checks ran on the same Mac; their supporting evidence files are no longer distributed. A local interface test is not evidence of a second physical device. Windows/Linux execution and instructor approval remain external verification tasks.",
        "small",
    )

    r.page(10, "10. Reproduction, limits, and open interpretation questions")
    r.code(
        "python3 -m venv .venv\nsource .venv/bin/activate\npython -m pip install -r requirements.txt\npython -m collab.certgen --out certs --names localhost 127.0.0.1\n# Server (one terminal)\npython -m collab.server --cert certs/server.crt --key certs/server.key\n# Alice and Bob (separate terminals; register, then log in)\npython -m collab.web --name alice --ca certs/ca.crt --web-port 8080\npython -m collab.web --name bob --ca certs/ca.crt --web-port 8081"
    )
    r.p(
        "For a 20-user same-IP demonstration, add --auth-limit 60 to the server. For LAN, include the actual server IP in certificate SANs, bind --host 0.0.0.0, securely distribute only ca.crt, and set each client's --host to that IP. HTTP stays on client loopback. The README contains full download-directory and CLI examples."
    )
    r.table(
        ["Boundary", "Current limit"],
        [
            (
                "Files",
                "25 MiB/file; two incoming and two outgoing; 50 MiB declared incoming total; receive job queue 256.",
            ),
            (
                "Congestion",
                "CUBIC flight limit 128 datagrams/path; initial window two; RTO 0.05-2 seconds, plus the application's minimum retry interval.",
            ),
            (
                "Application timing",
                "Heartbeat 2 s, expiry 10 s, chat gap wait 1 s, file idle 30 s and total transfer 15 minutes.",
            ),
            (
                "Not provided",
                "BBR, offline history, automatic reconnect, resumable files, password reset and browser multi-tab synchronization. BBR is not claimed; CUBIC is the implemented alternative.",
            ),
        ],
        [125, WIDTH - 125],
    )
    r.h("Questions requiring instructor confirmation")
    r.p(
        "(1) Does TCP control plus reliable UDP payload delivery satisfy the overview's TCP-transfer wording, given the explicit UDP file rubric? (2) Does server-mediated presence fan-out satisfy discovery broadcast, or is literal LAN broadcast autodiscovery required? (3) Is a documented application-level CUBIC adaptation acceptable, including the disclosed TCP-specific omissions? These are questions, not inferred approvals."
    )
    r.h("Regeneration and evidence integrity")
    r.p(
        "Install ReportLab as a report-generation dependency if not using a bundled runtime. Save a complete successful unittest run outside the repo, then execute python docs/build_report.py --test-log /path/to/test-results.log. The generator checks source test inventory against the log and refuses stale/mismatched counts. State diagrams are editable in this Python source. Packaging, repository visibility, publication, and submission were not performed."
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
