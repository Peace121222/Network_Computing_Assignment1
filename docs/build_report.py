"""Regenerates TECHNICAL_REPORT.pdf; requires reportlab."""
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Preformatted, Table, TableStyle, KeepTogether
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER
from reportlab.lib import colors
from reportlab.lib.units import inch
from pathlib import Path
out=Path(__file__).with_name('TECHNICAL_REPORT.pdf')
doc=SimpleDocTemplate(str(out), pagesize=(595,842),rightMargin=46,leftMargin=46,topMargin=47,bottomMargin=48)
ss=getSampleStyleSheet(); ss.add(ParagraphStyle(name='MainTitleX',parent=ss['Title'],fontSize=18,leading=24,spaceAfter=14));ss.add(ParagraphStyle(name='HeadX',parent=ss['Heading2'],spaceBefore=12,spaceAfter=7));ss.add(ParagraphStyle(name='BodyX',parent=ss['BodyText'],fontSize=9.4,leading=14,spaceAfter=7)); ss.add(ParagraphStyle(name='MonoX',fontName='Courier',fontSize=7,leading=10,spaceAfter=9));story=[]
def title(t):story.append(Paragraph(t,ss['MainTitleX']))
def head(t):story.append(Paragraph(t,ss['HeadX']))
def p(t):story.append(Paragraph(t,ss['BodyX']))
def pre(t):story.append(Preformatted(t,ss['MonoX']))
title('Technical Explanation Report')
p('<b>Assignment 1:</b> Distributed and Streaming-based Client-Server Collaboration Application')
p('<b>Prototype:</b> Collab LAN | Python standard-library sockets + cryptography | October 2026')
head('1. Objective and scope')
p('Build a self-hosted collaboration application for 10-20 concurrent users on a LAN: login and active-user discovery, unicast/broadcast messaging, reliable binary file transfer over UDP, resilience and encryption. The demo includes browser UI and CLI. The implementation is a reproducible academic prototype; its 20-client load target and WAN/loss resilience still require additional test evidence.')
head('2. System architecture')
pre('''Browser 8080 -> local HTTP bridge -> Alice client
                                     | TCP login/control :9000
Browser 8081 -> local HTTP bridge -> Bob client
                                     | UDP encrypted data :9001
                            +------------------+
                            |   Relay server   |
                            | TCP user registry|
                            | UDP ACK + retry  |
                            +------------------+
                 All UDP payloads use a shared Fernet key.''')
p('TCP: a 4-byte big-endian frame length followed by UTF-8 JSON. UDP: encrypted JSON (Fernet). The shared key is supplied via COLLAB_KEY. An unguessable per-session token from the TCP welcome must be attached to each client UDP packet. This provides session authorization but is not credential-based authentication or individual key management.')
head('3. Protocol specification')
rows=[['Message','Transport','Essential fields / meaning'],['login','TCP','type, name'],['welcome','TCP','type, token, udp_port'],['heartbeat','UDP','type, from, token'],['presence','UDP','type, names[]'],['data(chat)','UDP','id, from, to, kind, payload'],['data(file_start)','UDP','id, kind, meta:{transfer,filename,count,sha256}'],['data(file_chunk)','UDP','id, kind, meta:{transfer,index}, payload=base64'],['data(file_end)','UDP','id, kind, meta:{transfer}'],['ack','UDP','type, id, from, token (client); id only (server)']]
t=Table(rows,colWidths=[114,64,318],repeatRows=1,hAlign='LEFT');t.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,0),colors.HexColor('#dde8f4')),('GRID',(0,0),(-1,-1),.4,colors.lightgrey),('VALIGN',(0,0),(-1,-1),'TOP'),('FONTSIZE',(0,0),(-1,-1),7.1),('BOTTOMPADDING',(0,0),(-1,-1),5),('TOPPADDING',(0,0),(-1,-1),5)]));story.append(t)
p('Maximum encrypted UDP frame: 1100 bytes; file chunk: 320 bytes raw (base64 in JSON) to avoid common IP fragmentation. Each packet has a unique ID. The sending client tracks up to 6 in-flight packets and resends only unacknowledged packets after 250 ms, up to 15 attempts. The server independently forwards packets to recipients and retries at 250 ms up to 12 attempts; receivers deduplicate packet IDs and ACK before processing. The server currently does not persist offline messages.')
head('4. Client handshake sequence')
pre('''Client                      Server
 | -------- TCP connect -----> |
 | -------- login(name) -----> |
 | <------ welcome(token) ---- |
 | ------ UDP heartbeat -----> |
 | <------ presence(names) --- |
 | ----- UDP data(chat) -----> |
 | <--------- ACK ------------ |
 |             server forwards -> Recipient
 |                                Recipient -> server ACK''')
head('5. File-transfer sequence')
pre('''Sender                    Relay                    Receiver
  | file_start + checksum -> |  file_start ------->  |
  | <------ ACK ----------   |                ACK <- |
  | file_chunk[0..N-1] ---> |  chunks --------->    |
  | <---- ACK per chunk ---  |     receiver ACKs each|
  | retransmit missing ---> |                       |
  | file_end ------------->  |  file_end -------->   |
  |                         |   assemble ordered chunks
  |                         |   verify SHA-256; save file''')
p('For file data, payload bytes are base64-encoded into encrypted UDP JSON datagrams. A transfer ID and monotonically numbered chunk index preserve ordering after UDP reordering. The end marker is not proof of application-level completion: only a file_complete event at the receiver confirms verified assembly. Empty files are supported.')
head('6. Implementation steps and code mapping')
for x in ['1) Protocol design: common.py defines framing, serialization and Fernet; data messages contain unique IDs and types.', '2) Handshake: server.py / client.py use socket TCP connect, login and welcome.', '3) State: server.py stores connected usernames, token and last UDP endpoint.', '4) Concurrency: thread per TCP session, UDP loop and retransmit loop; independent client listener and heartbeat.', '5) Messaging: route() forwards broadcast and private encrypted UDP datagrams.', '6) File transfer: client.py splits binary content, sends start/chunks/end, verifies SHA-256.', '7) Resilience: socket timeout handling, reconnect after logout, UDP ACK/retries, duplicate suppression.', '8) Encryption: common.py wraps UDP JSON with Fernet (AES + HMAC).', '9) UI: webui.py serves JavaScript interface with chat, presence, file progress and upload.', '10) Testing: tests/test_integration.py runs isolated TCP/UDP end-to-end tests.']:
 p(x)
head('7. Challenges and solutions')
p('<b>Packet size:</b> Fernet, JSON and base64 add overhead. During the initial 125 KB binary-file test, a 480-byte chunk exceeded the configured 1100-byte UDP frame ceiling. The chunk size was reduced to 320 bytes; all five integration tests subsequently passed.')
p('<b>Out-of-order arrival:</b> a file is identified by transfer ID; chunk indices are stored in a dictionary, then reassembled in index order. A SHA-256 check rejects corruption.')
p('<b>Reliability and duplicates:</b> unique packet IDs, sender window, retries, recipient ACK and duplicate suppression. Note that acknowledging server ingress differs from acknowledging end-recipient completion.')
p('<b>UI integration:</b> the browser communicates with a localhost Python HTTP bridge, and only the bridge handles raw sockets. The UI does not rely on a WebSocket library or a Flask/Django networking framework.')
head('8. Test results and reproducibility')
p('Command: <font name="Courier">python -m unittest discover -s tests -v</font>. Observed result in this environment: 5 tests, 5 passed. Verified tests: presence/private+broadcast chat; 125,000-byte pseudorandom file SHA-256 match; empty file; duplicate login rejection; disconnect cleanup. These tests are localhost functional tests, not measurements under 20 clients or injected packet loss.')
head('9. Remaining work and deviations')
p('The brief contains a transport inconsistency: its goal describes custom UDP streaming, its TCP handshake criterion requires TCP, and the techniques section discusses TCP reliable transfer. This design uses TCP control/handshake plus UDP message and file transport. Confirm with instructor. Password-based account authentication, full BBR/CUBIC congestion algorithms, streaming disk I/O, stronger sender-to-recipient delivery receipts, 20-client stress validation and loss-injection evidence are not implemented. Do not claim these as completed rubric items. The baseline HTTP UI is for local use only; this prototype is not hardened for public internet deployment.')
head('10. Submission and demo instructions')
p('Run server in one terminal and two clients with different usernames in separate terminals, following README.md. Demonstrate active list, private chat, global chat, binary file received and its SHA-256, logout, and automated tests. Present the architecture diagram, packet fields and known limitations. Python dependencies are in requirements.txt.')
def footer(canvas,doc):
 canvas.saveState();canvas.setFont('Helvetica',8);canvas.drawString(46,28,'Collab LAN | Assignment 1 | Academic prototype');canvas.drawRightString(549,28,f'Page {doc.page}');canvas.restoreState()
doc.build(story,onFirstPage=footer,onLaterPages=footer)
print(out)
