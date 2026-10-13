"""Wire format, encrypted UDP frames and framed TCP control messages."""
import base64
import json
import os
import socket
import struct
from cryptography.fernet import Fernet, InvalidToken

MAX_FRAME = 2_000_000
UDP_MTU = 1100
CHUNK = 320

def get_key():
    key = os.getenv('COLLAB_KEY', '')
    if not key:
        raise RuntimeError('Set COLLAB_KEY (generate with python -m collab.keygen)')
    return key.encode('ascii')

def cipher():
    return Fernet(get_key())

def send_tcp(sock, data):
    raw = json.dumps(data, separators=(',', ':')).encode()
    if len(raw) > MAX_FRAME:
        raise ValueError('TCP frame too large')
    sock.sendall(struct.pack('!I', len(raw)) + raw)

def recv_exact(sock, n):
    result = bytearray()
    while len(result) < n:
        chunk = sock.recv(n-len(result))
        if not chunk:
            raise ConnectionError('TCP socket closed')
        result.extend(chunk)
    return bytes(result)

def recv_tcp(sock):
    size = struct.unpack('!I', recv_exact(sock, 4))[0]
    if size > MAX_FRAME:
        raise ValueError('TCP frame too large')
    return json.loads(recv_exact(sock, size))

def encode_udp(msg, f):
    raw = f.encrypt(json.dumps(msg, separators=(',', ':')).encode())
    if len(raw) > UDP_MTU:
        raise ValueError('UDP frame exceeds limit')
    return raw

def decode_udp(raw, f):
    try:
        return json.loads(f.decrypt(raw))
    except (InvalidToken, ValueError, UnicodeError, json.JSONDecodeError):
        return None

def b64(raw):
    return base64.b64encode(raw).decode('ascii')

def unb64(value):
    return base64.b64decode(value, validate=True)
