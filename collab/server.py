"""TCP authentication/presence; encrypted UDP data relay with ACK/retry."""
import argparse
import logging
import socket
import threading
import time
import uuid
from .common import cipher, decode_udp, encode_udp, recv_tcp, send_tcp

log = logging.getLogger(__name__)

class Server:
    def __init__(self, host='127.0.0.1', tcp_port=9000, udp_port=9001):
        self.host, self.tcp_port, self.udp_port = host, tcp_port, udp_port
        self.f = cipher()
        self.lock = threading.RLock()
        self.users = {}  # username => {sock, token, udp_addr, last_seen}
        self.running = threading.Event()
        self.threads = []
        self.pending = {}  # (destination, packet id) => {packet, retry_time, attempts}
        self.delivered = set()

    def start(self):
        self.tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.tcp.bind((self.host, self.tcp_port)); self.tcp.listen(32)
        self.tcp.settimeout(0.3)
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.bind((self.host, self.udp_port)); self.udp.settimeout(0.3)
        self.tcp_port = self.tcp.getsockname()[1]
        self.udp_port = self.udp.getsockname()[1]
        self.running.set()
        for task in [self.accept_loop, self.udp_loop, self.retransmit_loop]:
            t = threading.Thread(target=task, daemon=True)
            self.threads.append(t); t.start()
        log.info('Listening TCP %s UDP %s', self.tcp_port, self.udp_port)

    def close(self):
        self.running.clear()
        for s in [self.tcp, self.udp]:
            try: s.close()
            except OSError: pass
        with self.lock:
            for user in self.users.values():
                try: user['sock'].close()
                except OSError: pass
            self.users.clear()
        for t in self.threads: t.join(timeout=1)

    def accept_loop(self):
        while self.running.is_set():
            try: conn, address = self.tcp.accept()
            except socket.timeout: continue
            except OSError: break
            threading.Thread(target=self.handle_client, args=(conn,), daemon=True).start()

    def handle_client(self, conn):
        name = None
        conn.settimeout(4)
        try:
            hello = recv_tcp(conn)
            name = hello.get('name', '')
            if hello.get('type') != 'login' or not isinstance(name, str) or not (1 <= len(name) <= 24) or not name.replace('_', '').isalnum():
                send_tcp(conn, {'type':'error', 'message':'Invalid user name'}); return
            with self.lock:
                if name in self.users:
                    send_tcp(conn, {'type':'error','message':'User already connected'}); return
                token = uuid.uuid4().hex
                self.users[name] = dict(sock=conn, token=token, udp_addr=None, last_seen=time.monotonic())
            send_tcp(conn, {'type':'welcome', 'token':token, 'udp_port':self.udp_port})
            conn.settimeout(2)
            while self.running.is_set():
                try: msg = recv_tcp(conn)
                except socket.timeout: continue
                if msg.get('type') == 'logout': break
                if msg.get('type') == 'users':
                    with self.lock: active = list(self.users)
                    send_tcp(conn, {'type':'users','names':active})
        except (OSError, ValueError, ConnectionError, TypeError) as e:
            log.debug('TCP exit: %s', e)
        finally:
            with self.lock:
                if name in self.users and self.users[name]['sock'] is conn:
                    del self.users[name]
            try: conn.close()
            except OSError: pass

    def send_udp(self, msg, addr):
        try: self.udp.sendto(encode_udp(msg, self.f), addr)
        except (OSError, ValueError): pass

    def udp_loop(self):
        while self.running.is_set():
            try: raw, addr = self.udp.recvfrom(4096)
            except socket.timeout: continue
            except OSError: break
            msg = decode_udp(raw, self.f)
            if not isinstance(msg, dict): continue
            name, token = msg.get('from'), msg.get('token')
            with self.lock:
                user = self.users.get(name)
                if not user or user['token'] != token: continue
                user['udp_addr'] = addr
                user['last_seen'] = time.monotonic()
                kind = msg.get('type')
                if kind == 'heartbeat':
                    self.send_udp({'type':'presence','names':list(self.users)}, addr)
                elif kind == 'ack':
                    self.pending.pop((name, msg.get('id')), None)
                elif kind == 'data':
                    self.route(msg, addr)

    def route(self, msg, source_addr):
        msg_id = msg.get('id')
        if not isinstance(msg_id,str) or len(msg_id)>80 or not isinstance(msg.get('payload'),str): return
        if msg.get('kind') not in ('chat','file_start','file_chunk','file_end'): return
        # Authenticate source via TCP session token before accepting encrypted UDP datagrams.
        self.send_udp({'type':'ack','id':msg_id}, source_addr)
        targets = [n for n in self.users if n != msg['from']] if msg.get('to') == '*' else [msg.get('to')]
        for destination in targets:
            if destination not in self.users or destination == msg['from']: continue
            packet = {'type':'data','id':msg_id,'kind':msg['kind'],'from':msg['from'], 'to':destination,
                      'payload':msg['payload'],'meta':msg.get('meta', {})}
            key = (destination,msg_id)
            if key in self.pending: continue
            self.pending[key] = dict(packet=packet, attempts=0, retry_time=0)

    def retransmit_loop(self):
        while self.running.is_set():
            now = time.monotonic()
            with self.lock:
                for key, item in list(self.pending.items()):
                    if item['retry_time'] > now: continue
                    if item['attempts'] >= 12:
                        log.warning('Delivery expired %r', key); del self.pending[key]; continue
                    destination = self.users.get(key[0])
                    if not destination:
                        del self.pending[key]; continue
                    if destination['udp_addr']:
                        self.send_udp(item['packet'],destination['udp_addr'])
                        item['attempts'] += 1
                    item['retry_time'] = now + 0.25
            time.sleep(0.04)

def main():
    parser=argparse.ArgumentParser(); parser.add_argument('--host',default='127.0.0.1')
    parser.add_argument('--tcp-port',type=int,default=9000); parser.add_argument('--udp-port',type=int,default=9001)
    a=parser.parse_args(); logging.basicConfig(level=logging.INFO)
    server=Server(a.host,a.tcp_port,a.udp_port); server.start()
    try:
        while True: time.sleep(1)
    except KeyboardInterrupt: pass
    finally: server.close()
if __name__=='__main__': main()
