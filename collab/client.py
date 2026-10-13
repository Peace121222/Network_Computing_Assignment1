"""Client socket engine; no high-level networking libraries."""
import argparse
import hashlib
import json
import logging
import os
from pathlib import Path
import queue
import socket
import threading
import time
import uuid
from .common import b64, unb64, CHUNK, cipher, decode_udp, encode_udp, recv_tcp, send_tcp
log = logging.getLogger(__name__)

class Client:
    def __init__(self, name, host='127.0.0.1', port=9000, download_dir='downloads'):
        self.name, self.host, self.port = name, host, port
        self.f = cipher()
        self.download_dir = Path(download_dir)
        self.download_dir.mkdir(parents=True, exist_ok=True)
        self.events = queue.Queue()
        self.pending = {}
        self.pending_lock = threading.Lock()
        self.messages_seen = set()
        self.files = {}
        self.names = []
        self.running = threading.Event()

    def connect(self):
        self.tcp = socket.create_connection((self.host,self.port),timeout=5)
        send_tcp(self.tcp,{'type':'login','name':self.name})
        hello = recv_tcp(self.tcp)
        if hello.get('type') != 'welcome':
            self.tcp.close(); raise RuntimeError(hello.get('message','Login failed'))
        self.token = hello['token']; self.address = (self.host,hello['udp_port'])
        self.udp = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        self.udp.bind(('0.0.0.0',0)); self.udp.settimeout(0.2)
        self.running.set()
        self.threads = [threading.Thread(target=self.listen,daemon=True),threading.Thread(target=self.heartbeats,daemon=True)]
        for t in self.threads: t.start()
        self.send_raw({'type':'heartbeat'})

    def close(self):
        self.running.clear()
        try: send_tcp(self.tcp,{'type':'logout'})
        except OSError: pass
        for s in (self.tcp,self.udp):
            try:s.close()
            except OSError:pass
        for t in self.threads: t.join(timeout=1)

    def send_raw(self, message):
        self.udp.sendto(encode_udp(dict(message, **{'from':self.name,'token':self.token}),self.f),self.address)

    def heartbeats(self):
        while self.running.is_set():
            try:self.send_raw({'type':'heartbeat'})
            except OSError:break
            for _ in range(20):
                if not self.running.is_set():break
                time.sleep(0.1)

    def listen(self):
        while self.running.is_set():
            try: raw, _ = self.udp.recvfrom(4096)
            except socket.timeout:continue
            except OSError:break
            msg=decode_udp(raw,self.f)
            if not isinstance(msg,dict):continue
            typ=msg.get('type')
            if typ=='presence':
                self.names=msg.get('names',[])
                self.events.put({'type':'presence','names':self.names})
            elif typ=='ack':
                with self.pending_lock:
                    event=self.pending.get(msg.get('id'))
                if event:event.set()
            elif typ=='data':
                mid=msg.get('id')
                if not isinstance(mid,str):continue
                try: self.send_raw({'type':'ack','id':mid})
                except OSError:continue
                if mid in self.messages_seen:continue
                self.messages_seen.add(mid)
                if len(self.messages_seen)>200000:self.messages_seen.clear()
                try:self.on_data(msg)
                except (ValueError, KeyError, TypeError, OSError) as e:
                    self.events.put({'type':'error','message':str(e)})

    def on_data(self,msg):
        kind=msg.get('kind'); meta=msg.get('meta') or {}; sender=msg.get('from')
        if kind=='chat':
            self.events.put({'type':'chat','from':sender,'text':msg['payload']})
        elif kind=='file_start':
            transfer=meta['transfer']; count=int(meta['count'])
            if not 0 <= count <= 500000: raise ValueError('Invalid chunk count')
            self.files[(sender,transfer)]={'name':Path(meta['filename']).name,'total':count,
                                           'sha256':meta['sha256'],'chunks':{},'ended':False}
        elif kind=='file_chunk':
            key=(sender,meta['transfer']); transfer=self.files.get(key)
            if not transfer:return
            index=int(meta['index'])
            if 0<=index<transfer['total']:
                transfer['chunks'][index]=unb64(msg['payload'])
                self.events.put({'type':'file_progress','from':sender,'filename':transfer['name'],
                                 'received':len(transfer['chunks']),'total':transfer['total']})
            self.finish_file(key)
        elif kind=='file_end':
            key=(sender,meta['transfer'])
            if key in self.files:
                self.files[key]['ended']=True
                self.finish_file(key)

    def finish_file(self,key):
        f=self.files.get(key)
        if not f or not f['ended'] or len(f['chunks'])!=f['total']:return
        payload=b''.join(f['chunks'][i] for i in range(f['total']))
        if hashlib.sha256(payload).hexdigest()!=f['sha256']:
            self.events.put({'type':'error','message':'SHA256 mismatch on received file'})
            del self.files[key];return
        base=Path(f['name']).name or 'received.bin'
        destination=self.download_dir / (uuid.uuid4().hex[:8]+'_'+base)
        destination.write_bytes(payload)
        self.events.put({'type':'file_complete','from':key[0],'filename':base,'path':str(destination),'size':len(payload)})
        del self.files[key]

    def send_packets(self, packets, window=6, retries=15, timeout=0.25):
        """Bounded sliding window; only unacknowledged datagrams are retried."""
        inflight={}; i=0
        try:
            while i<len(packets) or inflight:
                while i<len(packets) and len(inflight)<window:
                    p=packets[i]; ev=threading.Event()
                    with self.pending_lock:self.pending[p['id']]=ev
                    inflight[p['id']]=(p,ev,0,0)
                    i+=1
                for mid,(p,ev,tries,last) in list(inflight.items()):
                    if ev.is_set():
                        del inflight[mid]
                        with self.pending_lock:self.pending.pop(mid,None)
                        continue
                    if time.monotonic()-last < timeout:continue
                    if tries>=retries:raise TimeoutError('No ACK for packet '+mid)
                    self.send_raw(p)
                    inflight[mid]=(p,ev,tries+1,time.monotonic())
                time.sleep(0.012)
        finally:
            with self.pending_lock:
                for mid in inflight:self.pending.pop(mid,None)

    def packet(self, to, kind, payload='', meta=None):
        return {'type':'data','id':uuid.uuid4().hex,'to':to,'kind':kind,'payload':payload,'meta':meta or {}}

    def chat(self, recipient,text):
        if not text or len(text)>1000:raise ValueError('Message must be 1-1000 characters')
        if recipient != '*' and recipient not in self.names:raise ValueError('Recipient not online')
        self.send_packets([self.packet(recipient,'chat',text)])
        self.events.put({'type':'sent','to':recipient,'text':text})

    def file(self,recipient,path):
        path=Path(path)
        if not path.is_file():raise FileNotFoundError(path)
        if recipient != '*' and recipient not in self.names:raise ValueError('Recipient not online')
        data=path.read_bytes()
        if len(data)>25*1024*1024:raise ValueError('File size limit: 25 MiB')
        transfer=uuid.uuid4().hex
        chunks=[data[i:i+CHUNK] for i in range(0,len(data),CHUNK)]
        meta={'transfer':transfer,'filename':path.name,'count':len(chunks),'sha256':hashlib.sha256(data).hexdigest()}
        self.send_packets([self.packet(recipient,'file_start','',meta)])
        packets=[self.packet(recipient,'file_chunk',b64(block),{'transfer':transfer,'index':i}) for i,block in enumerate(chunks)]
        self.send_packets(packets)
        self.send_packets([self.packet(recipient,'file_end','',{'transfer':transfer})])
        self.events.put({'type':'file_sent','filename':path.name,'to':recipient,'size':len(data)})

def main():
    p=argparse.ArgumentParser();p.add_argument('--name',required=True);p.add_argument('--host',default='127.0.0.1')
    p.add_argument('--port',type=int,default=9000);p.add_argument('--downloads',default='downloads')
    args=p.parse_args();logging.basicConfig(level=logging.INFO)
    c=Client(args.name,args.host,args.port,args.downloads);c.connect()
    print('Commands: /users, /msg USER MESSAGE, /all MESSAGE, /file USER PATH, /quit')
    def printer():
        while c.running.is_set():
            try:
                event=c.events.get(timeout=.3)
                if event['type']!='presence': print('\nEVENT',json.dumps(event,ensure_ascii=False))
            except queue.Empty:pass
    threading.Thread(target=printer,daemon=True).start()
    try:
        while True:
            line=input('> ').strip()
            if line=='/quit':break
            if line=='/users':print(c.names)
            elif line.startswith('/all '):c.chat('*',line[5:])
            elif line.startswith('/msg '):
                _,recipient,message=line.split(' ',2);c.chat(recipient,message)
            elif line.startswith('/file '):
                _,recipient,path=line.split(' ',2);c.file(recipient,path)
            else:print('Invalid command')
    except (KeyboardInterrupt,EOFError):pass
    finally:c.close()
if __name__=='__main__':main()
