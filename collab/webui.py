"""Dependency-free localhost HTTP UI; networking remains raw TCP/UDP sockets."""
import argparse
import json
import queue
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse
from .client import Client

PAGE=r'''<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Collab LAN</title>
<style>body{font:15px system-ui;background:#f1f5f9;color:#172134;margin:0}main{max-width:850px;margin:24px auto;padding:24px;background:white;border-radius:14px;box-shadow:0 4px 20px #0001}h1{margin-top:0}#messages{height:310px;overflow:auto;border:1px solid #cbd5e1;background:#fbfdff;padding:14px;border-radius:8px;margin:12px 0;white-space:pre-wrap}input,select,button{padding:10px;border:1px solid #94a3b8;border-radius:7px;font:inherit}button{cursor:pointer;background:#174c91;color:white}section{display:flex;gap:8px;margin:10px 0;flex-wrap:wrap}#message{flex:1;min-width:180px}.muted{color:#52667f}progress{width:100%}</style></head><body><main><h1>Collab LAN</h1><p class="muted">Logged in as <b id="self"></b> · encrypted UDP messaging and reliable file transfer</p><p>Online: <span id="online">Connecting...</span></p><div id="messages" role="log" aria-live="polite"></div><section><select id="to"><option value="*">Everyone</option></select><input id="message" maxlength="1000" placeholder="Type a message"><button onclick="sendChat()">Send</button></section><section><input type="file" id="file"><button onclick="sendFile()">Send file (max 25 MiB)</button></section><progress id="progress" max="100" value="0"></progress><p id="status" class="muted">Ready</p></main>
<script>let state={};const $=id=>document.getElementById(id);function line(x){$('messages').textContent+=x+'\n';$('messages').scrollTop=$('messages').scrollHeight}async function req(path,data){let r=await fetch(path,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)});let result=await r.json();if(!r.ok)throw Error(result.error||'Request failed');return result}
async function sendChat(){try{const text=$('message').value;await req('/chat',{to:$('to').value,text});$('message').value=''}catch(e){line('ERROR: '+e.message)}}
async function sendFile(){let f=$('file').files[0];if(!f)return; if(f.size>25*1024*1024){line('File exceeds 25 MiB');return}try{const bytes=new Uint8Array(await f.arrayBuffer());let parts=[];for(let b of bytes)parts.push(String.fromCharCode(b));$('status').textContent='Uploading to local client...';await req('/file',{to:$('to').value,filename:f.name,data:btoa(parts.join(''))});$('status').textContent='Transfer started'}catch(e){line('ERROR: '+e.message)}}
async function poll(){try{let x=await(await fetch('/events')).json();$('self').textContent=x.self;$('online').textContent=x.names.join(', ');let old=$('to').value;$('to').replaceChildren(new Option('Everyone','*'));for(let n of x.names)if(n!==x.self)$('to').add(new Option(n,n));$('to').value=[...$('to').options].some(o=>o.value===old)?old:'*';for(let e of x.events){if(e.type==='chat')line(e.from+': '+e.text);else if(e.type==='sent')line('You → '+e.to+': '+e.text);else if(e.type==='file_complete')line('File received from '+e.from+': '+e.filename+' saved to '+e.path);else if(e.type==='file_progress'){$('progress').value=e.total?100*e.received/e.total:100;$('status').textContent='Receiving '+e.filename+' '+e.received+'/'+e.total}else if(e.type==='error')line('ERROR: '+e.message);else if(e.type==='file_sent')line('File sent to server: '+e.filename);}}catch(e){$('status').textContent='Connection error: '+e.message}}
setInterval(poll,800);poll();$('message').addEventListener('keydown',e=>{if(e.key==='Enter')sendChat()});</script></body></html>'''

def handler_factory(client):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*args): pass
        def output(self,status,payload):
            raw=json.dumps(payload).encode()
            self.send_response(status);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
        def do_GET(self):
            if urlparse(self.path).path=='/':
                raw=PAGE.encode();self.send_response(200);self.send_header('Content-Type','text/html; charset=utf-8');self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
            elif self.path=='/events':
                events=[]
                for _ in range(100):
                    try: event=client.events.get_nowait()
                    except queue.Empty:break
                    if event.get('type')!='presence':events.append(event)
                self.output(200,dict(self=client.name,names=client.names,events=events))
            else:self.output(404,{'error':'Not found'})
        def do_POST(self):
            try:
                if self.headers.get('Content-Type','').split(';')[0]!='application/json':raise ValueError('Expected application/json')
                size=int(self.headers.get('Content-Length','0'))
                if not 0<size<37*1024*1024:raise ValueError('Invalid request length')
                data=json.loads(self.rfile.read(size))
                if self.path=='/chat':
                    threading.Thread(target=background,args=(client.chat,data['to'],data['text']),daemon=True).start()
                elif self.path=='/file':
                    import base64, tempfile, os
                    from pathlib import Path
                    name=Path(data['filename']).name
                    if not name or name in ('.','..'):raise ValueError('Invalid filename')
                    raw=base64.b64decode(data['data'],validate=True)
                    if len(raw)>25*1024*1024:raise ValueError('File too large')
                    tmpdir=Path(tempfile.mkdtemp(prefix='collab_upload_'))
                    path=tmpdir / name;path.write_bytes(raw)
                    def send_and_clean():
                        try:client.file(data['to'],path)
                        except Exception as e:client.events.put({'type':'error','message':str(e)})
                        finally:path.unlink(missing_ok=True);tmpdir.rmdir()
                    threading.Thread(target=send_and_clean,daemon=True).start()
                else:return self.output(404,{'error':'Not found'})
                self.output(202,{'accepted':True})
            except (ValueError,KeyError,TypeError) as e:self.output(400,{'error':str(e)})
    return Handler

def background(fn,*args):
    try:fn(*args)
    except Exception as e:
        # The web handler's input checks normally prevent this; log for diagnostics.
        import logging
        logging.exception('Background request error: %s',e)

def main():
    a=argparse.ArgumentParser();a.add_argument('--name',required=True);a.add_argument('--host',default='127.0.0.1');a.add_argument('--port',type=int,default=9000);a.add_argument('--web-port',type=int,default=8080);a.add_argument('--downloads',default='downloads')
    opts=a.parse_args();c=Client(opts.name,opts.host,opts.port,opts.downloads);c.connect()
    http=ThreadingHTTPServer(('127.0.0.1',opts.web_port),handler_factory(c));print(f'Open http://127.0.0.1:{opts.web_port} for user {opts.name}',flush=True)
    try:http.serve_forever()
    except KeyboardInterrupt:pass
    finally:http.server_close();c.close()
if __name__=='__main__':main()
