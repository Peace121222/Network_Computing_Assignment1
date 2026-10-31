"""Browser behavior, HTTP integration, admission limits, and upload cleanup."""

from http.client import HTTPConnection
from pathlib import Path
from unittest.mock import Mock, patch
import base64
import hashlib
import http.client
import json
import os
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import unittest

from cryptography.fernet import Fernet

from collab.web.handlers import PAGE, STATIC_DIR, handler_factory
from collab.web.runtime import BoundedHTTPServer
from tests.auth_support import Client, Server


def wait(test, predicate, timeout=5):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        threading.Event().wait(0.01)
    test.fail("UI state did not converge")


class WebUIIntegrationTests(unittest.TestCase):
    def setUp(self):
        env = patch.dict(os.environ, {"COLLAB_KEY": Fernet.generate_key().decode()})
        env.start()
        self.addCleanup(env.stop)
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.server = Server("127.0.0.1", 0, 0)
        self.server.start()
        self.addCleanup(self.server.close)
        self.a = Client(
            "alice", port=self.server.tcp_port, download_dir=self.root / "alice"
        )
        self.b = Client(
            "bob", port=self.server.tcp_port, download_dir=self.root / "bob"
        )
        self.addCleanup(self.a.close)
        self.addCleanup(self.b.close)
        self.a.connect()
        self.b.connect()
        wait(self, lambda: self.a.names == self.b.names == ["alice", "bob"])
        self.http = BoundedHTTPServer(("127.0.0.1", 0), handler_factory(self.b))
        self.thread = threading.Thread(target=self.http.serve_forever)
        self.thread.start()
        self.addCleanup(self.stop_http)

    def stop_http(self):
        self.http.server_close()
        self.thread.join(2)

    def get(self, path="/events"):
        connection = HTTPConnection("127.0.0.1", self.http.server_port, timeout=2)
        try:
            connection.request("GET", path)
            response = connection.getresponse()
            return response.status, response.read()
        finally:
            connection.close()

    def events(self):
        status, raw = self.get()
        self.assertEqual(status, 200)
        return json.loads(raw)

    def test_static_assets_are_served_with_exact_content_and_mime_type(self):
        resources = (
            ("/", "index.html", "text/html; charset=utf-8"),
            ("/static/style.css", "style.css", "text/css; charset=utf-8"),
            ("/static/app.js", "app.js", "text/javascript; charset=utf-8"),
        )
        for route, name, mime in resources:
            connection = HTTPConnection("127.0.0.1", self.http.server_port, timeout=2)
            try:
                connection.request("GET", route)
                response = connection.getresponse()
                raw = response.read()
                self.assertEqual(response.status, 200)
                self.assertEqual(response.getheader("Content-Type"), mime)
                self.assertEqual(int(response.getheader("Content-Length")), len(raw))
                self.assertEqual(raw, (STATIC_DIR / name).read_bytes())
            finally:
                connection.close()
        self.assertIn('<link rel="stylesheet" href="/static/style.css">', PAGE)
        self.assertIn('<script src="/static/app.js" defer></script>', PAGE)

    def test_non_allowlisted_static_paths_are_not_served(self):
        for route in (
            "/static/index.html",
            "/static/../handlers.py",
            "/static/%2e%2e/handlers.py",
            "/static/missing.js",
        ):
            with self.subTest(route=route):
                status, raw = self.get(route)
                self.assertEqual(status, 404)
                self.assertEqual(json.loads(raw), {"error": "Not found"})

    def test_http_ui_receives_messages_online_list_and_disconnect_status(self):
        status, raw = self.get("/")
        self.assertEqual(status, 200)
        self.assertIn(b'<script src="/static/app.js" defer></script>', raw)
        self.a.chat("bob", "Hello <b>Bob</b> — English text")
        snapshot = self.events()
        self.assertEqual(snapshot["names"], ["alice", "bob"])
        self.assertEqual(snapshot["status"], "connected")
        chat = next(e for e in snapshot["events"] if e["type"] == "chat")
        self.assertEqual(chat["from"], "alice")
        self.assertEqual(chat["text"], "Hello <b>Bob</b> — English text")
        self.a.close()
        wait(self, lambda: self.b.names == ["bob"])
        self.assertEqual(self.events()["names"], ["bob"])
        self.server.close()
        wait(self, lambda: self.b.status == "disconnected")
        snapshot = self.events()
        self.assertEqual(snapshot["status"], "disconnected")
        self.assertEqual(snapshot["names"], [])

    def test_file_progress_and_completion_keep_transfer_identity(self):
        content = b"file-data" * 1000
        source = self.root / "source.bin"
        source.write_bytes(content)
        self.a.file("bob", source)
        incoming = self.events()["events"]
        start = next(e for e in incoming if e["type"] == "file_receiving")
        progress = [e for e in incoming if e["type"] == "file_progress"]
        complete = next(e for e in incoming if e["type"] == "file_complete")
        self.assertTrue(progress)
        self.assertTrue(
            all(
                (e["transfer"], e["sender_session"])
                == (start["transfer"], start["sender_session"])
                for e in progress + [complete]
            )
        )
        self.assertEqual(progress[-1]["received"], progress[-1]["total"])
        self.assertEqual(Path(complete["path"]).read_bytes(), content)
        outgoing = list(self.a.events.queue)
        sending = next(e for e in outgoing if e["type"] == "file_send_progress")
        sent = next(e for e in outgoing if e["type"] == "file_sent")
        self.assertEqual(sending["transfer"], complete["transfer"])
        self.assertEqual(sent["transfer"], complete["transfer"])
        self.assertTrue(
            any(
                e["type"] == "file_send_progress" and e["sent"] == e["total"]
                for e in outgoing
            )
        )

    def test_empty_file_still_has_start_and_completion_events(self):
        source = self.root / "empty.bin"
        source.write_bytes(b"")
        self.a.file("bob", source)
        events = self.events()["events"]
        start = next(e for e in events if e["type"] == "file_receiving")
        complete = next(e for e in events if e["type"] == "file_complete")
        self.assertEqual(start["total"], 0)
        self.assertEqual(start["transfer"], complete["transfer"])
        self.assertEqual(Path(complete["path"]).read_bytes(), b"")


@unittest.skipUnless(
    shutil.which("node"), "Node is needed to exercise client-side JavaScript"
)
class BrowserLogicTests(unittest.TestCase):
    def test_rendering_messages_presence_and_independent_file_progress(self):
        script = (STATIC_DIR / "app.js").read_text(encoding="utf-8")

        harness = r"""
const vm = require('node:vm');
const assert = require('node:assert/strict');
class Element {
    constructor() { this.textContent=''; this.value=''; this.children=[]; this.options=[]; this.disabled=false; }
    setAttribute() {}
    addEventListener(name, callback) { (this.listeners ||= {})[name] = callback; }
    append(...items) { this.children.push(...items); }
    replaceChildren(...items) { this.options=items; this.value=items[0]?.value || ''; }
    add(item) { this.options.push(item); }
}
const elements = {};
for (const id of ['self','connection','online','messages','to','message','send-chat','send-file','file','transfers','status']) elements[id]=new Element();
elements.to.value='*';
const snapshots = [];
const sandbox = {
    document:{getElementById:id=>elements[id], createElement:()=>new Element()},
    Option:function(text,value){this.text=text;this.value=value;},
    setTimeout:()=>{},
    fetch:async()=>({ok:true,json:async()=>snapshots.shift()})
};
snapshots.push({self:'bob',names:['alice','bob'],status:'connected',events:[]});
vm.createContext(sandbox);
vm.runInContext(SCRIPT, sandbox);
(async()=>{
    await new Promise(resolve=>setImmediate(resolve));
    assert.equal(elements.connection.textContent,'Connected');
    assert.equal(elements['send-chat'].disabled,false);
    assert.deepEqual(elements.to.options.map(x=>x.value),['*','alice']);
    const run = code=>vm.runInContext(code,sandbox);
    run(`receiveEvent({type:'chat',from:'alice',text:'<img src=x onerror=alert(1)>'})`);
    assert.ok(elements.messages.textContent.includes('<img src=x onerror=alert(1)>'));
    assert.equal(elements.messages.children.length,0);
    run(`receiveEvent({type:'file_progress',transfer:'one',sender_session:'s',from:'alice',filename:'same.bin',received:1,total:4})`);
    run(`receiveEvent({type:'file_progress',transfer:'two',sender_session:'s',from:'alice',filename:'same.bin',received:3,total:4})`);
    assert.equal(elements.transfers.children.length,2);
    assert.equal(elements.transfers.children[0].children[1].value,25);
    assert.equal(elements.transfers.children[1].children[1].value,75);
    run(`receiveEvent({type:'file_complete',transfer:'one',sender_session:'s',from:'alice',filename:'same.bin',path:'downloads/file.bin'})`);
    assert.equal(elements.transfers.children[0].children[1].value,100);
    assert.equal(elements.transfers.children[0].children[2].textContent,'Received and saved');
    assert.equal(elements.transfers.children[1].children[1].value,75);
    run(`receiveEvent({type:'file_receiving',transfer:'empty',sender_session:'s',from:'alice',filename:'empty.bin',total:0})`);
    run(`receiveEvent({type:'file_complete',transfer:'empty',sender_session:'s',from:'alice',filename:'empty.bin',path:'downloads/empty.bin'})`);
    assert.equal(elements.transfers.children[2].children[1].value,100);
    run(`receiveEvent({type:'file_send_progress',transfer:'send',to:'alice',filename:'out.bin',sent:4,total:4})`);
    assert.ok(elements.transfers.children[3].children[2].textContent.includes('Waiting for recipient confirmation'));
    run(`receiveEvent({type:'file_sent',transfer:'send',to:'alice',filename:'out.bin'})`);
    assert.equal(elements.transfers.children[3].children[2].textContent,'Delivered to recipient(s)');
    assert.ok(!elements.messages.textContent.includes('File sent to server'));
    snapshots.push({self:'bob',names:['bob'],status:'connected',events:[]});
    elements.to.value='alice';
    await run('poll()');
    assert.equal(elements.to.value,'alice');
    assert.equal(elements.to.options.at(-1).text,'alice (offline)');
    // Hold HTTP acceptance open: double clicks and Enter must submit once,
    // even if a presence poll refreshes the connection controls meanwhile.
    let release, calls = 0;
    sandbox.fetch = async (path, options) => {
        assert.equal(path, '/chat');
        calls++;
        assert.deepEqual(JSON.parse(options.body), {to:'alice',text:'one message'});
        await new Promise(resolve => { release = resolve; });
        return {ok:true,json:async()=>({accepted:true})};
    };
    elements.message.value='one message';
    const first = run('sendChat()');
    await run('sendChat()');
    let prevented = 0;
    elements.message.listeners.keydown({key:'Enter',preventDefault(){prevented++;}});
    elements.message.listeners.keydown({key:'Enter',repeat:true,preventDefault(){prevented++;}});
    run("connection('connected')");
    assert.equal(calls,1);
    assert.equal(prevented,2);
    assert.equal(elements['send-chat'].disabled,true);
    elements.message.value='next draft';
    release();
    await first;
    assert.equal(elements.message.value,'next draft');
    assert.equal(elements['send-chat'].disabled,false);
    // A failed request preserves the draft and releases the submission guard.
    sandbox.fetch = async()=>{throw Error('network failure');};
    await run('sendChat()');
    assert.equal(elements.message.value,'next draft');
    assert.equal(elements['send-chat'].disabled,false);
    sandbox.fetch = async()=>({ok:true,json:async()=>({accepted:true})});
    await run('sendChat()');
    assert.equal(elements.message.value,'');
    sandbox.fetch = async()=>({ok:true,json:async()=>snapshots.shift()});
    snapshots.push({self:'bob',names:[],status:'disconnected',events:[]});
    await run('poll()');
    assert.equal(elements.online.textContent,'No active users');
    assert.equal(elements['send-chat'].disabled,true);
    assert.equal(elements['send-file'].disabled,true);
})().catch(error=>{console.error(error);process.exitCode=1;});
"""
        result = subprocess.run(
            [shutil.which("node"), "-e", harness.replace("SCRIPT", json.dumps(script))],
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stderr)


def wait_for(test, predicate, timeout=3):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if predicate():
            return
        time.sleep(0.005)
    test.fail("HTTP state did not converge")


class HTTPConcurrencyTests(unittest.TestCase):
    def setUp(self):
        self.env = patch.dict(
            os.environ, {"COLLAB_KEY": Fernet.generate_key().decode()}
        )
        self.env.start()
        self.temp = tempfile.TemporaryDirectory()
        self.client = Client("alice", download_dir=self.temp.name)
        self.client.status = "connected"
        self.client._session = {"stop": threading.Event()}
        self.client.chat = Mock()
        self.client.file = Mock()
        self.handler = handler_factory(self.client)
        self.http = BoundedHTTPServer(("127.0.0.1", 0), self.handler)
        self.server_thread = threading.Thread(target=self.http.serve_forever)
        self.server_thread.start()
        wait_for(self, self.http._serving.is_set)
        self.release = threading.Event()

    def tearDown(self):
        self.release.set()
        self.http.server_close()
        self.server_thread.join(2)
        self.temp.cleanup()
        self.env.stop()

    def request(self, path, data, *, raw=False):
        connection = http.client.HTTPConnection(
            "127.0.0.1", self.http.server_port, timeout=2
        )
        body = data if raw else json.dumps(data)
        try:
            connection.request("POST", path, body, {"Content-Type": "application/json"})
            response = connection.getresponse()
            return response.status, json.loads(response.read())
        finally:
            connection.close()

    def fill_active_senders(self):
        entered = threading.Barrier(3)

        def slow(*args):
            entered.wait(2)
            self.release.wait(5)

        self.client.chat.side_effect = slow
        for _ in range(2):
            self.assertEqual(
                self.request("/chat", {"to": "*", "text": "blocking"})[0], 202
            )
        entered.wait(2)
        return self.client._session

    def test_send_pool_returns_503_when_full_and_releases_slots(self):
        self.fill_active_senders()
        for _ in range(4):
            self.assertEqual(
                self.request("/chat", {"to": "*", "text": "queued"})[0], 202
            )
        self.assertEqual(self.request("/chat", {"to": "*", "text": "excess"})[0], 503)
        self.assertEqual(self.handler.runtime.tasks.admitted, 6)
        self.assertEqual(len(self.handler.runtime.tasks.threads), 2)

        self.client.chat.side_effect = None
        self.release.set()
        wait_for(self, lambda: self.handler.runtime.tasks.admitted == 0)

    def test_two_upload_slots_include_running_and_queued_and_cleanup(self):
        self.fill_active_senders()
        paths = []
        self.client.file.side_effect = lambda to, path: paths.append(path)
        payload = {
            "to": "*",
            "filename": "file.bin",
            "data": base64.b64encode(b"data").decode(),
        }
        created = []
        original = tempfile.mkdtemp

        def temporary(*args, **kwargs):
            path = original(*args, **kwargs)
            created.append(Path(path))
            return path

        try:
            with patch("collab.web.handlers.tempfile.mkdtemp", side_effect=temporary):
                self.assertEqual(self.request("/file", payload)[0], 202)
                self.assertEqual(self.request("/file", payload)[0], 202)
                self.assertEqual(self.request("/file", payload)[0], 503)
            self.assertEqual(len(created), 2)
            self.client.chat.side_effect = None
            self.release.set()
            wait_for(self, lambda: self.handler.runtime.tasks.admitted == 0)
            self.assertEqual(len(paths), 2)
            self.assertTrue(all(not directory.exists() for directory in created))
            self.assertTrue(self.handler.runtime.uploads.acquire(False))
            self.assertTrue(self.handler.runtime.uploads.acquire(False))
            self.handler.runtime.uploads.release()
            self.handler.runtime.uploads.release()
        finally:
            self.release.set()
            for directory in created:
                for path in directory.glob("*"):
                    path.unlink(missing_ok=True)
                if directory.exists():
                    directory.rmdir()

    def test_invalid_upload_and_failed_send_return_reservations_and_error(self):
        self.assertEqual(
            self.request("/file", {"to": "*", "filename": "../bad", "data": ""})[0], 400
        )
        self.assertEqual(
            self.request("/file", {"to": "*", "filename": "x", "data": "!!!!"})[0], 400
        )
        self.assertEqual(self.handler.runtime.tasks.admitted, 0)
        self.client.chat.side_effect = ValueError("send failed")
        self.assertEqual(self.request("/chat", {"to": "*", "text": "hi"})[0], 202)
        wait_for(self, lambda: self.handler.runtime.tasks.admitted == 0)
        self.assertTrue(
            any(
                e.get("message") == "send failed"
                for e in list(self.client.events.queue)
            )
        )

    def test_chat_body_limit_before_admission(self):
        self.assertEqual(self.request("/chat", "x" * (16 * 1024 + 1), raw=True)[0], 400)
        self.assertEqual(self.handler.runtime.tasks.admitted, 0)
        self.client.chat.assert_not_called()

    def test_queued_job_cannot_run_in_replacement_session(self):
        self.fill_active_senders()
        self.assertEqual(
            self.request("/chat", {"to": "*", "text": "old session"})[0], 202
        )
        with self.client._state_lock:
            self.client._session = {"stop": threading.Event()}
        self.client.chat.side_effect = None
        self.release.set()
        wait_for(self, lambda: self.handler.runtime.tasks.admitted == 0)
        texts = [call.args[1] for call in self.client.chat.call_args_list]
        self.assertNotIn("old session", texts)
        self.assertTrue(
            any(
                "session" in e.get("message", "")
                for e in list(self.client.events.queue)
            )
        )

    def test_http_handler_limit_has_eight_workers_and_sixteen_connections(self):
        sockets = []
        try:

            for _ in range(16):
                sock = socket.create_connection(
                    ("127.0.0.1", self.http.server_port), timeout=1
                )
                sock.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\n")
                sockets.append(sock)
            wait_for(self, lambda: self.http.handlers.admitted == 16)
            self.assertEqual(len(self.http.handlers.threads), 8)
            with socket.create_connection(
                ("127.0.0.1", self.http.server_port), timeout=1
            ) as excess:
                self.assertEqual(excess.recv(1), b"")
        finally:
            for sock in sockets:
                sock.close()
        wait_for(self, lambda: self.http.handlers.admitted == 0)

    def test_shutdown_cancels_queued_upload_and_closes_all_owned_workers(self):
        entered = threading.Barrier(3)

        def until_closed(*args):
            entered.wait(2)
            self.client._session["stop"].wait(3)

        self.client.chat.side_effect = until_closed
        for _ in range(2):
            self.assertEqual(
                self.request("/chat", {"to": "*", "text": "active"})[0], 202
            )
        entered.wait(2)
        directories = []
        original = tempfile.mkdtemp

        def temporary(*args, **kwargs):
            directory = original(*args, **kwargs)
            directories.append(Path(directory))
            return directory

        with patch("collab.web.handlers.tempfile.mkdtemp", side_effect=temporary):
            self.assertEqual(
                self.request(
                    "/file",
                    {
                        "to": "*",
                        "filename": "pending.bin",
                        "data": base64.b64encode(b"data").decode(),
                    },
                )[0],
                202,
            )
        workers = list(self.http.handlers.threads) + list(
            self.handler.runtime.tasks.threads
        )
        self.http.server_close()
        self.server_thread.join(1)
        self.assertEqual(self.handler.runtime.tasks.admitted, 0)
        self.assertFalse(any(t.is_alive() for t in workers))
        self.assertTrue(all(not path.exists() for path in directories))
        self.assertEqual(self.client.status, "disconnected")


if __name__ == "__main__":
    unittest.main()
