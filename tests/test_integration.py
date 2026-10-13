import hashlib
import os
from pathlib import Path
import queue
import tempfile
import time
import unittest
from cryptography.fernet import Fernet
from collab.client import Client
from collab.server import Server

class NetworkTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ['COLLAB_KEY']=Fernet.generate_key().decode()
        cls.s=Server('127.0.0.1',0,0);cls.s.start()

    @classmethod
    def tearDownClass(cls):cls.s.close()

    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.a=Client('alice','127.0.0.1',self.s.tcp_port,self.temp.name+'/alice')
        self.b=Client('bob','127.0.0.1',self.s.tcp_port,self.temp.name+'/bob')
        self.a.connect();self.b.connect()
        self.wait(lambda:'bob' in self.a.names and 'alice' in self.b.names)

    def tearDown(self):self.a.close();self.b.close();self.temp.cleanup()

    def wait(self,predicate,timeout=8):
        until=time.time()+timeout
        while time.time()<until:
            if predicate():return
            time.sleep(.04)
        self.fail('Timed out waiting for expected state')

    def get_event(self,client,typ,timeout=8):
        until=time.time()+timeout
        while time.time()<until:
            try:x=client.events.get(timeout=.1)
            except queue.Empty:continue
            if x['type']==typ:return x
        self.fail('No event '+typ)

    def test_01_login_presence_private_and_broadcast(self):
        self.a.chat('bob','private hello')
        self.assertEqual(self.get_event(self.b,'chat')['text'],'private hello')
        self.a.chat('*','broadcast hello')
        self.assertEqual(self.get_event(self.b,'chat')['text'],'broadcast hello')

    def test_02_binary_file_and_sha256(self):
        original=os.urandom(125000)
        src=Path(self.temp.name)/'sample.bin';src.write_bytes(original)
        self.a.file('bob',src)
        e=self.get_event(self.b,'file_complete',timeout=18)
        self.assertEqual(hashlib.sha256(Path(e['path']).read_bytes()).digest(),hashlib.sha256(original).digest())

    def test_03_empty_file(self):
        src=Path(self.temp.name)/'empty.bin';src.write_bytes(b'')
        self.a.file('bob',src)
        e=self.get_event(self.b,'file_complete')
        self.assertEqual(Path(e['path']).read_bytes(),b'')

    def test_04_duplicate_user_rejected(self):
        duplicate=Client('alice','127.0.0.1',self.s.tcp_port,self.temp.name+'/duplicate')
        with self.assertRaises(RuntimeError):duplicate.connect()

    def test_05_disconnect_cleanup(self):
        self.b.close()
        self.wait(lambda:'bob' not in self.s.users)

if __name__=='__main__':unittest.main()
