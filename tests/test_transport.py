"""SYNTHETIC transport interception; no actual sockets or remote bodies."""
import ast
import contextlib
import io
from pathlib import Path
import socket
import unittest
from unittest.mock import patch
import urllib.error
import urllib.request
import watcher as w

class Response:
    status = 200
    headers = {}
    def __init__(self, body=b'[]'): self.body = body
    def __enter__(self): return self
    def __exit__(self, *a): return False
    def read(self, count):
        part = self.body[:count]; self.body = self.body[count:]; return part
    read1 = read

class TransportTests(unittest.TestCase):
    def test_get_no_private_upload(self):
        calls = []
        def intercept(opener, request, **kwargs):
            calls.append(request)
            return Response()
        with patch.object(urllib.request.OpenerDirector, 'open', intercept), patch.object(socket.socket, 'connect', side_effect=AssertionError('network')):
            w.fetch('https://nodejs.org/dist/index.json', 1024, '"SYNTHETIC"')
        req = calls[0]
        self.assertEqual(req.get_method(), 'GET'); self.assertIsNone(req.data)
        self.assertTrue({k.lower() for k in req.headers} <= {'user-agent', 'accept', 'if-none-match'})
        public = req.full_url + str(req.headers)
        for secret in ['9001.0.0', '/home/', 'SYNTHETIC_inventory', 'localhost', 'software-watcher-smoke']:
            self.assertNotIn(secret, public)
    def test_byte_cap_and_encoded_refusal(self):
        with patch.object(urllib.request.OpenerDirector, 'open', return_value=Response(b'x'*20)):
            with self.assertRaises(w.SchemaError): w.fetch('https://nodejs.org/dist/index.json', 10)
        response = Response(); response.headers = {'Content-Encoding': 'gzip'}
        with patch.object(urllib.request.OpenerDirector, 'open', return_value=response):
            with self.assertRaises(w.SchemaError): w.fetch('https://nodejs.org/dist/index.json', 10)
    def test_304_transport(self):
        with patch.object(urllib.request.OpenerDirector, 'open', side_effect=urllib.error.HTTPError('https://nodejs.org/', 304, 'unchanged', {}, None)):
            self.assertEqual(w.fetch('https://nodejs.org/dist/index.json', 10, '"SYNTHETIC"'), (b'', '"SYNTHETIC"', 304))
    def test_ast_safety(self):
        tree = ast.parse(Path(w.__file__).read_text())
        forbidden = {'subprocess', 'pickle', 'http.server', 'socketserver'}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import): self.assertFalse({alias.name for alias in node.names} & forbidden)
            if isinstance(node, ast.ImportFrom): self.assertNotIn(node.module, forbidden)
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name): self.assertNotIn(node.func.id, {'eval', 'exec', 'compile'})
                if isinstance(node.func, ast.Attribute): self.assertNotIn(node.func.attr, {'bind', 'listen', 'start_server', 'system', 'socket'})
    def test_bad_etag_not_sent(self):
        def intercept(opener, req, **kw):
            self.assertNotIn('If-none-match', req.headers); return Response()
        with patch.object(urllib.request.OpenerDirector, 'open', intercept):
            w.fetch('https://nodejs.org/dist/index.json', 100, 'bad\r\nheader')
