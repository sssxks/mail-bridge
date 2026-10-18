import http.client
import json
import sys
import threading
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import http_server
from http.server import ThreadingHTTPServer
from oauth import OAuth


class HttpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.token = patch.object(http_server, 'TOKEN', 'mock-token-for-tests-00000000000000')
        cls.token.start()
        cls.server = ThreadingHTTPServer(('127.0.0.1', 0), http_server.Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()
        cls.token.stop()

    def request(self, method='POST', payload=None, **extra):
        headers = {'Authorization': 'Bearer mock-token-for-tests-00000000000000', 'Content-Type': 'application/json', 'Accept': 'application/json, text/event-stream'}
        headers.update(extra)
        connection = http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=5)
        connection.request(method, '/mcp', json.dumps(payload) if payload is not None else None, headers)
        response = connection.getresponse()
        status, body = response.status, response.read()
        connection.close()
        return status, json.loads(body) if body else None

    def test_auth_origin_and_accept(self):
        self.assertEqual(self.request(payload={}, Authorization='Bearer wrong')[0], 401)
        self.assertEqual(self.request(payload={}, Origin='https://evil.example')[0], 403)
        self.assertEqual(self.request(payload={}, Accept='text/html')[0], 406)
        self.assertEqual(self.request('GET')[0], 405)

    def test_mcp_lifecycle_and_tool(self):
        status, response = self.request(payload={'jsonrpc': '2.0', 'id': 1, 'method': 'initialize', 'params': {'protocolVersion': '2025-06-18'}})
        self.assertEqual(status, 200)
        self.assertEqual(response['result']['protocolVersion'], '2025-06-18')
        self.assertEqual(self.request(payload={'jsonrpc': '2.0', 'method': 'notifications/initialized'})[0], 202)
        _, response = self.request(payload={'jsonrpc': '2.0', 'id': 2, 'method': 'tools/list'})
        self.assertEqual(len(response['result']['tools']), 7)
        _, response = self.request(payload={'jsonrpc': '2.0', 'id': 3, 'method': 'tools/call', 'params': {'name': 'prepare_draft', 'arguments': {'to': ['x@example.com'], 'subject': 's', 'body': 'b'}}})
        self.assertFalse(response['result']['isError'])
        _, response = self.request(payload={'jsonrpc': '2.0', 'id': 4, 'method': 'server/discover'})
        self.assertEqual(response['result']['supportedVersions'], ['2026-07-28'])

    def test_oauth_metadata_and_scope_gate(self):
        with tempfile.TemporaryDirectory() as directory:
            auth = OAuth('https://mail.example.com', 'mock-owner-000000000000000000000000', Path(directory) / 'oauth.db', ['https://chatgpt.com/connector_platform_oauth_redirect'])
            with patch.object(http_server, 'OAUTH', auth), patch.object(auth, 'token_scopes', return_value={'mail:read'}):
                connection = http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=5)
                connection.request('GET', '/.well-known/oauth-protected-resource')
                response = connection.getresponse()
                self.assertEqual(response.status, 200)
                self.assertEqual(json.loads(response.read())['resource'], auth.resource)
                connection.close()
                _, listed = self.request(payload={'jsonrpc': '2.0', 'id': 1, 'method': 'tools/list'})
                send = next(t for t in listed['result']['tools'] if t['name'] == 'send_email')
                self.assertEqual(send['securitySchemes'][0]['scopes'], ['mail:send'])
                _, response = self.request(payload={'jsonrpc': '2.0', 'id': 2, 'method': 'tools/call', 'params': {'name': 'send_email', 'arguments': {}}})
                self.assertTrue(response['result']['isError'])
                self.assertIn('mcp/www_authenticate', response['result']['_meta'])


if __name__ == '__main__':
    unittest.main()
