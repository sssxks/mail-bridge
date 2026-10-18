import base64
import hashlib
import json
import sys
import tempfile
import unittest
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from oauth import OAuth
from server import SafeError, journal_connection


class Inputs(HTMLParser):
    def __init__(self):
        super().__init__()
        self.values = {}

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == 'input' and attrs.get('type') == 'hidden':
            self.values[attrs['name']] = attrs['value']


class OAuthTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = 'https://mail.example.com'
        self.owner = 'mock-owner-password-0000000000000000'
        self.redirect = 'https://chatgpt.com/connector_platform_oauth_redirect'
        self.auth = OAuth(self.base, self.owner, Path(self.temp.name) / 'oauth.db', [self.redirect])
        self.client = self.auth.register({'redirect_uris': [self.redirect]})['client_id']
        self.verifier = 'a' * 64
        challenge = base64.urlsafe_b64encode(hashlib.sha256(self.verifier.encode()).digest()).decode().rstrip('=')
        self.params = {'client_id': self.client, 'redirect_uri': self.redirect, 'response_type': 'code', 'code_challenge': challenge, 'code_challenge_method': 'S256', 'resource': self.auth.resource, 'state': 'state-from-client', 'scope': 'mail:read'}

    def tearDown(self):
        self.temp.cleanup()

    def authorize(self):
        raw, cookie = self.auth.authorization_form(self.params)
        form = Inputs()
        form.feed(raw.decode())
        form.values['owner_password'] = self.owner
        result = self.auth.authorize(form.values, cookie.split('=', 1)[1].split(';')[0])
        parsed = parse_qs(urlsplit(result).query)
        self.assertEqual(parsed['state'], ['state-from-client'])
        self.assertEqual(parsed['iss'], [self.base])
        return parsed['code'][0]

    def exchange(self, code):
        return self.auth.exchange({'grant_type': 'authorization_code', 'client_id': self.client, 'redirect_uri': self.redirect, 'code': code, 'code_verifier': self.verifier, 'resource': self.auth.resource})

    def test_pkce_code_single_use_and_refresh_rotation(self):
        code = self.authorize()
        tokens = self.exchange(code)
        self.assertEqual(self.auth.token_scopes(tokens['access_token']), {'mail:read'})
        self.assertIsNone(self.auth.token_scopes(self.owner))
        with self.assertRaises(SafeError):
            self.exchange(code)
        params = {'grant_type': 'refresh_token', 'client_id': self.client, 'refresh_token': tokens['refresh_token'], 'resource': self.auth.resource}
        rotated = self.auth.exchange(params)
        self.assertNotEqual(rotated['refresh_token'], tokens['refresh_token'])
        with self.assertRaises(SafeError):
            self.auth.exchange(params)
        with journal_connection(self.auth.path) as db:
            stored = json.dumps(db.execute('SELECT * FROM tokens').fetchall())
        self.assertNotIn(tokens['access_token'], stored)
        self.assertNotIn(rotated['refresh_token'], stored)

    def test_redirect_resource_scope_and_pkce_validation(self):
        with self.assertRaises(SafeError):
            self.auth.register({'redirect_uris': ['https://evil.example/callback']})
        for update in ({'redirect_uri': 'https://evil.example/callback'}, {'resource': 'https://evil.example'}, {'scope': 'admin'}, {'code_challenge_method': 'plain'}):
            with self.assertRaises(SafeError):
                self.auth.authorization_form(dict(self.params, **update))
        code = self.authorize()
        original = self.verifier
        self.verifier = 'b' * 64
        with self.assertRaises(SafeError):
            self.exchange(code)
        self.verifier = original
        self.assertIn('access_token', self.exchange(code))

    def test_owner_consent_and_form_tampering(self):
        for change in ({'owner_password': 'wrong'}, {'scope': 'mail:send'}):
            raw, cookie = self.auth.authorization_form(self.params)
            form = Inputs()
            form.feed(raw.decode())
            form.values['owner_password'] = self.owner
            form.values.update(change)
            with self.assertRaises(SafeError):
                self.auth.authorize(form.values, cookie.split('=', 1)[1].split(';')[0])


if __name__ == '__main__':
    unittest.main()
