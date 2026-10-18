"""Single-owner OAuth authorization-code + S256 PKCE for remote MCP clients.

Opaque bearer tokens are stored only as hashes with expiry, resource and scope.
No provider calls, arbitrary redirect fetches, or password grant are supported.
"""
import base64
import hashlib
import hmac
import html
import json
import os
import re
import secrets
import time
from pathlib import Path
from urllib.parse import urlsplit, urlencode, parse_qs
from server import journal_connection, SafeError

SCOPES = {'mail:read', 'mail:send'}


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


class OAuth:
    def __init__(self, base, owner_password, db_path=None, redirects=None):
        parsed = urlsplit(base)
        if parsed.scheme != 'https' or not parsed.netloc or parsed.path not in ('', '/') or parsed.query or parsed.fragment or parsed.username:
            raise ValueError('MAIL_BRIDGE_PUBLIC_URL must be an HTTPS origin without a path')
        self.base = base.rstrip('/')
        self.resource = self.base + '/mcp'
        self.owner_password = owner_password
        self.path = db_path or Path(os.environ.get('LOCALAPPDATA', str(Path.home() / '.local/share'))) / 'mail-bridge' / 'oauth.sqlite3'
        self.redirects = redirects or json.loads(os.environ.get('MAIL_BRIDGE_OAUTH_REDIRECT_URIS', '["https://chatgpt.com/connector_platform_oauth_redirect"]'))
        if not isinstance(self.redirects, list) or not self.redirects or any(not isinstance(uri, str) or not uri.startswith('https://') or urlsplit(uri).fragment or urlsplit(uri).username for uri in self.redirects):
            raise ValueError('Configure exact HTTPS OAuth redirect URI allowlist')
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        with journal_connection(self.path) as db:
            db.execute('CREATE TABLE IF NOT EXISTS clients (id TEXT PRIMARY KEY, redirects TEXT)')
            db.execute('CREATE TABLE IF NOT EXISTS codes (hash TEXT PRIMARY KEY, client TEXT, redirect TEXT, challenge TEXT, resource TEXT, scope TEXT, expires INTEGER)')
            db.execute('CREATE TABLE IF NOT EXISTS tokens (hash TEXT PRIMARY KEY, kind TEXT, client TEXT, resource TEXT, scope TEXT, expires INTEGER)')

    def metadata(self, resource=False):
        if resource:
            return {'resource': self.resource, 'authorization_servers': [self.base], 'scopes_supported': sorted(SCOPES)}
        return {'issuer': self.base, 'authorization_endpoint': self.base + '/oauth/authorize', 'token_endpoint': self.base + '/oauth/token', 'registration_endpoint': self.base + '/oauth/register', 'response_types_supported': ['code'], 'grant_types_supported': ['authorization_code', 'refresh_token'], 'token_endpoint_auth_methods_supported': ['none'], 'code_challenge_methods_supported': ['S256'], 'scopes_supported': sorted(SCOPES), 'authorization_response_iss_parameter_supported': True}

    def challenge(self, scope='mail:read'):
        return f'Bearer resource_metadata="{self.base}/.well-known/oauth-protected-resource", scope="{scope}"'

    def register(self, data):
        redirects = data.get('redirect_uris')
        if not isinstance(redirects, list) or not redirects or len(redirects) > 5 or any(uri not in self.redirects for uri in redirects):
            raise SafeError('invalid_redirect_uri')
        if data.get('token_endpoint_auth_method', 'none') != 'none':
            raise SafeError('invalid_client_metadata')
        client = secrets.token_urlsafe(32)
        with journal_connection(self.path) as db:
            if db.execute('SELECT count(*) FROM clients').fetchone()[0] >= 1000:
                raise SafeError('registration_limit_reached')
            db.execute('INSERT INTO clients VALUES (?,?)', (client, json.dumps(redirects)))
        return {'client_id': client, 'redirect_uris': redirects, 'token_endpoint_auth_method': 'none', 'grant_types': ['authorization_code', 'refresh_token'], 'response_types': ['code']}

    def validate_authorization(self, params):
        required = ('client_id', 'redirect_uri', 'response_type', 'code_challenge', 'code_challenge_method', 'resource', 'state')
        if any(not isinstance(params.get(key), str) or not 0 < len(params[key]) <= 2048 for key in required):
            raise SafeError('invalid_request')
        with journal_connection(self.path) as db:
            row = db.execute('SELECT redirects FROM clients WHERE id=?', (params['client_id'],)).fetchone()
        if not row or params['redirect_uri'] not in json.loads(row[0]) or params['redirect_uri'] not in self.redirects:
            raise SafeError('invalid_redirect_uri')
        if params['response_type'] != 'code' or params['code_challenge_method'] != 'S256' or not re.fullmatch(r'[A-Za-z0-9_-]{43}', params['code_challenge']):
            raise SafeError('invalid_request')
        if params['resource'] != self.resource:
            raise SafeError('invalid_target')
        scope = params.get('scope', 'mail:read')
        if not isinstance(scope, str) or not set(scope.split()) or not set(scope.split()) <= SCOPES:
            raise SafeError('invalid_scope')
        return {key: params[key] for key in required} | {'scope': ' '.join(sorted(set(scope.split())))}

    def form_signature(self, params):
        value = json.dumps(params, sort_keys=True, separators=(',', ':')).encode()
        return hmac.new(self.owner_password.encode(), value, hashlib.sha256).hexdigest()

    def authorization_form(self, params):
        params = self.validate_authorization(params)
        params['_csrf'] = secrets.token_urlsafe(32)
        params['_time'] = str(int(time.time()))
        params['_sig'] = self.form_signature(params)
        inputs = ''.join(f'<input type="hidden" name="{html.escape(key, quote=True)}" value="{html.escape(value, quote=True)}">' for key, value in params.items())
        page = '<!doctype html><meta charset="utf-8"><title>Mail Bridge authorization</title><h1>Authorize Mail Bridge</h1><p>Only the mailbox owner may authorize this connection.</p><p>Requested access: ' + html.escape(params['scope']) + '</p><p>Client callback: ' + html.escape(params['redirect_uri']) + '</p><p>Enter the independent service owner password. Never enter your mailbox authorization code here.</p><form method="post" action="/oauth/authorize">' + inputs + '<input type="password" name="owner_password" required autocomplete="off"><button type="submit">Authorize this client</button></form>'
        return page.encode(), '__Host-mail-bridge=' + params['_csrf'] + '; Secure; HttpOnly; SameSite=Lax; Path=/'

    def authorize(self, params, csrf_cookie):
        password = params.pop('owner_password', '')
        signature = params.pop('_sig', '')
        if not hmac.compare_digest(signature, self.form_signature(params)) or not hmac.compare_digest(params.get('_csrf', ''), csrf_cookie) or not 0 <= int(time.time()) - int(params.get('_time', '0')) <= 300:
            raise SafeError('invalid_request')
        if not hmac.compare_digest(password, self.owner_password):
            raise SafeError('access_denied')
        checked = self.validate_authorization(params)
        code = secrets.token_urlsafe(32)
        with journal_connection(self.path) as db:
            db.execute('DELETE FROM codes WHERE expires < ?', (int(time.time()),))
            db.execute('INSERT INTO codes VALUES (?,?,?,?,?,?,?)', (digest(code), checked['client_id'], checked['redirect_uri'], checked['code_challenge'], checked['resource'], checked['scope'], int(time.time())+120))
        return checked['redirect_uri'] + ('&' if '?' in checked['redirect_uri'] else '?') + urlencode({'code': code, 'state': checked['state'], 'iss': self.base})

    def exchange(self, params):
        if params.get('resource') != self.resource:
            raise SafeError('invalid_target')
        now = int(time.time())
        client = params.get('client_id', '')
        with journal_connection(self.path) as db:
            db.execute('BEGIN IMMEDIATE')
            if params.get('grant_type') == 'authorization_code':
                row = db.execute('SELECT client,redirect,challenge,resource,scope,expires FROM codes WHERE hash=?', (digest(params.get('code', '')),)).fetchone()
                verifier = params.get('code_verifier', '')
                if not re.fullmatch(r'[A-Za-z0-9._~-]{43,128}', verifier):
                    raise SafeError('invalid_grant')
                challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip('=')
                if not row or row[0] != client or row[1] != params.get('redirect_uri') or not hmac.compare_digest(row[2], challenge) or row[3] != self.resource or row[5] <= now:
                    raise SafeError('invalid_grant')
                scope = row[4]
                db.execute('DELETE FROM codes WHERE hash=?', (digest(params['code']),))
            elif params.get('grant_type') == 'refresh_token':
                row = db.execute('SELECT client,resource,scope,expires FROM tokens WHERE hash=? AND kind=?', (digest(params.get('refresh_token', '')), 'refresh')).fetchone()
                if not row or row[0] != client or row[1] != self.resource or row[3] <= now:
                    raise SafeError('invalid_grant')
                scope = row[2]
                db.execute('DELETE FROM tokens WHERE hash=?', (digest(params['refresh_token']),))
            else:
                raise SafeError('unsupported_grant_type')
            access, refresh = secrets.token_urlsafe(48), secrets.token_urlsafe(48)
            db.execute('DELETE FROM tokens WHERE expires < ?', (now,))
            db.execute('INSERT INTO tokens VALUES (?,?,?,?,?,?)', (digest(access), 'access', client, self.resource, scope, now+3600))
            db.execute('INSERT INTO tokens VALUES (?,?,?,?,?,?)', (digest(refresh), 'refresh', client, self.resource, scope, now+30*86400))
        return {'access_token': access, 'token_type': 'Bearer', 'expires_in': 3600, 'refresh_token': refresh, 'scope': scope}

    def token_scopes(self, token):
        with journal_connection(self.path) as db:
            row = db.execute('SELECT resource,scope,expires FROM tokens WHERE hash=? AND kind=?', (digest(token), 'access')).fetchone()
        if not row or row[0] != self.resource or row[2] <= time.time():
            return None
        return set(row[1].split())


def form_values(raw):
    values = parse_qs(raw, keep_blank_values=True, max_num_fields=30)
    if any(len(value) != 1 for value in values.values()):
        raise SafeError('invalid_request')
    return {key: value[0] for key, value in values.items()}
