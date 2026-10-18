"""Verify an upgrade on the host; private state and tokens never leave it."""
import hashlib
import json
import secrets
import sqlite3
import sys
import time
import urllib.error
import urllib.request

database, backup, origin = sys.argv[1:]
db = sqlite3.connect(database)
old = sqlite3.connect(f'file:{backup}?mode=ro', uri=True)
for table in ('runtime_accounts', 'clients', 'codes', 'tokens', 'attempts', 'account_attempts'):
    assert sorted(db.execute(f'SELECT * FROM {table}').fetchall()) == sorted(old.execute(f'SELECT * FROM {table}').fetchall()), f'{table} changed'
print('Account, OAuth and send records preserved')
token = secrets.token_urlsafe(32)
digest = hashlib.sha256(token.encode()).hexdigest()
db.execute('INSERT INTO tokens VALUES (?,?,?,?,?,?)', (digest, 'access', 'deployment-check', origin + '/mcp', 'mail:read', int(time.time()) + 120))
db.commit()

def rpc(method, params):
    params['_meta'] = {'io.modelcontextprotocol/protocolVersion': '2026-07-28', 'io.modelcontextprotocol/clientCapabilities': {}, 'io.modelcontextprotocol/clientInfo': {'name': 'deployment-check', 'version': '1'}}
    request = urllib.request.Request(origin + '/mcp', data=json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params}).encode(), headers={'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json', 'Accept': 'application/json, text/event-stream', 'Mcp-Method': method, 'MCP-Protocol-Version': '2026-07-28'})
    with urllib.request.urlopen(request, timeout=15) as response:
        value = json.load(response)
    assert 'error' not in value, 'RPC failed: ' + method
    return value['result']

try:
    assert rpc('server/discover', {})['capabilities']['events'] == {}
    catalog = rpc('tools/list', {})['tools']
    assert len(catalog) == 8
    assert not {'account_setup_status', 'configuration_status'} & {tool['name'] for tool in catalog}
    send = next(tool for tool in catalog if tool['name'] == 'send_email')
    assert 'confirm_send' not in send['inputSchema']['properties']
    events = rpc('events/list', {})['events']
    assert events[0]['name'] == 'message.created'
    assert events[0]['_meta']['securitySchemes'][0]['scopes'] == ['mail:read']
    accounts = rpc('tools/call', {'name': 'list_accounts', 'arguments': {}})
    assert not accounts.get('isError')
    count = json.loads(accounts['content'][0]['text'])['account_count']
    print(json.dumps({'events_enabled': True, 'tool_count': 8, 'event_scope': 'mail:read', 'account_count': count}))
finally:
    db.execute('DELETE FROM tokens WHERE hash=?', (digest,))
    db.commit()
    db.close()
    old.close()
