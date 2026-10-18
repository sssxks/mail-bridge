"""Open the desktop client's supported OAuth flow with explicit send scope.

Uses an invocation-only server definition, not another persistent MCP server.
The owner enters their password only in the real provider browser page.
CLI authorization URLs stay in a Git-excluded local log.
"""
import os
from pathlib import Path
import subprocess

root = Path(__file__).resolve().parent.parent
folder = root / '.research' / 'send-authorization'
folder.mkdir(parents=True, exist_ok=True)
bins = Path(os.environ['LOCALAPPDATA']) / 'OpenAI' / 'Codex' / 'bin'
candidates = list(bins.glob('*/codex.exe'))
if not candidates:
    raise SystemExit('Desktop Codex executable not found')
binary = max(candidates, key=lambda p: p.stat().st_mtime)
args = [str(binary), '-c',
        'mcp_servers.mail-bridge.url="https://mail.example.com/mcp"',
        'mcp', 'login', 'mail-bridge', '--oauth-client-registration', 'dcr',
        '--scopes', 'mail:read,mail:send']
print('Starting browser OAuth for mail-bridge: mail:read mail:send', flush=True)
with (folder / 'private-cli-output.txt').open('w', encoding='utf-8') as log:
    result = subprocess.run(args, stdout=log, stderr=subprocess.STDOUT)
print(f'OAuth client exited: {result.returncode}', flush=True)
raise SystemExit(result.returncode)
