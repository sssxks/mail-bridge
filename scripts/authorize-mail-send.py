"""Open the Codex client's supported OAuth flow with explicit send scope.

Uses an invocation-only server definition, not another persistent MCP server.
The owner enters their password only in the real provider browser page.
CLI authorization URLs stay in a Git-excluded local log.

Usage: uv run scripts/authorize-mail-send.py --server-url https://mail.example.com/mcp
Use --codex PATH when the executable is not on PATH or in the Windows desktop app.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--server-url', required=True, help='Public HTTPS MCP endpoint')
parser.add_argument('--codex', help='Codex executable; defaults to PATH or the Windows desktop app')
options = parser.parse_args()
binary = options.codex or shutil.which('codex')
if not binary and (local_app_data := os.environ.get('LOCALAPPDATA')):
    bins = Path(local_app_data) / 'OpenAI' / 'Codex' / 'bin'
    candidates = list(bins.glob('*/codex.exe'))
    if candidates:
        binary = str(max(candidates, key=lambda p: p.stat().st_mtime))
if not binary:
    parser.error('Codex executable not found; install it on PATH or supply --codex PATH')

root = Path(__file__).resolve().parent.parent
folder = root / '.research' / 'send-authorization'
folder.mkdir(parents=True, exist_ok=True)
args = [str(binary), '-c',
        'mcp_servers.mail-bridge.url=' + json.dumps(options.server_url),
        'mcp', 'login', 'mail-bridge', '--oauth-client-registration', 'dcr',
        '--scopes', 'mail:read,mail:send']
print('Starting browser OAuth for mail-bridge: mail:read mail:send', flush=True)
with (folder / 'private-cli-output.txt').open('w', encoding='utf-8') as log:
    result = subprocess.run(args, stdout=log, stderr=subprocess.STDOUT)
print(f'OAuth client exited: {result.returncode}', flush=True)
raise SystemExit(result.returncode)
