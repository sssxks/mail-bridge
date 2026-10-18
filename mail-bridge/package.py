"""Build a source/deployment ZIP using an explicit non-secret file allowlist."""
import hashlib
import zipfile
from pathlib import Path

root = Path(__file__).resolve().parent
files = [
    'server.py', 'http_server.py', 'oauth.py', 'README.md', 'requirements.lock',
    'config.example.json', 'Dockerfile', 'compose.example.yaml',
    'Caddyfile.example', '.dockerignore', '.gitignore', 'package.py',
    'tests/test_bridge.py', 'tests/test_http.py', 'tests/test_oauth.py', 'TEST-RESULTS.txt',
]
archive = root.parent / 'releases' / 'mail-bridge-http-0.1.0.zip'
archive.parent.mkdir(parents=True, exist_ok=True)
with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED) as output:
    for name in files:
        output.write(root / name, 'mail-bridge/' + name)
with zipfile.ZipFile(archive) as check:
    assert check.testzip() is None
    assert check.namelist() == ['mail-bridge/' + name for name in files]
print(archive.name)
print('SHA256: ' + hashlib.sha256(archive.read_bytes()).hexdigest())
