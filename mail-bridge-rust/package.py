"""Package reviewed source/deployment files only; exclude secrets and build output."""
from pathlib import Path
import zipfile
import hashlib
import tomllib

root = Path(__file__).resolve().parent
files = [
    'Cargo.toml', 'Cargo.lock', 'README.md', 'TEST-RESULTS.txt',
    'Dockerfile', 'Dockerfile.runtime', 'compose.example.yaml', '.dockerignore',
    '.gitignore', 'package.py', 'deploy/mail-bridge-rust.service',
    'deploy/service.env.example', 'deploy/nginx-location.example.conf',
    'deploy/migrate-accounts.py', 'deploy/verify-account-migration.py', 'deploy/SETUP.md', 'deploy/DEPLOYMENT.md',
    'src/accounts.rs', 'src/account_setup.rs', 'src/account_setup.html', 'tests/account_setup.rs',
    'src/main.rs', 'src/lib.rs', 'src/config.rs', 'src/db.rs', 'src/bounded_io.rs',
    'src/mail.rs', 'src/auth.rs', 'src/mcp.rs', 'src/http.rs', 'tests/core.rs', 'tests/events.rs', 'src/events.rs', 'src/webhook.rs', 'EVENTS.md',
]
version = tomllib.loads((root / 'Cargo.toml').read_text())['package']['version']
archive = root.parent / 'releases' / f'mail-bridge-rust-http-{version}.zip'
archive.parent.mkdir(parents=True, exist_ok=True)
with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED) as output:
    for name in files:
        output.write(root / name, 'mail-bridge-rust/' + name)
with zipfile.ZipFile(archive) as check:
    assert check.testzip() is None
    assert check.namelist() == ['mail-bridge-rust/' + name for name in files]
print(archive.name, archive.stat().st_size)
print('SHA256', hashlib.sha256(archive.read_bytes()).hexdigest())
