"""Owner-server SMTP TLS/auth check; never sends mail or prints credentials.

Run with sudo on the deployment host. Passwords stay in memory on that host.
"""
import json
import argparse
from contextlib import closing
import smtplib
import sqlite3
import ssl
from pathlib import Path

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--database', type=Path, required=True)
parser.add_argument('--account-id', required=True)
args = parser.parse_args()
with closing(sqlite3.connect(args.database.resolve().as_uri() + '?mode=ro', uri=True)) as db:
    row = db.execute('SELECT config,password FROM runtime_accounts WHERE id=?', (args.account_id,)).fetchone()
if row is None:
    raise SystemExit('Unknown account ID')
settings = [{'id': args.account_id, 'config': json.loads(row[0]), 'password': row[1]}]
failed = False
for account in settings:
    config = account['config']
    print(json.dumps({'account_id': account['id'], **{
        key: config[key] for key in ('smtp_host', 'smtp_port', 'smtp_security', 'smtp_enabled')
    }}), flush=True)
    try:
        password = account['password']
        context = ssl.create_default_context()
        if config['smtp_security'] == 'tls':
            connection = smtplib.SMTP_SSL(config['smtp_host'], config['smtp_port'], timeout=20, context=context)
        else:
            connection = smtplib.SMTP(config['smtp_host'], config['smtp_port'], timeout=20)
            connection.ehlo()
            connection.starttls(context=context)
        with connection:
            connection.ehlo()
            connection.login(config['username'], password)
            print(json.dumps({'account_id': account['id'], 'tls_auth': 'ok', 'mail_sent': False}), flush=True)
    except Exception as error:
        failed = True
        # Server responses can contain personal data; emit only the exception type.
        print(json.dumps({'account_id': account['id'], 'tls_auth': 'failed', 'error_type': type(error).__name__}), flush=True)
raise SystemExit(1 if failed else 0)
