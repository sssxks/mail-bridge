"""Owner-server SMTP TLS/auth check; never sends mail or prints credentials.

Run with sudo on the deployment host. Passwords stay in memory on that host.
"""
import json
import smtplib
import ssl
from pathlib import Path

root = Path('/etc/mail-bridge-rust')
settings = json.loads((root / 'config.json').read_text())
failed = False
for account in settings['accounts']:
    config = account['config']
    print(json.dumps({'account_id': account['id'], **{
        key: config[key] for key in ('smtp_host', 'smtp_port', 'smtp_security', 'smtp_enabled')
    }}), flush=True)
    try:
        credential = root / 'mailboxes' / account['password_file']
        password = credential.read_text().strip()
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
