#!/usr/bin/env python3
"""Offline, one-time import of old account files into the sole runtime store.

Run on the owner host after stopping the service and backing up all private state.
Never prints credentials. It preserves account IDs and SMTP policy; no login/send.
"""
import argparse
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess

ID = re.compile(r"[a-z0-9_-]{1,32}\Z")
FIELDS = {"username", "from_address", "imap_host", "imap_port", "imap_security",
          "smtp_host", "smtp_port", "smtp_security", "smtp_enabled"}


def import_accounts(config_path: Path, password_dir: Path, database: Path, owner_file: Path):
    if not database.is_file() or database.is_symlink():
        raise ValueError("Existing private database required")
    if config_path.is_symlink() or password_dir.is_symlink() or owner_file.is_symlink():
        raise ValueError("Symlinked migration sources are unsupported")
    if config_path.stat().st_size > 32768:
        raise ValueError("Configuration too large")
    source = json.loads(config_path.read_text(encoding="utf-8"))
    if set(source) != {"accounts"} or not 1 <= len(source["accounts"]) <= 8:
        raise ValueError("Expected 1-8 explicit accounts")
    owner = owner_file.read_text(encoding="utf-8").rstrip("\r\n")
    rows, ids, files = [], set(), set()
    for account in source["accounts"]:
        if set(account) != {"id", "name", "password_file", "config"}:
            raise ValueError("Unexpected account fields")
        account_id, filename = account["id"], account["password_file"]
        if not ID.fullmatch(account_id) or not ID.fullmatch(filename) or account_id in ids or filename in files:
            raise ValueError("Invalid or duplicate account identity")
        ids.add(account_id); files.add(filename)
        name, config = account["name"], dict(account["config"])
        if not isinstance(name, str) or not name.strip() or len(name) > 80 or any(c in name for c in "\r\n\0"):
            raise ValueError("Invalid display name")
        config.setdefault("smtp_enabled", False)
        if set(config) != FIELDS or type(config["smtp_enabled"]) is not bool:
            raise ValueError("Invalid configuration fields")
        for key in ("username", "from_address", "imap_host", "smtp_host"):
            value = config[key]
            if not isinstance(value, str) or not value.strip() or len(value) > 254 or any(c in value for c in "\r\n\0"):
                raise ValueError("Invalid account setting")
        if "@" not in config["from_address"]:
            raise ValueError("Invalid sender address")
        for protocol in ("imap", "smtp"):
            host, port = config[protocol + "_host"], config[protocol + "_port"]
            if len(host) > 253 or any(not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", part) for part in host.split(".")):
                raise ValueError("Invalid mail hostname")
            if type(port) is not int or not 1 <= port <= 65535 or config[protocol + "_security"] not in ("tls", "starttls"):
                raise ValueError("Invalid TLS settings")
        credential = password_dir / filename
        if credential.is_symlink() or not credential.is_file() or credential.stat().st_size > 1026:
            raise ValueError("Credential missing or invalid")
        password = credential.read_text(encoding="utf-8").rstrip("\r\n")
        if not password or len(password.encode()) > 1024 or any(c in password for c in "\r\n\0") or password == owner:
            raise ValueError("Invalid or reused credential")
        rows.append((account_id, name, json.dumps(config, separators=(",", ":")), password))
    if os.name == "posix":
        os.chmod(database.parent, 0o700)
        os.chmod(database, 0o600)
    db = sqlite3.connect(database)
    try:
        db.execute("PRAGMA synchronous=FULL")
        db.execute("BEGIN IMMEDIATE")
        db.execute("CREATE TABLE IF NOT EXISTS runtime_accounts(id TEXT PRIMARY KEY,name TEXT NOT NULL,config TEXT NOT NULL,password TEXT NOT NULL)")
        # Idempotent import accepts exact matches, never overwrites an existing account.
        for row in rows:
            old = db.execute("SELECT id,name,config,password FROM runtime_accounts WHERE id=?", (row[0],)).fetchone()
            if old is not None:
                if old[:2] != row[:2] or json.loads(old[2]) != json.loads(row[2]) or old[3] != row[3]:
                    raise ValueError("Existing account differs; refusing to overwrite")
            else:
                db.execute("INSERT INTO runtime_accounts VALUES (?,?,?,?)", row)
        if db.execute("SELECT count(*) FROM runtime_accounts").fetchone()[0] > 8:
            raise ValueError("Account limit exceeded")
        db.commit()
        return sorted(ids)
    except BaseException:
        db.rollback()
        raise
    finally:
        db.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("config", "password-dir", "database", "owner-file"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--service", default="mail-bridge-rust.service")
    args = parser.parse_args()
    state = subprocess.run(["systemctl", "show", args.service, "-p", "ActiveState", "--value"], capture_output=True, text=True)
    if state.returncode or state.stdout.strip() not in ("inactive", "failed"):
        raise SystemExit("Stop the service and take a private backup before importing")
    try:
        ids = import_accounts(args.config, args.password_dir, args.database, args.owner_file)
    except Exception:
        raise SystemExit("Import failed; private details suppressed. Restore the backup before restarting if needed.") from None
    print(json.dumps({"imported_account_ids": ids, "smtp_policy_preserved": True, "mailbox_opened": False, "email_sent": False}))


if __name__ == "__main__":
    main()
