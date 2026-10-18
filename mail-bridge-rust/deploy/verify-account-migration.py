#!/usr/bin/env python3
"""Verify an offline import without printing private rows or credentials."""
from contextlib import closing
import json
from pathlib import Path
import sqlite3
import sys


def verify(before: Path, after: Path, config: Path, passwords: Path):
    with closing(sqlite3.connect(before.as_uri() + "?mode=ro", uri=True)) as old, closing(sqlite3.connect(after.as_uri() + "?mode=ro", uri=True)) as new:
        tables = [r[0] for r in old.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")]
        for table in tables:
            if table == "runtime_accounts":
                continue
            # Table names come from the trusted original schema, still quote identifiers.
            query = 'SELECT * FROM "' + table.replace('"', '""') + '"'
            if sorted(old.execute(query).fetchall(), key=repr) != sorted(new.execute(query).fetchall(), key=repr):
                raise ValueError("Original private state changed")
        expected = json.loads(config.read_text(encoding="utf-8"))["accounts"]
        actual = {row[0]: row for row in new.execute("SELECT id,name,config,password FROM runtime_accounts")}
        if set(actual) != {a["id"] for a in expected}:
            raise ValueError("Account inventory changed")
        for account in expected:
            row = actual[account["id"]]
            source_config = dict(account["config"])
            source_config.setdefault("smtp_enabled", False)
            if row[1] != account["name"] or json.loads(row[2]) != source_config or row[3] != (passwords / account["password_file"]).read_text(encoding="utf-8").rstrip("\r\n"):
                raise ValueError("Account data changed")
        return {"account_ids": sorted(actual), "account_fields_and_credentials_match": True,
                "original_oauth_events_and_send_tables_unchanged": True,
                "original_tables_checked": len(tables)}


if __name__ == "__main__":
    try:
        result = verify(*(Path(arg).resolve() for arg in sys.argv[1:]))
    except Exception:
        raise SystemExit("Migration verification failed; private details suppressed") from None
    print(json.dumps(result))
