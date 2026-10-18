"""Offline migration regression; synthetic credentials only, no network."""
import importlib.util
from contextlib import closing
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("migration", ROOT / "mail-bridge-rust/deploy/migrate-accounts.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
VERIFY_SPEC = importlib.util.spec_from_file_location("verification", ROOT / "mail-bridge-rust/deploy/verify-account-migration.py")
VERIFICATION = importlib.util.module_from_spec(VERIFY_SPEC)
VERIFY_SPEC.loader.exec_module(VERIFICATION)


class MigrationTests(unittest.TestCase):
    def setUp(self):
        folder = ROOT / ".research/migration-tests"
        folder.mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=folder)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.db = self.root / "state.sqlite3"
        with closing(sqlite3.connect(self.db)) as db:
            db.execute("CREATE TABLE account_attempts(account_id TEXT,id TEXT,status TEXT)")
            db.execute("INSERT INTO account_attempts VALUES ('qq','existing-request','accepted_by_smtp')")
            db.execute("CREATE TABLE tokens(hash TEXT)")
            db.execute("INSERT INTO tokens VALUES ('synthetic-existing-token-hash')")
            db.commit()
        self.before = self.root / "before.sqlite3"
        with closing(sqlite3.connect(self.db)) as source, closing(sqlite3.connect(self.before)) as target:
            source.backup(target)
        self.config = {"accounts": []}
        for account_id in ("qq", "zju"):
            config = {"username": f"{account_id}@example.com", "from_address": f"{account_id}@example.com",
                      "imap_host": "imap.example.com", "imap_port": 993, "imap_security": "tls",
                      "smtp_host": "smtp.example.com", "smtp_port": 465, "smtp_security": "tls", "smtp_enabled": account_id == "qq"}
            self.config["accounts"].append({"id": account_id, "name": account_id, "password_file": account_id, "config": config})
            (self.root / account_id).write_text(f"synthetic-{account_id}-credential", encoding="utf-8")
        self.owner = self.root / "owner"
        self.owner.write_text("synthetic-owner-password-000000000000", encoding="utf-8")
        self.source = self.root / "legacy.json"

    def migrate(self):
        self.source.write_text(json.dumps(self.config), encoding="utf-8")
        return MODULE.import_accounts(self.source, self.root, self.db, self.owner)

    def test_preserves_credentials_policy_and_unrelated_state_idempotently(self):
        self.assertEqual(self.migrate(), ["qq", "zju"])
        self.assertEqual(self.migrate(), ["qq", "zju"])
        self.assertTrue(VERIFICATION.verify(self.before, self.db, self.source, self.root)["original_oauth_events_and_send_tables_unchanged"])
        with closing(sqlite3.connect(self.db)) as db:
            rows = db.execute("SELECT id,config,password FROM runtime_accounts ORDER BY id").fetchall()
            self.assertEqual(len(rows), 2)
            self.assertTrue(json.loads(rows[0][1])["smtp_enabled"])
            self.assertFalse(json.loads(rows[1][1])["smtp_enabled"])
            self.assertEqual(rows[0][2], "synthetic-qq-credential")
            self.assertEqual(db.execute("SELECT * FROM tokens").fetchall(), [("synthetic-existing-token-hash",)])
            self.assertEqual(db.execute("SELECT status FROM account_attempts").fetchall(), [("accepted_by_smtp",)])

    def test_verification_rejects_changed_private_state(self):
        self.migrate()
        with closing(sqlite3.connect(self.db)) as db:
            db.execute("DELETE FROM tokens")
            db.commit()
        with self.assertRaises(ValueError):
            VERIFICATION.verify(self.before, self.db, self.source, self.root)

    def test_conflict_rolls_back_the_whole_import(self):
        self.migrate()
        self.config["accounts"][0]["id"] = "new"
        self.config["accounts"][1]["name"] = "conflicting-name"
        with self.assertRaises(ValueError):
            self.migrate()
        with closing(sqlite3.connect(self.db)) as db:
            self.assertEqual(db.execute("SELECT id FROM runtime_accounts ORDER BY id").fetchall(), [("qq",), ("zju",)])

    def test_missing_credential_duplicate_and_path_traversal_fail(self):
        for mutation in ("missing", "duplicate", "traversal"):
            original = json.loads(json.dumps(self.config))
            if mutation == "missing":
                self.config["accounts"][1]["password_file"] = "absent"
            elif mutation == "duplicate":
                self.config["accounts"][1]["id"] = "qq"
            else:
                self.config["accounts"][1]["password_file"] = "../owner"
            with self.assertRaises(ValueError):
                self.migrate()
            self.config = original


if __name__ == "__main__":
    unittest.main()
