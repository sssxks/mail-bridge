//! SQLite persistence; connections and transactions stay inside this crate.
/// Implementation of accounts within this crate.
mod accounts;
/// Implementation of events within this crate.
pub mod events;
/// Implementation of oauth within this crate.
pub mod oauth;
use mail_bridge_core::{Error, Result, safe};
use rusqlite::{Connection, OptionalExtension, params};
use sha2::{Digest, Sha256};
use std::{
    path::Path,
    sync::{Arc, Mutex},
    time::Duration,
};

/// Compute the stable lowercase SHA-256 spelling used for token and event identities.
pub fn hash(value: impl AsRef<[u8]>) -> String {
    format!("{:x}", Sha256::digest(value.as_ref()))
}
/// Read the current Unix time in seconds at the clock boundary.
pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}
/// SQLite store handle with a private connection and its filesystem location.
///
/// Semantically one shared connection plus its stable path. All SQL and transaction
/// guards remain within this crate; callers use domain-specific persistence operations.
#[derive(Clone)]
pub struct Db(Arc<Mutex<Connection>>, Arc<Path>);
impl Db {
    /// Filesystem location of this store (contains no credentials).
    pub fn path(&self) -> &Path {
        &self.1
    }

    /// Check account schema without waiting for a busy process-local connection.
    pub fn ready(&self) -> bool {
        self.0.try_lock().is_ok_and(|db| {
            db.prepare("SELECT id FROM runtime_accounts LIMIT 0")
                .and_then(|mut statement| statement.exists([]))
                .is_ok()
        })
    }

    /// Open the private SQLite store and initialize legacy-compatible account/OAuth/send tables.
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(safe)?;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
            if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
                std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))
                    .map_err(safe)?;
            }
            // Create with private permissions, including the interval before SQLite opens it.
            std::fs::OpenOptions::new()
                .create(true)
                .truncate(false)
                .read(true)
                .write(true)
                .mode(0o600)
                .open(path)
                .map_err(safe)?;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(safe)?;
        }
        let db = Connection::open(path).map_err(safe)?;
        db.busy_timeout(Duration::from_millis(100)).map_err(safe)?;
        db.execute_batch("PRAGMA synchronous=FULL; PRAGMA cache_size=-1024; PRAGMA temp_store=MEMORY;
            CREATE TABLE IF NOT EXISTS runtime_accounts(id TEXT PRIMARY KEY,name TEXT NOT NULL,config TEXT NOT NULL,password TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS clients(id TEXT PRIMARY KEY,redirects TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS codes(hash TEXT PRIMARY KEY,client TEXT,redirect TEXT,challenge TEXT,resource TEXT,scope TEXT,expires INTEGER);
            CREATE TABLE IF NOT EXISTS tokens(hash TEXT PRIMARY KEY,kind TEXT,client TEXT,resource TEXT,scope TEXT,expires INTEGER);
            CREATE TABLE IF NOT EXISTS attempts(id TEXT PRIMARY KEY,fingerprint TEXT,status TEXT,message_id TEXT);
            CREATE TABLE IF NOT EXISTS account_attempts(account_id TEXT,id TEXT,fingerprint TEXT,status TEXT,message_id TEXT,PRIMARY KEY(account_id,id));
            INSERT OR IGNORE INTO account_attempts SELECT 'default',id,fingerprint,status,message_id FROM attempts;").map_err(safe)?;
        Ok(Self(Arc::new(Mutex::new(db)), path.into()))
    }
    /// Atomically reserve a send request identity or return its previously committed outcome.
    pub fn attempt(
        &self,
        account_id: &str,
        id: &str,
        fingerprint: &str,
        message_id: &str,
    ) -> Result<Option<(String, String)>> {
        let mut db = self.0.lock().map_err(safe)?;
        let tx = db
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(safe)?;
        let row: Option<(String, String, String)> = tx
            .query_row(
                "SELECT fingerprint,status,message_id FROM account_attempts WHERE account_id=? AND id=?",
                [account_id,id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()
            .map_err(safe)?;
        if let Some((old, status, message)) = row {
            if old != fingerprint {
                return Err(Error::Rejected(
                    "request_id already used for different content",
                ));
            }
            return Ok(Some((status, message)));
        }
        tx.execute(
            "INSERT INTO account_attempts VALUES (?,?,?,?,?)",
            params![
                account_id,
                id,
                fingerprint,
                "unknown_do_not_retry",
                message_id
            ],
        )
        .map_err(safe)?;
        tx.commit().map_err(safe)?;
        Ok(None)
    }
    /// Record SMTP acceptance for an already reserved account/request identity.
    pub fn mark_accepted(&self, account_id: &str, id: &str) -> Result<()> {
        self.0
            .lock()
            .map_err(safe)?
            .execute(
                "UPDATE account_attempts SET status='accepted_by_smtp' WHERE account_id=? AND id=?",
                [account_id, id],
            )
            .map_err(safe)?;
        Ok(())
    }
    /// Atomically remove OAuth and event state while preserving accounts and the send journal.
    pub fn revoke_oauth(&self) -> Result<()> {
        let mut db = self.0.lock().map_err(safe)?;
        let tx = db.transaction().map_err(safe)?;
        tx.execute_batch("DELETE FROM codes; DELETE FROM tokens; DELETE FROM clients;")
            .map_err(safe)?;
        for table in ["event_outbox", "event_subscriptions", "event_verifications"] {
            let exists: bool = tx
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name=?)",
                    [table],
                    |r| r.get(0),
                )
                .map_err(safe)?;
            if exists {
                tx.execute(&format!("DELETE FROM {table}"), [])
                    .map_err(safe)?;
            }
        }
        tx.commit().map_err(safe)?;
        Ok(())
    }
}
