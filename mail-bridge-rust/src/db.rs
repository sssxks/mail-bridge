use crate::{Error, Result, safe};
use rusqlite::{Connection, OptionalExtension, params};
use sha2::{Digest, Sha256};
use std::{
    path::Path,
    sync::{Arc, Mutex},
    time::Duration,
};

pub fn hash(value: impl AsRef<[u8]>) -> String {
    format!("{:x}", Sha256::digest(value.as_ref()))
}
pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}
#[derive(Clone)]
pub struct Db(pub Arc<Mutex<Connection>>);
impl Db {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(safe)?;
        }
        let db = Connection::open(path).map_err(safe)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(safe)?;
        }
        db.busy_timeout(Duration::from_millis(100)).map_err(safe)?;
        db.execute_batch("PRAGMA synchronous=FULL; PRAGMA cache_size=-1024; PRAGMA temp_store=MEMORY;
            CREATE TABLE IF NOT EXISTS clients(id TEXT PRIMARY KEY,redirects TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS codes(hash TEXT PRIMARY KEY,client TEXT,redirect TEXT,challenge TEXT,resource TEXT,scope TEXT,expires INTEGER);
            CREATE TABLE IF NOT EXISTS tokens(hash TEXT PRIMARY KEY,kind TEXT,client TEXT,resource TEXT,scope TEXT,expires INTEGER);
            CREATE TABLE IF NOT EXISTS attempts(id TEXT PRIMARY KEY,fingerprint TEXT,status TEXT,message_id TEXT);
            CREATE TABLE IF NOT EXISTS account_attempts(account_id TEXT,id TEXT,fingerprint TEXT,status TEXT,message_id TEXT,PRIMARY KEY(account_id,id));
            INSERT OR IGNORE INTO account_attempts SELECT 'default',id,fingerprint,status,message_id FROM attempts;").map_err(safe)?;
        Ok(Self(Arc::new(Mutex::new(db))))
    }
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
                return Err(Error("request_id already used for different content"));
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
