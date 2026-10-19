//! The single persistent account store, shared by setup, mail and events.
//!
//! | Operation | Frequency | Complexity | Storage | Forbidden implementation |
//! | --- | --- | --- | --- | --- |
//! | Restore | Startup | O(account bytes), at most 9 rows | Boxed parsed products | Runtime revalidation |
//! | Select/exist | Source operation | O(log n + selected bytes) | Primary-key lookup | Decode other credentials |
//! | Insert | Owner-confirmed setup | O(log n + account bytes) | SQLite primary key | Publish before commit |
use crate::Db;
use mail_bridge_core::{
    Error, Result,
    account::{AccountName, AccountSettings, MailboxCredential},
    safe,
};
use rusqlite::{OptionalExtension, params};

/// Decode one database row into the validated immutable account product.
fn decode(
    (id, name, config, password): (String, String, String, String),
) -> Result<AccountSettings> {
    Ok(AccountSettings {
        id: id.parse()?,
        name: AccountName::parse(name.into())?,
        config: std::sync::Arc::new(serde_json::from_str(&config).map_err(safe)?),
        password: MailboxCredential::parse(zeroize::Zeroizing::new(password))?,
    })
}

impl Db {
    /// Fetch exactly one account through its primary key; no unrelated credentials are loaded.
    pub fn runtime_account(&self, id: &str) -> Result<Option<AccountSettings>> {
        self.0
            .lock()
            .map_err(safe)?
            .query_row(
                "SELECT id,name,config,password FROM runtime_accounts WHERE id=?",
                [id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .optional()
            .map_err(safe)?
            .map(decode)
            .transpose()
    }
    /// Check account identity without loading configuration or credentials.
    pub fn runtime_account_exists(&self, id: &str) -> Result<bool> {
        self.0
            .lock()
            .map_err(safe)?
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM runtime_accounts WHERE id=?)",
                [id],
                |row| row.get(0),
            )
            .map_err(safe)
    }

    /// Load and parse the bounded account set for process startup.
    pub fn runtime_accounts(&self) -> Result<Box<[AccountSettings]>> {
        let db = self.0.lock().map_err(safe)?;
        let mut query = db
            .prepare("SELECT id,name,config,password FROM runtime_accounts ORDER BY id LIMIT 9")
            .map_err(safe)?;
        let rows = query
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                ))
            })
            .map_err(safe)?;
        rows.map(|row| decode(row.map_err(safe)?)).collect()
    }

    /// Read only account identities for the event catalog.
    pub fn runtime_account_ids(&self) -> Result<Box<[mail_bridge_core::account::Account]>> {
        let db = self.0.lock().map_err(safe)?;
        let mut query = db
            .prepare("SELECT id FROM runtime_accounts ORDER BY id LIMIT 9")
            .map_err(safe)?;
        query
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(safe)?
            .map(|row| row.map_err(safe)?.parse())
            .collect::<Result<_>>()
    }

    /// Persist an already parsed account before runtime activation.
    pub fn insert_runtime_account(&self, account: &AccountSettings) -> Result<()> {
        let config = serde_json::to_string(account.config.as_ref()).map_err(safe)?;
        // Commit before publishing to the in-memory registry. A failed write leaves it unchanged.
        self.0
            .lock()
            .map_err(safe)?
            .execute(
                "INSERT INTO runtime_accounts(id,name,config,password) VALUES (?,?,?,?)",
                params![
                    account.id.as_str(),
                    account.name.as_str(),
                    config,
                    account.password.as_str()
                ],
            )
            .map_err(|_| Error::Rejected("Account could not be saved; no account was activated"))?;
        Ok(())
    }
}
