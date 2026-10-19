//! The single persistent account store, shared by setup, mail and events.
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

    pub fn runtime_accounts(&self) -> Result<Vec<AccountSettings>> {
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
        let mut accounts = Vec::new();
        for row in rows {
            let (id, name, config, password) = row.map_err(safe)?;
            let account = AccountSettings {
                id: id.parse()?,
                name: AccountName::parse(name.into())?,
                config: std::sync::Arc::new(serde_json::from_str(&config).map_err(safe)?),
                password: MailboxCredential::parse(zeroize::Zeroizing::new(password))?,
            };
            accounts.push(account);
        }
        Ok(accounts)
    }

    pub fn runtime_account_ids(&self) -> Result<Vec<String>> {
        let db = self.0.lock().map_err(safe)?;
        let mut query = db
            .prepare("SELECT id FROM runtime_accounts ORDER BY id LIMIT 9")
            .map_err(safe)?;
        query
            .query_map([], |row| row.get(0))
            .map_err(safe)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(safe)
    }

    pub fn insert_runtime_account(&self, account: &AccountSettings) -> Result<()> {
        let config = serde_json::to_string(&account.config).map_err(safe)?;
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
            .map_err(|_| Error("Account could not be saved; no account was activated"))?;
        Ok(())
    }
}
