//! The single persistent account store, shared by setup, mail and events.
use crate::Db;
use mail_bridge_core::{
    Error, Result,
    account::{AccountSettings, MailboxCredential, validate},
    safe,
};
use rusqlite::params;

impl Db {
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
                id,
                name,
                config: serde_json::from_str(&config).map_err(safe)?,
                password: MailboxCredential::parse(zeroize::Zeroizing::new(password))?,
            };
            validate(&account)?;
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
        validate(account)?;
        let config = serde_json::to_string(&account.config).map_err(safe)?;
        // Commit before publishing to the in-memory registry. A failed write leaves it unchanged.
        self.0
            .lock()
            .map_err(safe)?
            .execute(
                "INSERT INTO runtime_accounts(id,name,config,password) VALUES (?,?,?,?)",
                params![account.id, account.name, config, account.password.as_str()],
            )
            .map_err(|_| Error("Account could not be saved; no account was activated"))?;
        Ok(())
    }
}
