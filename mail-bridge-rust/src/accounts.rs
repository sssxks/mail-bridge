//! The single persistent account store, shared by setup, mail and events.
use crate::{
    Error, Result,
    config::{AccountSettings, Config, valid_id},
    db::Db,
    safe,
};
use rusqlite::params;
use std::sync::Arc;
use zeroize::Zeroizing;

pub fn validate(account: &AccountSettings) -> Result<()> {
    if !valid_id(&account.id) {
        return Err(Error("Invalid account ID"));
    }
    crate::clean(&account.name, 80)?;
    account.config.validate()?;
    let password = account
        .password
        .as_ref()
        .ok_or(Error("Mailbox credential required"))?;
    if password.is_empty() || password.len() > 1024 || password.contains(['\r', '\n', '\0']) {
        return Err(Error("Invalid mailbox credential"));
    }
    Ok(())
}

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
                password: Some(Arc::new(Zeroizing::new(password))),
                credential_status: "ready",
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
                params![
                    account.id,
                    account.name,
                    config,
                    account.password.as_ref().unwrap().as_str()
                ],
            )
            .map_err(|_| Error("Account could not be saved; no account was activated"))?;
        Ok(())
    }
}

pub fn from_form(mut params: crate::auth::Params) -> Result<AccountSettings> {
    use crate::auth::val;
    let password = Zeroizing::new(params.remove("password").unwrap_or_default());
    let id = val(&params, "account_id")?.to_owned();
    let name = val(&params, "name")?.to_owned();
    let email = val(&params, "email")?.to_owned();
    crate::mail::address(&email)?;
    let username = params
        .get("username")
        .filter(|s| !s.is_empty())
        .cloned()
        .unwrap_or_else(|| email.clone());
    fn security(value: &str) -> Result<crate::config::Security> {
        match value {
            "tls" => Ok(crate::config::Security::Tls),
            "starttls" => Ok(crate::config::Security::Starttls),
            _ => Err(Error("TLS or STARTTLS required")),
        }
    }
    let smtp_host = params.get("smtp_host").cloned().unwrap_or_default();
    let smtp_port = if smtp_host.is_empty() {
        0
    } else {
        val(&params, "smtp_port")?.parse().map_err(safe)?
    };
    let account = AccountSettings {
        id,
        name,
        config: Config {
            username,
            from_address: email,
            imap_host: val(&params, "imap_host")?.to_owned(),
            imap_port: val(&params, "imap_port")?.parse().map_err(safe)?,
            imap_security: security(val(&params, "imap_security")?)?,
            smtp_host,
            smtp_port,
            smtp_security: security(
                params
                    .get("smtp_security")
                    .map(String::as_str)
                    .unwrap_or("tls"),
            )?,
            smtp_enabled: false,
        },
        password: Some(Arc::new(password)),
        credential_status: "ready",
    };
    validate(&account)?;
    Ok(account)
}
