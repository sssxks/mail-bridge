//! Bounded HTTP form decoding and private account setup input.
use mail_bridge_auth::{Params, val};
use mail_bridge_core::{
    Error, Result,
    account::{Account, AccountName, AccountSettings, MailboxCredential, RawConfig, Security},
    safe,
};
use zeroize::Zeroizing;

pub fn form(raw: &[u8]) -> Result<Params> {
    let pairs: Vec<(String, String)> =
        serde_urlencoded::from_bytes(raw).map_err(|_| Error("invalid_request"))?;
    if pairs.len() > 30 {
        return Err(Error("invalid_request"));
    }
    let mut result = Params::new();
    for (k, v) in pairs {
        if v.len() > 8192 || result.insert(k, v).is_some() {
            return Err(Error("invalid_request"));
        }
    }
    Ok(result)
}
pub fn from_form(mut params: Params) -> Result<AccountSettings> {
    let password = Zeroizing::new(params.remove("password").unwrap_or_default());
    let id = val(&params, "account_id")?.to_owned();
    let name = val(&params, "name")?.to_owned();
    let email = val(&params, "email")?.to_owned();
    mail_bridge_core::address(&email)?;
    let username = params
        .get("username")
        .filter(|s| !s.is_empty())
        .cloned()
        .unwrap_or_else(|| email.clone());
    fn security(value: &str) -> Result<Security> {
        match value {
            "tls" => Ok(Security::Tls),
            "starttls" => Ok(Security::Starttls),
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
        id: id.parse::<Account>()?,
        name: AccountName::parse(name.into())?,
        config: std::sync::Arc::new(
            RawConfig {
                username: username.into(),
                from_address: email.into(),
                imap_host: val(&params, "imap_host")?.into(),
                imap_port: val(&params, "imap_port")?.parse().map_err(safe)?,
                imap_security: security(val(&params, "imap_security")?)?,
                smtp_host: smtp_host.into(),
                smtp_port,
                smtp_security: security(
                    params
                        .get("smtp_security")
                        .map(String::as_str)
                        .unwrap_or("tls"),
                )?,
                smtp_enabled: false,
            }
            .try_into()?,
        ),
        password: MailboxCredential::parse(password)?,
    };
    Ok(account)
}
