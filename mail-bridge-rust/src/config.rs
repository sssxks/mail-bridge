use crate::{Error, Result, clean, safe};
use serde::{Deserialize, Serialize};
use std::{path::PathBuf, sync::Arc};
use zeroize::Zeroizing;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub username: String,
    pub from_address: String,
    pub imap_host: String,
    pub imap_port: u16,
    pub imap_security: Security,
    pub smtp_host: String,
    pub smtp_port: u16,
    pub smtp_security: Security,
    #[serde(default)]
    pub smtp_enabled: bool,
}
#[derive(Clone, Copy, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Security {
    Tls,
    Starttls,
}
impl Config {
    pub fn validate(&self) -> Result<()> {
        for value in [
            &self.username,
            &self.from_address,
            &self.imap_host,
            &self.smtp_host,
        ] {
            clean(value, 254)?;
        }
        for host in [&self.imap_host, &self.smtp_host] {
            if !host.is_ascii() || host.contains(['/', '@', ':', ' ']) {
                return Err(Error("Use a bare DNS mail hostname"));
            }
        }
        if self.imap_port == 0 || self.smtp_port == 0 {
            return Err(Error("Invalid port"));
        }
        crate::mail::address(&self.from_address)?;
        Ok(())
    }
}
#[derive(Clone)]
pub struct AccountSettings {
    pub id: String,
    pub name: String,
    pub config: Config,
    pub password: Option<Arc<Zeroizing<String>>>,
    pub credential_status: &'static str,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AccountFile {
    id: String,
    name: String,
    password_file: String,
    config: Config,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AccountsFile {
    accounts: Vec<AccountFile>,
}

pub fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 32
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
}
fn valid_password(value: &str) -> bool {
    !value.is_empty() && value.len() <= 1024 && !value.contains(['\r', '\n', '\0'])
}
fn file_password(path: &std::path::Path) -> (Option<Arc<Zeroizing<String>>>, &'static str) {
    match std::fs::metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return (None, "missing"),
        Ok(info) if info.is_file() && info.len() <= 1024 => {}
        _ => return (None, "invalid_or_unreadable"),
    }
    match std::fs::read_to_string(path) {
        Ok(value) if valid_password(value.trim_end_matches(['\r', '\n'])) => (
            Some(Arc::new(Zeroizing::new(
                value.trim_end_matches(['\r', '\n']).to_owned(),
            ))),
            "ready",
        ),
        _ => (None, "invalid_or_unreadable"),
    }
}
pub fn load_accounts(
    bytes: &[u8],
    password_dir: &std::path::Path,
    credential_prefix: &str,
    legacy_password: Option<String>,
) -> Result<Vec<AccountSettings>> {
    if bytes.len() > 32768 {
        return Err(Error("Config too large"));
    }
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|_| Error("Invalid account configuration"))?;
    if value.get("accounts").is_none() {
        let config: Config =
            serde_json::from_value(value).map_err(|_| Error("Invalid legacy configuration"))?;
        config.validate()?;
        let password = legacy_password
            .filter(|value| valid_password(value))
            .map(|value| Arc::new(Zeroizing::new(value)));
        let credential_status = if password.is_some() {
            "ready"
        } else {
            "missing"
        };
        return Ok(vec![AccountSettings {
            id: "default".into(),
            name: "Default account".into(),
            config,
            password,
            credential_status,
        }]);
    }
    let file: AccountsFile = serde_json::from_value(value)
        .map_err(|_| Error("Invalid account configuration; credentials must be separate files"))?;
    if file.accounts.is_empty() || file.accounts.len() > 8 {
        return Err(Error("Configure 1–8 accounts"));
    }
    let mut ids = std::collections::HashSet::new();
    let mut paths = std::collections::HashSet::new();
    let mut accounts = Vec::new();
    for account in file.accounts {
        if !valid_id(&account.id) || !ids.insert(account.id.clone()) {
            return Err(Error(
                "Account IDs must be unique, 1–32 lowercase ASCII letters/digits/hyphens/underscores",
            ));
        }
        clean(&account.name, 80)?;
        if !valid_id(&account.password_file) || !paths.insert(account.password_file.clone()) {
            return Err(Error("Each account needs a unique password-file basename"));
        }
        account.config.validate()?;
        let (password, credential_status) = file_password(
            &password_dir.join(format!("{credential_prefix}{}", account.password_file)),
        );
        accounts.push(AccountSettings {
            id: account.id,
            name: account.name,
            config: account.config,
            password,
            credential_status,
        });
    }
    Ok(accounts)
}

#[derive(Clone)]
pub struct Settings {
    pub accounts: Vec<AccountSettings>,
    pub owner_password: Arc<Zeroizing<String>>,
    pub public_url: String,
    pub redirects: Vec<String>,
    pub data_dir: PathBuf,
    pub bind: std::net::SocketAddr,
}
impl Settings {
    fn secret(name: &str) -> Result<String> {
        if let Some(path) = std::env::var_os(format!("{name}_FILE")) {
            let bytes = std::fs::read(path).map_err(safe)?;
            if bytes.len() > 1024 {
                return Err(Error("Secret file too large"));
            }
            return String::from_utf8(bytes)
                .map(|value| value.trim_end_matches(['\r', '\n']).to_owned())
                .map_err(safe);
        }
        std::env::var(name)
            .map_err(|_| Error("Set the required private server credential or its _FILE path"))
    }
    pub fn from_env() -> Result<Self> {
        let config_path = std::env::var("MAIL_BRIDGE_CONFIG")
            .map_err(|_| Error("Set MAIL_BRIDGE_CONFIG to an external private JSON file"))?;
        let config_path = PathBuf::from(config_path);
        let bytes = std::fs::read(&config_path).map_err(safe)?;
        if bytes.len() > 32768 {
            return Err(Error("Config too large"));
        }
        let (password_dir, prefix) =
            if let Some(path) = std::env::var_os("MAIL_BRIDGE_PASSWORDS_DIR") {
                (PathBuf::from(path), "")
            } else if let Some(path) = std::env::var_os("CREDENTIALS_DIRECTORY") {
                (PathBuf::from(path), "mailboxes_")
            } else {
                (
                    config_path
                        .parent()
                        .unwrap_or_else(|| std::path::Path::new("."))
                        .join("mailboxes"),
                    "",
                )
            };
        let legacy = if serde_json::from_slice::<serde_json::Value>(&bytes)
            .ok()
            .is_some_and(|v| v.get("accounts").is_none())
        {
            Self::secret("MAIL_BRIDGE_PASSWORD").ok()
        } else {
            None
        };
        let accounts = load_accounts(&bytes, &password_dir, prefix, legacy)?;
        let owner_password = Self::secret("MAIL_BRIDGE_OWNER_PASSWORD")?;
        if owner_password.len() < 32
            || owner_password.len() > 256
            || !owner_password.is_ascii()
            || owner_password.contains(['\r', '\n', '\0'])
        {
            return Err(Error("Owner password must be 32–256 ASCII characters"));
        }
        if accounts.iter().any(|a| {
            a.password
                .as_ref()
                .is_some_and(|p| p.as_str() == owner_password)
        }) {
            return Err(Error("Owner password must differ from mailbox credential"));
        }
        let public_url = std::env::var("MAIL_BRIDGE_PUBLIC_URL")
            .map_err(|_| Error("Set MAIL_BRIDGE_PUBLIC_URL to an HTTPS origin"))?;
        let url = url::Url::parse(&public_url).map_err(safe)?;
        if url.scheme() != "https"
            || url.host_str().is_none()
            || url.path() != "/"
            || url.query().is_some()
            || url.fragment().is_some()
            || !url.username().is_empty()
            || url.password().is_some()
        {
            return Err(Error(
                "Public URL must be an HTTPS origin without a path or credentials",
            ));
        }
        let redirects: Vec<String> = serde_json::from_str(
            &std::env::var("MAIL_BRIDGE_OAUTH_REDIRECT_URIS").unwrap_or_else(|_| {
                "[\"https://chatgpt.com/connector_platform_oauth_redirect\"]".into()
            }),
        )
        .map_err(safe)?;
        if redirects.is_empty() || redirects.len() > 10 {
            return Err(Error("Set exact OAuth redirect URI allowlist"));
        }
        for redirect in &redirects {
            let u = url::Url::parse(redirect).map_err(safe)?;
            if u.scheme() != "https"
                || u.host_str().is_none()
                || u.fragment().is_some()
                || !u.username().is_empty()
                || u.password().is_some()
            {
                return Err(Error(
                    "Redirects must be exact HTTPS URLs without credentials or fragments",
                ));
            }
        }
        Ok(Self {
            accounts,
            owner_password: Arc::new(Zeroizing::new(owner_password)),
            public_url: url.origin().ascii_serialization(),
            redirects,
            data_dir: std::env::var_os("MAIL_BRIDGE_DATA_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("./data")),
            bind: std::env::var("MAIL_BRIDGE_BIND")
                .unwrap_or_else(|_| "127.0.0.1:18765".into())
                .parse()
                .map_err(safe)?,
        })
    }
}
