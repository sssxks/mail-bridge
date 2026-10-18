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
        for value in [&self.username, &self.from_address, &self.imap_host] {
            clean(value, 254)?;
        }
        for host in std::iter::once(&self.imap_host)
            .chain((!self.smtp_host.is_empty() || self.smtp_enabled).then_some(&self.smtp_host))
        {
            if host.len() > 253
                || host.split('.').any(|part| {
                    part.is_empty()
                        || part.len() > 63
                        || part.starts_with('-')
                        || part.ends_with('-')
                        || !part.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                })
            {
                return Err(Error("Use a bare DNS mail hostname"));
            }
        }
        if self.imap_port == 0
            || ((!self.smtp_host.is_empty() || self.smtp_enabled) && self.smtp_port == 0)
            || (self.smtp_enabled && self.smtp_host.is_empty())
        {
            return Err(Error("Invalid port"));
        }
        crate::mail::address(&self.from_address)?;
        Ok(())
    }
}
/// A nonempty mailbox password of at most 1024 bytes, excluding CR, LF and NUL.
///
/// Semantically a constrained byte string (valid UTF-8). The private allocation
/// is immutable and shared across request tasks; the last owner zeroes it on drop.
/// Construction is the only validation boundary, and no Debug/Serialize surface
/// exposes the credential accidentally.
///
/// | Operation | Frequency | Complexity | Storage | Forbidden implementation |
/// | --- | --- | --- | --- | --- |
/// | Parse | Account load/setup | O(bytes) | Zeroizing boxed text | Unchecked construction |
/// | Clone/borrow | Request snapshot | O(1) | Immutable Arc | Copy secrets per request |
#[derive(Clone)]
pub struct MailboxCredential(Arc<Zeroizing<Box<str>>>);

impl MailboxCredential {
    /// Consume a temporary secret, erasing it even when parsing fails.
    pub fn parse(password: Zeroizing<String>) -> Result<Self> {
        if password.is_empty() || password.len() > 1024 || password.contains(['\r', '\n', '\0']) {
            return Err(Error("Invalid mailbox credential"));
        }
        Ok(Self(Arc::new(Zeroizing::new(password.as_str().into()))))
    }

    /// Borrow the credential only where authentication or persistence needs it.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod credential_tests {
    use super::MailboxCredential;
    use zeroize::Zeroizing;

    #[test]
    fn credential_boundaries_are_measured_in_bytes_and_preserve_text() {
        for value in [" secret ".to_owned(), "x".repeat(1024), "密".repeat(341)] {
            let credential = MailboxCredential::parse(Zeroizing::new(value.clone())).unwrap();
            let snapshot = credential.clone();
            drop(credential);
            assert_eq!(snapshot.as_str(), value);
        }
        for value in [
            "".to_owned(),
            "x".repeat(1025),
            "密".repeat(342),
            "a\rb".into(),
            "a\nb".into(),
            "a\0b".into(),
        ] {
            assert!(MailboxCredential::parse(Zeroizing::new(value)).is_err());
        }
    }
}

/// Stored account DTO: identity, display name, transport configuration and credential.
///
/// Every persisted account has a parsed credential; missing credentials belong
/// to runtime availability state, not to this storage representation. Other fields
/// are validated at the configuration/persistence boundary.
#[derive(Clone)]
pub struct AccountSettings {
    pub id: String,
    pub name: String,
    pub config: Config,
    pub password: MailboxCredential,
}
pub fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 32
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
}

#[derive(Clone)]
pub struct Settings {
    pub owner_password: Arc<Zeroizing<String>>,
    pub public_url: String,
    pub redirects: Vec<String>,
    pub data_dir: PathBuf,
    pub bind: std::net::SocketAddr,
}

/// HTTPS callbacks are exact. Native callbacks require an explicit loopback IP;
/// a configured HTTP URI without a port permits an ephemeral client port.
pub fn validate_oauth_redirect(redirect: &str) -> Result<url::Url> {
    let u = url::Url::parse(redirect).map_err(safe)?;
    let loopback = matches!(u.host(), Some(url::Host::Ipv4(ip)) if ip == std::net::Ipv4Addr::LOCALHOST)
        || matches!(u.host(), Some(url::Host::Ipv6(ip)) if ip == std::net::Ipv6Addr::LOCALHOST);
    if redirect.len() > 2048
        || redirect.trim() != redirect
        || u.host_str().is_none()
        || u.fragment().is_some()
        || !u.username().is_empty()
        || u.password().is_some()
        || (u.scheme() != "https"
            && !(u.scheme() == "http"
                && loopback
                && u.query().is_none()
                && u.port() != Some(0)
                && u.as_str() == redirect))
    {
        return Err(Error(
            "Use exact HTTPS callbacks or canonical HTTP loopback IP callbacks",
        ));
    }
    Ok(u)
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
        let owner_password = Self::secret("MAIL_BRIDGE_OWNER_PASSWORD")?;
        if owner_password.len() < 32
            || owner_password.len() > 256
            || !owner_password.is_ascii()
            || owner_password.contains(['\r', '\n', '\0'])
        {
            return Err(Error("Owner password must be 32–256 ASCII characters"));
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
            validate_oauth_redirect(redirect)?;
        }
        Ok(Self {
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
