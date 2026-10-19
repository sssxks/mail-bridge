use crate::{Error, Result, clean};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
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
        crate::address(&self.from_address)?;
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

pub fn validate(account: &AccountSettings) -> Result<()> {
    if !valid_id(&account.id) {
        return Err(Error("Invalid account ID"));
    }
    crate::clean(&account.name, 80)?;
    account.config.validate()?;
    Ok(())
}
