//! Parsed mailbox accounts and transport configuration.
//!
//! | Operation | Frequency | Complexity | Storage | Forbidden implementation |
//! | --- | --- | --- | --- | --- |
//! | Parse | Setup/load | O(text bytes) | Immutable boxed fields | Revalidate in business code |
//! | Snapshot | Each operation | O(1) | Shared immutable config | Clone every config string |
use crate::{Error, Result, clean};
use serde::{Deserialize, Serialize, Serializer};
use std::{borrow::Borrow, num::NonZeroU16, sync::Arc};
use zeroize::Zeroizing;

/// Account identity: `[a-z0-9_-]{1,32}` stored verbatim as immutable UTF-8.
/// Private encoding excludes empty, oversized and noncanonical identities.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "Box<str>", into = "Box<str>")]
pub struct Account(Box<str>);
impl TryFrom<Box<str>> for Account {
    type Error = Error;
    fn try_from(value: Box<str>) -> Result<Self> {
        if value.is_empty()
            || value.len() > 32
            || !value
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
        {
            return Err(Error("Invalid account ID"));
        }
        Ok(Self(value))
    }
}
impl std::str::FromStr for Account {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        Box::<str>::from(s).try_into()
    }
}
impl From<Account> for Box<str> {
    fn from(v: Account) -> Self {
        v.0
    }
}
impl Borrow<str> for Account {
    fn borrow(&self) -> &str {
        &self.0
    }
}
impl Account {
    /// Borrow the canonical identity.
    #[inline(always)]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Nonblank display name, at most 80 Unicode characters, without CR/LF/NUL.
/// The private boxed string is the original accepted text.
#[derive(Clone, Serialize)]
pub struct AccountName(Box<str>);
impl AccountName {
    /// Parse an external display name once.
    pub fn parse(value: Box<str>) -> Result<Self> {
        clean(&value, 80)?;
        Ok(Self(value))
    }
    /// Borrow the display name.
    #[inline(always)]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// TLS negotiation required by a configured mail endpoint.
#[derive(Clone, Copy, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Security {
    /// TLS before protocol greeting.
    Tls,
    /// Upgrade an initial connection with STARTTLS.
    Starttls,
}

/// `DNSName × NonzeroPort × Security` with a bare ASCII DNS hostname.
/// Private fields exclude malformed labels and zero ports.
#[derive(Clone)]
pub struct Endpoint {
    host: Box<str>,
    port: NonZeroU16,
    security: Security,
}
impl Endpoint {
    fn parse(host: Box<str>, port: u16, security: Security) -> Result<Self> {
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
        Ok(Self {
            host,
            port: NonZeroU16::new(port).ok_or(Error("Invalid port"))?,
            security,
        })
    }
    /// Borrow the validated DNS hostname.
    #[inline(always)]
    pub fn host(&self) -> &str {
        &self.host
    }
    /// Nonzero network port.
    #[inline(always)]
    pub fn port(&self) -> u16 {
        self.port.get()
    }
    /// Required TLS mode.
    #[inline(always)]
    pub fn security(&self) -> Security {
        self.security
    }
}
/// `Unconfigured | Disabled(endpoint) | Enabled(endpoint)`.
/// Configured endpoints always contain a nonzero port and valid hostname.
#[derive(Clone)]
enum Smtp {
    Unconfigured(Security),
    Disabled(Endpoint),
    Enabled(Endpoint),
}

/// Untrusted legacy storage/form representation, parsed into `Config` once.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawConfig {
    pub username: Box<str>,
    pub from_address: Box<str>,
    pub imap_host: Box<str>,
    pub imap_port: u16,
    pub imap_security: Security,
    pub smtp_host: Box<str>,
    pub smtp_port: u16,
    pub smtp_security: Security,
    #[serde(default)]
    pub smtp_enabled: bool,
}
/// `Username × SenderAddress × ImapEndpoint × SmtpState`.
/// Text is immutable, addresses are parsed, and cross-field SMTP constraints
/// are encoded by the private enum. Serde preserves the legacy database shape.
#[derive(Clone, Deserialize)]
#[serde(try_from = "RawConfig")]
pub struct Config {
    username: Box<str>,
    from_address: lettre::Address,
    imap: Endpoint,
    smtp: Smtp,
}
impl TryFrom<RawConfig> for Config {
    type Error = Error;
    fn try_from(raw: RawConfig) -> Result<Self> {
        clean(&raw.username, 254)?;
        let from_address = crate::address(&raw.from_address)?;
        let imap = Endpoint::parse(raw.imap_host, raw.imap_port, raw.imap_security)?;
        let smtp = if raw.smtp_host.is_empty() {
            if raw.smtp_enabled {
                return Err(Error("Invalid port"));
            }
            Smtp::Unconfigured(raw.smtp_security)
        } else {
            let endpoint = Endpoint::parse(raw.smtp_host, raw.smtp_port, raw.smtp_security)?;
            if raw.smtp_enabled {
                Smtp::Enabled(endpoint)
            } else {
                Smtp::Disabled(endpoint)
            }
        };
        Ok(Self {
            username: raw.username,
            from_address,
            imap,
            smtp,
        })
    }
}
impl Config {
    /// Mailbox login name.
    #[inline(always)]
    pub fn username(&self) -> &str {
        &self.username
    }
    /// Parsed sender address, preserving original spelling.
    #[inline(always)]
    pub fn sender(&self) -> &lettre::Address {
        &self.from_address
    }
    /// Borrow the parsed sender spelling.
    pub fn sender_text(&self) -> &str {
        self.from_address.as_ref()
    }
    /// Read endpoint, always configured.
    #[inline(always)]
    pub fn imap(&self) -> &Endpoint {
        &self.imap
    }
    /// Configured submission endpoint, including disabled configurations.
    #[inline(always)]
    pub fn smtp(&self) -> Option<&Endpoint> {
        match &self.smtp {
            Smtp::Disabled(e) | Smtp::Enabled(e) => Some(e),
            Smtp::Unconfigured(_) => None,
        }
    }
    /// Whether this account permits SMTP submission.
    #[inline(always)]
    pub fn sending_enabled(&self) -> bool {
        matches!(self.smtp, Smtp::Enabled(_))
    }
}
impl Serialize for Config {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut out = serializer.serialize_struct("Config", 9)?;
        out.serialize_field("username", self.username())?;
        out.serialize_field("from_address", self.sender_text())?;
        out.serialize_field("imap_host", self.imap.host())?;
        out.serialize_field("imap_port", &self.imap.port())?;
        out.serialize_field("imap_security", &self.imap.security())?;
        out.serialize_field("smtp_host", self.smtp().map_or("", Endpoint::host))?;
        out.serialize_field("smtp_port", &self.smtp().map_or(0, Endpoint::port))?;
        let security = match self.smtp {
            Smtp::Unconfigured(s) => s,
            Smtp::Disabled(ref e) | Smtp::Enabled(ref e) => e.security(),
        };
        out.serialize_field("smtp_security", &security)?;
        out.serialize_field("smtp_enabled", &self.sending_enabled())?;
        out.end()
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

/// Parsed account product: identity, display name, immutable config and credential.
/// Each component enforces its own constraints; no whole-account revalidation is needed.
#[derive(Clone)]
pub struct AccountSettings {
    pub id: Account,
    pub name: AccountName,
    pub config: Arc<Config>,
    pub password: MailboxCredential,
}
