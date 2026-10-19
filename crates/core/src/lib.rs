//! Shared account types and boundary validation.
/// Implementation of account within this crate.
pub mod account;

/// Result with a credential-safe error category.
pub type Result<T> = std::result::Result<T, Error>;
/// Meaningful failures: rejection, boundary IO failure, baseline failure or expired refresh.
/// Each variant has a fixed safe presentation; provider payloads are never retained.
#[derive(Debug, Clone)]
pub enum Error {
    /// A rejected request or business operation, with a static safe explanation.
    Rejected(&'static str),
    /// An IO/codec boundary failed; private upstream details have been discarded.
    Operation,
    /// A specific failure while establishing an IMAP event baseline.
    Baseline(BaselineFailure),
    /// A refresh lost its original subscription before it could commit.
    SubscriptionExpired,
}
/// Baseline failures that the event adapter maps to stable machine-readable reasons.
#[derive(Debug, Clone, Copy)]
pub enum BaselineFailure {
    /// The selected mailbox omitted UIDVALIDITY.
    MissingValidity,
    /// Mailbox contents changed while establishing the current baseline.
    MailboxChanged,
    /// The last observed UID cannot be advanced within the IMAP identifier range.
    UidExhausted,
    /// The baseline operation exceeded its deadline.
    Timeout,
    /// Mailbox authentication failed; provider details are suppressed.
    Authentication,
}
impl BaselineFailure {
    /// Stable integration reason independent of the human-readable message.
    pub fn reason(self) -> &'static str {
        match self {
            Self::MissingValidity => "imap_uidvalidity_missing",
            Self::MailboxChanged => "imap_mailbox_changed",
            Self::UidExhausted => "imap_uid_exhausted",
            Self::Timeout => "imap_baseline_timeout",
            Self::Authentication => "imap_authentication_failed",
        }
    }
}
impl Error {
    /// Safe text suitable for HTTP/MCP responses and process-level diagnostics.
    pub fn message(&self) -> &'static str {
        match self {
            Self::Rejected(message) => message,
            Self::Operation => {
                "Operation failed; provider details suppressed. Check local settings, TLS, server support or timeout."
            }
            Self::SubscriptionExpired => "Subscription expired during refresh",
            Self::Baseline(failure) => match failure {
                BaselineFailure::MissingValidity => "Missing UIDVALIDITY",
                BaselineFailure::MailboxChanged => {
                    "Mailbox changed while establishing event baseline"
                }
                BaselineFailure::UidExhausted => "IMAP UID space exhausted",
                BaselineFailure::Timeout => "Event baseline timeout",
                BaselineFailure::Authentication => "IMAP authentication failed; details suppressed",
            },
        }
    }
}
impl std::fmt::Display for Error {
    /// Write the credential-safe error presentation.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.message())
    }
}
impl std::error::Error for Error {}
/// Erase private provider details exactly at an IO or codec boundary.
pub fn safe<E>(_: E) -> Error {
    Error::Operation
}

/// Copy at most max Unicode characters from borrowed text.
pub fn clipped(value: &str, max: usize) -> String {
    value.chars().take(max).collect()
}
/// Check an external nonblank bounded text field before constructing a domain value.
pub fn clean(value: &str, max: usize) -> Result<()> {
    if value.trim().is_empty() || value.chars().count() > max || value.contains(['\r', '\n', '\0'])
    {
        return Err(Error::Rejected("Invalid text argument"));
    }
    Ok(())
}

/// Parse an explicit bare ASCII mailbox address.
pub fn address(raw: &str) -> Result<lettre::Address> {
    clean(raw, 254)?;
    if !raw.is_ascii() || raw.contains(['<', '>', ' ', '\t']) {
        return Err(Error::Rejected(
            "Use explicit bare ASCII recipient addresses",
        ));
    }
    raw.parse()
        .map_err(|_| Error::Rejected("Invalid email address"))
}

/// Generate an unpredictable URL-safe identifier from 256 bits of OS randomness.
pub fn random() -> String {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}
/// Implementation of scope within this crate.
pub mod scope;
