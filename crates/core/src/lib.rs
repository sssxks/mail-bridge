//! Shared account types and boundary validation.
pub mod account;

pub type Result<T> = std::result::Result<T, Error>;
#[derive(Debug, Clone)]
pub struct Error(pub &'static str);
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for Error {}
pub fn safe<E>(_: E) -> Error {
    Error(
        "Operation failed; provider details suppressed. Check local settings, TLS, server support or timeout.",
    )
}

pub fn clipped(value: &str, max: usize) -> String {
    value.chars().take(max).collect()
}
pub fn clean(value: &str, max: usize) -> Result<()> {
    if value.trim().is_empty() || value.chars().count() > max || value.contains(['\r', '\n', '\0'])
    {
        return Err(Error("Invalid text argument"));
    }
    Ok(())
}

/// Parse an explicit bare ASCII mailbox address.
pub fn address(raw: &str) -> Result<lettre::Address> {
    clean(raw, 254)?;
    if !raw.is_ascii() || raw.contains(['<', '>', ' ', '\t']) {
        return Err(Error("Use explicit bare ASCII recipient addresses"));
    }
    raw.parse().map_err(|_| Error("Invalid email address"))
}

/// Generate an unpredictable URL-safe identifier from 256 bits of OS randomness.
pub fn random() -> String {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}
