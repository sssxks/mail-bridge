pub mod auth;
pub mod bounded_io;
pub mod config;
pub mod db;
pub mod events;
pub mod http;
pub mod mail;
pub mod mcp;
pub mod webhook;

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
