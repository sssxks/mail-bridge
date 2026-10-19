//! The two mail permissions encoded without heap storage.
use crate::{Error, Result};
/// One permission understood by the service.
#[derive(Clone, Copy)]
pub enum Scope {
    /// Read mail and manage event subscriptions.
    Read,
    /// Submit mail through explicitly enabled SMTP.
    Send,
}
/// A nonempty subset of `{Read, Send}` encoded by two bits.
/// Parsing excludes zero and unknown bits; serialization order is read, then send.
#[derive(Clone, Copy)]
pub struct Scopes(u8);
impl Scopes {
    /// Parse a whitespace-delimited external scope set, accepting duplicate names.
    pub fn parse(value: &str) -> Result<Self> {
        let mut bits = 0;
        for name in value.split_whitespace() {
            bits |= match name {
                "mail:read" => 1,
                "mail:send" => 2,
                _ => return Err(Error::Rejected("invalid_scope")),
            };
        }
        if bits == 0 {
            return Err(Error::Rejected("invalid_scope"));
        }
        Ok(Self(bits))
    }
    /// Test one permission in constant time.
    #[inline(always)]
    pub fn contains(self, scope: Scope) -> bool {
        self.0
            & match scope {
                Scope::Read => 1,
                Scope::Send => 2,
            }
            != 0
    }
    /// Canonical wire/storage spelling with no allocation.
    #[inline(always)]
    pub fn as_str(self) -> &'static str {
        match self.0 {
            1 => "mail:read",
            2 => "mail:send",
            3 => "mail:read mail:send",
            _ => unreachable!("parsed nonempty scope set"),
        }
    }
}
