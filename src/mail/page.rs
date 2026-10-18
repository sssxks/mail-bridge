//! Parse untrusted page arguments into a request with valid search and cursor state.
//!
//! | Operation | Frequency | Complexity | Storage | Forbidden implementation |
//! | --- | --- | --- | --- | --- |
//! | Parse page | Once per request | O(folder + query length) | Owned boxed text | Revalidate per UID window |
//! | Inspect cursor/search | Per UID window | O(1) | Inline enum/optional criteria | Independent unchecked options |
use crate::{Error, Result, clean};
use serde::Deserialize;
use serde_json::Value;
use std::num::NonZeroU32;

/// An IMAP search key and its nonempty, bounded text.
///
/// Semantically `Field × Query`, where Field is SUBJECT/FROM/TO/TEXT and
/// Query contains 1–256 characters without CR, LF or NUL and is not whitespace-only.
/// Private fields encode the pair together; construction rejects unsupported keys.
pub struct SearchCriteria {
    field: &'static str,
    query: Box<str>,
}

impl SearchCriteria {
    /// Parse the external field name and query once, before issuing IMAP commands.
    pub fn parse(field: &str, query: Box<str>) -> Result<Self> {
        let field = match field {
            "SUBJECT" => "SUBJECT",
            "FROM" => "FROM",
            "TO" => "TO",
            "TEXT" => "TEXT",
            _ => return Err(Error("Unsupported search field")),
        };
        clean(&query, 256)?;
        Ok(Self { field, query })
    }

    /// The canonical, allowlisted IMAP search key.
    pub(super) fn field(&self) -> &str {
        self.field
    }

    /// Validated query text; quoting/literal framing remains the transport's job.
    pub(super) fn query(&self) -> &str {
        &self.query
    }
}

/// `Latest | InMailbox(validity) | Before(validity, uid)`.
///
/// Nonzero integers exclude invalid IMAP identifiers; the Before variant cannot
/// exist without the UIDVALIDITY that gives its UID meaning.
enum Cursor {
    Latest,
    InMailbox(NonZeroU32),
    Before {
        validity: NonZeroU32,
        uid: NonZeroU32,
    },
}

/// `Folder × Limit[1,20] × Cursor × (List | Search(criteria))`.
///
/// Private fields prevent mutation after parsing. `None` means list mode;
/// `Some` contains both a supported field and a valid query. Folder is boxed,
/// nonempty text with at most 512 characters and no CR/LF/NUL.
pub struct Page {
    folder: Box<str>,
    limit: u8,
    cursor: Cursor,
    search: Option<SearchCriteria>,
}

/// Wire DTO: arbitrary combinations are permitted only until `Page::parse`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPage {
    #[serde(default = "inbox")]
    folder: Box<str>,
    #[serde(default = "default_limit")]
    limit: usize,
    before_uid: Option<u32>,
    uidvalidity: Option<u32>,
    field: Option<Box<str>>,
    query: Option<Box<str>>,
}

/// Default mailbox when no folder was supplied.
fn inbox() -> Box<str> {
    "INBOX".into()
}

/// Default bounded message count.
fn default_limit() -> usize {
    10
}

impl Page {
    /// Parse the existing JSON contract, including its operation-specific errors.
    pub fn parse(args: Value, search: bool) -> Result<Self> {
        let raw: RawPage =
            serde_json::from_value(args).map_err(|_| Error("Invalid page arguments"))?;
        clean(&raw.folder, 512)?;
        let invalid =
            Error("Invalid page; provide limit 1–20 and preserve UIDVALIDITY with before_uid");
        if !(1..=20).contains(&raw.limit) {
            return Err(invalid);
        }
        let cursor = match (raw.before_uid, raw.uidvalidity) {
            (None, None) => Cursor::Latest,
            (None, Some(validity)) => Cursor::InMailbox(NonZeroU32::new(validity).ok_or(invalid)?),
            (Some(uid), Some(validity)) => Cursor::Before {
                validity: NonZeroU32::new(validity).ok_or_else(|| invalid.clone())?,
                uid: NonZeroU32::new(uid).ok_or(invalid)?,
            },
            (Some(_), None) => return Err(invalid),
        };
        let criteria = if search {
            let field = raw
                .field
                .as_deref()
                .ok_or(Error("Unsupported search field"))?;
            // Preserve field error precedence when both field and query are invalid.
            if !matches!(field, "SUBJECT" | "FROM" | "TO" | "TEXT") {
                return Err(Error("Unsupported search field"));
            }
            Some(SearchCriteria::parse(
                field,
                raw.query.ok_or(Error("Search query missing"))?,
            )?)
        } else {
            if raw.field.is_some() || raw.query.is_some() {
                return Err(Error("Use search_messages for search fields"));
            }
            None
        };
        Ok(Self {
            folder: raw.folder,
            limit: raw.limit as u8,
            cursor,
            search: criteria,
        })
    }

    /// Mailbox name before modified UTF-7 encoding.
    pub(super) fn folder(&self) -> &str {
        &self.folder
    }

    /// Maximum returned message count, always in 1–20.
    pub(super) fn limit(&self) -> usize {
        usize::from(self.limit)
    }

    /// Exclusive UID upper bound, meaningful only within the stored validity.
    pub(super) fn before_uid(&self) -> Option<u32> {
        match self.cursor {
            Cursor::Before { uid, .. } => Some(uid.get()),
            _ => None,
        }
    }

    /// Required mailbox generation, if supplied by the caller.
    pub(super) fn uidvalidity(&self) -> Option<u32> {
        match self.cursor {
            Cursor::Latest => None,
            Cursor::InMailbox(validity) | Cursor::Before { validity, .. } => Some(validity.get()),
        }
    }

    /// Search criteria, or list mode when absent.
    pub(super) fn search(&self) -> Option<&SearchCriteria> {
        self.search.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn cursor_and_limit_boundaries() {
        for args in [
            json!({}),
            json!({"uidvalidity":1}),
            json!({"before_uid":1,"uidvalidity":u32::MAX,"limit":20}),
        ] {
            assert!(Page::parse(args, false).is_ok());
        }
        for args in [
            json!({"before_uid":1}),
            json!({"uidvalidity":0}),
            json!({"before_uid":0,"uidvalidity":1}),
            json!({"before_uid":1,"uidvalidity":0}),
            json!({"limit":0}),
            json!({"limit":21}),
            json!({"extra":true}),
        ] {
            assert!(Page::parse(args, false).is_err());
        }
    }

    #[test]
    fn search_requires_a_complete_safe_pair() {
        for field in ["SUBJECT", "FROM", "TO", "TEXT"] {
            let page = Page::parse(json!({"field":field,"query":"中文"}), true).unwrap();
            let criteria = page.search().unwrap();
            assert_eq!(criteria.field(), field);
            assert_eq!(criteria.query(), "中文");
        }
        for args in [
            json!({}),
            json!({"field":"FROM"}),
            json!({"query":"x"}),
            json!({"field":"ALL","query":"x"}),
            json!({"field":"TEXT","query":" "}),
            json!({"field":"TEXT","query":"a\r\nb"}),
            json!({"field":"TEXT","query":"x".repeat(257)}),
        ] {
            assert!(Page::parse(args, true).is_err());
        }
        assert!(Page::parse(json!({"field":"TEXT","query":"x"}), false).is_err());
        assert!(SearchCriteria::parse("ALL\r\nLOGOUT", "x".into()).is_err());
    }
}
