//! Parse mail requests before acquiring permits or opening a provider connection.
//!
//! | Operation | Frequency | Complexity | Storage | Forbidden implementation |
//! | --- | --- | --- | --- | --- |
//! | Parse | Once per request | O(argument bytes) | Owned validated request | Parse after login |
//! | Dispatch | Once per request | O(1) | Enum | String-based operation selection |
use crate::page::Page;
use mail_bridge_core::{Error, Result, account::Mailbox};
use serde::Deserialize;
use serde_json::Value;
use std::num::NonZeroU32;

/// `Folders(valid page) | Message(valid reference) | Page(valid list/search)`.
/// Each payload can only be constructed by parsing its external representation.
pub enum ReadCommand {
    /// Enumerate a bounded folder page.
    Folders(FolderPage),
    /// Read one message scoped to a mailbox generation.
    Message(MessageRef),
    /// List or search a bounded UID page.
    Page(Page),
}
/// `Offset[0,10000] × Limit[1,100]`, parsed once and immutable thereafter.
pub struct FolderPage {
    /// Validated folder-page offset in the inclusive range 0–10000.
    pub(crate) offset: usize,
    /// Validated upper bound on the number of returned entries.
    pub(crate) limit: usize,
}
/// `Mailbox × NonzeroUID × NonzeroUIDVALIDITY`; zero identifiers are unrepresentable.
pub struct MessageRef {
    /// Mailbox name parsed before any provider connection.
    pub(crate) folder: Mailbox,
    /// Message UID scoped to a mailbox generation.
    pub(crate) uid: NonZeroU32,
    /// Mailbox UIDVALIDITY; a changed value invalidates earlier UIDs.
    pub(crate) validity: NonZeroU32,
}
impl ReadCommand {
    /// Decode one of the four read operations, rejecting unknown tools before IO.
    pub fn parse(name: &str, args: Value) -> Result<Self> {
        match name {
            "list_folders" => {
                /// Untrusted request product; only the enclosing parser turns its fields into a valid command.
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct Raw {
                    /// Validated folder-page offset in the inclusive range 0–10000.
                    #[serde(default)]
                    offset: usize,
                    /// Validated upper bound on the number of returned entries.
                    #[serde(default = "limit")]
                    limit: usize,
                }
                /// Return the fixed page default or the bounded-resource error for this context.
                fn limit() -> usize {
                    10
                }
                let raw: Raw = serde_json::from_value(args)
                    .map_err(|_| Error::Rejected("Invalid folder arguments"))?;
                if raw.offset > 10000 || !(1..=100).contains(&raw.limit) {
                    return Err(Error::Rejected("Invalid folder page"));
                }
                Ok(Self::Folders(FolderPage {
                    offset: raw.offset,
                    limit: raw.limit,
                }))
            }
            "read_message" => {
                /// Untrusted request product; only the enclosing parser turns its fields into a valid command.
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct Raw {
                    /// Mailbox name parsed before any provider connection.
                    #[serde(default = "inbox")]
                    folder: Box<str>,
                    /// Message UID scoped to a mailbox generation.
                    uid: u32,
                    /// External mailbox generation paired with a message/cursor UID.
                    uidvalidity: u32,
                }
                /// Default an omitted mailbox name to INBOX.
                fn inbox() -> Box<str> {
                    "INBOX".into()
                }
                let raw: Raw = serde_json::from_value(args)
                    .map_err(|_| Error::Rejected("Invalid UID arguments"))?;
                let folder = raw.folder.try_into()?;
                Ok(Self::Message(MessageRef {
                    folder,
                    uid: NonZeroU32::new(raw.uid)
                        .ok_or(Error::Rejected("Invalid UID or UIDVALIDITY"))?,
                    validity: NonZeroU32::new(raw.uidvalidity)
                        .ok_or(Error::Rejected("Invalid UID or UIDVALIDITY"))?,
                }))
            }
            "list_messages" | "search_messages" => {
                Ok(Self::Page(Page::parse(args, name == "search_messages")?))
            }
            _ => Err(Error::Rejected("Unknown tool")),
        }
    }
}
