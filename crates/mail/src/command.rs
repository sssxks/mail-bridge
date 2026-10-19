//! Parse mail requests before acquiring permits or opening a provider connection.
//!
//! | Operation | Frequency | Complexity | Storage | Forbidden implementation |
//! | --- | --- | --- | --- | --- |
//! | Parse | Once per request | O(argument bytes) | Owned validated request | Parse after login |
//! | Dispatch | Once per request | O(1) | Enum | String-based operation selection |
use crate::page::Page;
use mail_bridge_core::{Error, Result, clean};
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
    pub(crate) offset: usize,
    pub(crate) limit: usize,
}
/// `Mailbox × NonzeroUID × NonzeroUIDVALIDITY`; zero identifiers are unrepresentable.
pub struct MessageRef {
    pub(crate) folder: Box<str>,
    pub(crate) uid: NonZeroU32,
    pub(crate) validity: NonZeroU32,
}
impl ReadCommand {
    /// Decode one of the four read operations, rejecting unknown tools before IO.
    pub fn parse(name: &str, args: Value) -> Result<Self> {
        match name {
            "list_folders" => {
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct Raw {
                    #[serde(default)]
                    offset: usize,
                    #[serde(default = "limit")]
                    limit: usize,
                }
                fn limit() -> usize {
                    10
                }
                let raw: Raw =
                    serde_json::from_value(args).map_err(|_| Error("Invalid folder arguments"))?;
                if raw.offset > 10000 || !(1..=100).contains(&raw.limit) {
                    return Err(Error("Invalid folder page"));
                }
                Ok(Self::Folders(FolderPage {
                    offset: raw.offset,
                    limit: raw.limit,
                }))
            }
            "read_message" => {
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct Raw {
                    #[serde(default = "inbox")]
                    folder: Box<str>,
                    uid: u32,
                    uidvalidity: u32,
                }
                fn inbox() -> Box<str> {
                    "INBOX".into()
                }
                let raw: Raw =
                    serde_json::from_value(args).map_err(|_| Error("Invalid UID arguments"))?;
                clean(&raw.folder, 512)?;
                Ok(Self::Message(MessageRef {
                    folder: raw.folder,
                    uid: NonZeroU32::new(raw.uid).ok_or(Error("Invalid UID or UIDVALIDITY"))?,
                    validity: NonZeroU32::new(raw.uidvalidity)
                        .ok_or(Error("Invalid UID or UIDVALIDITY"))?,
                }))
            }
            "list_messages" | "search_messages" => {
                Ok(Self::Page(Page::parse(args, name == "search_messages")?))
            }
            _ => Err(Error("Unknown tool")),
        }
    }
}
