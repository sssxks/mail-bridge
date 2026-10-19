//! Header-only summaries carried by newly queued events.
use serde::Serialize;

/// A decoded mailbox address, with independently optional display name/address.
#[derive(Serialize)]
pub struct Sender {
    name: Option<Box<str>>,
    address: Option<Box<str>>,
}

/// UID plus decoded subject, sender list and RFC3339 Date header.
/// Missing/unparseable headers map to null or an empty sender list.
/// Payloads are owned because the IMAP response buffer is released after parsing.
pub struct MessageSummary {
    pub uid: u32,
    pub subject: Option<Box<str>>,
    pub from: Box<[Sender]>,
    pub date: Option<Box<str>>,
}
impl MessageSummary {
    /// Parse only the bounded header block; MIME bodies are never decoded.
    pub fn parse(uid: u32, raw: &[u8]) -> Self {
        let mail = mail_parser::MessageParser::default().parse_headers(raw);
        Self {
            uid,
            subject: mail
                .as_ref()
                .and_then(|m| m.subject())
                .map(|s| mail_bridge_core::clipped(s, 1000).into()),
            from: mail
                .as_ref()
                .and_then(|m| m.from())
                .map(|addresses| {
                    addresses
                        .iter()
                        .take(20)
                        .map(|a| Sender {
                            name: a
                                .name
                                .as_deref()
                                .map(|s| mail_bridge_core::clipped(s, 1000).into()),
                            address: a
                                .address
                                .as_deref()
                                .map(|s| mail_bridge_core::clipped(s, 254).into()),
                        })
                        .collect()
                })
                .unwrap_or_default(),
            date: mail
                .as_ref()
                .and_then(|m| m.date())
                .map(|d| d.to_rfc3339().into()),
        }
    }
}
