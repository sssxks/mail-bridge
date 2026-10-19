//! Parse mail content at the request boundary, retaining typed recipients.
//!
//! | Operation | Frequency | Complexity | Storage | Forbidden implementation |
//! | --- | --- | --- | --- | --- |
//! | Parse | Once per request | O(content bytes) | Boxed recipients/text | Validate again during preview/send |
//! | Preview/fingerprint | Once per operation | O(content bytes) | Borrowed serialization | Duplicate stored JSON |
//! | Build message | Once per send | O(content bytes) | Consume draft | Reparse recipients |
use lettre::{
    Address, Message,
    message::{Mailbox, header::ContentType},
};
use mail_bridge_core::address;
use mail_bridge_core::{Error, Result, clean, safe};
use serde::{Deserialize, Serialize, Serializer};
use serde_json::{Value, json};

/// Untrusted wire product `Recipients × Subject × Body` without constraints.
/// Only `parse` may turn it into content accepted by the mail workflow.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawDraft {
    pub to: Box<[Box<str>]>,
    pub subject: Box<str>,
    pub body: Box<str>,
}

/// `Recipients[1,20] × Subject × Body` with validated bare ASCII addresses,
/// nonblank subject of at most 500 characters without CR/LF/NUL, and nonblank
/// body of at most 20000 characters without NUL.
///
/// # Encoding
/// Private boxed fields are immutable. Recipients retain their original spelling
/// in lettre's parsed Address representation; order and duplicates are preserved.
/// Serialization keeps the legacy object shape used by durable send fingerprints.
#[derive(Serialize)]
pub(super) struct Draft {
    #[serde(serialize_with = "serialize_recipients")]
    to: Box<[Address]>,
    subject: Box<str>,
    body: Box<str>,
}

/// Serialize the original address strings without an intermediate string vector.
fn serialize_recipients<S: Serializer>(
    to: &[Address],
    serializer: S,
) -> std::result::Result<S::Ok, S::Error> {
    serializer.collect_seq(to.iter().map(AsRef::<str>::as_ref))
}

impl RawDraft {
    /// Enforce the request contract once, before preview, journal or SMTP access.
    pub(super) fn parse(self) -> Result<Draft> {
        if self.to.is_empty() || self.to.len() > 20 {
            return Err(Error("Provide 1–20 explicit recipients"));
        }
        let to = self
            .to
            .iter()
            .map(|raw| address(raw))
            .collect::<Result<Box<[_]>>>()?;
        clean(&self.subject, 500)?;
        if self.body.trim().is_empty()
            || self.body.chars().count() > 20000
            || self.body.contains('\0')
        {
            return Err(Error("Body must contain 1–20000 characters"));
        }
        Ok(Draft {
            to,
            subject: self.subject,
            body: self.body,
        })
    }
}

impl Draft {
    /// Produce the existing preview response without revalidating content.
    pub(super) fn preview(&self) -> Value {
        let mut value = json!(self);
        value["status"] = json!("preview_only_not_saved_or_sent");
        value
    }

    /// Move validated recipients into the message; sender parsing and MIME
    /// construction remain fallible at the transport boundary.
    pub(super) fn message(self, from: &Address, id: &str) -> Result<Message> {
        let mut message = Message::builder()
            .from(Mailbox::new(None, from.clone()))
            .subject(self.subject.as_ref())
            .message_id(Some(id.to_owned()))
            .header(ContentType::TEXT_PLAIN);
        for recipient in self.to.into_vec() {
            message = message.to(Mailbox::new(None, recipient));
        }
        message.body(self.body.into_string()).map_err(safe)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialization_preserves_the_durable_fingerprint_and_preview() {
        let raw = json!({"to":["Mixed.Case@EXAMPLE.com", "a@example.com", "a@example.com"], "subject":" 中文 ", "body":" body\r\n"});
        let draft = serde_json::from_value::<RawDraft>(raw.clone())
            .unwrap()
            .parse()
            .unwrap();
        assert_eq!(json!(draft), raw);
        let mut preview = raw;
        preview["status"] = json!("preview_only_not_saved_or_sent");
        assert_eq!(draft.preview(), preview);
        let message = draft
            .message(
                &address("sender@example.com").unwrap(),
                "<test@example.com>",
            )
            .unwrap();
        assert_eq!(message.envelope().to().len(), 3);
    }

    #[test]
    fn content_boundaries_and_header_injection() {
        for (field, value) in [
            ("to", json!([])),
            ("to", json!(vec!["a@example.com"; 21])),
            ("to", json!(["Name <a@example.com>"])),
            ("subject", json!("x\r\nBcc: y@example.com")),
            ("subject", json!("中".repeat(501))),
            ("subject", json!(" ")),
            ("body", json!("中".repeat(20001))),
            ("body", json!("a\0b")),
            ("body", json!("\r\n")),
        ] {
            let mut raw = json!({"to":["a@example.com"],"subject":"hello","body":"body"});
            raw[field] = value;
            assert!(
                serde_json::from_value::<RawDraft>(raw)
                    .unwrap()
                    .parse()
                    .is_err()
            );
        }
        let raw = json!({"to":vec!["a@example.com";20],"subject":"中".repeat(500),"body":"中".repeat(20000)});
        assert!(
            serde_json::from_value::<RawDraft>(raw)
                .unwrap()
                .parse()
                .is_ok()
        );
    }
}
