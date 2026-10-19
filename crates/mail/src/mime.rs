//! MIME header extraction and body rendition selection.
/// Implementation of body within this crate.
mod body;
use crate::bounded_io::MAX_MAIL;
use mail_bridge_core::{Error, Result, clipped};
use serde_json::{Value, json};

/// Extract bounded MIME headers and optionally render the preferred inline body.
pub fn parse_mail(raw: &[u8], with_body: bool) -> Result<Value> {
    if raw.len() > MAX_MAIL {
        return Err(Error::Rejected("Message exceeds 2 MiB limit"));
    }
    let mail = mail_parser::MessageParser::default()
        .parse(raw)
        .ok_or(Error::Rejected("Invalid MIME message"))?;
    let mut output = json!({"subject":clipped(mail.subject().unwrap_or(""),1000),"message_id":clipped(mail.message_id().unwrap_or(""),1000),"from":mail.from(),"to":mail.to(),"date":mail.date(),"untrusted_email_content":true});
    if with_body {
        let body = body::render(&mail)?;
        output["body"] = json!(clipped(&body.text, 20000));
        output["body_truncated"] = json!(body.text.chars().count() > 20000);
        output["body_source"] = json!(body.source());
        output["attachment_count"] = json!(mail.attachment_count());
    }
    Ok(output)
}
