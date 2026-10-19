use mail_bridge_core::{Error, Result};
use mail_parser::{Message, MimeHeaders, PartType};
use std::collections::HashSet;

/// One rendered MIME rendition; retain one extra character to report clipping.
/// Source bits distinguish plain text (1), rendered HTML (2), or mixed (3).
#[derive(Default)]
pub(super) struct Body {
    /// Mutable rendered text retaining one extra character for truncation reporting.
    pub text: String,
    /// Two provenance bits: plain text = 1, HTML = 2, both = 3.
    sources: u8,
}
impl Body {
    /// Describe the rendered body provenance from its two source bits.
    pub fn source(&self) -> &'static str {
        match self.sources {
            1 => "text",
            2 => "html",
            3 => "mixed",
            _ => "none",
        }
    }
    /// Append bounded nonempty inline text while combining source provenance.
    fn append(&mut self, other: Self) {
        if other.text.trim().is_empty() {
            return;
        }
        self.sources |= other.sources;
        let remaining = 20001usize.saturating_sub(self.text.chars().count());
        if remaining > 0 {
            if !self.text.is_empty() {
                self.text.push('\n');
            }
            let remaining = 20001usize.saturating_sub(self.text.chars().count());
            self.text.extend(other.text.chars().take(remaining));
        }
    }
}

/// Render inline body parts, never attachments or nested message contents.
/// In multipart/alternative, select the last supported nonempty rendition (the
/// sender's preferred representation), rather than assuming text/plain is complete.
/// Walk each selected subtree once; cap depth at 64 and retained text at 20,001
/// Unicode characters per subtree. HTML rendering never fetches external assets.
pub(super) fn render(mail: &Message<'_>) -> Result<Body> {
    let inline: HashSet<_> = mail
        .text_body
        .iter()
        .chain(&mail.html_body)
        .copied()
        .collect();
    render_part(mail, &inline, 0, 0)
}

/// Walk one MIME subtree with explicit depth and retained-text limits.
fn render_part(mail: &Message<'_>, inline: &HashSet<u32>, id: u32, depth: usize) -> Result<Body> {
    if depth > 64 {
        return Err(Error::Rejected(
            "MIME body nesting exceeds limit; use your mail client",
        ));
    }
    let Some(part) = mail.part(id) else {
        return Err(Error::Rejected("Invalid MIME body structure"));
    };
    if part
        .content_disposition()
        .is_some_and(|d| d.is_attachment())
        || part.attachment_name().is_some()
    {
        return Ok(Body::default());
    }
    match &part.body {
        PartType::Multipart(children) => {
            let mut body = Body::default();
            if part.is_content_type("multipart", "alternative") {
                for child in children.iter().rev() {
                    let candidate = render_part(mail, inline, *child, depth + 1)?;
                    if !candidate.text.trim().is_empty() {
                        return Ok(candidate);
                    }
                }
            } else {
                for child in children {
                    body.append(render_part(mail, inline, *child, depth + 1)?);
                }
            }
            Ok(body)
        }
        PartType::Text(text) if inline.contains(&id) => Ok(Body {
            text: mail_bridge_core::clipped(text, 20001),
            sources: 1,
        }),
        PartType::Html(html) if inline.contains(&id) => {
            let text = html2text::from_read(html.as_bytes(), 100)
                .map_err(|_| Error::Rejected("HTML body rendering failed; use your mail client"))?;
            Ok(Body {
                text: mail_bridge_core::clipped(&text, 20001),
                sources: 2,
            })
        }
        _ => Ok(Body::default()),
    }
}
