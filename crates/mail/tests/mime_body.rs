//! Synthetic fixtures only: no personal mail, addresses, invitation codes or URLs.
use base64::{Engine, engine::general_purpose::STANDARD};
use mail_bridge_mail::parse_mail;

fn alternative(plain: &str, html: &str) -> String {
    // Encode UTF-8 as quoted-printable, with bounded physical line lengths.
    let encoded_html = html
        .as_bytes()
        .chunks(24)
        .map(|chunk| {
            chunk
                .iter()
                .map(|b| format!("={b:02X}"))
                .collect::<String>()
        })
        .collect::<Vec<_>>()
        .join("=\r\n");
    format!(
        "Content-Type: multipart/alternative; boundary=alternative\r\n\r\n\
         --alternative\r\nContent-Type: text/plain; charset=utf-8\r\n\
         Content-Transfer-Encoding: base64\r\n\r\n{}\r\n\
         --alternative\r\nContent-Type: text/html; charset=utf-8\r\n\
         Content-Transfer-Encoding: quoted-printable\r\n\r\n{encoded_html}\r\n\
         --alternative\r\nContent-Type: text/calendar; charset=utf-8\r\n\r\n\
         BEGIN:VCALENDAR\r\nEND:VCALENDAR\r\n--alternative--\r\n",
        STANDARD.encode(plain)
    )
}

#[test]
fn invitation_placeholder_does_not_hide_html_details() {
    let raw = format!(
        "MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=mixed\r\n\r\n\
         --mixed\r\n{}\r\n--mixed\r\nContent-Type: application/ics\r\n\
         Content-Disposition: attachment; filename=interview.ics\r\n\r\n\
         BEGIN:VCALENDAR\r\nEND:VCALENDAR\r\n--mixed--\r\n",
        alternative(
            "新面试",
            "<p>职位：测试工程师</p><p>面试时间：2030年1月2日10:00</p><p>请确认是否参加，提前20分钟调试双机位。</p><a href=\"https://interview.example.test/join\">进入面试</a><script>do_not_execute()</script>"
        )
    );
    let parsed = parse_mail(raw.as_bytes(), true).unwrap();
    let body = parsed["body"].as_str().unwrap();
    for detail in [
        "测试工程师",
        "2030年1月2日10:00",
        "请确认是否参加",
        "双机位",
        "https://interview.example.test/join",
    ] {
        assert!(
            body.contains(detail),
            "Missing synthetic interview detail: {detail}"
        );
    }
    assert!(!body.contains("do_not_execute"));
    assert!(!body.contains("BEGIN:VCALENDAR"));
    assert_eq!(parsed["attachment_count"], 2);
    assert_eq!(parsed["body_truncated"], false);
    assert_eq!(parsed["body_source"], "html");
    assert_eq!(parsed["untrusted_email_content"], true);
}

#[test]
fn empty_html_falls_back_to_nonempty_plain_text() {
    let raw = alternative("请在2030年1月2日参加面试", "<html><body> </body></html>");
    let parsed = parse_mail(raw.as_bytes(), true).unwrap();
    assert_eq!(
        parsed["body"].as_str().unwrap().trim(),
        "请在2030年1月2日参加面试"
    );
    assert_eq!(parsed["body_source"], "text");
}

#[test]
fn mixed_body_parts_are_joined_but_text_attachments_are_excluded() {
    let raw = b"Content-Type: multipart/mixed; boundary=m\r\n\r\n\
        --m\r\nContent-Type: text/plain\r\n\r\nFirst section\r\n\
        --m\r\nContent-Type: text/html\r\n\r\n<p>Second section</p>\r\n\
        --m\r\nContent-Type: text/plain\r\nContent-Disposition: attachment; filename=private.txt\r\n\r\n\
        attachment-secret\r\n--m--\r\n";
    let parsed = parse_mail(raw, true).unwrap();
    let body = parsed["body"].as_str().unwrap();
    assert!(body.contains("First section"));
    assert!(body.contains("Second section"));
    assert!(!body.contains("attachment-secret"));
    assert_eq!(parsed["attachment_count"], 1);
}

#[test]
fn preferred_html_keeps_character_limit_and_headers_remain_body_free() {
    let raw = alternative("新面试", &format!("<p>{}</p>", "中".repeat(21000)));
    let parsed = parse_mail(raw.as_bytes(), true).unwrap();
    assert!(parsed["body"].as_str().unwrap().chars().count() <= 20000);
    assert_eq!(parsed["body_truncated"], true);
    let headers = parse_mail(raw.as_bytes(), false).unwrap();
    assert!(headers.get("body").is_none());
    assert!(headers.get("body_source").is_none());
}

#[test]
fn related_html_rendition_is_selected_without_inline_image_or_attached_message() {
    let raw = b"Content-Type: multipart/mixed; boundary=m\r\n\r\n\
        --m\r\nContent-Type: multipart/alternative; boundary=a\r\n\r\n\
        --a\r\nContent-Type: text/plain\r\n\r\nPlaceholder\r\n\
        --a\r\nContent-Type: multipart/related; boundary=r\r\n\r\n\
        --r\r\nContent-Type: text/html\r\n\r\n<p>Full interview details</p><img src=\"cid:photo\">\r\n\
        --r\r\nContent-Type: image/png\r\nContent-ID: <photo>\r\n\r\nimage-secret\r\n\
        --r--\r\n--a--\r\n\
        --m\r\nContent-Type: message/rfc822\r\nContent-Disposition: attachment\r\n\r\n\
        Subject: Attached mail\r\n\r\nattached-message-secret\r\n--m--\r\n";
    let parsed = parse_mail(raw, true).unwrap();
    let body = parsed["body"].as_str().unwrap();
    assert!(body.contains("Full interview details"));
    assert!(!body.contains("Placeholder"));
    assert!(!body.contains("image-secret"));
    assert!(!body.contains("attached-message-secret"));
    assert_eq!(parsed["body_source"], "html");
}

#[test]
fn html_attachment_inside_alternative_does_not_replace_body() {
    let raw = b"Content-Type: multipart/alternative; boundary=a\r\n\r\n\
        --a\r\nContent-Type: text/plain\r\n\r\nActual body\r\n\
        --a\r\nContent-Type: text/html\r\nContent-Disposition: attachment; filename=private.html\r\n\r\n\
        <p>attachment-secret</p>\r\n--a--\r\n";
    let parsed = parse_mail(raw, true).unwrap();
    assert_eq!(parsed["body"].as_str().unwrap().trim(), "Actual body");
    assert_eq!(parsed["body_source"], "text");
}
