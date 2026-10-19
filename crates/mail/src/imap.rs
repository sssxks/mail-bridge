//! Bounded read-only IMAP operations and mailbox encoding.
use crate::{
    backend::RealBackend,
    bounded_io::{GuardIo, MAX_MAIL},
    command::ReadCommand,
    mime::parse_mail,
    page::SearchCriteria,
};
use async_imap::{Client, Session};
use base64::{Engine, engine::general_purpose::STANDARD};
use futures_util::TryStreamExt;
use mail_bridge_core::{Error, Result, account::Security, clean, safe};
use serde_json::{Value, json};
use std::{collections::HashSet, sync::Arc};
use tokio::net::TcpStream;
use tokio_rustls::{
    TlsConnector,
    client::TlsStream,
    rustls::{ClientConfig, RootCertStore, pki_types::ServerName},
};

/// Authenticated TLS IMAP session whose input is guarded before protocol allocation.
pub type ImapSession = Session<GuardIo<TlsStream<TcpStream>>>;
/// Escape already bounded text as an IMAP quoted argument.
pub fn quote(raw: &str) -> Result<String> {
    clean(raw, 512)?;
    Ok(format!(
        "\"{}\"",
        raw.replace('\\', "\\\\").replace('"', "\\\"")
    ))
}
/// Encode a mailbox name in IMAP modified UTF-7.
pub fn utf7_encode(value: &str) -> String {
    let mut result = String::new();
    let mut pending = Vec::<u8>::new();
    /// Append one buffered UTF-16 segment to the modified UTF-7 output and reuse its buffer.
    fn flush(pending: &mut Vec<u8>, out: &mut String) {
        if !pending.is_empty() {
            out.push('&');
            out.push_str(
                &STANDARD
                    .encode(&*pending)
                    .trim_end_matches('=')
                    .replace('/', ","),
            );
            out.push('-');
            pending.clear();
        }
    }
    for c in value.chars() {
        if (' '..='~').contains(&c) {
            flush(&mut pending, &mut result);
            if c == '&' {
                result.push_str("&-");
            } else {
                result.push(c);
            }
        } else {
            for unit in c.encode_utf16(&mut [0; 2]) {
                pending.extend_from_slice(&unit.to_be_bytes());
            }
        }
    }
    flush(&mut pending, &mut result);
    result
}
/// Decode IMAP modified UTF-7 and reject malformed encoded segments.
pub fn utf7_decode(value: &str) -> Result<String> {
    let mut result = String::new();
    let mut rest = value;
    while let Some(index) = rest.find('&') {
        result.push_str(&rest[..index]);
        rest = &rest[index + 1..];
        let end = rest
            .find('-')
            .ok_or(Error::Rejected("Invalid mailbox encoding"))?;
        if end == 0 {
            result.push('&');
        } else {
            let mut encoded = rest[..end].replace(',', "/");
            while !encoded.len().is_multiple_of(4) {
                encoded.push('=');
            }
            let raw = STANDARD.decode(encoded).map_err(safe)?;
            if raw.len() % 2 != 0 {
                return Err(Error::Rejected("Invalid mailbox encoding"));
            }
            let units: Vec<u16> = raw
                .as_chunks::<2>()
                .0
                .iter()
                .map(|b| u16::from_be_bytes([b[0], b[1]]))
                .collect();
            result.push_str(&String::from_utf16(&units).map_err(safe)?);
        }
        rest = &rest[end + 1..];
    }
    result.push_str(rest);
    Ok(result)
}
impl RealBackend {
    /// Open TLS/STARTTLS and authenticate with the selected parsed account credential.
    pub async fn connect(&self) -> Result<ImapSession> {
        let roots = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let tls = TlsConnector::from(Arc::new(
            ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        ));
        let domain = ServerName::try_from(self.config.imap().host().to_owned()).map_err(safe)?;
        let tcp = TcpStream::connect((self.config.imap().host(), self.config.imap().port()))
            .await
            .map_err(safe)?;
        let client = if self.config.imap().security() == Security::Starttls {
            let mut plain = Client::new(GuardIo::new(tcp));
            if plain.read_response().await.map_err(safe)?.is_none() {
                return Err(Error::Rejected("Missing IMAP greeting"));
            }
            plain
                .run_command_and_check_ok("STARTTLS", None)
                .await
                .map_err(safe)?;
            Client::new(GuardIo::new(
                tls.connect(domain, plain.into_inner().inner)
                    .await
                    .map_err(safe)?,
            ))
        } else {
            let mut client =
                Client::new(GuardIo::new(tls.connect(domain, tcp).await.map_err(safe)?));
            if client.read_response().await.map_err(safe)?.is_none() {
                return Err(Error::Rejected("Missing IMAP greeting"));
            }
            client
        };
        // The library quotes credentials; no credentials appear in a URL or log.
        client
            .login(&self.config.username(), self.password.as_str())
            .await
            .map_err(|_| Error::Baseline(mail_bridge_core::BaselineFailure::Authentication))
    }
    /// Execute a typed read command on an already authenticated bounded session.
    pub async fn read_session<
        T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + std::fmt::Debug + Send,
    >(
        session: &mut Session<T>,
        command: ReadCommand,
    ) -> Result<Value> {
        let command = match command {
            ReadCommand::Folders(f) => {
                let mut names = session.list(None, Some("*")).await.map_err(safe)?;
                let mut count = 0;
                let mut folders = Vec::new();
                while let Some(name) = names.try_next().await.map_err(safe)? {
                    if count >= f.offset && folders.len() <= f.limit {
                        folders.push(utf7_decode(name.name())?);
                    }
                    count += 1;
                    if count > 10000 {
                        return Err(Error::Rejected("Folder listing exceeds limit"));
                    }
                }
                let has_more = folders.len() > f.limit;
                folders.truncate(f.limit);
                return Ok(
                    json!({"folders":folders,"next_offset":if has_more{Some(f.offset+f.limit)}else{None}}),
                );
            }
            ReadCommand::Message(a) => {
                let selected = session
                    .examine(utf7_encode(&a.folder))
                    .await
                    .map_err(safe)?;
                if selected.uid_validity != Some(a.validity.get()) {
                    return Err(Error::Rejected(
                        "UIDVALIDITY changed; list this folder again",
                    ));
                }
                let size = {
                    let mut stream = session
                        .uid_fetch(a.uid.to_string(), "(UID RFC822.SIZE)")
                        .await
                        .map_err(safe)?;
                    let mut size = None;
                    while let Some(f) = stream.try_next().await.map_err(safe)? {
                        if f.uid == Some(a.uid.get()) {
                            size = f.size;
                        }
                    }
                    size.ok_or(Error::Rejected("UID not found"))?
                };
                if size as usize > MAX_MAIL {
                    return Err(Error::Rejected(
                        "Message exceeds 2 MiB limit; use your mail client",
                    ));
                }
                let mut stream = session
                    // The size preflight and GuardIo bound allocation. A full PEEK
                    // has an explicit complete literal, unlike a requested prefix.
                    .uid_fetch(a.uid.to_string(), "(UID BODY.PEEK[])")
                    .await
                    .map_err(safe)?;
                let mut result = None;
                while let Some(f) = stream.try_next().await.map_err(safe)? {
                    if f.uid == Some(a.uid.get()) {
                        let body = f.body().ok_or(Error::Rejected("Body unavailable"))?;
                        let mut value = parse_mail(body, true)?;
                        value["uid"] = json!(a.uid.get());
                        value["uidvalidity"] = json!(a.validity.get());
                        value["reported_size_bytes"] = json!(size);
                        value["received_size_bytes"] = json!(body.len());
                        value["size_metadata_mismatch"] = json!(body.len() != size as usize);
                        if body.len() != size as usize {
                            value["size_warning"] = json!(
                                "Provider RFC822.SIZE differs from the full IMAP literal. Body was fetched in full; verify critical details against the original message if content appears incomplete."
                            );
                        }
                        result = Some(value);
                    }
                }
                return result.ok_or(Error::Rejected("UID not found"));
            }
            ReadCommand::Page(page) => page,
        };
        let a = command;
        let selected = session
            .examine(utf7_encode(a.folder()))
            .await
            .map_err(safe)?;
        let validity = selected
            .uid_validity
            .ok_or(Error::Rejected("Server omitted UIDVALIDITY"))?;
        if a.uidvalidity().is_some_and(|v| v != validity) {
            return Err(Error::Rejected(
                "UIDVALIDITY changed; list this folder again",
            ));
        }
        let mut upper = if let Some(next) = a.before_uid().or(selected.uid_next) {
            next.saturating_sub(1)
        } else if selected.exists == 0 {
            0
        } else {
            // Some servers omit UIDNEXT on EXAMINE. Fetch only the last
            // message's UID by sequence number; never SEARCH the whole mailbox
            // or download a body to discover the bounded search window.
            let mut stream = session.fetch("*", "(UID)").await.map_err(safe)?;
            let mut highest = None;
            while let Some(fetch) = stream.try_next().await.map_err(safe)? {
                if let Some(uid) = fetch.uid.filter(|uid| *uid > 0) {
                    highest = Some(highest.unwrap_or(0).max(uid));
                }
            }
            highest.ok_or(Error::Rejected(
                "Server omitted last message UID; list this folder again",
            ))?
        };
        let mut uids = Vec::new();
        let mut next = None;
        let candidate = a.search().and_then(SearchCriteria::domain_candidate);
        // Bounded UID windows, never materialize an all-mailbox SEARCH result.
        for _ in 0..8 {
            if upper == 0 {
                break;
            }
            let lower = upper.saturating_sub(1023).max(1);
            let range = format!("UID {lower}:{upper}");
            let found = if let Some(criteria) = a.search() {
                search(session, &range, candidate.as_ref().unwrap_or(criteria)).await?
            } else {
                session.uid_search(&range).await.map_err(safe)?
            };
            let mut found: Vec<u32> = found
                .into_iter()
                .filter(|uid| *uid >= lower && *uid <= upper)
                .collect();
            found.sort_unstable_by(|a, b| b.cmp(a));
            for uid in found {
                uids.push(uid);
                if uids.len() == a.limit() {
                    next = if uid > 1 { Some(uid) } else { None };
                    break;
                }
            }
            if uids.len() == a.limit() {
                break;
            }
            upper = lower - 1;
            next = if upper > 0 { Some(lower) } else { None };
        }
        let mut messages = Vec::new();
        for uid in uids {
            let mut stream = session
                .uid_fetch(uid.to_string(), "(UID BODY.PEEK[HEADER]<0.8192>)")
                .await
                .map_err(safe)?;
            while let Some(fetch) = stream.try_next().await.map_err(safe)? {
                if fetch.uid == Some(uid) {
                    let raw = fetch
                        .header()
                        .or_else(|| fetch.body())
                        .ok_or(Error::Rejected("Header unavailable"))?;
                    if candidate.is_some()
                        && a.search()
                            .is_some_and(|criteria| !criteria.matches_header(raw))
                    {
                        continue;
                    }
                    let mut message = parse_mail(raw, false)?;
                    message["uid"] = json!(uid);
                    messages.push(message);
                }
            }
        }
        let mut result = json!({"messages":messages,"uidvalidity":validity,"next_before_uid":next,"scan_limited":upper>0});
        if a.search().is_some() {
            result["search_complete"] = json!(false);
            result["search_strategy"] = json!(if candidate.is_some() {
                "domain_token_candidates_with_header_verification"
            } else {
                "provider_index"
            });
            result["search_warning"] = json!(
                "Provider search indexes can omit matches. An empty result is not proof that no matching mail exists. Continue with next_before_uid when present; try an exact address, a simpler keyword, or the mail provider's client."
            );
        }
        Ok(result)
    }
}
/// Issue a bounded UID search, using a synchronizing literal for UTF-8 text.
pub async fn search<
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + std::fmt::Debug + Send,
>(
    session: &mut Session<T>,
    range: &str,
    criteria: &SearchCriteria,
) -> Result<HashSet<u32>> {
    let field = criteria.field();
    let query = criteria.query();
    if query.is_ascii() {
        return session
            .uid_search(format!("{range} {field} {}", quote(query)?))
            .await
            .map_err(safe);
    }
    // Synchronizing literal for UTF-8, using the library's parser and command tags.
    use async_imap::imap_proto::{MailboxDatum, Response, Status};
    let id = session
        .run_command(format!(
            "UID SEARCH CHARSET UTF-8 {range} {field} {{{}}}",
            query.len()
        ))
        .await
        .map_err(safe)?;
    let mut sent = false;
    let mut found = HashSet::new();
    while let Some(response) = session.read_response().await.map_err(safe)? {
        match response.parsed() {
            Response::Continue(_) => {
                if sent {
                    return Err(Error::Rejected("Unexpected continuation"));
                }
                session.run_command_untagged(query).await.map_err(safe)?;
                sent = true;
            }
            Response::MailboxData(MailboxDatum::Search(ids)) => {
                found.extend(ids.iter().copied());
            }
            Response::Done { tag, status, .. } if tag == &id => {
                if *status == Status::Ok && sent {
                    return Ok(found);
                }
                return Err(Error::Rejected("Server rejected UTF-8 search"));
            }
            _ => {}
        }
    }
    Err(Error::Rejected("Search response incomplete"))
}
