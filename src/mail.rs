use crate::{
    Error, Result,
    bounded_io::{GuardIo, MAX_MAIL},
    clean, clipped,
    config::{Config, MailboxCredential, Security},
    db::{Db, hash},
    safe,
};
use async_imap::{Client, Session};
use base64::{Engine, engine::general_purpose::STANDARD};
use futures_util::{TryStreamExt, future::BoxFuture};
use lettre::{
    Address, AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
    transport::smtp::authentication::Credentials,
};
use serde::Deserialize;

mod draft;
use draft::RawDraft;
use serde_json::{Value, json};
use std::{collections::HashSet, sync::Arc, time::Duration};
use tokio::{net::TcpStream, sync::Semaphore};
use tokio_rustls::{
    TlsConnector,
    client::TlsStream,
    rustls::{ClientConfig, RootCertStore, pki_types::ServerName},
};

pub type ImapSession = Session<GuardIo<TlsStream<TcpStream>>>;
pub fn address(raw: &str) -> Result<Address> {
    clean(raw, 254)?;
    if !raw.is_ascii() || raw.contains(['<', '>', ' ', '\t']) {
        return Err(Error("Use explicit bare ASCII recipient addresses"));
    }
    raw.parse().map_err(|_| Error("Invalid email address"))
}
pub fn quote(raw: &str) -> Result<String> {
    clean(raw, 512)?;
    Ok(format!(
        "\"{}\"",
        raw.replace('\\', "\\\\").replace('"', "\\\"")
    ))
}
pub fn utf7_encode(value: &str) -> String {
    let mut result = String::new();
    let mut pending = Vec::<u8>::new();
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
pub fn utf7_decode(value: &str) -> Result<String> {
    let mut result = String::new();
    let mut rest = value;
    while let Some(index) = rest.find('&') {
        result.push_str(&rest[..index]);
        rest = &rest[index + 1..];
        let end = rest.find('-').ok_or(Error("Invalid mailbox encoding"))?;
        if end == 0 {
            result.push('&');
        } else {
            let mut encoded = rest[..end].replace(',', "/");
            while !encoded.len().is_multiple_of(4) {
                encoded.push('=');
            }
            let raw = STANDARD.decode(encoded).map_err(safe)?;
            if raw.len() % 2 != 0 {
                return Err(Error("Invalid mailbox encoding"));
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
pub fn parse_mail(raw: &[u8], with_body: bool) -> Result<Value> {
    if raw.len() > MAX_MAIL {
        return Err(Error("Message exceeds 2 MiB limit"));
    }
    let mail = mail_parser::MessageParser::default()
        .parse(raw)
        .ok_or(Error("Invalid MIME message"))?;
    let mut output = json!({"subject":clipped(mail.subject().unwrap_or(""),1000),"message_id":clipped(mail.message_id().unwrap_or(""),1000),"from":mail.from(),"to":mail.to(),"date":mail.date(),"untrusted_email_content":true});
    if with_body {
        let body = mail
            .body_text(0)
            .map(|s| s.into_owned())
            .or_else(|| {
                mail.body_html(0)
                    .and_then(|h| html2text::from_read(h.as_bytes(), 100).ok())
            })
            .unwrap_or_default();
        output["body"] = json!(clipped(&body, 20000));
        output["body_truncated"] = json!(body.chars().count() > 20000);
        output["attachment_count"] = json!(mail.attachment_count());
    }
    Ok(output)
}

pub mod page;
use page::{Page, SearchCriteria};

fn inbox() -> String {
    "INBOX".into()
}
fn default_limit() -> usize {
    10
}

pub trait Backend: Send + Sync {
    fn read<'a>(&'a self, name: &'a str, args: Value) -> BoxFuture<'a, Result<Value>>;
    fn send(&self, message: Message) -> BoxFuture<'_, Result<()>>;
}
#[derive(Clone)]
pub struct RealBackend {
    pub config: Config,
    pub password: MailboxCredential,
}
impl RealBackend {
    pub async fn connect(&self) -> Result<ImapSession> {
        let roots = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let tls = TlsConnector::from(Arc::new(
            ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        ));
        let domain = ServerName::try_from(self.config.imap_host.clone()).map_err(safe)?;
        let tcp = TcpStream::connect((self.config.imap_host.as_str(), self.config.imap_port))
            .await
            .map_err(safe)?;
        let client = if self.config.imap_security == Security::Starttls {
            let mut plain = Client::new(GuardIo::new(tcp));
            if plain.read_response().await.map_err(safe)?.is_none() {
                return Err(Error("Missing IMAP greeting"));
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
                return Err(Error("Missing IMAP greeting"));
            }
            client
        };
        // The library quotes credentials; no credentials appear in a URL or log.
        client
            .login(&self.config.username, self.password.as_str())
            .await
            .map_err(|_| Error("IMAP authentication failed; details suppressed"))
    }
    pub async fn read_session<
        T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + std::fmt::Debug + Send,
    >(
        session: &mut Session<T>,
        name: &str,
        args: Value,
    ) -> Result<Value> {
        if name == "list_folders" {
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct F {
                #[serde(default)]
                offset: usize,
                #[serde(default = "default_limit")]
                limit: usize,
            }
            let f: F =
                serde_json::from_value(args).map_err(|_| Error("Invalid folder arguments"))?;
            if f.offset > 10000 || !(1..=100).contains(&f.limit) {
                return Err(Error("Invalid folder page"));
            }
            let mut names = session.list(None, Some("*")).await.map_err(safe)?;
            let mut count = 0;
            let mut folders = Vec::new();
            while let Some(name) = names.try_next().await.map_err(safe)? {
                if count >= f.offset && folders.len() <= f.limit {
                    folders.push(utf7_decode(name.name())?);
                }
                count += 1;
                if count > 10000 {
                    return Err(Error("Folder listing exceeds limit"));
                }
            }
            let has_more = folders.len() > f.limit;
            folders.truncate(f.limit);
            return Ok(
                json!({"folders":folders,"next_offset":if has_more{Some(f.offset+f.limit)}else{None}}),
            );
        }
        if name == "read_message" {
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Read {
                #[serde(default = "inbox")]
                folder: String,
                uid: u32,
                uidvalidity: u32,
            }
            let a: Read =
                serde_json::from_value(args).map_err(|_| Error("Invalid UID arguments"))?;
            clean(&a.folder, 512)?;
            if a.uid == 0 || a.uidvalidity == 0 {
                return Err(Error("Invalid UID or UIDVALIDITY"));
            }
            let selected = session
                .examine(utf7_encode(&a.folder))
                .await
                .map_err(safe)?;
            if selected.uid_validity != Some(a.uidvalidity) {
                return Err(Error("UIDVALIDITY changed; list this folder again"));
            }
            let size = {
                let mut stream = session
                    .uid_fetch(a.uid.to_string(), "(UID RFC822.SIZE)")
                    .await
                    .map_err(safe)?;
                let mut size = None;
                while let Some(f) = stream.try_next().await.map_err(safe)? {
                    if f.uid == Some(a.uid) {
                        size = f.size;
                    }
                }
                size.ok_or(Error("UID not found"))?
            };
            if size as usize > MAX_MAIL {
                return Err(Error("Message exceeds 2 MiB limit; use your mail client"));
            }
            let mut stream = session
                .uid_fetch(
                    a.uid.to_string(),
                    format!("(UID BODY.PEEK[]<0.{}>)", MAX_MAIL + 1),
                )
                .await
                .map_err(safe)?;
            let mut result = None;
            while let Some(f) = stream.try_next().await.map_err(safe)? {
                if f.uid == Some(a.uid) {
                    let body = f.body().ok_or(Error("Body unavailable"))?;
                    if body.len() != size as usize {
                        return Err(Error("Body changed or was truncated"));
                    }
                    let mut value = parse_mail(body, true)?;
                    value["uid"] = json!(a.uid);
                    value["uidvalidity"] = json!(a.uidvalidity);
                    result = Some(value);
                }
            }
            return result.ok_or(Error("UID not found"));
        }
        let a = Page::parse(args, name == "search_messages")?;
        let selected = session
            .examine(utf7_encode(a.folder()))
            .await
            .map_err(safe)?;
        let validity = selected
            .uid_validity
            .ok_or(Error("Server omitted UIDVALIDITY"))?;
        if a.uidvalidity().is_some_and(|v| v != validity) {
            return Err(Error("UIDVALIDITY changed; list this folder again"));
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
            highest.ok_or(Error(
                "Server omitted last message UID; list this folder again",
            ))?
        };
        let mut uids = Vec::new();
        let mut next = None;
        // Bounded UID windows, never materialize an all-mailbox SEARCH result.
        for _ in 0..8 {
            if upper == 0 {
                break;
            }
            let lower = upper.saturating_sub(1023).max(1);
            let range = format!("UID {lower}:{upper}");
            let found = if let Some(criteria) = a.search() {
                search(session, &range, criteria).await?
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
                    let mut message = parse_mail(
                        fetch
                            .header()
                            .or_else(|| fetch.body())
                            .ok_or(Error("Header unavailable"))?,
                        false,
                    )?;
                    message["uid"] = json!(uid);
                    messages.push(message);
                }
            }
        }
        Ok(
            json!({"messages":messages,"uidvalidity":validity,"next_before_uid":next,"scan_limited":upper>0}),
        )
    }
}
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
                    return Err(Error("Unexpected continuation"));
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
                return Err(Error("Server rejected UTF-8 search"));
            }
            _ => {}
        }
    }
    Err(Error("Search response incomplete"))
}
impl Backend for RealBackend {
    fn read<'a>(&'a self, name: &'a str, args: Value) -> BoxFuture<'a, Result<Value>> {
        Box::pin(async move {
            let mut session = self.connect().await?;
            let value = Self::read_session(&mut session, name, args).await;
            let _ = session.logout().await;
            value
        })
    }
    fn send(&self, message: Message) -> BoxFuture<'_, Result<()>> {
        Box::pin(async move {
            let builder = if self.config.smtp_security == Security::Tls {
                AsyncSmtpTransport::<Tokio1Executor>::relay(&self.config.smtp_host)
            } else {
                AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&self.config.smtp_host)
            }
            .map_err(safe)?;
            let transport = builder
                .port(self.config.smtp_port)
                .timeout(Some(Duration::from_secs(20)))
                .credentials(Credentials::new(
                    self.config.username.clone(),
                    self.password.as_str().to_owned(),
                ))
                .build();
            transport.send(message).await.map_err(|_|Error("SMTP result uncertain; check manually before any new attempt. Do not automatically retry."))?;
            Ok(())
        })
    }
}
#[derive(Clone)]
pub struct MailAccount {
    pub id: String,
    pub name: String,
    pub config: Config,
    pub backend: Option<Arc<dyn Backend>>,
    pub credential_status: &'static str,
}
impl MailAccount {
    fn status(&self) -> Value {
        json!({"account_id":self.id,"name":self.name,"from_address":self.config.from_address,"smtp_enabled":self.config.smtp_enabled,"credential_status":self.credential_status,"connection_tested":false})
    }
}
#[derive(Clone)]
pub struct MailService {
    pub accounts: Arc<std::sync::RwLock<std::collections::BTreeMap<String, MailAccount>>>,
    pub db: Db,
    pub gate: Arc<Semaphore>,
}
impl MailService {
    pub fn new(accounts: Vec<crate::config::AccountSettings>, db: Db) -> Self {
        let accounts = accounts
            .into_iter()
            .map(|account| {
                let backend = Arc::new(RealBackend {
                    config: account.config.clone(),
                    password: account.password,
                });
                let id = account.id.clone();
                (
                    id,
                    MailAccount {
                        id: account.id,
                        name: account.name,
                        config: account.config,
                        backend: Some(backend),
                        credential_status: "ready",
                    },
                )
            })
            .collect();
        Self {
            accounts: Arc::new(std::sync::RwLock::new(accounts)),
            db,
            gate: Arc::new(Semaphore::new(1)),
        }
    }
    pub fn from_store(db: Db) -> Result<Self> {
        let accounts = db.runtime_accounts()?;
        if accounts.len() > 8 {
            return Err(Error("Configure at most 8 accounts"));
        }
        Ok(Self::new(accounts, db))
    }
    pub fn add_account(&self, account: crate::config::AccountSettings) -> Result<()> {
        crate::accounts::validate(&account)?;
        if account.config.smtp_enabled {
            return Err(Error("New accounts must have SMTP disabled"));
        }
        let mut accounts = self.accounts.write().map_err(safe)?;
        if accounts.contains_key(&account.id) {
            return Err(Error("Account ID already exists; choose a new ID"));
        }
        if accounts.len() >= 8 {
            return Err(Error("Configure at most 8 accounts"));
        }
        self.db.insert_runtime_account(&account)?;
        let backend = Arc::new(RealBackend {
            config: account.config.clone(),
            password: account.password,
        });
        accounts.insert(
            account.id.clone(),
            MailAccount {
                id: account.id,
                name: account.name,
                config: account.config,
                backend: Some(backend),
                credential_status: "ready",
            },
        );
        Ok(())
    }
    pub async fn dispatch(&self, name: &str, mut args: Value) -> Result<Value> {
        if name == "list_accounts" {
            let object = args.as_object().ok_or(Error("Invalid arguments"))?;
            if !object.is_empty() {
                return Err(Error("Unexpected arguments"));
            }
            let accounts = self.accounts.read().map_err(safe)?;
            let statuses: Vec<_> = accounts.values().map(MailAccount::status).collect();
            return Ok(
                json!({"accounts":statuses,"account_count":accounts.len(),"max_mail_bytes":MAX_MAIL,"mail_concurrency":1,"transport":"streamable_http"}),
            );
        }
        let account_id = args
            .as_object_mut()
            .ok_or(Error("Invalid arguments"))?
            .remove("account_id")
            .and_then(|v| v.as_str().map(str::to_owned))
            .ok_or(Error(
                "An explicit account_id is required; use list_accounts",
            ))?;
        let account = self
            .accounts
            .read()
            .map_err(safe)?
            .get(&account_id)
            .cloned()
            .ok_or(Error("Unknown account_id; use list_accounts"))?;
        let _permit = self.gate.clone().try_acquire_owned().map_err(|_| {
            Error("Mail operation busy; try later. Do not retry an uncertain send.")
        })?;
        let mut result=tokio::time::timeout(Duration::from_secs(45),self.inner(name,args,&account)).await.map_err(|_|Error("Mail operation timed out. A send may already have been accepted; never automatically retry."))??;
        result
            .as_object_mut()
            .ok_or(Error("Invalid mail response"))?
            .insert("account_id".into(), json!(account.id));
        Ok(result)
    }
    async fn inner(&self, name: &str, args: Value, account: &MailAccount) -> Result<Value> {
        match name {
            "prepare_draft" => {
                let draft: RawDraft = serde_json::from_value(args)
                    .map_err(|_| Error("Provide recipients, subject and body"))?;
                let mut preview=draft.parse()?.preview();
                preview["from_address"]=json!(account.config.from_address);
                Ok(preview)
            }
            "send_email" => {
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct Send {
                    to: Box<[Box<str>]>,
                    subject: Box<str>,
                    body: Box<str>,
                    request_id: String,
                }
                let send: Send = serde_json::from_value(args).map_err(|_| {
                    Error(
                        "Recipients, subject, body and request_id required",
                    )
                })?;
                let draft = RawDraft {
                    to: send.to,
                    subject: send.subject,
                    body: send.body,
                }.parse()?;
                if !account.config.smtp_enabled {
                    return Err(Error(
                        "SMTP is disabled for this account",
                    ));
                }
                if !(16..=80).contains(&send.request_id.len())
                    || !send
                        .request_id
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
                {
                    return Err(Error("Invalid request_id"));
                }
                let backend=account.backend.as_ref().ok_or(Error("Selected account credential is missing or invalid; enter it privately on the server"))?;
                let id = format!(
                    "<{}@{}>",
                    crate::auth::random(),
                    account.config
                        .from_address
                        .rsplit('@')
                        .next()
                        .unwrap_or("localhost")
                );
                let fingerprint = hash(
                    serde_json::to_vec(&json!([
                        account.id,
                        account.config.username,
                        account.config.from_address,
                        account.config.smtp_host,
                        account.config.smtp_port,
                        &draft
                    ]))
                    .map_err(safe)?,
                );
                let message = draft.message(&account.config.from_address, &id)?;
                if let Some((status, id)) = self.db.attempt(&account.id, &send.request_id, &fingerprint, &id)? {
                    return Ok(json!({"status":status,"message_id":id,"retried":false}));
                }
                // The durable journal is committed before a single SMTP attempt.
                backend.send(message).await?;
                self.db.mark_accepted(&account.id, &send.request_id)?;
                Ok(json!({"status":"accepted_by_smtp","message_id":id,"retried":false}))
            }
            "list_folders" | "list_messages" | "search_messages" | "read_message" => {
                account.backend.as_ref().ok_or(Error("Selected account credential is missing or invalid; enter it privately on the server"))?.read(name, args).await
            }
            _ => Err(Error("Unknown tool")),
        }
    }
}
