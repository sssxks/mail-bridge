//! Mail subscriptions, IMAP observation and webhook delivery.
pub mod webhook;
use futures_util::{TryStreamExt, future::BoxFuture};
use mail_bridge_auth::Auth;
use mail_bridge_core::{Error, Result, safe};
use mail_bridge_mail::{RealBackend, utf7_encode};
use mail_bridge_store::{
    Db,
    events::{PendingEvent, SubscriptionRecord},
    hash, now,
};
use webhook::Transport;

pub mod message;
use message::MessageSummary;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use subtle::ConstantTimeEq;
use tokio_util::sync::CancellationToken;

const EVENT: &str = "message.created";
const MAX_SUBS: i64 = 2;
const MAX_QUEUE: i64 = 128;
/// Safe operational breadcrumb: callers supply static categories, never payloads.
pub fn audit(action: &'static str, status: &'static str, reason: &'static str) {
    eprintln!(
        "mail_event time={} action={action} status={status} reason={reason}",
        date(now())
    );
}
pub fn date(seconds: i64) -> String {
    chrono::DateTime::from_timestamp(seconds, 0)
        .expect("bounded timestamp")
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}
#[derive(Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Filters {
    pub account_id: String,
    pub mailbox: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Delivery {
    pub mode: String,
    pub url: String,
    pub secret: Option<String>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Subscribe {
    pub name: String,
    pub arguments: Filters,
    pub delivery: Delivery,
    pub cursor: Option<String>,
    pub ttl_ms: Option<u64>,
    pub max_age_ms: Option<u64>,
}
#[derive(Clone)]
pub struct Subscription {
    pub id: String,
    pub owner: String,
    pub filters: Filters,
    pub url: String,
    pub secret: String,
    pub previous: Option<String>,
    pub rotate_until: i64,
    pub expires: i64,
    pub validity: u32,
    pub uid: u32,
    pub truncated: bool,
    pub paused: bool,
    pub last_error: Option<String>,
}
pub struct Snapshot {
    pub validity: u32,
    pub next_uid: u32,
}
pub struct Scan {
    pub validity: u32,
    pub next_uid: u32,
    pub messages: Vec<MessageSummary>,
    pub scanned_to: u32,
}
pub trait Source: Send + Sync {
    fn available(&self, account: &str) -> bool;
    fn snapshot<'a>(&'a self, filters: &'a Filters) -> BoxFuture<'a, Result<Snapshot>>;
    fn scan<'a>(
        &'a self,
        filters: &'a Filters,
        validity: u32,
        uid: u32,
    ) -> BoxFuture<'a, Result<Scan>>;
    fn wait<'a>(&'a self, filters: &'a Filters) -> BoxFuture<'a, Result<()>>;
}
pub struct ImapSource {
    db: Db,
}
impl ImapSource {
    pub fn new(db: Db) -> Self {
        Self { db }
    }
    /// Some Coremail servers omit UIDNEXT, including from STATUS. Fetching only
    /// the last existing UID gives a bounded from-now watermark without bodies.
    async fn observed_next_uid<
        T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + std::fmt::Debug + Send,
    >(
        session: &mut async_imap::Session<T>,
        next: Option<u32>,
        exists: u32,
    ) -> Result<u32> {
        if let Some(next) = next.filter(|next| *next > 0) {
            return Ok(next);
        }
        if exists == 0 {
            return Ok(1);
        }
        let mut fetched = session.fetch("*", "(UID)").await.map_err(safe)?;
        let mut last = None;
        while let Some(message) = fetched.try_next().await.map_err(safe)? {
            if let Some(uid) = message.uid.filter(|uid| *uid > 0) {
                last = Some(last.map_or(uid, |old: u32| old.max(uid)));
            }
        }
        last.ok_or(Error("Mailbox changed while establishing event baseline"))?
            .checked_add(1)
            .ok_or(Error("IMAP UID space exhausted"))
    }
    /// Establish the no-history baseline using EXAMINE and at most one UID fetch.
    pub async fn snapshot_session<
        T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + std::fmt::Debug + Send,
    >(
        session: &mut async_imap::Session<T>,
        mailbox: &str,
    ) -> Result<Snapshot> {
        let selected = session.examine(utf7_encode(mailbox)).await.map_err(safe)?;
        let validity = selected.uid_validity.ok_or(Error("Missing UIDVALIDITY"))?;
        let next_uid = Self::observed_next_uid(session, selected.uid_next, selected.exists).await?;
        Ok(Snapshot { validity, next_uid })
    }
    /// Scan a bounded UID window and fetch at most 128 header summaries.
    /// One SEARCH and one batched PEEK fetch use O(n log n + header bytes),
    /// with n <= 1024 UIDs and at most 8 KiB per fetched header; no body fetches.
    pub async fn scan_session<
        T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + std::fmt::Debug + Send,
    >(
        session: &mut async_imap::Session<T>,
        mailbox: &str,
        validity: u32,
        uid: u32,
    ) -> Result<Scan> {
        let selected = session.examine(utf7_encode(mailbox)).await.map_err(safe)?;
        let current = selected.uid_validity.ok_or(Error("Missing UIDVALIDITY"))?;
        let next = Self::observed_next_uid(session, selected.uid_next, selected.exists).await?;
        let end = next.saturating_sub(1).min(uid.saturating_add(1024));
        let mut uids = if current == validity && end > uid {
            session
                .uid_search(format!("UID {}:{end}", uid.saturating_add(1)))
                .await
                .map_err(safe)?
                .into_iter()
                .filter(|v| *v > uid && *v <= end)
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        };
        uids.sort_unstable();
        let scanned_to = if uids.len() > MAX_QUEUE as usize {
            uids.truncate(MAX_QUEUE as usize);
            uids.last().copied().unwrap_or(uid)
        } else {
            end
        };
        let mut messages = Vec::with_capacity(uids.len());
        if !uids.is_empty() {
            let sequence = uids
                .iter()
                .map(u32::to_string)
                .collect::<Vec<_>>()
                .join(",");
            let mut fetched = session
                .uid_fetch(sequence, "(UID BODY.PEEK[HEADER]<0.8192>)")
                .await
                .map_err(safe)?;
            while let Some(fetch) = fetched.try_next().await.map_err(safe)? {
                if let Some(id) = fetch.uid.filter(|id| uids.binary_search(id).is_ok()) {
                    let raw = fetch.header().ok_or(Error("Event header unavailable"))?;
                    messages.push(MessageSummary::parse(id, raw));
                }
            }
        }
        Ok(Scan {
            validity: current,
            next_uid: next,
            messages,
            scanned_to,
        })
    }
    fn account(&self, id: &str) -> Result<RealBackend> {
        let account = self
            .db
            .runtime_accounts()?
            .into_iter()
            .find(|a| a.id == id)
            .ok_or(Error("Account unavailable for events"))?;
        Ok(RealBackend {
            config: account.config,
            password: account.password,
        })
    }
}
impl Source for ImapSource {
    fn available(&self, id: &str) -> bool {
        self.account(id).is_ok()
    }
    fn snapshot<'a>(&'a self, f: &'a Filters) -> BoxFuture<'a, Result<Snapshot>> {
        Box::pin(async move {
            let mut session = self.account(&f.account_id)?.connect().await?;
            let snapshot = Self::snapshot_session(&mut session, &f.mailbox).await?;
            let _ = session.logout().await;
            Ok(snapshot)
        })
    }
    fn scan<'a>(&'a self, f: &'a Filters, validity: u32, uid: u32) -> BoxFuture<'a, Result<Scan>> {
        Box::pin(async move {
            let mut session = self.account(&f.account_id)?.connect().await?;
            let scan = Self::scan_session(&mut session, &f.mailbox, validity, uid).await;
            let _ = session.logout().await;
            scan
        })
    }
    fn wait<'a>(&'a self, f: &'a Filters) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let mut session = self.account(&f.account_id)?.connect().await?;
            session
                .examine(utf7_encode(&f.mailbox))
                .await
                .map_err(safe)?;
            let capabilities = session.capabilities().await.map_err(safe)?;
            if capabilities.has_str("IDLE") {
                let mut idle = session.idle();
                idle.init().await.map_err(safe)?;
                {
                    let (wait, _interrupt) = idle.wait_with_timeout(Duration::from_secs(30));
                    let _ = wait.await.map_err(safe)?;
                }
                let mut session = idle.done().await.map_err(safe)?;
                let _ = session.logout().await;
            } else {
                let _ = session.logout().await;
                tokio::time::sleep(Duration::from_secs(30)).await;
            }
            Ok(())
        })
    }
}
pub struct Events {
    pub db: Db,
    pub auth: Arc<Auth>,
    pub source: Arc<dyn Source>,
    pub transport: Arc<dyn Transport>,
    ids: Vec<String>,
    subscribe_gate: tokio::sync::Mutex<()>,
    pub workers: Mutex<HashMap<String, CancellationToken>>,
    attempts: Mutex<HashMap<String, Instant>>,
}
impl Events {
    pub fn new(
        db: Db,
        auth: Arc<Auth>,
        source: Arc<dyn Source>,
        transport: Arc<dyn Transport>,
        ids: Vec<String>,
    ) -> Result<Self> {
        db.init_events()?;
        Ok(Self {
            db,
            auth,
            source,
            transport,
            ids,
            subscribe_gate: tokio::sync::Mutex::new(()),
            workers: Mutex::new(HashMap::new()),
            attempts: Mutex::new(HashMap::new()),
        })
    }
    pub fn catalog(&self) -> Value {
        let mut ids = self.ids.clone();
        if let Ok(runtime) = self.db.runtime_account_ids() {
            ids.extend(runtime);
            ids.sort();
            ids.dedup();
        }
        json!({"events":[{"name":EVENT,"description":"A newly observed IMAP message in one explicitly selected account/mailbox. Includes subject, sender and date headers; no body or attachments. No historical replay.","delivery":["webhook"],"inputSchema":{"type":"object","properties":{"account_id":{"type":"string","enum":ids},"mailbox":{"type":"string","minLength":1,"maxLength":512}},"required":["account_id","mailbox"],"additionalProperties":false},"payloadSchema":{"type":"object","properties":{"account_id":{"type":"string"},"mailbox":{"type":"string"},"message_id":{"type":"string"},"uid":{"type":"integer"},"uidvalidity":{"type":"integer"},"subject":{"type":["string","null"]},"from":{"type":"array","items":{"type":"object","properties":{"name":{"type":["string","null"]},"address":{"type":["string","null"]}},"required":["name","address"],"additionalProperties":false}},"date":{"type":["string","null"]}},"required":["account_id","mailbox","message_id","uid","uidvalidity"],"additionalProperties":false},"_meta":{"securitySchemes":[{"type":"oauth2","scopes":["mail:read"]}]}}]})
    }
    fn checked(&self, request: &Subscribe, with_secret: bool) -> Result<String> {
        if request.name != EVENT
            || request.delivery.mode != "webhook"
            || !(self.ids.contains(&request.arguments.account_id)
                || self
                    .db
                    .runtime_account_ids()?
                    .contains(&request.arguments.account_id))
        {
            return Err(Error("Invalid event or account"));
        }
        mail_bridge_core::clean(&request.arguments.mailbox, 512)?;
        if request.cursor.is_some() {
            return Err(Error("This event does not support protocol replay"));
        }
        if with_secret {
            webhook::key(
                request
                    .delivery
                    .secret
                    .as_deref()
                    .ok_or(Error("Signing secret required"))?,
            )?;
        }
        Ok(webhook::callback_url(&request.delivery.url)?.to_string())
    }
    pub fn identity(owner: &str, url: &str, filters: &Filters) -> String {
        format!(
            "sub_{}",
            hash(
                serde_json::to_vec(&json!([owner, url, EVENT, filters])).expect("static identity")
            )
        )
    }
    pub fn get(&self, id: &str) -> Result<Option<Subscription>> {
        Ok(self.db.subscription(id)?.map(Subscription::from))
    }
    pub fn active(&self) -> Result<Vec<Subscription>> {
        Ok(self
            .db
            .subscriptions()?
            .into_iter()
            .map(Subscription::from)
            .collect())
    }
    pub async fn subscribe(
        &self,
        owner: &str,
        request: Subscribe,
    ) -> std::result::Result<Value, EventError> {
        let _gate = self.subscribe_gate.lock().await;
        self.db
            .expire_verifications()
            .map_err(EventError::internal)?;
        let url = self.checked(&request, true).map_err(EventError::invalid)?;
        if !self
            .auth
            .event_grant_active(owner)
            .map_err(EventError::internal)?
            || !self.source.available(&request.arguments.account_id)
        {
            return Err(EventError::forbidden());
        }
        let id = Self::identity(owner, &url, &request.arguments);
        let old = self
            .get(&id)
            .map_err(EventError::internal)?
            .filter(|s| s.expires > now());
        if old.is_none()
            && self
                .active()
                .map_err(EventError::internal)?
                .iter()
                .filter(|s| s.expires > now())
                .count()
                >= MAX_SUBS as usize
        {
            return Err(EventError::limit());
        }
        let secret = request.delivery.secret.as_deref().expect("checked");
        let cached = self
            .db
            .callback_verified(owner, &url)
            .map_err(EventError::internal)?;
        if !cached {
            let delay = {
                let mut attempts = self
                    .attempts
                    .lock()
                    .map_err(safe)
                    .map_err(EventError::internal)?;
                attempts.retain(|_, time| time.elapsed() < Duration::from_secs(300));
                let host = url::Url::parse(&url)
                    .expect("checked URL")
                    .host_str()
                    .expect("host")
                    .to_owned();
                let delay = attempts.get(&host).map_or(Duration::ZERO, |time| {
                    Duration::from_secs(2).saturating_sub(time.elapsed())
                });
                if attempts.len() > 128 {
                    return Err(EventError::limit());
                }
                attempts.insert(host, Instant::now() + delay);
                delay
            };
            // The subscribe gate serializes these requests. Pace a second valid
            // callback on the same host instead of failing a two-trigger task.
            tokio::time::sleep(delay).await;
            let challenge = mail_bridge_core::random();
            let body = serde_json::to_vec(&json!({"type":"verification","challenge":challenge}))
                .map_err(safe)
                .map_err(EventError::internal)?;
            let header = webhook::headers(
                secret,
                None,
                &format!("msg_verification_{}", mail_bridge_core::random()),
                &id,
                &body,
            )
            .map_err(EventError::invalid)?;
            let reply = self
                .transport
                .post(&url, header, body)
                .await
                .map_err(|e| EventError::callback(e.0))?;
            let echoed = serde_json::from_slice::<Value>(&reply.body)
                .ok()
                .and_then(|v| {
                    v.get("challenge")
                        .and_then(Value::as_str)
                        .map(str::to_owned)
                });
            if !(200..300).contains(&reply.status)
                || !echoed
                    .is_some_and(|value| bool::from(value.as_bytes().ct_eq(challenge.as_bytes())))
            {
                return Err(EventError::callback("challenge_failed"));
            }
            self.db
                .verify_callback(owner, &url)
                .map_err(EventError::internal)?;
            audit("subscribe", "callback_verified", "ok");
        }
        let snapshot = if old.is_none() {
            Some(
                tokio::time::timeout(
                    Duration::from_secs(15),
                    self.source.snapshot(&request.arguments),
                )
                .await
                .map_err(|_| EventError::upstream(Error("Event baseline timeout")))?
                .map_err(EventError::upstream)?,
            )
        } else {
            None
        };
        let seconds = (request
            .ttl_ms
            .unwrap_or(3_600_000)
            .clamp(60_000, 86_400_000)
            / 1000) as i64;
        let expires = now() + seconds;
        let record = SubscriptionRecord {
            id: id.clone(),
            owner: owner.to_owned(),
            account: request.arguments.account_id,
            mailbox: request.arguments.mailbox,
            url,
            secret: secret.to_owned(),
            previous: None,
            rotate_until: 0,
            expires,
            validity: 0,
            uid: 0,
            truncated: false,
            paused: false,
            last_error: None,
        };
        let truncated = self
            .db
            .refresh_subscription(
                &record,
                snapshot.map(|s| (s.validity, s.next_uid.saturating_sub(1))),
            )
            .map_err(|error| {
                if error.0 == "Subscription expired during refresh" {
                    EventError::upstream(error)
                } else {
                    EventError::internal(error)
                }
            })?;
        Ok(
            json!({"id":id,"refreshBefore":date(expires),"cursor":null,"truncated":truncated,"deliveryStatus":{"active":true,"lastError":null}}),
        )
    }
    pub async fn unsubscribe(
        &self,
        owner: &str,
        request: Subscribe,
    ) -> std::result::Result<Value, EventError> {
        let _gate = self.subscribe_gate.lock().await;
        let url = self.checked(&request, false).map_err(EventError::invalid)?;
        let id = Self::identity(owner, &url, &request.arguments);
        self.remove(&id).map_err(EventError::internal)?;
        Ok(json!({}))
    }
    pub fn remove(&self, id: &str) -> Result<()> {
        if let Some(cancel) = self.workers.lock().map_err(safe)?.remove(id) {
            cancel.cancel();
        }
        self.db.remove_subscription(id)
    }
    pub async fn scan_once(&self, id: &str) -> Result<()> {
        let Some(sub) = self.get(id)? else {
            return Ok(());
        };
        if sub.expires <= now()
            || !self.auth.event_grant_active(&sub.owner)?
            || !self.source.available(&sub.filters.account_id)
        {
            self.remove(id)?;
            return Ok(());
        }
        if sub.paused {
            return Ok(());
        }
        let scan = tokio::time::timeout(
            Duration::from_secs(20),
            self.source.scan(&sub.filters, sub.validity, sub.uid),
        )
        .await
        .map_err(|_| Error("Event upstream timeout"))??;
        let mut messages = scan.messages;
        messages.retain(|message| message.uid > sub.uid);
        messages.sort_unstable_by_key(|message| message.uid);
        messages.dedup_by_key(|message| message.uid);
        let messages = messages.into_iter().map(|message| {
            let uid = message.uid;
            let stable = hash(serde_json::to_vec(&json!([sub.filters, scan.validity, uid])).map_err(safe)?);
            let event = format!("evt_{stable}");
            let body = serde_json::to_vec(&json!({"eventId":event,"name":EVENT,"timestamp":date(now()),"data":{"account_id":sub.filters.account_id,"mailbox":sub.filters.mailbox,"message_id":format!("imap_{stable}"),"uidvalidity":scan.validity,"uid":uid,"subject":message.subject,"from":message.from,"date":message.date},"cursor":null})).map_err(safe)?;
            Ok(PendingEvent {uid,id:event,body})
        }).collect::<Result<Vec<_>>>()?;
        if self.db.enqueue_scan(
            id,
            (sub.validity, sub.uid),
            (scan.validity, scan.next_uid),
            scan.scanned_to,
            &messages,
        )? {
            audit("scan", "queued", "new_uid");
        }
        Ok(())
    }
    pub async fn deliver_once(&self, id: &str) -> Result<bool> {
        let Some(sub) = self.get(id)? else {
            return Ok(false);
        };
        if sub.expires <= now() || !self.auth.event_grant_active(&sub.owner)? {
            self.remove(id)?;
            return Ok(false);
        }
        if sub.paused {
            return Ok(false);
        }
        let Some(item) = self.db.due_event(id)? else {
            return Ok(false);
        };
        let mail_bridge_store::events::OutboxItem {
            event,
            body,
            attempts,
        } = item;
        let headers = webhook::headers(
            &sub.secret,
            sub.previous.as_deref().filter(|_| sub.rotate_until > now()),
            &event,
            id,
            &body,
        )?;
        let reply = self.transport.post(&sub.url, headers, body).await;
        // Unsubscribe/revocation can cancel this future; never schedule new work
        // for a subscription removed while the request was in flight.
        if self.get(id)?.is_none() {
            return Ok(false);
        }
        let (accepted, retry, reason) = match reply {
            Ok(reply) if (200..300).contains(&reply.status) => (true, false, ""),
            Ok(reply) if reply.status == 410 => {
                self.remove(id)?;
                audit("deliver", "removed", "http_410");
                return Ok(false);
            }
            Ok(reply) if reply.status == 413 => (false, false, "http_4xx"),
            Ok(reply) if reply.status == 429 || reply.status >= 500 => (false, true, "http_5xx"),
            Ok(_) => (false, false, "http_4xx"),
            Err(error) => (false, true, error.0),
        };
        let failure = if accepted {
            None
        } else {
            let count = if retry { attempts + 1 } else { 5 };
            let backoff = [1, 4, 16, 60, 300][attempts.min(4) as usize];
            Some((count, now() + backoff, reason))
        };
        self.db.finish_delivery(id, &event, failure)?;
        audit(
            "deliver",
            if accepted {
                "accepted"
            } else if failure.is_some_and(|f| f.0 >= 5) {
                "paused"
            } else {
                "retry"
            },
            if accepted { "http_2xx" } else { reason },
        );
        Ok(true)
    }
    pub fn start(self: Arc<Self>, shutdown: CancellationToken) {
        tokio::spawn(async move {
            loop {
                let subscriptions = self.active().unwrap_or_default();
                for sub in subscriptions {
                    if sub.expires <= now()
                        || !self.auth.event_grant_active(&sub.owner).unwrap_or(false)
                        || !self.source.available(&sub.filters.account_id)
                    {
                        let _ = self.remove(&sub.id);
                        continue;
                    }
                    let mut workers = self.workers.lock().expect("worker lock");
                    if sub.paused {
                        if let Some(cancel) = workers.remove(&sub.id) {
                            cancel.cancel();
                        }
                        continue;
                    }
                    if workers.contains_key(&sub.id) {
                        continue;
                    }
                    let cancel = shutdown.child_token();
                    workers.insert(sub.id.clone(), cancel.clone());
                    let delivery = self.clone();
                    let deliver_id = sub.id.clone();
                    let delivery_cancel = cancel.clone();
                    tokio::spawn(async move {
                        loop {
                            let work = async {
                                if delivery.get(&deliver_id)?.is_none_or(|s| s.paused) {
                                    return Ok(false);
                                }
                                delivery.deliver_once(&deliver_id).await?;
                                Ok::<_, Error>(true)
                            };
                            let keep = tokio::select! {_=delivery_cancel.cancelled()=>break,result=work=>result.unwrap_or(true)};
                            if !keep {
                                break;
                            }
                            tokio::select! {_=delivery_cancel.cancelled()=>break,_=tokio::time::sleep(Duration::from_secs(1))=>{}}
                        }
                    });
                    let service = self.clone();
                    tokio::spawn(async move {
                        let mut backoff = 1;
                        loop {
                            let work = async {
                                service.scan_once(&sub.id).await?;
                                let current =
                                    service.get(&sub.id)?.ok_or(Error("Subscription ended"))?;
                                if current.paused {
                                    return Err(Error("Subscription paused"));
                                }
                                tokio::time::timeout(
                                    Duration::from_secs(40),
                                    service.source.wait(&current.filters),
                                )
                                .await
                                .map_err(|_| Error("Event wait timeout"))?
                            };
                            let result =
                                tokio::select! {_ = cancel.cancelled()=>break,result=work=>result};
                            if result.is_err() {
                                if service.get(&sub.id).ok().flatten().is_none() {
                                    break;
                                }
                                tokio::select! {_=cancel.cancelled()=>break,_=tokio::time::sleep(Duration::from_secs(backoff))=>{}};
                                backoff = (backoff * 2).min(60);
                            } else {
                                backoff = 1;
                                tokio::select! {_=cancel.cancelled()=>break,_=tokio::time::sleep(Duration::from_secs(1))=>{}}
                            }
                        }
                    });
                }
                tokio::select! {_=shutdown.cancelled()=>break,_=tokio::time::sleep(Duration::from_secs(1))=>{}}
            }
            if let Ok(mut workers) = self.workers.lock() {
                for (_, cancel) in workers.drain() {
                    cancel.cancel();
                }
            }
        });
    }
}
pub struct EventError {
    pub code: i32,
    pub message: &'static str,
    pub reason: Option<&'static str>,
}
impl EventError {
    fn invalid(_: Error) -> Self {
        Self {
            code: -32602,
            message: "Invalid event arguments or webhook destination",
            reason: None,
        }
    }
    fn internal(_: Error) -> Self {
        Self {
            code: -32603,
            message: "Event operation failed; private details suppressed",
            reason: None,
        }
    }
    fn forbidden() -> Self {
        Self {
            code: -32024,
            message: "Event access denied or account credential unavailable",
            reason: None,
        }
    }
    fn limit() -> Self {
        Self {
            code: -32025,
            message: "Event resource limit reached",
            reason: None,
        }
    }
    fn upstream(error: Error) -> Self {
        Self {
            code: -32603,
            message: "Could not establish mailbox baseline; existing OAuth remains valid. Retry the subscription after resolving the IMAP error.",
            reason: Some(match error.0 {
                "Missing UIDVALIDITY" => "imap_uidvalidity_missing",
                "Mailbox changed while establishing event baseline" => "imap_mailbox_changed",
                "IMAP UID space exhausted" => "imap_uid_exhausted",
                "Event baseline timeout" => "imap_baseline_timeout",
                "Subscription expired during refresh" => "subscription_expired",
                "IMAP authentication failed; details suppressed" => "imap_authentication_failed",
                _ => "imap_baseline_failed",
            }),
        }
    }
    // The OpenAI integration documents -32015; the linked draft currently
    // calls this -32027. This adapter follows the OpenAI-facing contract.
    fn callback(reason: &'static str) -> Self {
        Self {
            code: -32015,
            message: "Callback verification failed",
            reason: Some(reason),
        }
    }
}

impl From<SubscriptionRecord> for Subscription {
    fn from(row: SubscriptionRecord) -> Self {
        Self {
            id: row.id,
            owner: row.owner,
            filters: Filters {
                account_id: row.account,
                mailbox: row.mailbox,
            },
            url: row.url,
            secret: row.secret,
            previous: row.previous,
            rotate_until: row.rotate_until,
            expires: row.expires,
            validity: row.validity,
            uid: row.uid,
            truncated: row.truncated,
            paused: row.paused,
            last_error: row.last_error,
        }
    }
}
