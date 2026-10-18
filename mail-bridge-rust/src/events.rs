//! ChatGPT's webhook subset of MCP Events. No polling/SSE delivery API.
use crate::{
    Error, Result,
    auth::Auth,
    db::{Db, hash, now},
    mail::{RealBackend, utf7_encode},
    safe,
    webhook::{self, Transport},
};
use futures_util::future::BoxFuture;
use rusqlite::{OptionalExtension, params};
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
    pub uids: Vec<u32>,
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
    fn account(&self, id: &str) -> Result<RealBackend> {
        let account = self
            .db
            .runtime_accounts()?
            .into_iter()
            .find(|a| a.id == id)
            .ok_or(Error("Account unavailable for events"))?;
        Ok(RealBackend {
            config: account.config,
            password: account
                .password
                .ok_or(Error("Account unavailable for events"))?,
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
            let selected = session
                .examine(utf7_encode(&f.mailbox))
                .await
                .map_err(safe)?;
            let snapshot = Snapshot {
                validity: selected.uid_validity.ok_or(Error("Missing UIDVALIDITY"))?,
                next_uid: selected.uid_next.ok_or(Error("Missing UIDNEXT"))?,
            };
            let _ = session.logout().await;
            Ok(snapshot)
        })
    }
    fn scan<'a>(&'a self, f: &'a Filters, validity: u32, uid: u32) -> BoxFuture<'a, Result<Scan>> {
        Box::pin(async move {
            let mut session = self.account(&f.account_id)?.connect().await?;
            let selected = session
                .examine(utf7_encode(&f.mailbox))
                .await
                .map_err(safe)?;
            let current = selected.uid_validity.ok_or(Error("Missing UIDVALIDITY"))?;
            let next = selected.uid_next.ok_or(Error("Missing UIDNEXT"))?;
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
            let _ = session.logout().await;
            Ok(Scan {
                validity: current,
                next_uid: next,
                uids,
                scanned_to: end,
            })
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
        db.0.lock().map_err(safe)?.execute_batch("
            CREATE TABLE IF NOT EXISTS event_subscriptions(id TEXT PRIMARY KEY,owner TEXT,account TEXT,mailbox TEXT,url TEXT,secret TEXT,previous TEXT,rotate_until INTEGER,expires INTEGER,validity INTEGER,uid INTEGER,truncated INTEGER,last_error TEXT,paused INTEGER NOT NULL DEFAULT 0);
            CREATE TABLE IF NOT EXISTS event_outbox(sub TEXT,event TEXT,body BLOB,attempts INTEGER,next_attempt INTEGER,PRIMARY KEY(sub,event));
            CREATE TABLE IF NOT EXISTS event_verifications(owner TEXT,url TEXT,expires INTEGER,PRIMARY KEY(owner,url));
        ").map_err(safe)?;
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
        json!({"events":[{"name":EVENT,"description":"A newly observed IMAP message in one explicitly selected account/mailbox. No body, subject or sender is pushed. No historical replay.","delivery":["webhook"],"inputSchema":{"type":"object","properties":{"account_id":{"type":"string","enum":ids},"mailbox":{"type":"string","minLength":1,"maxLength":512}},"required":["account_id","mailbox"],"additionalProperties":false},"payloadSchema":{"type":"object","properties":{"account_id":{"type":"string"},"mailbox":{"type":"string"},"message_id":{"type":"string"},"uid":{"type":"integer"},"uidvalidity":{"type":"integer"}},"required":["account_id","mailbox","message_id","uid","uidvalidity"],"additionalProperties":false},"_meta":{"securitySchemes":[{"type":"oauth2","scopes":["mail:read","mail:events"]}]}}]})
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
        crate::clean(&request.arguments.mailbox, 512)?;
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
    fn row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Subscription> {
        Ok(Subscription {
            id: row.get(0)?,
            owner: row.get(1)?,
            filters: Filters {
                account_id: row.get(2)?,
                mailbox: row.get(3)?,
            },
            url: row.get(4)?,
            secret: row.get(5)?,
            previous: row.get(6)?,
            rotate_until: row.get(7)?,
            expires: row.get(8)?,
            validity: row.get(9)?,
            uid: row.get(10)?,
            truncated: row.get(11)?,
            paused: row.get(12)?,
            last_error: row.get(13)?,
        })
    }
    pub fn get(&self, id: &str) -> Result<Option<Subscription>> {
        self.db.0.lock().map_err(safe)?.query_row("SELECT id,owner,account,mailbox,url,secret,previous,rotate_until,expires,validity,uid,truncated,paused,last_error FROM event_subscriptions WHERE id=?",[id],Self::row).optional().map_err(safe)
    }
    pub fn active(&self) -> Result<Vec<Subscription>> {
        let db = self.db.0.lock().map_err(safe)?;
        let mut query=db.prepare("SELECT id,owner,account,mailbox,url,secret,previous,rotate_until,expires,validity,uid,truncated,paused,last_error FROM event_subscriptions").map_err(safe)?;
        query
            .query_map([], Self::row)
            .map_err(safe)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(safe)
    }
    pub async fn subscribe(
        &self,
        owner: &str,
        request: Subscribe,
    ) -> std::result::Result<Value, EventError> {
        let _gate = self.subscribe_gate.lock().await;
        self.db
            .0
            .lock()
            .map_err(safe)
            .map_err(EventError::internal)?
            .execute("DELETE FROM event_verifications WHERE expires<=?", [now()])
            .map_err(safe)
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
            .0
            .lock()
            .map_err(safe)
            .map_err(EventError::internal)?
            .query_row(
                "SELECT expires FROM event_verifications WHERE owner=? AND url=?",
                params![owner, url],
                |r| r.get::<_, i64>(0),
            )
            .optional()
            .map_err(safe)
            .map_err(EventError::internal)?
            .is_some_and(|expires| expires > now());
        if !cached {
            {
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
                if attempts
                    .get(&host)
                    .is_some_and(|time| time.elapsed() < Duration::from_secs(2))
                {
                    return Err(EventError::limit());
                }
                if attempts.len() > 128 {
                    return Err(EventError::limit());
                }
                attempts.insert(host, Instant::now());
            }
            let challenge = crate::auth::random();
            let body = serde_json::to_vec(&json!({"type":"verification","challenge":challenge}))
                .map_err(safe)
                .map_err(EventError::internal)?;
            let header = webhook::headers(
                secret,
                None,
                &format!("msg_verification_{}", crate::auth::random()),
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
                .0
                .lock()
                .map_err(safe)
                .map_err(EventError::internal)?
                .execute(
                    "INSERT OR REPLACE INTO event_verifications VALUES (?,?,?)",
                    params![owner, url, now() + 300],
                )
                .map_err(safe)
                .map_err(EventError::internal)?;
        }
        let snapshot = if old.is_none() {
            Some(
                tokio::time::timeout(
                    Duration::from_secs(15),
                    self.source.snapshot(&request.arguments),
                )
                .await
                .map_err(|_| EventError::upstream())?
                .map_err(|_| EventError::upstream())?,
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
        // Workers may have advanced the cursor during callback verification.
        // Read the latest row and replace it under the same database lock.
        let db = self
            .db
            .0
            .lock()
            .map_err(safe)
            .map_err(EventError::internal)?;
        let old=db.query_row("SELECT id,owner,account,mailbox,url,secret,previous,rotate_until,expires,validity,uid,truncated,paused,last_error FROM event_subscriptions WHERE id=?",[&id],Self::row).optional().map_err(safe).map_err(EventError::internal)?.filter(|s|s.expires>now());
        let (validity, uid, previous, rotate_until, truncated) = if let Some(old) = old {
            let rotated = !bool::from(old.secret.as_bytes().ct_eq(secret.as_bytes()));
            (
                old.validity,
                old.uid,
                if rotated {
                    Some(old.secret)
                } else {
                    old.previous
                },
                if rotated {
                    now() + 300
                } else {
                    old.rotate_until
                },
                old.truncated,
            )
        } else {
            let snapshot = snapshot.ok_or_else(EventError::upstream)?;
            // An expired identity starts from now; its old pending deliveries
            // must not leak into a newly granted subscription.
            db.execute("DELETE FROM event_outbox WHERE sub=?", [&id])
                .map_err(safe)
                .map_err(EventError::internal)?;
            (
                snapshot.validity,
                snapshot.next_uid.saturating_sub(1),
                None,
                0,
                false,
            )
        };
        db.execute(
            "INSERT OR REPLACE INTO event_subscriptions VALUES (?,?,?,?,?,?,?,?,?,?,?,?,NULL,0)",
            params![
                id,
                owner,
                request.arguments.account_id,
                request.arguments.mailbox,
                url,
                secret,
                previous,
                rotate_until,
                expires,
                validity,
                uid,
                truncated
            ],
        )
        .map_err(safe)
        .map_err(EventError::internal)?;
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
        let mut db = self.db.0.lock().map_err(safe)?;
        let tx = db.transaction().map_err(safe)?;
        tx.execute("DELETE FROM event_outbox WHERE sub=?", [id])
            .map_err(safe)?;
        tx.execute("DELETE FROM event_subscriptions WHERE id=?", [id])
            .map_err(safe)?;
        tx.commit().map_err(safe)?;
        Ok(())
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
        let mut db = self.db.0.lock().map_err(safe)?;
        let tx = db.transaction().map_err(safe)?;
        let current: Option<(u32, u32)> = tx
            .query_row(
                "SELECT validity,uid FROM event_subscriptions WHERE id=?",
                [id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(safe)?;
        if current != Some((sub.validity, sub.uid)) {
            return Ok(());
        }
        if scan.validity != sub.validity {
            // OpenAI does not support gap control webhooks. Report truncation on
            // refresh, start at the new current UIDNEXT, never flood old mail.
            tx.execute("UPDATE event_subscriptions SET validity=?,uid=?,truncated=1,last_error='uidvalidity_changed' WHERE id=?",params![scan.validity,scan.next_uid.saturating_sub(1),id]).map_err(safe)?;
            tx.commit().map_err(safe)?;
            return Ok(());
        }
        let pending: i64 = tx
            .query_row("SELECT count(*) FROM event_outbox WHERE sub=?", [id], |r| {
                r.get(0)
            })
            .map_err(safe)?;
        let available = (MAX_QUEUE - pending).max(0) as usize;
        let mut uids = scan.uids;
        uids.retain(|uid| *uid > sub.uid);
        uids.sort_unstable();
        uids.dedup();
        let mut watermark = sub.uid;
        for uid in uids.iter().take(available) {
            let stable =
                hash(serde_json::to_vec(&json!([sub.filters, scan.validity, uid])).map_err(safe)?);
            let event = format!("evt_{stable}");
            let body=serde_json::to_vec(&json!({"eventId":event,"name":EVENT,"timestamp":date(now()),"data":{"account_id":sub.filters.account_id,"mailbox":sub.filters.mailbox,"message_id":format!("imap_{stable}"),"uidvalidity":scan.validity,"uid":uid},"cursor":null})).map_err(safe)?;
            tx.execute(
                "INSERT OR IGNORE INTO event_outbox VALUES (?,?,?,0,?)",
                params![id, event, body, now()],
            )
            .map_err(safe)?;
            watermark = *uid;
        }
        if uids.len() <= available {
            watermark = watermark.max(scan.scanned_to);
        }
        tx.execute(
            "UPDATE event_subscriptions SET uid=? WHERE id=?",
            params![watermark, id],
        )
        .map_err(safe)?;
        tx.commit().map_err(safe)?;
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
        let item:Option<(String,Vec<u8>,i64)>=self.db.0.lock().map_err(safe)?.query_row("SELECT event,body,attempts FROM event_outbox WHERE sub=? AND next_attempt<=? AND attempts<5 ORDER BY rowid LIMIT 1",params![id,now()],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional().map_err(safe)?;
        let Some((event, body, attempts)) = item else {
            return Ok(false);
        };
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
                return Ok(false);
            }
            Ok(reply) if reply.status == 413 => (false, false, "http_4xx"),
            Ok(reply) if reply.status == 429 || reply.status >= 500 => (false, true, "http_5xx"),
            Ok(_) => (false, false, "http_4xx"),
            Err(error) => (false, true, error.0),
        };
        let db = self.db.0.lock().map_err(safe)?;
        if accepted {
            db.execute(
                "DELETE FROM event_outbox WHERE sub=? AND event=?",
                params![id, event],
            )
            .map_err(safe)?;
        } else {
            let count = if retry { attempts + 1 } else { 5 };
            let backoff = [1, 4, 16, 60, 300][attempts.min(4) as usize];
            if count >= 5 {
                db.execute(
                    "DELETE FROM event_outbox WHERE sub=? AND event=?",
                    params![id, event],
                )
                .map_err(safe)?;
                db.execute(
                    "UPDATE event_subscriptions SET last_error=?,truncated=1,paused=1 WHERE id=?",
                    params![reason, id],
                )
                .map_err(safe)?;
            } else {
                db.execute(
                    "UPDATE event_outbox SET attempts=?,next_attempt=? WHERE sub=? AND event=?",
                    params![count, now() + backoff, id, event],
                )
                .map_err(safe)?;
                db.execute(
                    "UPDATE event_subscriptions SET last_error=? WHERE id=?",
                    params![reason, id],
                )
                .map_err(safe)?;
            }
        }
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
    fn upstream() -> Self {
        Self {
            code: -32603,
            message: "Could not establish mailbox baseline",
            reason: None,
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
    pub fn rpc(self) -> rmcp::ErrorData {
        rmcp::ErrorData::new(
            rmcp::model::ErrorCode(self.code),
            self.message,
            self.reason.map(|reason| json!({"reason":reason})),
        )
    }
}
