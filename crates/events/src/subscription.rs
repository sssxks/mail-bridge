//! Subscription arguments, lifecycle and callback verification.
use crate::{
    EVENT, Events, audit, date,
    source::Source,
    webhook::{self, Transport},
};
use mail_bridge_auth::Auth;
use mail_bridge_core::{Error, Result, safe};
use mail_bridge_store::{Db, events::SubscriptionRecord, hash, now};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use subtle::ConstantTimeEq;

const MAX_SUBS: usize = 2;
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
                >= MAX_SUBS
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
