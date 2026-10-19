//! Subscription arguments, lifecycle and callback verification.
use crate::{
    EVENT, Events, audit, date,
    source::Source,
    webhook::{self, Callback, SigningKey, Transport},
};
use mail_bridge_auth::Auth;
use mail_bridge_core::{
    Error, Result,
    account::{Account, Mailbox},
    safe,
};
use mail_bridge_store::{
    Db,
    events::{SubscriptionRecord, SubscriptionRefresh},
    hash, now,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use subtle::ConstantTimeEq;

/// Maximum simultaneously live subscriptions: two.
const MAX_SUBS: usize = 2;
/// Wire/product selection `AccountText × MailboxText`; parsed before starting source work.
#[derive(Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Filters {
    /// Explicit mailbox account selected by the external request.
    pub account_id: Account,
    /// Mailbox name before modified UTF-7 encoding.
    pub mailbox: Mailbox,
}
/// Untrusted webhook request product `Mode × URL × OptionalSecret`, parsed by subscription setup.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Delivery {
    /// External delivery mode; only webhook is accepted.
    pub mode: String,
    /// Callback URL used for subscription identity and delivery.
    pub url: String,
    /// Webhook signing secret/key; never included in event payloads.
    pub secret: Option<String>,
}
/// External event request product: event name, filters, delivery, cursor and lifetime hints.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Subscribe {
    /// External event name, restricted to message.created.
    pub name: String,
    /// Explicit account and mailbox filters for this subscription.
    pub arguments: Filters,
    /// Requested webhook destination and optional signing secret.
    pub delivery: Delivery,
    /// Optional external cursor; replay cursors are rejected for these events.
    pub cursor: Option<String>,
    /// Requested subscription lifetime, bounded before persistence.
    pub ttl_ms: Option<u64>,
    /// Reserved external age hint; this source always starts from the current baseline.
    pub max_age_ms: Option<u64>,
}
/// Owned persisted subscription snapshot with parsed current/previous signing keys.
///
/// Semantically identity, owner, filters, callback, expiry, generation/cursor and delivery status.
/// Snapshots are detached from persistence; updates go through store operations.
#[derive(Clone)]
pub struct Subscription {
    /// Stable identity of this account, subscription or queued event.
    pub id: String,
    /// Immutable independent owner credential; never serialized.
    pub owner: String,
    /// Explicit account/mailbox selection of the subscription.
    pub filters: Filters,
    /// Callback URL used for subscription identity and delivery.
    pub url: String,
    /// Webhook signing secret/key; never included in event payloads.
    pub secret: SigningKey,
    /// Previous signing key retained during a bounded rotation overlap.
    pub previous: Option<SigningKey>,
    /// Unix deadline after which the previous signing key is no longer used.
    pub rotate_until: i64,
    /// Unix expiry time checked before granting or starting work.
    pub expires: i64,
    /// Mailbox UIDVALIDITY; a changed value invalidates earlier UIDs.
    pub validity: u32,
    /// Message UID scoped to a mailbox generation.
    pub uid: u32,
    /// Whether delivery continuity was lost or a mailbox generation changed.
    pub truncated: bool,
    /// Whether terminal delivery failure has stopped background work.
    pub paused: bool,
    /// Last credential-safe delivery reason, absent after a successful refresh.
    pub last_error: Option<String>,
}
impl Events {
    /// Construct this component from its explicit dependencies.
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
            ids: ids
                .into_iter()
                .map(|id| id.parse())
                .collect::<Result<Box<[_]>>>()?,
            subscribe_gate: tokio::sync::Mutex::new(()),
            workers: Mutex::new(HashMap::new()),
            attempts: Mutex::new(HashMap::new()),
        })
    }
    /// Build the event catalog from the current bounded account set.
    pub fn catalog(&self) -> Value {
        let mut ids = self.ids.to_vec();
        if let Ok(runtime) = self.db.runtime_account_ids() {
            ids.extend(runtime);
            ids.sort();
            ids.dedup();
        }
        json!({"events":[{"name":EVENT,"description":"A newly observed IMAP message in one explicitly selected account/mailbox. Includes subject, sender and date headers; no body or attachments. No historical replay.","delivery":["webhook"],"inputSchema":{"type":"object","properties":{"account_id":{"type":"string","enum":ids},"mailbox":{"type":"string","minLength":1,"maxLength":512}},"required":["account_id","mailbox"],"additionalProperties":false},"payloadSchema":{"type":"object","properties":{"account_id":{"type":"string"},"mailbox":{"type":"string"},"message_id":{"type":"string"},"uid":{"type":"integer"},"uidvalidity":{"type":"integer"},"subject":{"type":["string","null"]},"from":{"type":"array","items":{"type":"object","properties":{"name":{"type":["string","null"]},"address":{"type":["string","null"]}},"required":["name","address"],"additionalProperties":false}},"date":{"type":["string","null"]}},"required":["account_id","mailbox","message_id","uid","uidvalidity"],"additionalProperties":false},"_meta":{"securitySchemes":[{"type":"oauth2","scopes":["mail:read"]}]}}]})
    }
    /// Parse and bind an external request to its registered account/callback policy.
    fn checked(&self, request: &Subscribe) -> Result<Callback> {
        if request.name != EVENT
            || request.delivery.mode != "webhook"
            || !(self.ids.contains(&request.arguments.account_id)
                || self
                    .db
                    .runtime_account_exists(request.arguments.account_id.as_str())?)
        {
            return Err(Error::Rejected("Invalid event or account"));
        }
        if request.cursor.is_some() {
            return Err(Error::Rejected(
                "This event does not support protocol replay",
            ));
        }
        Callback::parse(&request.delivery.url)
    }
    /// Derive a stable subscription identity from owner, callback and filters.
    pub fn identity(owner: &str, url: &str, filters: &Filters) -> String {
        format!(
            "sub_{}",
            hash(
                serde_json::to_vec(&json!([owner, url, EVENT, filters])).expect("static identity")
            )
        )
    }
    /// Read one persisted subscription and parse its signing keys.
    pub fn get(&self, id: &str) -> Result<Option<Subscription>> {
        self.db
            .subscription(id)?
            .map(Subscription::try_from)
            .transpose()
    }
    /// Read subscription snapshots used by the supervisor and refresh bound.
    pub fn active(&self) -> Result<Vec<Subscription>> {
        self.db
            .subscriptions()?
            .into_iter()
            .map(Subscription::try_from)
            .collect::<Result<_>>()
    }
    /// Verify callback ownership, establish a baseline and persist a bounded subscription.
    pub async fn subscribe(
        &self,
        owner: &str,
        request: Subscribe,
    ) -> std::result::Result<Value, EventError> {
        let _gate = self.subscribe_gate.lock().await;
        self.db
            .expire_verifications()
            .map_err(EventError::internal)?;
        let callback = self.checked(&request).map_err(EventError::invalid)?;
        let url = callback.as_str();
        let secret = request
            .delivery
            .secret
            .as_deref()
            .ok_or_else(|| EventError::invalid(Error::Rejected("Signing secret required")))?;
        let signing = SigningKey::parse(secret).map_err(EventError::invalid)?;
        if !self
            .auth
            .event_grant_active(owner)
            .map_err(EventError::internal)?
            || !self
                .source
                .available(&request.arguments.account_id)
                .map_err(EventError::internal)?
        {
            return Err(EventError::forbidden());
        }
        let id = Self::identity(owner, url, &request.arguments);
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
        let cached = self
            .db
            .callback_verified(owner, url)
            .map_err(EventError::internal)?;
        if !cached {
            let delay = {
                let mut attempts = self
                    .attempts
                    .lock()
                    .map_err(safe)
                    .map_err(EventError::internal)?;
                attempts.retain(|_, time| time.elapsed() < Duration::from_secs(300));
                let host = callback.host().to_owned();
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
                &signing,
                None,
                &format!("msg_verification_{}", mail_bridge_core::random()),
                &id,
                &body,
            )
            .map_err(EventError::invalid)?;
            let reply = self
                .transport
                .post(url, header, body)
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
                .verify_callback(owner, url)
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
                .map_err(|_| {
                    EventError::upstream(Error::Baseline(
                        mail_bridge_core::BaselineFailure::Timeout,
                    ))
                })?
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
        let record = SubscriptionRefresh {
            id: &id,
            owner,
            account: &request.arguments.account_id,
            mailbox: &request.arguments.mailbox,
            url,
            secret,
            expires,
        };
        let truncated = self
            .db
            .refresh_subscription(
                &record,
                snapshot.map(|s| (s.validity, s.next_uid.saturating_sub(1))),
            )
            .map_err(|error| {
                if matches!(error, Error::SubscriptionExpired) {
                    EventError::upstream(error)
                } else {
                    EventError::internal(error)
                }
            })?;
        Ok(
            json!({"id":id,"refreshBefore":date(expires),"cursor":null,"truncated":truncated,"deliveryStatus":{"active":true,"lastError":null}}),
        )
    }
    /// Resolve the caller-bound subscription identity and remove its pending work.
    pub async fn unsubscribe(
        &self,
        owner: &str,
        request: Subscribe,
    ) -> std::result::Result<Value, EventError> {
        let _gate = self.subscribe_gate.lock().await;
        let callback = self.checked(&request).map_err(EventError::invalid)?;
        let url = callback.as_str();
        let id = Self::identity(owner, url, &request.arguments);
        self.remove(&id).map_err(EventError::internal)?;
        Ok(json!({}))
    }
    /// Cancel registered workers, then atomically delete subscription and outbox state.
    pub fn remove(&self, id: &str) -> Result<()> {
        if let Some(cancel) = self.workers.lock().map_err(safe)?.remove(id) {
            cancel.cancel();
        }
        self.db.remove_subscription(id)
    }
}
/// Credential-safe MCP event error product `Code × Message × OptionalReason`.
/// Constructors map internal categories at the event protocol boundary.
pub struct EventError {
    /// Machine-readable MCP event error code.
    pub code: i32,
    /// Static credential-safe error presentation.
    pub message: &'static str,
    /// Stable machine-readable failure reason, independent of human wording.
    pub reason: Option<&'static str>,
}
impl EventError {
    /// Convert a rejected external request into the event protocol error category.
    fn invalid(_: Error) -> Self {
        Self {
            code: -32602,
            message: "Invalid event arguments or webhook destination",
            reason: None,
        }
    }
    /// Suppress private boundary details while reporting an internal event failure.
    fn internal(_: Error) -> Self {
        Self {
            code: -32603,
            message: "Event operation failed; private details suppressed",
            reason: None,
        }
    }
    /// Report unavailable credentials or missing event authorization.
    fn forbidden() -> Self {
        Self {
            code: -32024,
            message: "Event access denied or account credential unavailable",
            reason: None,
        }
    }
    /// Return the fixed page default or the bounded-resource error for this context.
    fn limit() -> Self {
        Self {
            code: -32025,
            message: "Event resource limit reached",
            reason: None,
        }
    }
    /// Map typed baseline failures to stable integration reasons.
    fn upstream(error: Error) -> Self {
        Self {
            code: -32603,
            message: "Could not establish mailbox baseline; existing OAuth remains valid. Retry the subscription after resolving the IMAP error.",
            reason: Some(match error {
                Error::Baseline(failure) => failure.reason(),
                Error::SubscriptionExpired => "subscription_expired",
                _ => "imap_baseline_failed",
            }),
        }
    }
    // The OpenAI integration documents -32015; the linked draft currently
    // calls this -32027. This adapter follows the OpenAI-facing contract.
    /// Report a credential-safe callback verification failure.
    fn callback(reason: &'static str) -> Self {
        Self {
            code: -32015,
            message: "Callback verification failed",
            reason: Some(reason),
        }
    }
}

impl TryFrom<SubscriptionRecord> for Subscription {
    /// Failure decoding a persisted signing key at the storage boundary.
    type Error = Error;
    /// Parse the external representation into this type, enforcing its invariants.
    fn try_from(row: SubscriptionRecord) -> Result<Self> {
        Ok(Self {
            id: row.id,
            owner: row.owner,
            filters: Filters {
                account_id: row.account.parse()?,
                mailbox: row.mailbox.parse()?,
            },
            url: row.url,
            secret: SigningKey::parse(&row.secret)?,
            previous: row.previous.as_deref().map(SigningKey::parse).transpose()?,
            rotate_until: row.rotate_until,
            expires: row.expires,
            validity: row.validity,
            uid: row.uid,
            truncated: row.truncated,
            paused: row.paused,
            last_error: row.last_error,
        })
    }
}
