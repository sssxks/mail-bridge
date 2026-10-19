//! Subscription records and transactional outbox operations.
//!
//! | Operation | Frequency | Complexity | Storage | Forbidden implementation |
//! | --- | --- | --- | --- | --- |
//! | Refresh | Subscription request | O(log s + pending deletes) | One transaction | Replace a cursor from an old snapshot |
//! | Queue scan | Each UID window | O(q + k log q + rendered bytes), q <= 128, k <= free slots | Transactional outbox | Render events that cannot fit |
//! | Finish delivery | Each attempt | O(log q) | Typed outcome and transaction | Partial retry/pause updates |
use crate::{Db, now};
use mail_bridge_core::{Error, Result, safe};
use rusqlite::{OptionalExtension, params};
use subtle::ConstantTimeEq;

/// Persisted subscription, independent of event protocol DTOs.
pub struct SubscriptionRecord {
    /// Stable identity of this account, subscription or queued event.
    pub id: String,
    /// Immutable independent owner credential; never serialized.
    pub owner: String,
    /// Mailbox account to which the persisted record belongs.
    pub account: String,
    /// Mailbox name before modified UTF-7 encoding.
    pub mailbox: String,
    /// Callback URL used for subscription identity and delivery.
    pub url: String,
    /// Webhook signing secret/key; never included in event payloads.
    pub secret: String,
    /// Previous signing key retained during a bounded rotation overlap.
    pub previous: Option<String>,
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

/// A rendered event and its IMAP UID, ready for bounded outbox insertion.
pub struct PendingEvent {
    /// Message UID scoped to a mailbox generation.
    pub uid: u32,
    /// Stable identity of this account, subscription or queued event.
    pub id: String,
    /// Owned outgoing content, queued JSON bytes or bounded response bytes.
    pub body: Vec<u8>,
}

/// One due delivery attempt.
pub struct OutboxItem {
    /// Stable event identity preserved across retry attempts.
    pub event: String,
    /// Owned outgoing content, queued JSON bytes or bounded response bytes.
    pub body: Vec<u8>,
    /// Completed delivery failures or bounded callback-attempt history.
    pub attempts: Attempts,
}

/// Explicit subscription select-column order consumed by the row decoder.
const COLUMNS: &str = "id,owner,account,mailbox,url,secret,previous,rotate_until,expires,validity,uid,truncated,paused,last_error";

/// Decode the persisted subscription column order into an owned record.
fn row(r: &rusqlite::Row<'_>) -> rusqlite::Result<SubscriptionRecord> {
    Ok(SubscriptionRecord {
        id: r.get(0)?,
        owner: r.get(1)?,
        account: r.get(2)?,
        mailbox: r.get(3)?,
        url: r.get(4)?,
        secret: r.get(5)?,
        previous: r.get(6)?,
        rotate_until: r.get(7)?,
        expires: r.get(8)?,
        validity: r.get(9)?,
        uid: r.get(10)?,
        truncated: r.get(11)?,
        paused: r.get(12)?,
        last_error: r.get(13)?,
    })
}

impl Db {
    /// Initialize optional event state when events are enabled.
    pub fn init_events(&self) -> Result<()> {
        self.0.lock().map_err(safe)?.execute_batch("
            CREATE TABLE IF NOT EXISTS event_subscriptions(id TEXT PRIMARY KEY,owner TEXT,account TEXT,mailbox TEXT,url TEXT,secret TEXT,previous TEXT,rotate_until INTEGER,expires INTEGER,validity INTEGER,uid INTEGER,truncated INTEGER,last_error TEXT,paused INTEGER NOT NULL DEFAULT 0);
            CREATE TABLE IF NOT EXISTS event_outbox(sub TEXT,event TEXT,body BLOB,attempts INTEGER,next_attempt INTEGER,PRIMARY KEY(sub,event));
            CREATE TABLE IF NOT EXISTS event_verifications(owner TEXT,url TEXT,expires INTEGER,PRIMARY KEY(owner,url));
        ").map_err(safe)
    }

    /// Read one subscription.
    pub fn subscription(&self, id: &str) -> Result<Option<SubscriptionRecord>> {
        self.0
            .lock()
            .map_err(safe)?
            .query_row(
                &format!("SELECT {COLUMNS} FROM event_subscriptions WHERE id=?"),
                [id],
                row,
            )
            .optional()
            .map_err(safe)
    }

    /// Read the bounded subscription set.
    pub fn subscriptions(&self) -> Result<Vec<SubscriptionRecord>> {
        let db = self.0.lock().map_err(safe)?;
        let mut query = db
            .prepare(&format!("SELECT {COLUMNS} FROM event_subscriptions"))
            .map_err(safe)?;
        query
            .query_map([], row)
            .map_err(safe)?
            .collect::<rusqlite::Result<_>>()
            .map_err(safe)
    }

    /// Expire callback verification cache entries.
    pub fn expire_verifications(&self) -> Result<()> {
        self.0
            .lock()
            .map_err(safe)?
            .execute("DELETE FROM event_verifications WHERE expires<=?", [now()])
            .map_err(safe)?;
        Ok(())
    }

    /// Whether this owner recently verified this exact callback URL.
    pub fn callback_verified(&self, owner: &str, url: &str) -> Result<bool> {
        Ok(self
            .0
            .lock()
            .map_err(safe)?
            .query_row(
                "SELECT expires FROM event_verifications WHERE owner=? AND url=?",
                params![owner, url],
                |r| r.get::<_, i64>(0),
            )
            .optional()
            .map_err(safe)?
            .is_some_and(|expires| expires > now()))
    }

    /// Cache successful callback verification for five minutes.
    pub fn verify_callback(&self, owner: &str, url: &str) -> Result<()> {
        self.0
            .lock()
            .map_err(safe)?
            .execute(
                "INSERT OR REPLACE INTO event_verifications VALUES (?,?,?)",
                params![owner, url, now() + 300],
            )
            .map_err(safe)?;
        Ok(())
    }

    /// Refresh from the latest cursor, rotate secrets, or start a new baseline atomically.
    /// `baseline` contains UIDVALIDITY and the last UID preceding the subscription.
    pub fn refresh_subscription(
        &self,
        record: &SubscriptionRefresh<'_>,
        baseline: Option<(u32, u32)>,
    ) -> Result<bool> {
        let mut db = self.0.lock().map_err(safe)?;
        let tx = db.transaction().map_err(safe)?;
        let old = tx
            .query_row(
                &format!("SELECT {COLUMNS} FROM event_subscriptions WHERE id=?"),
                [&record.id],
                row,
            )
            .optional()
            .map_err(safe)?
            .filter(|s| s.expires > now());
        let (validity, uid, previous, rotate_until, truncated) = if let Some(old) = old {
            let rotated = !bool::from(old.secret.as_bytes().ct_eq(record.secret.as_bytes()));
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
            let (validity, uid) = baseline.ok_or(Error::SubscriptionExpired)?;
            tx.execute("DELETE FROM event_outbox WHERE sub=?", [&record.id])
                .map_err(safe)?;
            (validity, uid, None, 0, false)
        };
        tx.execute(
            "INSERT OR REPLACE INTO event_subscriptions VALUES (?,?,?,?,?,?,?,?,?,?,?,?,NULL,0)",
            params![
                record.id,
                record.owner,
                record.account,
                record.mailbox,
                record.url,
                record.secret,
                previous,
                rotate_until,
                record.expires,
                validity,
                uid,
                truncated
            ],
        )
        .map_err(safe)?;
        tx.commit().map_err(safe)?;
        Ok(truncated)
    }

    /// Delete a subscription and all its pending events in one transaction.
    pub fn remove_subscription(&self, id: &str) -> Result<()> {
        let mut db = self.0.lock().map_err(safe)?;
        let tx = db.transaction().map_err(safe)?;
        tx.execute("DELETE FROM event_outbox WHERE sub=?", [id])
            .map_err(safe)?;
        tx.execute("DELETE FROM event_subscriptions WHERE id=?", [id])
            .map_err(safe)?;
        tx.commit().map_err(safe)
    }

    /// Enqueue an observed UID window and advance its cursor in the same transaction.
    /// Stale scans are ignored; the queue holds at most 128 events per subscription.
    pub fn enqueue_scan(
        &self,
        id: &str,
        expected: (u32, u32),
        observed: (u32, u32),
        scanned_to: u32,
        messages: impl ExactSizeIterator<Item = Result<PendingEvent>>,
    ) -> Result<bool> {
        let mut db = self.0.lock().map_err(safe)?;
        let tx = db.transaction().map_err(safe)?;
        let current = tx
            .query_row(
                "SELECT validity,uid FROM event_subscriptions WHERE id=?",
                [id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(safe)?;
        if current != Some(expected) {
            return Ok(false);
        }
        if observed.0 != expected.0 {
            tx.execute("UPDATE event_subscriptions SET validity=?,uid=?,truncated=1,last_error='uidvalidity_changed' WHERE id=?",params![observed.0,observed.1.saturating_sub(1),id]).map_err(safe)?;
            tx.commit().map_err(safe)?;
            return Ok(false);
        }
        let pending: i64 = tx
            .query_row("SELECT count(*) FROM event_outbox WHERE sub=?", [id], |r| {
                r.get(0)
            })
            .map_err(safe)?;
        let available = (128 - pending).max(0) as usize;
        let mut watermark = expected.1;
        let message_count = messages.len();
        for message in messages.take(available) {
            let message = message?;
            tx.execute(
                "INSERT OR IGNORE INTO event_outbox VALUES (?,?,?,0,?)",
                params![id, message.id, message.body, now()],
            )
            .map_err(safe)?;
            watermark = message.uid;
        }
        if message_count <= available {
            watermark = watermark.max(scanned_to);
        }
        tx.execute(
            "UPDATE event_subscriptions SET uid=? WHERE id=?",
            params![watermark, id],
        )
        .map_err(safe)?;
        tx.commit().map_err(safe)?;
        Ok(message_count > 0 && available > 0)
    }

    /// Read the first due event without holding a lock during the HTTP request.
    pub fn due_event(&self, id: &str) -> Result<Option<OutboxItem>> {
        self.0.lock().map_err(safe)?.query_row("SELECT event,body,attempts FROM event_outbox WHERE sub=? AND next_attempt<=? AND attempts<5 ORDER BY rowid LIMIT 1",params![id,now()],|r|Ok(OutboxItem {event:r.get(0)?,body:r.get(1)?,attempts:Attempts::from_sql(r.get(2)?)?})).optional().map_err(safe)
    }

    /// Commit a delivery acknowledgement or one valid retry/pause transition.
    pub fn finish_delivery(
        &self,
        id: &str,
        event: &str,
        outcome: DeliveryOutcome<'_>,
    ) -> Result<()> {
        let mut db = self.0.lock().map_err(safe)?;
        let tx = db.transaction().map_err(safe)?;
        match outcome {
            DeliveryOutcome::Accepted => {
                tx.execute(
                    "DELETE FROM event_outbox WHERE sub=? AND event=?",
                    params![id, event],
                )
                .map_err(safe)?;
            }
            DeliveryOutcome::Paused { reason } => {
                tx.execute(
                    "DELETE FROM event_outbox WHERE sub=? AND event=?",
                    params![id, event],
                )
                .map_err(safe)?;
                tx.execute(
                    "UPDATE event_subscriptions SET last_error=?,truncated=1,paused=1 WHERE id=?",
                    params![reason, id],
                )
                .map_err(safe)?;
            }
            DeliveryOutcome::Retry {
                attempt,
                at,
                reason,
            } => {
                tx.execute(
                    "UPDATE event_outbox SET attempts=?,next_attempt=? WHERE sub=? AND event=?",
                    params![attempt.0, at, id, event],
                )
                .map_err(safe)?;
                tx.execute(
                    "UPDATE event_subscriptions SET last_error=? WHERE id=?",
                    params![reason, id],
                )
                .map_err(safe)?;
            }
        }
        tx.commit().map_err(safe)
    }
}

/// Only the fields a refresh operation can replace; cursor and rotation state stay in storage.
pub struct SubscriptionRefresh<'a> {
    /// Stable identity of this account, subscription or queued event.
    pub id: &'a str,
    /// Immutable independent owner credential; never serialized.
    pub owner: &'a str,
    /// Mailbox account to which the persisted record belongs.
    pub account: &'a str,
    /// Mailbox name before modified UTF-7 encoding.
    pub mailbox: &'a str,
    /// Callback URL used for subscription identity and delivery.
    pub url: &'a str,
    /// Webhook signing secret/key; never included in event payloads.
    pub secret: &'a str,
    /// Unix expiry time checked before granting or starting work.
    pub expires: i64,
}
/// Completed failed attempts in `[0,4]`; SQL decoding excludes invalid counters.
pub struct Attempts(u8);
impl Attempts {
    /// Decode a delivery counter and reject values outside the five-attempt budget.
    fn from_sql(value: u8) -> rusqlite::Result<Self> {
        if value < 5 {
            Ok(Self(value))
        } else {
            Err(rusqlite::Error::IntegralValueOutOfRange(
                2,
                i64::from(value),
            ))
        }
    }
    /// The next retry in `[1,4]`, or exhaustion after the fifth failure.
    pub fn next_retry(&self) -> Option<RetryAttempt> {
        (self.0 < 4).then_some(RetryAttempt(self.0 + 1))
    }
    /// Delay corresponding to the current failed attempt counter.
    pub fn backoff(&self) -> i64 {
        [1, 4, 16, 60, 300][usize::from(self.0)]
    }
}
/// A retry ordinal in `[1,4]`, constructed only from a valid current counter.
pub struct RetryAttempt(u8);
/// `Accepted | Retry(valid ordinal, deadline, reason) | Paused(reason)`.
pub enum DeliveryOutcome<'a> {
    /// The callback accepted the event; delete its pending outbox entry.
    Accepted,
    /// A valid remaining retry with a deadline and safe failure reason.
    Retry {
        /// A valid retry ordinal in the range 1–4.
        attempt: RetryAttempt,
        /// Unix deadline for the next delivery attempt.
        at: i64,
        /// Stable machine-readable failure reason, independent of human wording.
        reason: &'a str,
    },
    /// Retry budget is exhausted or failure is terminal; pause the subscription.
    Paused {
        /// Stable machine-readable failure reason, independent of human wording.
        reason: &'a str,
    },
}
