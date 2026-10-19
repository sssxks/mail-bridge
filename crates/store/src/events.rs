//! Subscription records and transactional outbox operations.
use crate::{Db, now};
use mail_bridge_core::{Error, Result, safe};
use rusqlite::{OptionalExtension, params};
use subtle::ConstantTimeEq;

/// Persisted subscription, independent of event protocol DTOs.
pub struct SubscriptionRecord {
    pub id: String,
    pub owner: String,
    pub account: String,
    pub mailbox: String,
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

/// A rendered event and its IMAP UID, ready for bounded outbox insertion.
pub struct PendingEvent {
    pub uid: u32,
    pub id: String,
    pub body: Vec<u8>,
}

/// One due delivery attempt.
pub struct OutboxItem {
    pub event: String,
    pub body: Vec<u8>,
    pub attempts: i64,
}

const COLUMNS: &str = "id,owner,account,mailbox,url,secret,previous,rotate_until,expires,validity,uid,truncated,paused,last_error";

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
        record: &SubscriptionRecord,
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
            let (validity, uid) = baseline.ok_or(Error("Subscription expired during refresh"))?;
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
        messages: &[PendingEvent],
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
        for message in messages.iter().take(available) {
            tx.execute(
                "INSERT OR IGNORE INTO event_outbox VALUES (?,?,?,0,?)",
                params![id, message.id, message.body, now()],
            )
            .map_err(safe)?;
            watermark = message.uid;
        }
        if messages.len() <= available {
            watermark = watermark.max(scanned_to);
        }
        tx.execute(
            "UPDATE event_subscriptions SET uid=? WHERE id=?",
            params![watermark, id],
        )
        .map_err(safe)?;
        tx.commit().map_err(safe)?;
        Ok(!messages.is_empty() && available > 0)
    }

    /// Read the first due event without holding a lock during the HTTP request.
    pub fn due_event(&self, id: &str) -> Result<Option<OutboxItem>> {
        self.0.lock().map_err(safe)?.query_row("SELECT event,body,attempts FROM event_outbox WHERE sub=? AND next_attempt<=? AND attempts<5 ORDER BY rowid LIMIT 1",params![id,now()],|r|Ok(OutboxItem {event:r.get(0)?,body:r.get(1)?,attempts:r.get(2)?})).optional().map_err(safe)
    }

    /// Commit delivery acknowledgement or retry/pause state together.
    pub fn finish_delivery(
        &self,
        id: &str,
        event: &str,
        failure: Option<(i64, i64, &str)>,
    ) -> Result<()> {
        let mut db = self.0.lock().map_err(safe)?;
        let tx = db.transaction().map_err(safe)?;
        match failure {
            None => {
                tx.execute(
                    "DELETE FROM event_outbox WHERE sub=? AND event=?",
                    params![id, event],
                )
                .map_err(safe)?;
            }
            Some((count, _, reason)) if count >= 5 => {
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
            Some((count, next, reason)) => {
                tx.execute(
                    "UPDATE event_outbox SET attempts=?,next_attempt=? WHERE sub=? AND event=?",
                    params![count, next, id, event],
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
