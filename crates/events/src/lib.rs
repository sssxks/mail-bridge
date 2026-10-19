//! Mail subscriptions, IMAP observation and webhook delivery.
/// Implementation of message within this crate.
pub mod message;
/// Implementation of source within this crate.
pub mod source;
/// Implementation of subscription within this crate.
pub mod subscription;
/// Implementation of webhook within this crate.
pub mod webhook;
/// Implementation of worker within this crate.
mod worker;

use mail_bridge_auth::Auth;
use mail_bridge_store::{Db, now};
use source::Source;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Instant,
};
use tokio_util::sync::CancellationToken;
use webhook::Transport;

/// The sole supported event name: message.created.
const EVENT: &str = "message.created";
/// Safe operational breadcrumb: callers supply static categories, never payloads.
pub fn audit(action: &'static str, status: &'static str, reason: &'static str) {
    eprintln!(
        "mail_event time={} action={action} status={status} reason={reason}",
        date(now())
    );
}
/// Format a bounded Unix timestamp as an RFC3339 UTC value.
pub fn date(seconds: i64) -> String {
    chrono::DateTime::from_timestamp(seconds, 0)
        .expect("bounded timestamp")
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// Event coordinator with persistent subscriptions and bounded worker bookkeeping.
///
/// Semantically `Store × Auth × Source × Transport × WorkerMap × CallbackAttempts`.
/// Mutable bookkeeping remains behind the existing synchronization primitives.
pub struct Events {
    /// Shared handle to the private SQLite persistence boundary.
    db: Db,
    /// Authorization service used to resolve current grants.
    auth: Arc<Auth>,
    /// Event source used for baselines, bounded scans and waiting.
    source: Arc<dyn Source>,
    /// Webhook transport with destination and response bounds.
    transport: Arc<dyn Transport>,
    /// Additional immutable account identities supplied by the host.
    ids: Box<[mail_bridge_core::account::Account]>,
    /// Serializes callback verification and subscription updates.
    subscribe_gate: tokio::sync::Mutex<()>,
    /// Subscription identity to cancellation-token map for active worker groups.
    workers: Mutex<HashMap<String, CancellationToken>>,
    /// Completed delivery failures or bounded callback-attempt history.
    attempts: Mutex<HashMap<String, Instant>>,
}

impl Events {
    /// Number of registered subscription worker groups.
    pub fn worker_count(&self) -> mail_bridge_core::Result<usize> {
        Ok(self.workers.lock().map_err(mail_bridge_core::safe)?.len())
    }
}
