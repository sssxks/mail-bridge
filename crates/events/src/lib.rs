//! Mail subscriptions, IMAP observation and webhook delivery.
pub mod message;
pub mod source;
pub mod subscription;
pub mod webhook;
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

const EVENT: &str = "message.created";
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

pub struct Events {
    db: Db,
    auth: Arc<Auth>,
    source: Arc<dyn Source>,
    transport: Arc<dyn Transport>,
    ids: Vec<String>,
    subscribe_gate: tokio::sync::Mutex<()>,
    pub workers: Mutex<HashMap<String, CancellationToken>>,
    attempts: Mutex<HashMap<String, Instant>>,
}
