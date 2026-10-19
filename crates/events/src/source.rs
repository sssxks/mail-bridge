//! IMAP event baselines, bounded header scans and IDLE waiting.
use crate::{message::MessageSummary, subscription::Filters};
use futures_util::{TryStreamExt, future::BoxFuture};
use mail_bridge_core::{Error, Result, safe};
use mail_bridge_mail::{backend::RealBackend, imap::utf7_encode};
use mail_bridge_store::Db;
use std::time::Duration;

/// Maximum header batch/outbox capacity per subscription: 128.
const MAX_QUEUE: usize = 128;
/// `UIDVALIDITY × UIDNEXT` observed when selecting a mailbox; the baseline starts from now.
pub struct Snapshot {
    /// Mailbox UIDVALIDITY; a changed value invalidates earlier UIDs.
    pub validity: u32,
    /// Next UID watermark observed when the mailbox was selected.
    pub next_uid: u32,
}
/// `Generation × NextUID × HeaderSummaries × ScannedWatermark` for one bounded UID window.
pub struct Scan {
    /// Mailbox UIDVALIDITY; a changed value invalidates earlier UIDs.
    pub validity: u32,
    /// Next UID watermark observed when the mailbox was selected.
    pub next_uid: u32,
    /// Header summaries or rendered events from a bounded UID window.
    pub messages: Vec<MessageSummary>,
    /// Last UID covered by this scan, including gaps with no returned message.
    pub scanned_to: u32,
}
/// Event-source boundary for account availability, baselines, bounded scans and waiting.
/// Lookup failure is distinct from confirmed account absence.
pub trait Source: Send + Sync {
    /// Distinguish a missing account from a failed availability lookup.
    fn available(&self, account: &str) -> Result<bool>;
    /// Establish the current no-history mailbox baseline.
    fn snapshot<'a>(&'a self, filters: &'a Filters) -> BoxFuture<'a, Result<Snapshot>>;
    /// Read one bounded UID window without fetching message bodies or setting seen flags.
    fn scan<'a>(
        &'a self,
        filters: &'a Filters,
        validity: u32,
        uid: u32,
    ) -> BoxFuture<'a, Result<Scan>>;
    /// Wait for mailbox activity using IDLE when available, otherwise bounded polling.
    fn wait<'a>(&'a self, filters: &'a Filters) -> BoxFuture<'a, Result<()>>;
}
/// IMAP event source owning a store handle; each operation resolves exactly one parsed account.
pub struct ImapSource {
    /// Shared handle to the private SQLite persistence boundary.
    db: Db,
}
impl ImapSource {
    /// Construct this component from its explicit dependencies.
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
        last.ok_or(Error::Baseline(
            mail_bridge_core::BaselineFailure::MailboxChanged,
        ))?
        .checked_add(1)
        .ok_or(Error::Baseline(
            mail_bridge_core::BaselineFailure::UidExhausted,
        ))
    }
    /// Establish the no-history baseline using EXAMINE and at most one UID fetch.
    pub async fn snapshot_session<
        T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + std::fmt::Debug + Send,
    >(
        session: &mut async_imap::Session<T>,
        mailbox: &str,
    ) -> Result<Snapshot> {
        let selected = session.examine(utf7_encode(mailbox)).await.map_err(safe)?;
        let validity = selected.uid_validity.ok_or(Error::Baseline(
            mail_bridge_core::BaselineFailure::MissingValidity,
        ))?;
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
        let current = selected.uid_validity.ok_or(Error::Baseline(
            mail_bridge_core::BaselineFailure::MissingValidity,
        ))?;
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
        let scanned_to = if uids.len() > MAX_QUEUE {
            uids.truncate(MAX_QUEUE);
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
                    let raw = fetch
                        .header()
                        .ok_or(Error::Rejected("Event header unavailable"))?;
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
    /// Load only the selected account and bind its immutable config to the real provider.
    fn account(&self, id: &str) -> Result<RealBackend> {
        let account = self
            .db
            .runtime_account(id)?
            .ok_or(Error::Rejected("Account unavailable for events"))?;
        Ok(RealBackend::new(account.config, account.password))
    }
}
impl Source for ImapSource {
    /// Distinguish an absent mailbox account from a failed availability lookup.
    fn available(&self, id: &str) -> Result<bool> {
        self.db.runtime_account_exists(id)
    }
    /// Establish the current no-history mailbox baseline.
    fn snapshot<'a>(&'a self, f: &'a Filters) -> BoxFuture<'a, Result<Snapshot>> {
        Box::pin(async move {
            let mut session = self.account(&f.account_id)?.connect().await?;
            let snapshot = Self::snapshot_session(&mut session, &f.mailbox).await?;
            let _ = session.logout().await;
            Ok(snapshot)
        })
    }
    /// Read one bounded UID window without fetching message bodies or setting seen flags.
    fn scan<'a>(&'a self, f: &'a Filters, validity: u32, uid: u32) -> BoxFuture<'a, Result<Scan>> {
        Box::pin(async move {
            let mut session = self.account(&f.account_id)?.connect().await?;
            let scan = Self::scan_session(&mut session, &f.mailbox, validity, uid).await;
            let _ = session.logout().await;
            scan
        })
    }
    /// Wait for mailbox activity using IDLE when available, otherwise bounded polling.
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
