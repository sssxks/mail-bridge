//! Shared account registry, concurrency budgets, drafts and durable sending.
//!
//! | Operation | Frequency | Complexity | Storage | Forbidden implementation |
//! | --- | --- | --- | --- | --- |
//! | Parse command | Each call | O(argument bytes) | Typed request | Parse after permits/login |
//! | Resolve account | Each call | O(log n), n <= 8 | Immutable Arc snapshot | Clone configuration strings |
//! | Activate account | Confirmed setup | O(log n + database write) | Existing synchronized registry | Publish before persistence |
//! | Send | Explicit submission | O(content bytes + journal + network) | Durable deduplication identity | Resend a recorded request |
use crate::{
    backend::{Backend, RealBackend},
    bounded_io::MAX_MAIL,
    command::ReadCommand,
    draft::{Draft, RawDraft},
};
use mail_bridge_core::{
    Error, Result,
    account::{Account, AccountName, AccountSettings, Config},
    safe,
};
use mail_bridge_store::{Db, hash};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{sync::Arc, time::Duration};
use tokio::sync::Semaphore;

/// Immutable runtime account snapshot with an optional provider and independent operation budgets.
/// Credential status is derived from provider availability rather than stored separately.
#[derive(Clone)]
struct MailAccount {
    /// Stable identity of this account, subscription or queued event.
    id: Account,
    /// Parsed account display name shared with request snapshots.
    name: AccountName,
    /// Shared immutable parsed mailbox configuration.
    config: Arc<Config>,
    /// Optional provider dependency; absence is reported as missing credentials.
    backend: Option<Arc<dyn Backend>>,
    /// Independent per-account IMAP and SMTP permit budgets.
    concurrency: AccountConcurrency,
}
/// Independent IMAP and SMTP budgets for one account. Clones share the budgets.
/// At most two reads and one send may hold account permits; the service also
/// bounds total active operations. Waiting for an account never holds a global permit.
#[derive(Clone)]
struct AccountConcurrency {
    /// Configured read endpoint or its independent concurrency budget.
    imap: Arc<Semaphore>,
    /// Submission state or its independent concurrency budget.
    smtp: Arc<Semaphore>,
}
impl Default for AccountConcurrency {
    /// Create independent budgets of two IMAP reads and one SMTP send.
    fn default() -> Self {
        Self {
            imap: Arc::new(Semaphore::new(2)),
            smtp: Arc::new(Semaphore::new(1)),
        }
    }
}
/// Total ordinary mail operations, excluding local previews and event watchers.
pub const MAIL_CONCURRENCY: usize = 4;
impl MailAccount {
    /// Describe the immutable account without contacting its provider or serializing credentials.
    fn status(&self) -> Value {
        json!({"account_id":self.id,"name":self.name,"from_address":self.config.sender_text(),"smtp_enabled":self.config.sending_enabled(),"credential_status":if self.backend.is_some(){"ready"}else{"missing"},"connection_tested":false})
    }
}
/// Bounded account registry, durable send store and global admission budget.
///
/// Semantically `Map<Account, Snapshot>[0,8] × Store × Capacity`. Construction rejects
/// duplicate identities; accounts are published only after their database write succeeds.
#[derive(Clone)]
pub struct MailService {
    /// Bounded registry of immutable account snapshots keyed by canonical identity.
    accounts: Arc<std::sync::RwLock<std::collections::BTreeMap<Account, Arc<MailAccount>>>>,
    /// Shared handle to the private SQLite persistence boundary.
    db: Db,
    /// Shared fixed-capacity admission budget; permits live for the entire operation.
    gate: Arc<Semaphore>,
}
impl MailService {
    /// Construct a bounded registry with explicit provider dependencies.
    /// Duplicate identities and oversized registries are rejected before activation.
    pub fn with_backends(
        accounts: impl IntoIterator<Item = (AccountSettings, Option<Arc<dyn Backend>>)>,
        db: Db,
        capacity: std::num::NonZeroUsize,
    ) -> Result<Self> {
        let mut registry = std::collections::BTreeMap::new();
        for (account, backend) in accounts {
            if registry.len() >= 8 {
                return Err(Error::Rejected("Configure at most 8 accounts"));
            }
            let id = account.id.clone();
            let account = Arc::new(MailAccount {
                id: account.id,
                name: account.name,
                config: account.config,
                backend,
                concurrency: AccountConcurrency::default(),
            });
            if registry.insert(id, account).is_some() {
                return Err(Error::Rejected("Duplicate account ID"));
            }
        }
        Ok(Self {
            accounts: Arc::new(std::sync::RwLock::new(registry)),
            db,
            gate: Arc::new(Semaphore::new(capacity.get())),
        })
    }
    /// Probe local persistence without opening any mailbox connection.
    pub fn ready(&self) -> bool {
        self.db.ready()
    }
    /// Restore the bounded runtime registry from the sole persistent account store.
    pub fn from_store(db: Db) -> Result<Self> {
        let accounts = db.runtime_accounts()?;
        if accounts.len() > 8 {
            return Err(Error::Rejected("Configure at most 8 accounts"));
        }
        let accounts = accounts.into_iter().map(|account| {
            let backend: Arc<dyn Backend> = Arc::new(RealBackend::new(
                account.config.clone(),
                account.password.clone(),
            ));
            (account, Some(backend))
        });
        Self::with_backends(
            accounts,
            db,
            std::num::NonZeroUsize::new(MAIL_CONCURRENCY).expect("positive constant"),
        )
    }
    /// Commit a new SMTP-disabled account before publishing its immutable runtime snapshot.
    pub fn add_account(&self, account: mail_bridge_core::account::AccountSettings) -> Result<()> {
        if account.config.sending_enabled() {
            return Err(Error::Rejected("New accounts must have SMTP disabled"));
        }
        let mut accounts = self.accounts.write().map_err(safe)?;
        if accounts.contains_key(&account.id) {
            return Err(Error::Rejected(
                "Account ID already exists; choose a new ID",
            ));
        }
        if accounts.len() >= 8 {
            return Err(Error::Rejected("Configure at most 8 accounts"));
        }
        self.db.insert_runtime_account(&account)?;
        let backend = Arc::new(RealBackend::new(account.config.clone(), account.password));
        accounts.insert(
            account.id.clone(),
            Arc::new(MailAccount {
                id: account.id,
                name: account.name,
                config: account.config,
                backend: Some(backend),
                concurrency: AccountConcurrency::default(),
            }),
        );
        Ok(())
    }
    /// Parse the external command before registry lookup, permit acquisition or provider IO.
    pub async fn dispatch(&self, name: &str, mut args: Value) -> Result<Value> {
        if name == "list_accounts" {
            let object = args
                .as_object()
                .ok_or(Error::Rejected("Invalid arguments"))?;
            if !object.is_empty() {
                return Err(Error::Rejected("Unexpected arguments"));
            }
            let accounts = self.accounts.read().map_err(safe)?;
            let statuses: Vec<_> = accounts.values().map(|account| account.status()).collect();
            return Ok(
                json!({"accounts":statuses,"account_count":accounts.len(),"max_mail_bytes":MAX_MAIL,"mail_concurrency":MAIL_CONCURRENCY,"imap_concurrency_per_account":2,"smtp_concurrency_per_account":1,"transport":"streamable_http"}),
            );
        }
        let account_id = args
            .as_object_mut()
            .ok_or(Error::Rejected("Invalid arguments"))?
            .remove("account_id")
            .and_then(|v| v.as_str().map(str::to_owned))
            .ok_or(Error::Rejected(
                "An explicit account_id is required; use list_accounts",
            ))?;
        let account_id: Account = account_id.parse()?;
        let command = Command::parse(name, args)?;
        let account = self
            .accounts
            .read()
            .map_err(safe)?
            .get(account_id.as_str())
            .cloned()
            .ok_or(Error::Rejected("Unknown account_id; use list_accounts"))?;
        if matches!(command, Command::Send { .. }) && !account.config.sending_enabled() {
            return Err(Error::Rejected("SMTP is disabled for this account"));
        }
        let mut result = if matches!(command, Command::Preview(_)) {
            self.inner(command, &account).await?
        } else {
            let account_gate = match &command {
                Command::Send { .. } => &account.concurrency.smtp,
                Command::Read(_) => &account.concurrency.imap,
                Command::Preview(_) => unreachable!("preview bypasses the network queue"),
            };
            // One shared queue deadline: never spend five seconds on each gate.
            // The permits live in this request future, including cancellation.
            let (_account_permit, _global_permit) = tokio::time::timeout(
                Duration::from_secs(5),
                async {
                    let account_permit = account_gate.acquire().await.map_err(safe)?;
                    let global_permit = self.gate.acquire().await.map_err(safe)?;
                    Ok::<_, Error>((account_permit, global_permit))
                },
            )
            .await
            .map_err(|_| Error::Rejected("Mail queue wait timed out; this call did not start. Retry later, keeping the same request_id for a send."))??;
            let sending = matches!(command, Command::Send { .. });
            tokio::time::timeout(Duration::from_secs(45), self.inner(command, &account))
                .await
                .map_err(|_| if sending {
                    Error::Rejected("Mail send timed out; delivery is uncertain. Keep the same request_id; never retry with a new ID.")
                } else {
                    Error::Rejected("Mail read timed out; retry later.")
                })??
        };
        result
            .as_object_mut()
            .ok_or(Error::Rejected("Invalid mail response"))?
            .insert("account_id".into(), json!(account.id));
        Ok(result)
    }
    /// Execute a parsed preview, read or journaled send under its selected account snapshot.
    async fn inner(&self, command: Command, account: &MailAccount) -> Result<Value> {
        match command {
            Command::Preview(draft) => {
                let mut preview = draft.preview();
                preview["from_address"] = json!(account.config.sender_text());
                Ok(preview)
            }
            Command::Send {draft, request} => {
                let backend=account.backend.as_ref().ok_or(Error::Rejected("Selected account credential is missing or invalid; enter it privately on the server"))?;
                let id = format!(
                    "<{}@{}>",
                    mail_bridge_core::random(),
                    account.config.sender().domain()
                );
                let fingerprint = hash(
                    serde_json::to_vec(&json!([
                        account.id,
                        account.config.username(),
                        account.config.sender_text(),
                        account.config.smtp().map_or("", |s|s.host()),
                        account.config.smtp().map_or(0, |s|s.port()),
                        &draft
                    ]))
                    .map_err(safe)?,
                );
                let message = draft.message(account.config.sender(), &id)?;
                if let Some((status, id)) = self.db.attempt(account.id.as_str(), &request, &fingerprint, &id)? {
                    return Ok(json!({"status":status,"message_id":id,"retried":false}));
                }
                // The durable journal is committed before a single SMTP attempt.
                backend.send(message).await?;
                self.db.mark_accepted(account.id.as_str(), &request)?;
                Ok(json!({"status":"accepted_by_smtp","message_id":id,"retried":false}))
            }
            Command::Read(command) => {
                account.backend.as_ref().ok_or(Error::Rejected("Selected account credential is missing or invalid; enter it privately on the server"))?.read(command).await
            }
        }
    }
}

/// A complete parsed mail operation; no raw JSON enters provider IO.
enum Command {
    /// An already parsed provider read command.
    Read(ReadCommand),
    /// Validated content that performs no provider IO.
    Preview(Draft),
    /// Validated content paired with its preserved deduplication identity.
    Send {
        /** Validated recipients, subject and body for preview or submission. */
        draft: Draft,
        /** Preserved request identity used by the durable send journal. */
        request: Box<str>,
    },
}
impl Command {
    /// Parse an external representation once before the resulting value enters business code.
    fn parse(name: &str, args: Value) -> Result<Self> {
        match name {
            "prepare_draft" => Ok(Self::Preview(
                serde_json::from_value::<RawDraft>(args)
                    .map_err(|_| Error::Rejected("Provide recipients, subject and body"))?
                    .parse()?,
            )),
            "send_email" => {
                /// Untrusted request product; only the enclosing parser turns its fields into a valid command.
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct Raw {
                    /// Explicit recipients in their original order.
                    to: Box<[Box<str>]>,
                    /// Decoded subject or validated outgoing subject, according to this representation.
                    subject: Box<str>,
                    /// Owned outgoing content, queued JSON bytes or bounded response bytes.
                    body: Box<str>,
                    /// External deduplication key, parsed before queueing or SMTP access.
                    request_id: Box<str>,
                }
                let raw: Raw = serde_json::from_value(args).map_err(|_| {
                    Error::Rejected("Recipients, subject, body and request_id required")
                })?;
                let draft = RawDraft {
                    to: raw.to,
                    subject: raw.subject,
                    body: raw.body,
                }
                .parse()?;
                if !(16..=80).contains(&raw.request_id.len())
                    || !raw
                        .request_id
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
                {
                    return Err(Error::Rejected("Invalid request_id"));
                }
                Ok(Self::Send {
                    draft,
                    request: raw.request_id,
                })
            }
            _ => Ok(Self::Read(ReadCommand::parse(name, args)?)),
        }
    }
}
