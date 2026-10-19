//! Shared account registry, concurrency budgets, drafts and durable sending.
use crate::{
    backend::{Backend, RealBackend},
    bounded_io::MAX_MAIL,
    draft::RawDraft,
};
use mail_bridge_core::{Error, Result, account::Config, safe};
use mail_bridge_store::{Db, hash};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{sync::Arc, time::Duration};
use tokio::sync::Semaphore;

#[derive(Clone)]
pub struct MailAccount {
    pub id: String,
    pub name: String,
    pub config: Config,
    pub backend: Option<Arc<dyn Backend>>,
    pub credential_status: &'static str,
    pub concurrency: AccountConcurrency,
}
/// Independent IMAP and SMTP budgets for one account. Clones share the budgets.
/// At most two reads and one send may hold account permits; the service also
/// bounds total active operations. Waiting for an account never holds a global permit.
#[derive(Clone)]
pub struct AccountConcurrency {
    imap: Arc<Semaphore>,
    smtp: Arc<Semaphore>,
}
impl Default for AccountConcurrency {
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
    fn status(&self) -> Value {
        json!({"account_id":self.id,"name":self.name,"from_address":self.config.from_address,"smtp_enabled":self.config.smtp_enabled,"credential_status":self.credential_status,"connection_tested":false})
    }
}
#[derive(Clone)]
pub struct MailService {
    pub accounts: Arc<std::sync::RwLock<std::collections::BTreeMap<String, MailAccount>>>,
    pub db: Db,
    pub gate: Arc<Semaphore>,
}
impl MailService {
    pub fn new(accounts: Vec<mail_bridge_core::account::AccountSettings>, db: Db) -> Self {
        let accounts = accounts
            .into_iter()
            .map(|account| {
                let backend = Arc::new(RealBackend {
                    config: account.config.clone(),
                    password: account.password,
                });
                let id = account.id.clone();
                (
                    id,
                    MailAccount {
                        id: account.id,
                        name: account.name,
                        config: account.config,
                        backend: Some(backend),
                        credential_status: "ready",
                        concurrency: AccountConcurrency::default(),
                    },
                )
            })
            .collect();
        Self {
            accounts: Arc::new(std::sync::RwLock::new(accounts)),
            db,
            gate: Arc::new(Semaphore::new(MAIL_CONCURRENCY)),
        }
    }
    pub fn from_store(db: Db) -> Result<Self> {
        let accounts = db.runtime_accounts()?;
        if accounts.len() > 8 {
            return Err(Error("Configure at most 8 accounts"));
        }
        Ok(Self::new(accounts, db))
    }
    pub fn add_account(&self, account: mail_bridge_core::account::AccountSettings) -> Result<()> {
        mail_bridge_core::account::validate(&account)?;
        if account.config.smtp_enabled {
            return Err(Error("New accounts must have SMTP disabled"));
        }
        let mut accounts = self.accounts.write().map_err(safe)?;
        if accounts.contains_key(&account.id) {
            return Err(Error("Account ID already exists; choose a new ID"));
        }
        if accounts.len() >= 8 {
            return Err(Error("Configure at most 8 accounts"));
        }
        self.db.insert_runtime_account(&account)?;
        let backend = Arc::new(RealBackend {
            config: account.config.clone(),
            password: account.password,
        });
        accounts.insert(
            account.id.clone(),
            MailAccount {
                id: account.id,
                name: account.name,
                config: account.config,
                backend: Some(backend),
                credential_status: "ready",
                concurrency: AccountConcurrency::default(),
            },
        );
        Ok(())
    }
    pub async fn dispatch(&self, name: &str, mut args: Value) -> Result<Value> {
        if name == "list_accounts" {
            let object = args.as_object().ok_or(Error("Invalid arguments"))?;
            if !object.is_empty() {
                return Err(Error("Unexpected arguments"));
            }
            let accounts = self.accounts.read().map_err(safe)?;
            let statuses: Vec<_> = accounts.values().map(MailAccount::status).collect();
            return Ok(
                json!({"accounts":statuses,"account_count":accounts.len(),"max_mail_bytes":MAX_MAIL,"mail_concurrency":MAIL_CONCURRENCY,"imap_concurrency_per_account":2,"smtp_concurrency_per_account":1,"transport":"streamable_http"}),
            );
        }
        let account_id = args
            .as_object_mut()
            .ok_or(Error("Invalid arguments"))?
            .remove("account_id")
            .and_then(|v| v.as_str().map(str::to_owned))
            .ok_or(Error(
                "An explicit account_id is required; use list_accounts",
            ))?;
        let account = self
            .accounts
            .read()
            .map_err(safe)?
            .get(&account_id)
            .cloned()
            .ok_or(Error("Unknown account_id; use list_accounts"))?;
        let mut result = if name == "prepare_draft" {
            self.inner(name, args, &account).await?
        } else {
            let account_gate = match name {
                "send_email" => &account.concurrency.smtp,
                "list_folders" | "list_messages" | "search_messages" | "read_message" => {
                    &account.concurrency.imap
                }
                _ => return Err(Error("Unknown tool")),
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
            .map_err(|_| Error("Mail queue wait timed out; this call did not start. Retry later, keeping the same request_id for a send."))??;
            tokio::time::timeout(Duration::from_secs(45), self.inner(name, args, &account))
                .await
                .map_err(|_| if name == "send_email" {
                    Error("Mail send timed out; delivery is uncertain. Keep the same request_id; never retry with a new ID.")
                } else {
                    Error("Mail read timed out; retry later.")
                })??
        };
        result
            .as_object_mut()
            .ok_or(Error("Invalid mail response"))?
            .insert("account_id".into(), json!(account.id));
        Ok(result)
    }
    async fn inner(&self, name: &str, args: Value, account: &MailAccount) -> Result<Value> {
        match name {
            "prepare_draft" => {
                let draft: RawDraft = serde_json::from_value(args)
                    .map_err(|_| Error("Provide recipients, subject and body"))?;
                let mut preview=draft.parse()?.preview();
                preview["from_address"]=json!(account.config.from_address);
                Ok(preview)
            }
            "send_email" => {
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct Send {
                    to: Box<[Box<str>]>,
                    subject: Box<str>,
                    body: Box<str>,
                    request_id: String,
                }
                let send: Send = serde_json::from_value(args).map_err(|_| {
                    Error(
                        "Recipients, subject, body and request_id required",
                    )
                })?;
                let draft = RawDraft {
                    to: send.to,
                    subject: send.subject,
                    body: send.body,
                }.parse()?;
                if !account.config.smtp_enabled {
                    return Err(Error(
                        "SMTP is disabled for this account",
                    ));
                }
                if !(16..=80).contains(&send.request_id.len())
                    || !send
                        .request_id
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
                {
                    return Err(Error("Invalid request_id"));
                }
                let backend=account.backend.as_ref().ok_or(Error("Selected account credential is missing or invalid; enter it privately on the server"))?;
                let id = format!(
                    "<{}@{}>",
                    mail_bridge_core::random(),
                    account.config
                        .from_address
                        .rsplit('@')
                        .next()
                        .unwrap_or("localhost")
                );
                let fingerprint = hash(
                    serde_json::to_vec(&json!([
                        account.id,
                        account.config.username,
                        account.config.from_address,
                        account.config.smtp_host,
                        account.config.smtp_port,
                        &draft
                    ]))
                    .map_err(safe)?,
                );
                let message = draft.message(&account.config.from_address, &id)?;
                if let Some((status, id)) = self.db.attempt(&account.id, &send.request_id, &fingerprint, &id)? {
                    return Ok(json!({"status":status,"message_id":id,"retried":false}));
                }
                // The durable journal is committed before a single SMTP attempt.
                backend.send(message).await?;
                self.db.mark_accepted(&account.id, &send.request_id)?;
                Ok(json!({"status":"accepted_by_smtp","message_id":id,"retried":false}))
            }
            "list_folders" | "list_messages" | "search_messages" | "read_message" => {
                account.backend.as_ref().ok_or(Error("Selected account credential is missing or invalid; enter it privately on the server"))?.read(name, args).await
            }
            _ => Err(Error("Unknown tool")),
        }
    }
}
