//! Mail provider interface and real account transport.
use crate::command::ReadCommand;
use futures_util::future::BoxFuture;
use lettre::Message;
use mail_bridge_core::{
    Result,
    account::{Config, MailboxCredential},
};
use serde_json::Value;
use std::sync::Arc;

/// Provider boundary accepting parsed read commands or fully built outgoing messages.
pub trait Backend: Send + Sync {
    /// Execute an already parsed read command through the selected provider.
    fn read(&self, command: ReadCommand) -> BoxFuture<'_, Result<Value>>;
    /// Submit one built message through the selected account transport.
    fn send(&self, message: Message) -> BoxFuture<'_, Result<()>>;
}
/// Immutable provider product `SharedConfig × MailboxCredential`; both components are already parsed.
#[derive(Clone)]
pub struct RealBackend {
    /// Shared immutable parsed mailbox configuration.
    pub(crate) config: Arc<Config>,
    /// Parsed zeroizing mailbox credential; never exposed through serialization.
    pub(crate) password: MailboxCredential,
}
impl RealBackend {
    /// Bind one immutable configuration snapshot to its parsed credential.
    pub fn new(config: Arc<Config>, password: MailboxCredential) -> Self {
        Self { config, password }
    }
}
impl Backend for RealBackend {
    /// Execute an already parsed read command through the selected provider.
    fn read(&self, command: ReadCommand) -> BoxFuture<'_, Result<Value>> {
        Box::pin(async move {
            let mut session = self.connect().await?;
            let value = Self::read_session(&mut session, command).await;
            let _ = session.logout().await;
            value
        })
    }
    /// Submit one built message through the selected account transport.
    fn send(&self, message: Message) -> BoxFuture<'_, Result<()>> {
        Box::pin(crate::smtp::send(self, message))
    }
}
