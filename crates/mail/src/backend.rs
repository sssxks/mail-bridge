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

pub trait Backend: Send + Sync {
    fn read(&self, command: ReadCommand) -> BoxFuture<'_, Result<Value>>;
    fn send(&self, message: Message) -> BoxFuture<'_, Result<()>>;
}
#[derive(Clone)]
pub struct RealBackend {
    pub config: Arc<Config>,
    pub password: MailboxCredential,
}
impl Backend for RealBackend {
    fn read(&self, command: ReadCommand) -> BoxFuture<'_, Result<Value>> {
        Box::pin(async move {
            let mut session = self.connect().await?;
            let value = Self::read_session(&mut session, command).await;
            let _ = session.logout().await;
            value
        })
    }
    fn send(&self, message: Message) -> BoxFuture<'_, Result<()>> {
        Box::pin(crate::smtp::send(self, message))
    }
}
