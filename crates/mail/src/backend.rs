//! Mail provider interface and real account transport.
use futures_util::future::BoxFuture;
use lettre::Message;
use mail_bridge_core::{
    Result,
    account::{Config, MailboxCredential},
};
use serde_json::Value;

pub trait Backend: Send + Sync {
    fn read<'a>(&'a self, name: &'a str, args: Value) -> BoxFuture<'a, Result<Value>>;
    fn send(&self, message: Message) -> BoxFuture<'_, Result<()>>;
}
#[derive(Clone)]
pub struct RealBackend {
    pub config: Config,
    pub password: MailboxCredential,
}
impl Backend for RealBackend {
    fn read<'a>(&'a self, name: &'a str, args: Value) -> BoxFuture<'a, Result<Value>> {
        Box::pin(async move {
            let mut session = self.connect().await?;
            let value = Self::read_session(&mut session, name, args).await;
            let _ = session.logout().await;
            value
        })
    }
    fn send(&self, message: Message) -> BoxFuture<'_, Result<()>> {
        Box::pin(crate::smtp::send(self, message))
    }
}
