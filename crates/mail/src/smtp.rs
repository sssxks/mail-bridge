//! SMTP submission with the selected account's credentials.
use crate::backend::RealBackend;
use lettre::{
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
    transport::smtp::authentication::Credentials,
};
use mail_bridge_core::{Error, Result, account::Security, safe};
use std::time::Duration;

/// Submit one built message through the selected account transport.
pub(crate) async fn send(backend: &RealBackend, message: Message) -> Result<()> {
    let endpoint = backend
        .config
        .smtp()
        .ok_or(Error::Rejected("SMTP is disabled for this account"))?;
    let builder = if endpoint.security() == Security::Tls {
        AsyncSmtpTransport::<Tokio1Executor>::relay(endpoint.host())
    } else {
        AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(endpoint.host())
    }
    .map_err(safe)?;
    let transport = builder
        .port(endpoint.port())
        .timeout(Some(Duration::from_secs(20)))
        .credentials(Credentials::new(
            backend.config.username().to_owned(),
            backend.password.as_str().to_owned(),
        ))
        .build();
    transport.send(message).await.map_err(|_|Error::Rejected("SMTP result uncertain; check manually before any new attempt. Do not automatically retry."))?;
    Ok(())
}
