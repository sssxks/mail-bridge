//! SMTP submission with the selected account's credentials.
use crate::backend::RealBackend;
use lettre::{
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
    transport::smtp::authentication::Credentials,
};
use mail_bridge_core::{Error, Result, account::Security, safe};
use std::time::Duration;

pub(crate) async fn send(backend: &RealBackend, message: Message) -> Result<()> {
    let builder = if backend.config.smtp_security == Security::Tls {
        AsyncSmtpTransport::<Tokio1Executor>::relay(&backend.config.smtp_host)
    } else {
        AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&backend.config.smtp_host)
    }
    .map_err(safe)?;
    let transport = builder
        .port(backend.config.smtp_port)
        .timeout(Some(Duration::from_secs(20)))
        .credentials(Credentials::new(
            backend.config.username.clone(),
            backend.password.as_str().to_owned(),
        ))
        .build();
    transport.send(message).await.map_err(|_|Error("SMTP result uncertain; check manually before any new attempt. Do not automatically retry."))?;
    Ok(())
}
