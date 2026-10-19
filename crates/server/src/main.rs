use mail_bridge_auth::Auth;
use mail_bridge_mail::service::MailService;
use mail_bridge_rust::{
    config::Settings,
    http::{LimitedListener, router},
};
use mail_bridge_store::Db;
use std::{future::IntoFuture, sync::Arc, time::Duration};
use tokio_util::sync::CancellationToken;

// systemd and Docker send SIGTERM; interactive terminals send Ctrl+C.
/// Wait for Ctrl+C or the platform termination signal.
async fn shutdown_signal() -> std::io::Result<()> {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => result,
            _ = terminate.recv() => Ok(()),
        }
    }
    #[cfg(not(unix))]
    tokio::signal::ctrl_c().await
}

/// Cancel workers and drain HTTP requests under one explicit shutdown deadline.
async fn serve_until_shutdown(
    server: impl Future<Output = std::io::Result<()>>,
    signal: impl Future<Output = std::io::Result<()>>,
    shutdown: CancellationToken,
    grace: Duration,
) -> mail_bridge_core::Result<()> {
    tokio::pin!(server);
    let result = tokio::select! {
        result = &mut server => result.map_err(mail_bridge_core::safe),
        signal = signal => {
            shutdown.cancel();
            if signal.is_err() {
                Err(mail_bridge_core::Error::Rejected("Shutdown signal handler failed"))
            } else {
                println!("Shutdown requested; draining HTTP requests.");
                match tokio::time::timeout(grace, server).await {
                    Ok(result) => result.map_err(mail_bridge_core::safe),
                    Err(_) => Err(mail_bridge_core::Error::Rejected("HTTP shutdown deadline exceeded; inspect send journal before retrying sends")),
                }
            }
        }
    };
    shutdown.cancel();
    result
}
/// Run the process and print only a credential-safe failure before returning a failing exit status.
fn main() {
    if let Err(error) = run() {
        eprintln!("{}", error);
        std::process::exit(1);
    }
}
/// Construct dependencies and start the bounded HTTP service on the current-thread runtime.
fn run() -> mail_bridge_core::Result<()> {
    let settings = Settings::from_env()?;
    let db = Db::open(&settings.data_dir.join("mail-bridge.sqlite3"))?;
    if std::env::args().any(|arg| arg == "--revoke-oauth") {
        db.revoke_oauth()?;
        println!("OAuth connections revoked; send journal preserved.");
        return Ok(());
    }
    let auth = Arc::new(Auth::new(&settings.auth_config(), db.clone())?);
    let mail = Arc::new(MailService::from_store(db.clone())?);
    let events =
        if std::env::var("MAIL_BRIDGE_EVENTS_ENABLED").map_or(true, |v| v == "true" || v == "1") {
            Some(Arc::new(mail_bridge_events::Events::new(
                db.clone(),
                auth.clone(),
                Arc::new(mail_bridge_events::source::ImapSource::new(db.clone())),
                Arc::new(mail_bridge_events::webhook::HttpsTransport),
                vec![],
            )?))
        } else {
            None
        };
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(2)
        .build()
        .map_err(mail_bridge_core::safe)?
        .block_on(async move {
            let listener = tokio::net::TcpListener::bind(settings.bind)
                .await
                .map_err(mail_bridge_core::safe)?;
            let listener = LimitedListener::new(listener, std::num::NonZeroUsize::new(24).expect("positive constant"));
            println!("Mail Bridge Rust: HTTP MCP ready on loopback/configured interface; no mailbox connection until requested.");
            let shutdown = CancellationToken::new();
            if let Some(events) = events.clone() {
                events.start(shutdown.clone());
            }
            let server = axum::serve(listener, router( auth, mail, events))
                .with_graceful_shutdown(shutdown.clone().cancelled_owned())
                .into_future();
            serve_until_shutdown(server, shutdown_signal(), shutdown, Duration::from_secs(60)).await
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn shutdown_cancels_workers_and_waits_for_requests() {
        let shutdown = CancellationToken::new();
        let worker = shutdown.clone();
        let completed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let drained = completed.clone();
        let server = async move {
            worker.cancelled().await;
            tokio::task::yield_now().await;
            drained.store(true, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        };
        serve_until_shutdown(
            server,
            async { Ok(()) },
            shutdown.clone(),
            Duration::from_secs(1),
        )
        .await
        .unwrap();
        assert!(shutdown.is_cancelled());
        assert!(completed.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[tokio::test]
    async fn shutdown_has_a_deadline() {
        let shutdown = CancellationToken::new();
        let result = serve_until_shutdown(
            std::future::pending(),
            async { Ok(()) },
            shutdown.clone(),
            Duration::ZERO,
        )
        .await;
        assert!(result.unwrap_err().message().contains("deadline exceeded"));
        assert!(shutdown.is_cancelled());
    }

    #[tokio::test]
    async fn server_and_signal_failures_cancel_workers() {
        for server_fails in [false, true] {
            let shutdown = CancellationToken::new();
            let failure = async { Err(std::io::Error::other("synthetic failure")) };
            let result = if server_fails {
                serve_until_shutdown(
                    failure,
                    std::future::pending(),
                    shutdown.clone(),
                    Duration::ZERO,
                )
                .await
            } else {
                serve_until_shutdown(
                    std::future::pending(),
                    failure,
                    shutdown.clone(),
                    Duration::ZERO,
                )
                .await
            };
            assert!(result.is_err());
            assert!(shutdown.is_cancelled());
        }
    }
}
