use mail_bridge_rust::{
    auth::Auth,
    config::Settings,
    db::Db,
    http::{LimitedListener, router_with_events},
    mail::MailService,
};
use std::sync::Arc;
fn main() {
    if let Err(error) = run() {
        eprintln!("{}", error);
        std::process::exit(1);
    }
}
fn run() -> mail_bridge_rust::Result<()> {
    let settings = Settings::from_env()?;
    let db = Db::open(&settings.data_dir.join("mail-bridge.sqlite3"))?;
    if std::env::args().any(|arg| arg == "--revoke-oauth") {
        db.revoke_oauth()?;
        println!("OAuth connections revoked; send journal preserved.");
        return Ok(());
    }
    let auth = Arc::new(Auth::new(&settings, db.clone()));
    let mail = Arc::new(MailService::new(settings.accounts.clone(), db.clone()));
    let events =
        if std::env::var("MAIL_BRIDGE_EVENTS_ENABLED").is_ok_and(|v| v == "true" || v == "1") {
            Some(Arc::new(mail_bridge_rust::events::Events::new(
                db,
                auth.clone(),
                Arc::new(mail_bridge_rust::events::ImapSource::new(
                    &settings.accounts,
                )),
                Arc::new(mail_bridge_rust::webhook::HttpsTransport),
                settings.accounts.iter().map(|a| a.id.clone()).collect(),
            )?))
        } else {
            None
        };
    tokio::runtime::Builder::new_current_thread().enable_all().max_blocking_threads(2).build().map_err(mail_bridge_rust::safe)?.block_on(async move{
        let listener=tokio::net::TcpListener::bind(settings.bind).await.map_err(mail_bridge_rust::safe)?;
        let listener=LimitedListener{inner:listener,gate:Arc::new(tokio::sync::Semaphore::new(8))};
        println!("Mail Bridge Rust: HTTP MCP ready on loopback/configured interface; no mailbox connection until requested.");
        let shutdown=tokio_util::sync::CancellationToken::new();
        if let Some(events)=events.clone(){events.start(shutdown.clone());}
        let signal=shutdown.clone();
        let result=axum::serve(listener,router_with_events(&settings,auth,mail,events)).with_graceful_shutdown(async move{let _=tokio::signal::ctrl_c().await;signal.cancel();}).await.map_err(mail_bridge_rust::safe);
        shutdown.cancel();result
    })
}
