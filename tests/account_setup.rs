use axum::{
    Router,
    body::Body,
    http::{HeaderMap, Request, StatusCode},
};
use http_body_util::BodyExt;
use mail_bridge_rust::{
    account_setup::AccountSetup,
    auth::{Auth, Params},
    config::{AccountSettings, Settings},
    db::{Db, hash, now},
    http::router,
    mail::MailService,
};
use serde_json::{Value, json};
use std::sync::Arc;
use tower::ServiceExt;
use zeroize::Zeroizing;

const OWNER: &str = "synthetic-owner-password-00000000000000";
const MAILBOX: &str = "synthetic-mailbox-only-secret";
fn fixture() -> (tempfile::TempDir, Settings, Db, Arc<Auth>, Arc<MailService>) {
    let dir = tempfile::tempdir().unwrap();
    let settings = Settings {
        owner_password: Arc::new(Zeroizing::new(OWNER.into())),
        public_url: "https://mail.example.com".into(),
        redirects: vec![],
        data_dir: dir.path().into(),
        bind: "127.0.0.1:0".parse().unwrap(),
    };
    let db = Db::open(&dir.path().join("mail-bridge.sqlite3")).unwrap();
    db.0.lock()
        .unwrap()
        .execute(
            "INSERT INTO tokens VALUES (?,'access','client-a',?,'mail:read',?)",
            rusqlite::params![
                hash("read-token"),
                "https://mail.example.com/mcp",
                now() + 3600
            ],
        )
        .unwrap();
    let auth = Arc::new(Auth::new(&settings, db.clone()));
    let mail = Arc::new(MailService::from_store(db.clone()).unwrap());
    (dir, settings, db, auth, mail)
}
fn fields(id: &str) -> Params {
    [
        ("account_id", id),
        ("name", "工作邮箱"),
        ("email", "owner@example.com"),
        ("imap_host", "imap.example.com"),
        ("imap_port", "993"),
        ("imap_security", "tls"),
        ("password", MAILBOX),
    ]
    .into_iter()
    .map(|(k, v)| (k.into(), v.into()))
    .collect()
}
fn account(id: &str) -> AccountSettings {
    mail_bridge_rust::accounts::from_form(fields(id)).unwrap()
}
fn hidden(page: &str) -> Params {
    page.split("<input type=\"hidden\" name=\"")
        .skip(1)
        .map(|s| {
            let (key, rest) = s.split_once('"').unwrap();
            (
                key.into(),
                rest.strip_prefix(" value=\"")
                    .unwrap()
                    .split('"')
                    .next()
                    .unwrap()
                    .into(),
            )
        })
        .collect()
}

#[test]
fn invitation_requires_opening_rotates_csrf_and_saves_once() {
    let (_dir, settings, db, auth, mail) = fixture();
    let setup = AccountSetup::default();
    let invitation = setup.begin("client-a", &settings.public_url).unwrap();
    let url = url::Url::parse(invitation["setup_url"].as_str().unwrap()).unwrap();
    let ticket = url
        .query_pairs()
        .find(|(key, _)| key == "ticket")
        .unwrap()
        .1
        .into_owned();
    let mut unopened = fields("work");
    unopened.insert("ticket".into(), ticket.clone());
    unopened.insert("owner_password".into(), OWNER.into());
    unopened.insert("_csrf".into(), "invented".into());
    assert!(setup.submit(unopened, "invented", &auth, &mail).is_err());

    let (first, _) = setup.page(&ticket, &auth).unwrap();
    let (second, _) = setup.page(&ticket, &auth).unwrap();
    let mut stale = hidden(&first);
    let stale_csrf = stale["_csrf"].clone();
    stale.extend(fields("work"));
    stale.insert("owner_password".into(), OWNER.into());
    assert!(setup.submit(stale, &stale_csrf, &auth, &mail).is_err());

    let mut current = hidden(&second);
    let csrf = current["_csrf"].clone();
    current.extend(fields("work"));
    current.insert("owner_password".into(), OWNER.into());
    let mut invalid = current.clone();
    invalid.insert("imap_port".into(), "0".into());
    assert!(setup.submit(invalid, &csrf, &auth, &mail).is_err());
    assert!(db.runtime_accounts().unwrap().is_empty());

    assert_eq!(
        setup.submit(current.clone(), &csrf, &auth, &mail).unwrap(),
        "work"
    );
    assert!(setup.submit(current, &csrf, &auth, &mail).is_err());
    assert!(setup.page(&ticket, &auth).is_err());
    assert_eq!(db.runtime_accounts().unwrap().len(), 1);
}

async fn request(
    app: Router,
    path: &str,
    method: &str,
    body: String,
    token: Option<&str>,
    cookie: Option<&str>,
    origin: Option<&str>,
) -> (StatusCode, HeaderMap, Vec<u8>) {
    let mut builder = Request::builder()
        .uri(path)
        .method(method)
        .header("Host", "mail.example.com")
        .header("Accept", "application/json, text/event-stream")
        .header("MCP-Protocol-Version", "2025-06-18")
        .header(
            "Content-Type",
            if path == "/mcp" {
                "application/json"
            } else {
                "application/x-www-form-urlencoded"
            },
        );
    if let Some(token) = token {
        builder = builder.header("Authorization", format!("Bearer {token}"));
    }
    if let Some(cookie) = cookie {
        builder = builder.header("Cookie", cookie);
    }
    if let Some(origin) = origin {
        builder = builder.header("Origin", origin);
    }
    let response = app
        .oneshot(builder.body(Body::from(body)).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    (
        status,
        headers,
        response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
}
async fn rpc(app: Router, name: &str, args: Value) -> Value {
    let (status,_,body)=request(app,"/mcp","POST",json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":name,"arguments":args}}).to_string(),Some("read-token"),None,None).await;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    let response: Value = serde_json::from_slice(&body).unwrap();
    assert_ne!(response["result"]["isError"], true, "{response}");
    serde_json::from_str(response["result"]["content"][0]["text"].as_str().unwrap()).unwrap()
}

#[tokio::test]
async fn mcp_to_private_form_live_account_and_restart() {
    let (_dir, settings, db, auth, mail) = fixture();
    let app = router(&settings, auth, mail.clone());
    let (status, _, _) = request(app.clone(), "/mcp", "POST", "{}".into(), None, None, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let invitation = rpc(app.clone(), "begin_account_setup", json!({})).await;
    assert!(invitation.get("setup_id").is_none());
    assert_eq!(
        rpc(app.clone(), "list_accounts", json!({})).await["account_count"],
        0
    );
    assert!(
        !mail_bridge_rust::mcp::TOOLS
            .iter()
            .any(|tool| tool.name == "account_setup_status")
    );
    let url = url::Url::parse(invitation["setup_url"].as_str().unwrap()).unwrap();
    let path = format!("{}?{}", url.path(), url.query().unwrap());
    let (status, headers, page) =
        request(app.clone(), &path, "GET", String::new(), None, None, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers["cache-control"], "no-store");
    assert_eq!(headers["referrer-policy"], "strict-origin");
    assert!(
        headers["content-security-policy"]
            .to_str()
            .unwrap()
            .contains("frame-ancestors 'none'")
    );
    let cookie = headers["set-cookie"]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    let mut params = hidden(std::str::from_utf8(&page).unwrap());
    params.extend(fields("work"));
    params.insert("owner_password".into(), OWNER.into());
    let encoded = serde_urlencoded::to_string(&params).unwrap();
    for origin in [None, Some("https://evil.example")] {
        assert_eq!(
            request(
                app.clone(),
                "/accounts/setup",
                "POST",
                encoded.clone(),
                None,
                Some(&cookie),
                origin
            )
            .await
            .0,
            StatusCode::FORBIDDEN
        );
    }
    assert_eq!(
        request(
            app.clone(),
            "/accounts/setup",
            "POST",
            encoded.clone(),
            None,
            None,
            Some(&settings.public_url)
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    let (status, _, body) = request(
        app.clone(),
        "/accounts/setup",
        "POST",
        encoded.clone(),
        None,
        Some(&cookie),
        Some(&settings.public_url),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    assert!(!String::from_utf8_lossy(&body).contains(MAILBOX));
    assert!(!String::from_utf8_lossy(&body).contains(OWNER));
    let listed = rpc(app.clone(), "list_accounts", json!({})).await;
    assert_eq!(listed["account_count"], 1);
    assert_eq!(listed["accounts"][0]["account_id"], "work");
    assert_eq!(listed["accounts"][0]["smtp_enabled"], false);
    assert_eq!(listed["accounts"][0]["connection_tested"], false);
    assert!(!listed.to_string().contains(MAILBOX));
    // A mail request can use the just-added account on the same service instance.
    assert_eq!(mail.dispatch("prepare_draft",json!({"account_id":"work","to":["recipient@example.com"],"subject":"Hello","body":"Preview only"})).await.unwrap()["account_id"],"work");
    assert_eq!(
        request(
            app.clone(),
            "/accounts/setup",
            "POST",
            encoded,
            None,
            Some(&cookie),
            Some(&settings.public_url)
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        request(app, &path, "GET", String::new(), None, None, None)
            .await
            .0,
        StatusCode::BAD_REQUEST
    );
    let reopened = Db::open(&settings.data_dir.join("mail-bridge.sqlite3")).unwrap();
    let restarted = MailService::from_store(reopened).unwrap();
    assert_eq!(
        restarted
            .dispatch("list_accounts", json!({}))
            .await
            .unwrap(),
        listed
    );
    assert_eq!(db.runtime_accounts().unwrap()[0].password.as_str(), MAILBOX);
}

#[test]
fn owner_confirmation_client_binding_revocation_and_capacity() {
    let (_dir, settings, db, auth, mail) = fixture();
    let setup = AccountSetup::default();
    let invitation = setup.begin("client-a", &settings.public_url).unwrap();
    let url = url::Url::parse(invitation["setup_url"].as_str().unwrap()).unwrap();
    let ticket = url
        .query_pairs()
        .find(|(k, _)| k == "ticket")
        .unwrap()
        .1
        .into_owned();
    let (page, _) = setup.page(&ticket, &auth).unwrap();
    let mut params = hidden(&page);
    params.extend(fields("work"));
    let csrf = params["_csrf"].clone();
    params.insert("owner_password".into(), "incorrect-owner".into());
    assert!(setup.submit(params.clone(), &csrf, &auth, &mail).is_err());
    params.insert("owner_password".into(), OWNER.into());
    params.insert("password".into(), OWNER.into());
    assert!(setup.submit(params.clone(), &csrf, &auth, &mail).is_err());
    params.insert("password".into(), MAILBOX.into());
    params.insert("smtp_enabled".into(), "true".into());
    assert!(setup.submit(params.clone(), &csrf, &auth, &mail).is_err());
    params.remove("smtp_enabled");
    db.revoke_oauth().unwrap();
    assert!(setup.submit(params, &csrf, &auth, &mail).is_err());
    assert!(setup.page(&ticket, &auth).is_err());
    assert!(db.runtime_accounts().unwrap().is_empty());
    for _ in 1..8 {
        setup.begin("client-a", &settings.public_url).unwrap();
    }
    assert!(setup.begin("client-a", &settings.public_url).is_err());
}

#[tokio::test]
async fn store_duplicate_limit_commit_failure_and_existing_smtp_policy() {
    let (_dir, _settings, db, _auth, mail) = fixture();
    let clone = mail.clone();
    let a = account("same");
    let barrier = Arc::new(std::sync::Barrier::new(2));
    let threads: Vec<_> = (0..2)
        .map(|_| {
            let mail = mail.clone();
            let a = a.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                mail.add_account(a).is_ok()
            })
        })
        .collect();
    assert_eq!(
        threads
            .into_iter()
            .map(|t| t.join().unwrap() as usize)
            .sum::<usize>(),
        1
    );
    assert_eq!(
        clone.dispatch("list_accounts", json!({})).await.unwrap()["account_count"],
        1
    );
    db.0.lock()
        .unwrap()
        .execute_batch("PRAGMA query_only=ON")
        .unwrap();
    assert!(mail.add_account(account("failed")).is_err());
    assert_eq!(
        clone.dispatch("list_accounts", json!({})).await.unwrap()["account_count"],
        1
    );
    db.0.lock()
        .unwrap()
        .execute_batch("PRAGMA query_only=OFF")
        .unwrap();
    for i in 1..8 {
        mail.add_account(account(&format!("a{i}"))).unwrap();
    }
    assert!(mail.add_account(account("ninth")).is_err());
    assert_eq!(db.runtime_accounts().unwrap().len(), 8);
    // Imported accounts can retain an explicitly enabled SMTP policy.
    db.0.lock().unwrap().execute("UPDATE runtime_accounts SET config=json_set(config,'$.smtp_host','smtp.example.com','$.smtp_port',465,'$.smtp_enabled',json('true')) WHERE id='same'",[]).unwrap();
    let restored = MailService::from_store(db).unwrap();
    let listed = restored.dispatch("list_accounts", json!({})).await.unwrap();
    let account = listed["accounts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|account| account["account_id"] == "same")
        .unwrap();
    assert_eq!(account["smtp_enabled"], true);
}

#[test]
fn invalid_configuration_and_plaintext_tls_are_rejected() {
    for (key, value) in [
        ("account_id", "../escape"),
        ("imap_host", "https://imap.example.com"),
        ("imap_host", "host\r\nInjected"),
        ("imap_port", "0"),
        ("imap_port", "65536"),
        ("imap_security", "none"),
        ("password", ""),
        ("password", "two\nlines"),
    ] {
        let mut f = fields("work");
        f.insert(key.into(), value.into());
        assert!(mail_bridge_rust::accounts::from_form(f).is_err(), "{key}");
    }
}

#[test]
fn event_source_and_catalog_see_new_accounts_without_starting_watchers() {
    use mail_bridge_rust::events::{Events, ImapSource, Source};
    let (_dir, _settings, db, auth, mail) = fixture();
    let source = Arc::new(ImapSource::new(db.clone()));
    let events = Events::new(
        db,
        auth,
        source.clone(),
        Arc::new(mail_bridge_rust::webhook::HttpsTransport),
        vec![],
    )
    .unwrap();
    assert!(!source.available("work"));
    assert_eq!(
        events.catalog()["events"][0]["inputSchema"]["properties"]["account_id"]["enum"],
        json!([])
    );
    mail.add_account(account("work")).unwrap();
    assert!(source.available("work"));
    assert_eq!(
        events.catalog()["events"][0]["inputSchema"]["properties"]["account_id"]["enum"],
        json!(["work"])
    );
    assert!(events.active().unwrap().is_empty());
    assert!(events.workers.lock().unwrap().is_empty());
}
