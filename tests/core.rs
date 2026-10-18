use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use futures_util::future::BoxFuture;
use http_body_util::BodyExt;
use lettre::Message;
use mail_bridge_rust::{
    Error, Result,
    auth::{Auth, Params},
    bounded_io::GuardIo,
    config::{Config, Security, Settings},
    db::{Db, hash},
    http::router,
    mail::{
        Backend, MailAccount, MailService, RealBackend,
        page::{Page, SearchCriteria},
        parse_mail, search, utf7_decode, utf7_encode,
    },
};
use serde_json::{Value, json};
use std::{
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tower::ServiceExt;
use zeroize::Zeroizing;

#[derive(Default)]
struct Fake {
    sent: AtomicUsize,
    fail: AtomicBool,
}
impl Backend for Fake {
    fn read<'a>(&'a self, _: &'a str, _: Value) -> BoxFuture<'a, Result<Value>> {
        Box::pin(async { Err(Error("Mock read is not connected")) })
    }
    fn send(&self, _: Message) -> BoxFuture<'_, Result<()>> {
        Box::pin(async {
            self.sent.fetch_add(1, Ordering::SeqCst);
            if self.fail.load(Ordering::SeqCst) {
                Err(Error("SMTP outcome uncertain; do not retry"))
            } else {
                Ok(())
            }
        })
    }
}
fn mock_config() -> Config {
    Config {
        username: "mock@example.com".into(),
        from_address: "mock@example.com".into(),
        imap_host: "imap.example.com".into(),
        imap_port: 993,
        imap_security: Security::Tls,
        smtp_host: "smtp.example.com".into(),
        smtp_port: 465,
        smtp_security: Security::Tls,
        smtp_enabled: true,
    }
}
fn settings(path: &Path) -> Settings {
    Settings {
        owner_password: Arc::new(Zeroizing::new(
            "mock-owner-password-0000000000000000".into(),
        )),
        public_url: "https://mail.example.com".into(),
        redirects: vec!["https://chatgpt.com/connector_platform_oauth_redirect".into()],
        data_dir: path.to_owned(),
        bind: "127.0.0.1:18765".parse().unwrap(),
    }
}
fn setup() -> (tempfile::TempDir, Settings, Db, Arc<Fake>, Arc<MailService>) {
    let dir = tempfile::tempdir().unwrap();
    let settings = settings(dir.path());
    let db = Db::open(&dir.path().join("test.db")).unwrap();
    let fake = Arc::new(Fake::default());
    let account = MailAccount {
        id: "qq".into(),
        name: "Mock QQ".into(),
        config: mock_config(),
        backend: Some(fake.clone()),
        credential_status: "ready",
        concurrency: Default::default(),
    };
    let service = Arc::new(MailService {
        accounts: Arc::new(std::sync::RwLock::new([("qq".into(), account)].into())),
        db: db.clone(),
        gate: Arc::new(tokio::sync::Semaphore::new(1)),
    });
    (dir, settings, db, fake, service)
}

/// Controllable network latency: each backend operation reports entry and waits
/// for a release, so concurrency assertions do not depend on wall-clock timing.
struct SlowBackend {
    started: tokio::sync::mpsc::UnboundedSender<&'static str>,
    release: tokio::sync::Semaphore,
}
impl Backend for SlowBackend {
    fn read<'a>(&'a self, _: &'a str, _: Value) -> BoxFuture<'a, Result<Value>> {
        Box::pin(async move {
            self.started.send("read").unwrap();
            self.release.acquire().await.unwrap().forget();
            Ok(json!({"messages": []}))
        })
    }
    fn send(&self, _: Message) -> BoxFuture<'_, Result<()>> {
        Box::pin(async move {
            self.started.send("send").unwrap();
            self.release.acquire().await.unwrap().forget();
            Ok(())
        })
    }
}
fn slow_backend() -> (
    Arc<SlowBackend>,
    tokio::sync::mpsc::UnboundedReceiver<&'static str>,
) {
    let (started, receiver) = tokio::sync::mpsc::unbounded_channel();
    (
        Arc::new(SlowBackend {
            started,
            release: tokio::sync::Semaphore::new(0),
        }),
        receiver,
    )
}
fn start_read(
    service: &Arc<MailService>,
    account: &'static str,
) -> tokio::task::JoinHandle<Result<Value>> {
    let service = service.clone();
    tokio::spawn(async move {
        service
            .dispatch("list_messages", json!({"account_id": account}))
            .await
    })
}

#[tokio::test(start_paused = true)]
async fn concurrent_reads_are_bounded_and_other_accounts_make_progress() {
    let (_dir, _, _, _, original) = setup();
    let mut service = (*original).clone();
    service.gate = Arc::new(tokio::sync::Semaphore::new(
        mail_bridge_rust::mail::MAIL_CONCURRENCY,
    ));
    let (backend, mut started) = slow_backend();
    {
        let mut accounts = service.accounts.write().unwrap();
        accounts.get_mut("qq").unwrap().backend = Some(backend.clone());
        for id in ["zju", "third"] {
            let mut account = accounts["qq"].clone();
            account.id = id.into();
            account.concurrency = Default::default();
            accounts.insert(id.into(), account);
        }
    }
    let service = Arc::new(service);
    let first = start_read(&service, "qq");
    let second = start_read(&service, "qq");
    assert_eq!(started.recv().await, Some("read"));
    assert_eq!(started.recv().await, Some("read"));
    let waiting = start_read(&service, "qq");
    tokio::task::yield_now().await;
    assert!(started.try_recv().is_err());
    let other1 = start_read(&service, "zju");
    let other2 = start_read(&service, "zju");
    assert_eq!(started.recv().await, Some("read"));
    assert_eq!(started.recv().await, Some("read"));
    let global_waiting = start_read(&service, "third");
    tokio::task::yield_now().await;
    assert!(started.try_recv().is_err());
    // Local work remains available even when every network slot is occupied.
    service
        .dispatch(
            "prepare_draft",
            json!({"account_id":"qq","to":["a@example.com"],"subject":"s","body":"b"}),
        )
        .await
        .unwrap();
    service.dispatch("list_accounts", json!({})).await.unwrap();
    backend.release.add_permits(6);
    for task in [first, second, waiting, other1, other2, global_waiting] {
        task.await.unwrap().unwrap();
    }
    assert_eq!(started.recv().await, Some("read"));
    assert_eq!(started.recv().await, Some("read"));
    assert_eq!(service.gate.available_permits(), 4);
}

#[tokio::test(start_paused = true)]
async fn queue_timeout_and_cancellation_never_start_backend_or_leak_permits() {
    let (_dir, _, _, _, service) = setup();
    let (backend, mut started) = slow_backend();
    service
        .accounts
        .write()
        .unwrap()
        .get_mut("qq")
        .unwrap()
        .backend = Some(backend.clone());
    let held = service.gate.acquire().await.unwrap();
    let cancelled = start_read(&service, "qq");
    tokio::task::yield_now().await;
    cancelled.abort();
    assert!(cancelled.await.unwrap_err().is_cancelled());
    let waiting = start_read(&service, "qq");
    tokio::task::yield_now().await;
    tokio::time::advance(std::time::Duration::from_secs(5)).await;
    assert!(
        waiting
            .await
            .unwrap()
            .unwrap_err()
            .0
            .contains("this call did not start")
    );
    assert!(started.try_recv().is_err());
    drop(held);
    let active = start_read(&service, "qq");
    assert_eq!(started.recv().await, Some("read"));
    active.abort();
    assert!(active.await.unwrap_err().is_cancelled());
    assert_eq!(service.gate.available_permits(), 1);
    backend.release.add_permits(1);
    start_read(&service, "qq").await.unwrap().unwrap();
}

#[tokio::test(start_paused = true)]
async fn sends_do_not_block_reads_and_concurrent_duplicate_sends_are_deduplicated() {
    let (_dir, _, _, _, original) = setup();
    let mut service = (*original).clone();
    service.gate = Arc::new(tokio::sync::Semaphore::new(4));
    let (backend, mut started) = slow_backend();
    service
        .accounts
        .write()
        .unwrap()
        .get_mut("qq")
        .unwrap()
        .backend = Some(backend.clone());
    let service = Arc::new(service);
    let args = json!({"account_id":"qq","to":["a@example.com"],"subject":"s","body":"b","request_id":"concurrent-send-0001"});
    let send = |args: Value| {
        let service = service.clone();
        tokio::spawn(async move { service.dispatch("send_email", args).await })
    };
    let first = send(args.clone());
    assert_eq!(started.recv().await, Some("send"));
    let duplicate = send(args);
    let read = start_read(&service, "qq");
    assert_eq!(started.recv().await, Some("read"));
    tokio::task::yield_now().await;
    assert!(started.try_recv().is_err());
    backend.release.add_permits(2);
    assert_eq!(first.await.unwrap().unwrap()["status"], "accepted_by_smtp");
    assert_eq!(
        duplicate.await.unwrap().unwrap()["status"],
        "accepted_by_smtp"
    );
    read.await.unwrap().unwrap();
    assert!(started.try_recv().is_err());
}
async fn mock_imap(
    script: Vec<(String, String)>,
) -> (
    async_imap::Session<GuardIo<tokio::io::DuplexStream>>,
    tokio::task::JoinHandle<()>,
) {
    let (client, server) = tokio::io::duplex(65536);
    let handle = tokio::spawn(async move {
        let mut reader = BufReader::new(server);
        let mut tag = String::new();
        for (expected, response) in script {
            let mut line = String::new();
            reader.read_line(&mut line).await.unwrap();
            assert!(
                line.contains(&expected),
                "expected {expected:?}, got {line:?}"
            );
            if line.starts_with('A') {
                tag = line.split_whitespace().next().unwrap().to_owned();
            }
            reader
                .get_mut()
                .write_all(response.replace("%TAG%", &tag).as_bytes())
                .await
                .unwrap();
        }
    });
    let client = async_imap::Client::new(GuardIo::new(client));
    let session = client
        .login("mock-user", "mock-pass")
        .await
        .map_err(|(e, _)| e)
        .unwrap();
    (session, handle)
}
fn login() -> (String, String) {
    ("LOGIN".into(), "%TAG% OK logged in\r\n".into())
}
fn examine(validity: u32, next: u32) -> (String, String) {
    (
        "EXAMINE \"INBOX\"".into(),
        format!(
            "* 3 EXISTS\r\n* OK [UIDVALIDITY {validity}] valid\r\n* OK [UIDNEXT {next}] next\r\n%TAG% OK [READ-ONLY] opened\r\n"
        ),
    )
}
const RAW:&[u8]=b"Subject: =?utf-8?b?5Lit5paH?=\r\nFrom: a@example.com\r\nContent-Type: text/plain; charset=gb18030\r\nContent-Transfer-Encoding: base64\r\n\r\n1tDOxA==\r\n";
fn fetch(uid: u32, section: &str, raw: &[u8]) -> (String, String) {
    (
        format!("UID FETCH {uid} (UID BODY.PEEK"),
        format!(
            "* 1 FETCH (UID {uid} BODY[{section}] {{{}}}\r\n{})\r\n%TAG% OK fetched\r\n",
            raw.len(),
            std::str::from_utf8(raw).unwrap()
        ),
    )
}

#[test]
fn unicode_and_mime() {
    for value in ["中文&文件夹", "INBOX", "测试/子目录", "😀"] {
        assert_eq!(utf7_decode(&utf7_encode(value)).unwrap(), value);
    }
    let parsed = parse_mail(RAW, true).unwrap();
    assert_eq!(parsed["subject"], "中文");
    assert_eq!(parsed["body"].as_str().unwrap().trim(), "中文");
    let html=parse_mail(b"Content-Type: text/html\r\n\r\n<p>Hello</p><script>secret_script()</script><img src=\"https://tracking.example/\">",true).unwrap();
    assert!(html["body"].as_str().unwrap().contains("Hello"));
    assert!(!html["body"].as_str().unwrap().contains("secret_script"));
}
#[test]
fn input_controls() {
    assert!(Page::parse(json!({"before_uid":10}), false).is_err());
    assert!(serde_json::from_value::<Config>(json!({"imap_security":"none"})).is_err());
    assert!(mail_bridge_rust::auth::form(b"scope=mail%3Aread&scope=mail%3Asend").is_err());
}
#[tokio::test]
async fn missing_uidnext_uses_bounded_uid_fetch() {
    for (name, extra) in [
        ("list_messages", json!({})),
        (
            "search_messages",
            json!({"field":"SUBJECT", "query":"hello"}),
        ),
    ] {
        let mut args = json!({"limit":1});
        args.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        let (mut session, handle) = mock_imap(vec![
            login(),
            (
                "EXAMINE".into(),
                "* 3 EXISTS\r\n* OK [UIDVALIDITY 77] valid\r\n%TAG% OK opened\r\n".into(),
            ),
            (
                " FETCH * (UID)".into(),
                "* 3 FETCH (UID 4096)\r\n%TAG% OK fetched\r\n".into(),
            ),
            (
                if name == "search_messages" {
                    "UID SEARCH UID 3073:4096 SUBJECT \"hello\""
                } else {
                    "UID SEARCH UID 3073:4096"
                }
                .into(),
                "* SEARCH 4096\r\n%TAG% OK searched\r\n".into(),
            ),
            fetch(4096, "HEADER", RAW),
        ])
        .await;
        let page = RealBackend::read_session(&mut session, name, args)
            .await
            .unwrap();
        assert_eq!(page["messages"][0]["uid"], 4096);
        assert_eq!(page["uidvalidity"], 77);
        handle.await.unwrap();
    }
    let (mut session, handle) = mock_imap(vec![
        login(),
        (
            "EXAMINE".into(),
            "* 0 EXISTS\r\n* OK [UIDVALIDITY 77] valid\r\n%TAG% OK opened\r\n".into(),
        ),
    ])
    .await;
    let page = RealBackend::read_session(&mut session, "list_messages", json!({}))
        .await
        .unwrap();
    assert_eq!(page["messages"], json!([]));
    assert!(page["next_before_uid"].is_null());
    handle.await.unwrap();
    let (mut session, handle) = mock_imap(vec![
        login(),
        (
            "EXAMINE".into(),
            "* 3 EXISTS\r\n* OK [UIDVALIDITY 77] valid\r\n%TAG% OK opened\r\n".into(),
        ),
        (" FETCH * (UID)".into(), "%TAG% OK vanished\r\n".into()),
    ])
    .await;
    assert!(
        RealBackend::read_session(&mut session, "list_messages", json!({}))
            .await
            .is_err()
    );
    handle.await.unwrap();
}
#[tokio::test]
async fn uid_pages_and_readonly_peek() {
    let script = vec![
        login(),
        examine(77, 31),
        (
            "UID SEARCH UID 1:30".into(),
            "* SEARCH 2 30 10\r\n%TAG% OK searched\r\n".into(),
        ),
        fetch(30, "HEADER", RAW),
        fetch(10, "HEADER", RAW),
    ];
    let (mut session, handle) = mock_imap(script).await;
    let page = RealBackend::read_session(&mut session, "list_messages", json!({"limit":2}))
        .await
        .unwrap();
    assert_eq!(page["messages"][0]["uid"], 30);
    assert_eq!(page["messages"][1]["uid"], 10);
    assert_eq!(page["next_before_uid"], 10);
    assert_eq!(page["uidvalidity"], 77);
    handle.await.unwrap();
    let script = vec![
        login(),
        examine(77, 31),
        (
            "UID SEARCH UID 1:9".into(),
            "* SEARCH 2\r\n%TAG% OK searched\r\n".into(),
        ),
        fetch(2, "HEADER", RAW),
    ];
    let (mut session, handle) = mock_imap(script).await;
    let page = RealBackend::read_session(
        &mut session,
        "list_messages",
        json!({"before_uid":10,"uidvalidity":77}),
    )
    .await
    .unwrap();
    assert_eq!(page["messages"][0]["uid"], 2);
    assert!(page["next_before_uid"].is_null());
    handle.await.unwrap();
}
#[tokio::test]
async fn body_size_uidvalidity_and_utf8_search() {
    let script = vec![
        login(),
        examine(77, 31),
        (
            "UID FETCH 10 (UID RFC822.SIZE)".into(),
            format!(
                "* 1 FETCH (UID 10 RFC822.SIZE {})\r\n%TAG% OK size\r\n",
                RAW.len()
            ),
        ),
        fetch(10, "", RAW),
    ];
    let (mut session, handle) = mock_imap(script).await;
    let mail = RealBackend::read_session(
        &mut session,
        "read_message",
        json!({"uid":10,"uidvalidity":77}),
    )
    .await
    .unwrap();
    assert_eq!(mail["body"].as_str().unwrap().trim(), "中文");
    handle.await.unwrap();
    let (mut session, handle) = mock_imap(vec![login(), examine(78, 31)]).await;
    assert!(
        RealBackend::read_session(
            &mut session,
            "read_message",
            json!({"uid":10,"uidvalidity":77})
        )
        .await
        .is_err()
    );
    handle.await.unwrap();
    let (mut session, handle) = mock_imap(vec![
        login(),
        (
            "UID SEARCH CHARSET UTF-8 UID 1:30 SUBJECT {6}".into(),
            "+ continue\r\n".into(),
        ),
        ("中文".into(), "* SEARCH 10\r\n%TAG% OK searched\r\n".into()),
    ])
    .await;
    assert!(
        search(
            &mut session,
            "UID 1:30",
            &SearchCriteria::parse("SUBJECT", "中文".into()).unwrap()
        )
        .await
        .unwrap()
        .contains(&10)
    );
    handle.await.unwrap();
}
#[tokio::test]
async fn literal_limit_before_parser_allocation() {
    let (mut writer, reader) = tokio::io::duplex(1024);
    writer
        .write_all(b"* 1 FETCH (BODY[] {99999999}\r\n")
        .await
        .unwrap();
    drop(writer);
    let mut guard = GuardIo::new(reader);
    let mut output = Vec::new();
    assert!(guard.read_to_end(&mut output).await.is_err());
    assert!(output.is_empty());
}
#[tokio::test]
async fn durable_send_dedup_and_ambiguous_failure() {
    let (dir, _settings, db, fake, service) = setup();
    let args = json!({"account_id":"qq","to":["a@example.com"],"subject":"中文","body":"正文","request_id":"send-request-00001"});
    assert_eq!(
        service.dispatch("send_email", args.clone()).await.unwrap()["status"],
        "accepted_by_smtp"
    );
    let restarted = MailService {
        accounts: service.accounts.clone(),
        db: Db::open(&dir.path().join("test.db")).unwrap(),
        gate: Arc::new(tokio::sync::Semaphore::new(1)),
    };
    restarted
        .dispatch("send_email", args.clone())
        .await
        .unwrap();
    assert_eq!(fake.sent.load(Ordering::SeqCst), 1);
    let mut changed = args.clone();
    changed["body"] = json!("changed");
    assert!(service.dispatch("send_email", changed).await.is_err());
    fake.fail.store(true, Ordering::SeqCst);
    let mut uncertain = args.clone();
    uncertain["request_id"] = json!("send-request-00002");
    assert!(
        service
            .dispatch("send_email", uncertain.clone())
            .await
            .is_err()
    );
    assert_eq!(
        service.dispatch("send_email", uncertain).await.unwrap()["status"],
        "unknown_do_not_retry"
    );
    assert_eq!(fake.sent.load(Ordering::SeqCst), 2);
    service
        .accounts
        .write()
        .unwrap()
        .get_mut("qq")
        .unwrap()
        .config
        .smtp_enabled = false;
    assert!(service.dispatch("send_email", args).await.is_err());
    let _permit = service.gate.acquire().await.unwrap();
    assert!(
        service
            .dispatch("list_messages", json!({"account_id":"qq"}))
            .await
            .is_err()
    );
    drop(db);
}

async fn request(
    app: axum::Router,
    path: &str,
    method: &str,
    body: String,
    token: Option<&str>,
    cookie: Option<&str>,
    origin: Option<&str>,
) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header("Host", "mail.example.com")
        .header("Accept", "application/json, text/event-stream")
        .header("MCP-Protocol-Version", "2025-06-18")
        .header(
            "Content-Type",
            if path == "/oauth/token" || path == "/oauth/authorize" {
                "application/x-www-form-urlencoded"
            } else {
                "application/json"
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
    let (status, headers) = (response.status(), response.headers().clone());
    let bytes = response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes()
        .to_vec();
    (status, headers, bytes)
}
fn hidden(page: &str) -> Params {
    let mut result = Params::new();
    for part in page.split("<input type=\"hidden\" name=\"").skip(1) {
        let (key, rest) = part.split_once('"').unwrap();
        let rest = rest.strip_prefix(" value=\"").unwrap();
        let value = rest.split('"').next().unwrap();
        result.insert(
            key.into(),
            html_escape::decode_html_entities(value).into_owned(),
        );
    }
    result
}

#[test]
fn oauth_redirect_policy_is_explicit_and_loopback_only() {
    let (dir, mut settings, db, _fake, _service) = setup();
    let native = "http://127.0.0.1:58597/callback";
    let web = settings.redirects[0].clone();
    assert!(!Auth::new(&settings, db.clone()).redirect_allowed(native));
    settings.redirects.extend([
        "http://127.0.0.1/callback".into(),
        "http://[::1]/callback".into(),
    ]);
    let auth = Auth::new(&settings, db.clone());
    for allowed in [
        native,
        "http://127.0.0.1:58598/callback",
        "http://[::1]:58597/callback",
        &web,
    ] {
        assert!(auth.redirect_allowed(allowed), "{allowed}");
        assert!(auth.register(json!({"redirect_uris":[allowed]})).is_ok());
    }
    for rejected in [
        "http://evil.example:58597/callback",
        "http://localhost:58597/callback",
        "http://127.0.0.2:58597/callback",
        "http://0.0.0.0:58597/callback",
        "http://127.0.0.1.evil.example:58597/callback",
        "http://127.0.0.1:58597/callback/extra",
        "http://127.0.0.1:58597/%63allback",
        "http://127.0.0.1:58597/callback?next=https://evil.example",
        "http://127.0.0.1:58597/callback#fragment",
        "http://user@127.0.0.1:58597/callback",
        "http://127.0.0.1:0/callback",
        "http://2130706433:58597/callback",
        "https://127.0.0.1:58597/callback",
        "https://chatgpt.com/connector_platform_oauth_redirect/extra",
    ] {
        assert!(!auth.redirect_allowed(rejected), "{rejected}");
        assert!(auth.register(json!({"redirect_uris":[rejected]})).is_err());
    }
    settings.redirects = vec![native.into()];
    let fixed = Auth::new(&settings, db);
    assert!(fixed.redirect_allowed(native));
    assert!(!fixed.redirect_allowed("http://127.0.0.1:58598/callback"));
    drop(dir);
}

#[tokio::test]
async fn http_oauth_pkce_mcp_and_scope() {
    oauth_pkce_mcp_and_scope_for_callback("https://chatgpt.com/connector_platform_oauth_redirect")
        .await;
    oauth_pkce_mcp_and_scope_for_callback("http://127.0.0.1:58597/callback").await;
}

async fn oauth_pkce_mcp_and_scope_for_callback(callback: &str) {
    let (_dir, mut settings, db, _fake, service) = setup();
    if callback.starts_with("http:") {
        settings.redirects = vec!["http://127.0.0.1/callback".into()];
    }
    let auth = Arc::new(Auth::new(&settings, db.clone()));
    assert_eq!(
        auth.metadata(false)["scopes_supported"],
        json!(["mail:read"])
    );
    assert_eq!(
        auth.metadata(true)["scopes_supported"],
        json!(["mail:read"])
    );
    let app = router(&settings, auth.clone(), service);
    let (status, headers, _) = request(
        app.clone(),
        "/mcp",
        "POST",
        json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}).to_string(),
        None,
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(
        headers["www-authenticate"]
            .to_str()
            .unwrap()
            .contains("resource_metadata")
    );
    let (status, _, bytes) = request(
        app.clone(),
        "/.well-known/oauth-protected-resource",
        "GET",
        "".into(),
        None,
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        serde_json::from_slice::<Value>(&bytes).unwrap()["resource"],
        auth.resource
    );
    let (status, _, bytes) = request(
        app.clone(),
        "/oauth/register",
        "POST",
        json!({"redirect_uris":[callback],"token_endpoint_auth_method":"none"}).to_string(),
        None,
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let client = serde_json::from_slice::<Value>(&bytes).unwrap()["client_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let verifier = "a".repeat(64);
    let challenge = oauth2::PkceCodeChallenge::from_code_verifier_sha256(
        &oauth2::PkceCodeVerifier::new(verifier.clone()),
    );
    let params = Params::from([
        ("client_id".into(), client.clone()),
        ("redirect_uri".into(), callback.into()),
        ("response_type".into(), "code".into()),
        ("code_challenge".into(), challenge.as_str().into()),
        ("code_challenge_method".into(), "S256".into()),
        ("resource".into(), auth.resource.clone()),
        ("state".into(), "mock-state".into()),
        ("scope".into(), "mail:read".into()),
    ]);
    let mut wrong_callback = params.clone();
    wrong_callback.insert(
        "redirect_uri".into(),
        "http://127.0.0.1:58598/callback".into(),
    );
    assert!(auth.consent_form(&wrong_callback).is_err());
    let path = format!(
        "/oauth/authorize?{}",
        serde_urlencoded::to_string(&params).unwrap()
    );
    let (status, headers, bytes) =
        request(app.clone(), &path, "GET", "".into(), None, None, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers["referrer-policy"], "strict-origin");
    let callback_origin = url::Url::parse(callback)
        .unwrap()
        .origin()
        .ascii_serialization();
    let csp = headers["content-security-policy"].to_str().unwrap();
    assert!(csp.contains(&format!("form-action 'self' {callback_origin};")));
    assert!(!csp.contains("*"));
    let cookie = headers["set-cookie"]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    let mut fields = hidden(std::str::from_utf8(&bytes).unwrap());
    fields.insert(
        "owner_password".into(),
        settings.owner_password.as_str().to_owned(),
    );
    // Retain strict Origin, signed fields, cookie and owner-password checks.
    for origin in [None, Some("null"), Some("https://evil.example")] {
        let response = request(
            app.clone(),
            "/oauth/authorize",
            "POST",
            serde_urlencoded::to_string(&fields).unwrap(),
            None,
            Some(&cookie),
            origin,
        )
        .await;
        assert_eq!(response.0, StatusCode::FORBIDDEN);
    }
    assert_eq!(
        request(
            app.clone(),
            "/oauth/authorize",
            "POST",
            serde_urlencoded::to_string(&fields).unwrap(),
            None,
            None,
            Some(&settings.public_url)
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    let mut tampered = fields.clone();
    tampered.insert("scope".into(), "mail:read mail:send".into());
    assert_eq!(
        request(
            app.clone(),
            "/oauth/authorize",
            "POST",
            serde_urlencoded::to_string(&tampered).unwrap(),
            None,
            Some(&cookie),
            Some(&settings.public_url)
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    let (status, headers, _) = request(
        app.clone(),
        "/oauth/authorize",
        "POST",
        serde_urlencoded::to_string(&fields).unwrap(),
        None,
        Some(&cookie),
        Some(&settings.public_url),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let location = url::Url::parse(headers["location"].to_str().unwrap()).unwrap();
    let returned: Params = location.query_pairs().into_owned().collect();
    assert_eq!(returned["iss"], settings.public_url);
    assert_eq!(returned["state"], "mock-state");
    let mut exchange = Params::from([
        ("grant_type".into(), "authorization_code".into()),
        ("client_id".into(), client.clone()),
        ("redirect_uri".into(), callback.into()),
        ("code".into(), returned["code"].clone()),
        ("code_verifier".into(), verifier),
        ("resource".into(), auth.resource.clone()),
    ]);
    let body = serde_urlencoded::to_string(&exchange).unwrap();
    let mut invalid_pkce = exchange.clone();
    invalid_pkce.insert("code_verifier".into(), "b".repeat(64));
    assert!(auth.exchange(&invalid_pkce).is_err());
    let mut invalid_callback = exchange.clone();
    invalid_callback.insert(
        "redirect_uri".into(),
        "http://127.0.0.1:58598/callback".into(),
    );
    assert!(auth.exchange(&invalid_callback).is_err());
    assert!(
        auth.register(json!({"redirect_uris":["https://evil.example/callback"]}))
            .is_err()
    );
    let (status, _, bytes) = request(
        app.clone(),
        "/oauth/token",
        "POST",
        body.clone(),
        None,
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let tokens: Value = serde_json::from_slice(&bytes).unwrap();
    let token = tokens["access_token"].as_str().unwrap();
    assert_eq!(
        request(app.clone(), "/oauth/token", "POST", body, None, None, None)
            .await
            .0,
        StatusCode::BAD_REQUEST
    );
    let(status,_,bytes)=request(app.clone(),"/mcp","POST",json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"local-test","version":"1"}}}).to_string(),Some(token),None,None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        serde_json::from_slice::<Value>(&bytes).unwrap()["result"]["capabilities"]["tools"]
            .is_object()
    );
    let (_, _, bytes) = request(
        app.clone(),
        "/mcp",
        "POST",
        json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}).to_string(),
        Some(token),
        None,
        None,
    )
    .await;
    let listed: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(listed["result"]["tools"].as_array().unwrap().len(), 8);
    let(_,_,bytes)=request(app.clone(),"/mcp","POST",json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"prepare_draft","arguments":{"account_id":"qq","to":["a@example.com"],"subject":"subject","body":"body"}}}).to_string(),Some(token),None,None).await;
    assert_eq!(
        serde_json::from_slice::<Value>(&bytes).unwrap()["result"]["isError"],
        false
    );
    let(_,_,bytes)=request(app.clone(),"/mcp","POST",json!({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"send_email","arguments":{"account_id":"qq","to":["a@example.com"],"subject":"subject","body":"body","request_id":"request-000000001"}}}).to_string(),Some(token),None,None).await;
    assert_eq!(
        serde_json::from_slice::<Value>(&bytes).unwrap()["result"]["isError"],
        true
    );
    assert!(
        std::str::from_utf8(&bytes)
            .unwrap()
            .contains("mcp/www_authenticate")
    );
    let refresh = tokens["refresh_token"].as_str().unwrap().to_owned();
    exchange = Params::from([
        ("grant_type".into(), "refresh_token".into()),
        ("client_id".into(), client),
        ("refresh_token".into(), refresh.clone()),
        ("resource".into(), auth.resource.clone()),
    ]);
    let rotated = auth.exchange(&exchange).unwrap();
    assert_ne!(rotated["refresh_token"], refresh);
    assert!(auth.exchange(&exchange).is_err());
    {
        let db = db.0.lock().unwrap();
        let stored: String = db
            .query_row("SELECT hash FROM tokens WHERE hash=?", [hash(token)], |r| {
                r.get(0)
            })
            .unwrap();
        assert_ne!(stored, token);
    }
    assert_eq!(
        request(
            app.clone(),
            "/mcp",
            "POST",
            "{}".into(),
            Some(token),
            None,
            Some("https://evil.example")
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
}
#[tokio::test]
async fn probes_check_local_state_without_mail_access() {
    let (_dir, settings, db, fake, mail) = setup();
    let app = router(&settings, Arc::new(Auth::new(&settings, db.clone())), mail);
    for path in ["/healthz", "/readyz"] {
        let (status, headers, body) =
            request(app.clone(), path, "GET", String::new(), None, None, None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(headers["cache-control"], "no-store");
        assert_eq!(
            serde_json::from_slice::<Value>(&body).unwrap(),
            json!({"status":"ok"})
        );
    }
    db.0.lock()
        .unwrap()
        .execute("DROP TABLE runtime_accounts", [])
        .unwrap();
    assert_eq!(
        request(
            app.clone(),
            "/readyz",
            "GET",
            String::new(),
            None,
            None,
            None
        )
        .await
        .0,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        request(app, "/healthz", "GET", String::new(), None, None, None)
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(fake.sent.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn privacy_headers_cover_rejections_and_rate_limits() {
    let (_dir, settings, db, _fake, mail) = setup();
    let app = router(&settings, Arc::new(Auth::new(&settings, db)), mail);
    for (path, method, body, origin, expected) in [
        (
            "/missing",
            "GET",
            String::new(),
            None,
            StatusCode::NOT_FOUND,
        ),
        ("/mcp", "POST", "{}".into(), None, StatusCode::UNAUTHORIZED),
        (
            "/oauth/register",
            "POST",
            "x".repeat(65537),
            None,
            StatusCode::PAYLOAD_TOO_LARGE,
        ),
        (
            "/oauth/authorize",
            "POST",
            String::new(),
            Some("https://evil.example"),
            StatusCode::FORBIDDEN,
        ),
    ] {
        let (status, headers, _) =
            request(app.clone(), path, method, body, None, None, origin).await;
        assert_eq!(status, expected);
        assert_eq!(headers["cache-control"], "no-store");
        assert_eq!(headers["referrer-policy"], "no-referrer");
        assert_eq!(headers["x-content-type-options"], "nosniff");
    }
    for attempt in 0..11 {
        let (status, headers, _) = request(
            app.clone(),
            "/oauth/authorize",
            "POST",
            String::new(),
            None,
            None,
            Some("https://mail.example.com"),
        )
        .await;
        assert_eq!(
            status,
            if attempt < 10 {
                StatusCode::BAD_REQUEST
            } else {
                StatusCode::TOO_MANY_REQUESTS
            }
        );
        assert_eq!(headers["cache-control"], "no-store");
        assert_eq!(headers["x-content-type-options"], "nosniff");
    }
}

#[tokio::test]
async fn local_http_socket_smoke() {
    let (_dir, settings, db, _fake, mail) = setup();
    let app = router(&settings, Arc::new(Auth::new(&settings, db)), mail);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let mut client = tokio::net::TcpStream::connect(address).await.unwrap();
    client.write_all(b"GET /.well-known/oauth-protected-resource HTTP/1.1\r\nHost: mail.example.com\r\nConnection: close\r\n\r\n").await.unwrap();
    let mut raw = String::new();
    client.read_to_string(&mut raw).await.unwrap();
    assert!(raw.starts_with("HTTP/1.1 200"));
    assert!(raw.contains("https://mail.example.com/mcp"));
    server.abort();
}

#[tokio::test]
async fn two_account_sender_and_request_id_isolation() {
    let (dir, _settings, _db, qq, original) = setup();
    let mut service = (*original).clone();
    let zju = Arc::new(Fake::default());
    let mut account = service.accounts.read().unwrap()["qq"].clone();
    account.id = "zju".into();
    account.concurrency = Default::default();
    account.name = "Mock ZJU".into();
    account.config.username = "school@zju.example".into();
    account.config.from_address = "school@zju.example".into();
    account.config.smtp_port = 994;
    account.backend = Some(zju.clone());
    service
        .accounts
        .write()
        .unwrap()
        .insert("zju".into(), account);
    let listed = service.dispatch("list_accounts", json!({})).await.unwrap();
    assert_eq!(listed["accounts"].as_array().unwrap().len(), 2);
    assert!(!listed.to_string().contains("mock-mailbox-only"));
    let args = json!({"to":["recipient@example.com"],"subject":"Subject","body":"Body"});
    assert!(
        service
            .dispatch("prepare_draft", args.clone())
            .await
            .is_err()
    );
    let mut send = args.clone();
    send["account_id"] = json!("qq");
    let preview = service
        .dispatch("prepare_draft", send.clone())
        .await
        .unwrap();
    assert_eq!(preview["account_id"], "qq");
    assert_eq!(preview["from_address"], "mock@example.com");
    send["account_id"] = json!("zju");
    let preview = service
        .dispatch("prepare_draft", send.clone())
        .await
        .unwrap();
    assert_eq!(preview["account_id"], "zju");
    assert_eq!(preview["from_address"], "school@zju.example");
    send["request_id"] = json!("shared-request-000001");
    for id in ["qq", "zju"] {
        send["account_id"] = json!(id);
        assert_eq!(
            service.dispatch("send_email", send.clone()).await.unwrap()["account_id"],
            id
        );
    }
    assert_eq!(qq.sent.load(Ordering::SeqCst), 1);
    assert_eq!(zju.sent.load(Ordering::SeqCst), 1);
    service.db = Db::open(&dir.path().join("test.db")).unwrap();
    for id in ["qq", "zju"] {
        send["account_id"] = json!(id);
        service.dispatch("send_email", send.clone()).await.unwrap();
    }
    assert_eq!(qq.sent.load(Ordering::SeqCst), 1);
    assert_eq!(zju.sent.load(Ordering::SeqCst), 1);
    send["account_id"] = json!("unknown");
    assert!(service.dispatch("send_email", send).await.is_err());
    assert!(
        service
            .dispatch(
                "read_message",
                json!({"account_id":"unknown","uid":1,"uidvalidity":1})
            )
            .await
            .is_err()
    );
    service
        .accounts
        .write()
        .unwrap()
        .get_mut("zju")
        .unwrap()
        .backend = None;
    service
        .accounts
        .write()
        .unwrap()
        .get_mut("zju")
        .unwrap()
        .credential_status = "missing";
    let status = service.dispatch("list_accounts", json!({})).await.unwrap();
    let account = status["accounts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|account| account["account_id"] == "zju")
        .unwrap();
    assert_eq!(account["credential_status"], "missing");
    assert!(
        service
            .dispatch("list_messages", json!({"account_id":"zju"}))
            .await
            .is_err()
    );
    assert_eq!(qq.sent.load(Ordering::SeqCst), 1);
    assert_eq!(zju.sent.load(Ordering::SeqCst), 1);
    for tool in mail_bridge_rust::mcp::TOOLS.iter() {
        if !matches!(tool.name.as_ref(), "list_accounts" | "begin_account_setup") {
            assert!(
                tool.input_schema["required"]
                    .as_array()
                    .unwrap()
                    .contains(&json!("account_id"))
            );
        }
    }
}
