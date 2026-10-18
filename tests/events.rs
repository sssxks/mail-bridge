use base64::{Engine, engine::general_purpose::STANDARD};
use futures_util::future::BoxFuture;
use hmac::{Hmac, Mac};
use mail_bridge_rust::{
    Result,
    auth::Auth,
    config::Settings,
    db::{Db, hash, now},
    events::{Events, Filters, Scan, Snapshot, Source, Subscribe},
    webhook::{self, CallbackError, Reply, Transport},
};
use rusqlite::params;
use serde_json::{Value, json};
use sha2::Sha256;
use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};
use zeroize::Zeroizing;

type DeliveryCall = (Vec<(String, String)>, Vec<u8>);
type TestSetup = (
    tempfile::TempDir,
    Settings,
    Db,
    Arc<Auth>,
    Arc<Mail>,
    Arc<Receiver>,
    Arc<Events>,
);

#[derive(Default)]
struct Mail {
    state: Mutex<BTreeMap<String, (u32, u32)>>,
    snapshots: AtomicUsize,
    scans: AtomicUsize,
}
impl Mail {
    fn set(&self, a: &str, v: u32, next: u32) {
        self.state.lock().unwrap().insert(a.into(), (v, next));
    }
}
impl Source for Mail {
    fn available(&self, a: &str) -> bool {
        self.state.lock().unwrap().contains_key(a)
    }
    fn snapshot<'a>(&'a self, f: &'a Filters) -> BoxFuture<'a, Result<Snapshot>> {
        Box::pin(async move {
            self.snapshots.fetch_add(1, Ordering::SeqCst);
            let (validity, next_uid) = self.state.lock().unwrap()[&f.account_id];
            Ok(Snapshot { validity, next_uid })
        })
    }
    fn scan<'a>(&'a self, f: &'a Filters, v: u32, uid: u32) -> BoxFuture<'a, Result<Scan>> {
        Box::pin(async move {
            self.scans.fetch_add(1, Ordering::SeqCst);
            let (validity, next_uid) = self.state.lock().unwrap()[&f.account_id];
            Ok(Scan {
                validity,
                next_uid,
                uids: if v == validity {
                    ((uid + 1)..next_uid).collect()
                } else {
                    vec![]
                },
                scanned_to: next_uid - 1,
            })
        })
    }
    fn wait<'a>(&'a self, _: &'a Filters) -> BoxFuture<'a, Result<()>> {
        Box::pin(std::future::pending())
    }
}
#[derive(Default)]
struct Receiver {
    calls: Mutex<Vec<DeliveryCall>>,
    statuses: Mutex<Vec<u16>>,
    bad_echo: Mutex<bool>,
}
fn header<'a>(h: &'a [(String, String)], name: &str) -> &'a str {
    &h.iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .unwrap()
        .1
}
fn mock_secret() -> String {
    format!("whsec_{}", STANDARD.encode([7u8; 32]))
}
impl Transport for Receiver {
    fn post<'a>(
        &'a self,
        _: &'a str,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    ) -> BoxFuture<'a, std::result::Result<Reply, CallbackError>> {
        Box::pin(async move {
            // Independently verify the exact wire bytes using the Standard Webhooks formula.
            let mut mac = Hmac::<Sha256>::new_from_slice(&[7u8; 32]).unwrap();
            mac.update(
                format!(
                    "{}.{}.",
                    header(&headers, "webhook-id"),
                    header(&headers, "webhook-timestamp")
                )
                .as_bytes(),
            );
            mac.update(&body);
            let signature = format!("v1,{}", STANDARD.encode(mac.finalize().into_bytes()));
            assert!(
                header(&headers, "webhook-signature")
                    .split(' ')
                    .any(|s| s == signature)
            );
            let value: Value = serde_json::from_slice(&body).unwrap();
            self.calls.lock().unwrap().push((headers, body));
            if value["type"] == "verification" {
                return Ok(Reply{status:200,body:serde_json::to_vec(&json!({"challenge":if *self.bad_echo.lock().unwrap(){json!("wrong")}else{value["challenge"].clone()}})).unwrap()});
            }
            let status = if self.statuses.lock().unwrap().is_empty() {
                200
            } else {
                self.statuses.lock().unwrap().remove(0)
            };
            Ok(Reply {
                status,
                body: vec![],
            })
        })
    }
}
fn request(account: &str) -> Subscribe {
    serde_json::from_value(json!({"name":"message.created","arguments":{"account_id":account,"mailbox":"INBOX"},"delivery":{"mode":"webhook","url":format!("https://{account}.example.com/events"),"secret":mock_secret()},"cursor":null})).unwrap()
}
fn setup() -> TestSetup {
    let dir = tempfile::tempdir().unwrap();
    let db = Db::open(&dir.path().join("events.db")).unwrap();
    let settings = Settings {
        owner_password: Arc::new(Zeroizing::new(
            "test-owner-placeholder-0000000000000000".into(),
        )),
        public_url: "https://mail.example.com".into(),
        redirects: vec![],
        data_dir: dir.path().into(),
        bind: "127.0.0.1:18765".parse().unwrap(),
    };
    let auth = Arc::new(Auth::new(&settings, db.clone()));
    db.0.lock()
        .unwrap()
        .execute(
            "INSERT INTO tokens VALUES (?,'refresh','owner',?,'mail:read',?)",
            params![hash("mock-refresh"), auth.resource, now() + 86400],
        )
        .unwrap();
    let source = Arc::new(Mail::default());
    source.set("qq", 1, 101);
    source.set("zju", 1, 101);
    let receiver = Arc::new(Receiver::default());
    let events = Arc::new(
        Events::new(
            db.clone(),
            auth.clone(),
            source.clone(),
            receiver.clone(),
            vec!["qq".into(), "zju".into()],
        )
        .unwrap(),
    );
    (dir, settings, db, auth, source, receiver, events)
}
fn accepted(result: std::result::Result<Value, mail_bridge_rust::events::EventError>) -> Value {
    result.unwrap_or_else(|e| panic!("event error {} {}", e.code, e.message))
}
fn pending(db: &Db) -> i64 {
    db.0.lock()
        .unwrap()
        .query_row("SELECT count(*) FROM event_outbox", [], |r| r.get(0))
        .unwrap()
}

#[tokio::test]
async fn from_now_restart_signed_retry_and_account_isolation() {
    let (_dir, _settings, db, auth, mail, receiver, events) = setup();
    let qq = accepted(events.subscribe("owner", request("qq")).await)["id"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(events.get(&qq).unwrap().unwrap().uid, 100);
    assert_eq!(pending(&db), 0);
    assert_eq!(
        accepted(events.subscribe("owner", request("qq")).await)["id"],
        qq
    );
    assert_eq!(receiver.calls.lock().unwrap().len(), 1);
    let zju = accepted(events.subscribe("owner", request("zju")).await)["id"]
        .as_str()
        .unwrap()
        .to_owned();
    mail.set("qq", 1, 103);
    mail.set("zju", 1, 102);
    events.scan_once(&qq).await.unwrap();
    events.scan_once(&zju).await.unwrap();
    assert_eq!(pending(&db), 3);
    let restarted = Events::new(
        db.clone(),
        auth,
        mail.clone(),
        receiver.clone(),
        vec!["qq".into(), "zju".into()],
    )
    .unwrap();
    receiver.statuses.lock().unwrap().extend([503, 200]);
    assert!(restarted.deliver_once(&qq).await.unwrap());
    assert_eq!(pending(&db), 3);
    db.0.lock()
        .unwrap()
        .execute("UPDATE event_outbox SET next_attempt=0", [])
        .unwrap();
    restarted.deliver_once(&qq).await.unwrap();
    assert_eq!(pending(&db), 2);
    {
        let calls = receiver.calls.lock().unwrap();
        assert_eq!(calls[2].1, calls[3].1);
        assert_eq!(
            header(&calls[2].0, "webhook-id"),
            header(&calls[3].0, "webhook-id")
        );
    }
    restarted.deliver_once(&qq).await.unwrap();
    restarted.deliver_once(&zju).await.unwrap();
    restarted.scan_once(&qq).await.unwrap();
    assert_eq!(pending(&db), 0);
    let calls = receiver.calls.lock().unwrap();
    let q: Value = serde_json::from_slice(&calls[3].1).unwrap();
    let z: Value = serde_json::from_slice(&calls[5].1).unwrap();
    assert_eq!(q["data"]["uid"], z["data"]["uid"]);
    assert_ne!(q["eventId"], z["eventId"]);
    assert_ne!(q["data"]["account_id"], z["data"]["account_id"]);
    assert_eq!(q["data"].as_object().unwrap().len(), 5);
    assert!(q.get("subject").is_none());
}
#[tokio::test]
async fn verification_errors_and_ssrf_are_rejected_before_mail_access() {
    let (_d, _s, _db, _a, mail, receiver, events) = setup();
    *receiver.bad_echo.lock().unwrap() = true;
    let error = events
        .subscribe("owner", request("qq"))
        .await
        .err()
        .unwrap();
    assert_eq!(error.code, -32015);
    assert_eq!(error.reason, Some("challenge_failed"));
    assert_eq!(mail.snapshots.load(Ordering::SeqCst), 0);
    assert!(events.active().unwrap().is_empty());
    for target in [
        "http://example.com/",
        "https://127.0.0.1/",
        "https://[::ffff:127.0.0.1]/",
        "https://169.254.169.254/",
        "https://example.com:8443/",
        "https://user:pass@example.com/",
        "https://example.com/#fragment",
    ] {
        let mut r = request("qq");
        r.delivery.url = target.into();
        assert_eq!(
            events.subscribe("owner", r).await.err().unwrap().code,
            -32602
        );
    }
    assert_eq!(receiver.calls.lock().unwrap().len(), 1);
    for ip in [
        "10.0.0.1",
        "100.64.0.1",
        "192.168.0.1",
        "198.18.0.1",
        "224.0.0.1",
        "::1",
        "fc00::1",
        "fe80::1",
        "2001:db8::1",
        "2002:7f00:1::",
        "::ffff:8.8.8.8",
    ] {
        assert!(!webhook::public_ip(ip.parse().unwrap()), "{ip}");
    }
    for ip in ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"] {
        assert!(webhook::public_ip(ip.parse().unwrap()));
    }
}
#[tokio::test]
async fn unsubscribe_expiry_revocation_uidvalidity_and_rotation() {
    let (_d, _s, db, _a, mail, receiver, events) = setup();
    let id = accepted(events.subscribe("owner", request("qq")).await)["id"]
        .as_str()
        .unwrap()
        .to_owned();
    accepted(events.unsubscribe("another-owner", request("qq")).await);
    assert!(events.get(&id).unwrap().is_some());
    mail.set("qq", 2, 501);
    events.scan_once(&id).await.unwrap();
    assert_eq!(pending(&db), 0);
    assert!(events.get(&id).unwrap().unwrap().truncated);
    let mut rotated = request("qq");
    rotated.delivery.secret = Some(format!("whsec_{}", STANDARD.encode([9u8; 32])));
    assert_eq!(
        accepted(events.subscribe("owner", rotated).await)["truncated"],
        true
    );
    mail.set("qq", 2, 502);
    events.scan_once(&id).await.unwrap();
    events.deliver_once(&id).await.unwrap();
    assert_eq!(
        header(
            &receiver.calls.lock().unwrap().last().unwrap().0,
            "webhook-signature"
        )
        .split(' ')
        .count(),
        2
    );
    accepted(events.unsubscribe("owner", request("qq")).await);
    accepted(events.unsubscribe("owner", request("qq")).await);
    assert!(events.get(&id).unwrap().is_none());
    assert!(!events.deliver_once(&id).await.unwrap());
    accepted(events.subscribe("owner", request("qq")).await);
    mail.set("qq", 2, 503);
    events.scan_once(&id).await.unwrap();
    assert_eq!(pending(&db), 1);
    db.0.lock()
        .unwrap()
        .execute("UPDATE event_subscriptions SET expires=0", [])
        .unwrap();
    accepted(events.subscribe("owner", request("qq")).await);
    assert_eq!(pending(&db), 0);
    assert_eq!(events.get(&id).unwrap().unwrap().uid, 502);
    db.0.lock()
        .unwrap()
        .execute("UPDATE event_subscriptions SET expires=0", [])
        .unwrap();
    events.scan_once(&id).await.unwrap();
    assert!(events.get(&id).unwrap().is_none());
    accepted(events.subscribe("owner", request("qq")).await);
    db.0.lock()
        .unwrap()
        .execute("DELETE FROM tokens", [])
        .unwrap();
    events.scan_once(&id).await.unwrap();
    assert!(events.get(&id).unwrap().is_none());
    assert_eq!(
        events
            .subscribe("owner", request("qq"))
            .await
            .err()
            .unwrap()
            .code,
        -32024
    );
    db.revoke_oauth().unwrap();
    let proofs: i64 =
        db.0.lock()
            .unwrap()
            .query_row("SELECT count(*) FROM event_verifications", [], |r| r.get(0))
            .unwrap();
    assert_eq!(proofs, 0);
}
#[tokio::test]
async fn bounded_queue_and_terminal_delivery_failures() {
    let (_d, _s, db, _a, mail, receiver, events) = setup();
    let id = accepted(events.subscribe("owner", request("qq")).await)["id"]
        .as_str()
        .unwrap()
        .to_owned();
    mail.set("qq", 1, 1000);
    events.scan_once(&id).await.unwrap();
    assert_eq!(pending(&db), 128);
    assert_eq!(events.get(&id).unwrap().unwrap().uid, 228);
    receiver.statuses.lock().unwrap().extend([413]);
    events.deliver_once(&id).await.unwrap();
    assert!(events.get(&id).unwrap().unwrap().paused);
    assert_eq!(pending(&db), 127);
    assert!(!events.deliver_once(&id).await.unwrap());
    accepted(events.subscribe("owner", request("qq")).await);
    assert!(!events.get(&id).unwrap().unwrap().paused);
    receiver.statuses.lock().unwrap().extend([503; 5]);
    for _ in 0..5 {
        db.0.lock()
            .unwrap()
            .execute("UPDATE event_outbox SET next_attempt=0", [])
            .unwrap();
        events.deliver_once(&id).await.unwrap();
    }
    assert!(events.get(&id).unwrap().unwrap().paused);
    assert_eq!(pending(&db), 126);
    accepted(events.subscribe("owner", request("qq")).await);
    receiver.statuses.lock().unwrap().extend([410]);
    events.deliver_once(&id).await.unwrap();
    assert!(events.get(&id).unwrap().is_none());
    assert_eq!(pending(&db), 0);
}

async fn rpc(
    app: axum::Router,
    method: &str,
    mut args: Value,
    scope_token: &str,
) -> (axum::http::StatusCode, axum::http::HeaderMap, Value) {
    use http_body_util::BodyExt;
    use tower::ServiceExt;
    args["_meta"] = json!({"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{},"io.modelcontextprotocol/clientInfo":{"name":"event-mock","version":"1"}});
    let req = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("Host", "mail.example.com")
        .header("Mcp-Method", method)
        .header("Accept", "application/json, text/event-stream")
        .header("Content-Type", "application/json")
        .header("MCP-Protocol-Version", "2026-07-28")
        .header("Authorization", format!("Bearer {scope_token}"))
        .body(axum::body::Body::from(
            json!({"jsonrpc":"2.0","id":1,"method":method,"params":args}).to_string(),
        ))
        .unwrap();
    let response = app.oneshot(req).await.unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let value = serde_json::from_slice(&body)
        .unwrap_or_else(|_| panic!("HTTP {status}: {}", String::from_utf8_lossy(&body)));
    (status, headers, value)
}
#[tokio::test]
async fn actual_mcp2026_discovery_catalog_subscribe_and_scope_challenge() {
    let (_d, settings, db, auth, _mail, _receiver, events) = setup();
    for (token, scope) in [("read", "mail:read"), ("send", "mail:send")] {
        db.0.lock()
            .unwrap()
            .execute(
                "INSERT INTO tokens VALUES (?,'access','owner',?,?,?)",
                params![hash(token), auth.resource, scope, now() + 3600],
            )
            .unwrap();
    }
    let mail = Arc::new(mail_bridge_rust::mail::MailService {
        accounts: Arc::new(std::sync::RwLock::new(BTreeMap::new())),
        db: db.clone(),
        gate: Arc::new(tokio::sync::Semaphore::new(1)),
    });
    let app = mail_bridge_rust::http::router_with_events(
        &settings,
        auth.clone(),
        mail.clone(),
        Some(events.clone()),
    );
    let (_, _, discover) = rpc(app.clone(), "server/discover", json!({}), "read").await;
    assert!(
        discover["result"]["capabilities"]["events"].is_object(),
        "{discover}"
    );
    assert_eq!(
        discover["result"]["supportedVersions"],
        json!(["2026-07-28"])
    );
    let (_, _, catalog) = rpc(app.clone(), "events/list", json!({}), "read").await;
    assert_eq!(
        catalog["result"]["events"][0]["name"], "message.created",
        "{catalog}"
    );
    let args = json!({"name":"message.created","arguments":{"account_id":"qq","mailbox":"INBOX"},"delivery":{"mode":"webhook","url":"https://qq.example.com/events","secret":mock_secret()},"cursor":null});
    let (status, headers, _) = rpc(app.clone(), "events/subscribe", args.clone(), "send").await;
    assert_eq!(status, 403);
    assert!(
        headers["www-authenticate"]
            .to_str()
            .unwrap()
            .contains("mail:read")
    );
    let (_, _, sub) = rpc(app.clone(), "events/subscribe", args.clone(), "read").await;
    assert!(sub["result"]["id"].as_str().is_some(), "{sub}");
    let (_, _, unsub) = rpc(app, "events/unsubscribe", args, "read").await;
    assert_eq!(unsub["result"], json!({}));
    assert!(events.active().unwrap().is_empty());
    let off = mail_bridge_rust::http::router(&settings, auth, mail);
    let (_, _, discover) = rpc(off.clone(), "server/discover", json!({}), "read").await;
    assert!(discover["result"]["capabilities"].get("events").is_none());
    let (_, _, catalog) = rpc(off, "events/list", json!({}), "read").await;
    assert_eq!(catalog["error"]["code"], -32601);
}
#[tokio::test]
async fn zero_subscriptions_means_no_mail_watch() {
    let (_d, _s, _db, _a, mail, receiver, events) = setup();
    let shutdown = tokio_util::sync::CancellationToken::new();
    events.start(shutdown.clone());
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    shutdown.cancel();
    assert_eq!(mail.snapshots.load(Ordering::SeqCst), 0);
    assert_eq!(mail.scans.load(Ordering::SeqCst), 0);
    assert!(receiver.calls.lock().unwrap().is_empty());
}
