use base64::{Engine, engine::general_purpose::STANDARD};
use futures_util::future::BoxFuture;
use hmac::{Hmac, Mac};
use mail_bridge_auth::{Auth, AuthConfig};
use mail_bridge_core::Result;
use mail_bridge_events::{
    Events,
    message::MessageSummary,
    source::{Scan, Snapshot, Source},
    subscription::{Filters, Subscribe},
    webhook::{CallbackError, Reply, Transport},
};
use mail_bridge_store::{Db, hash, now};
use rusqlite::params;
use serde_json::{Value, json};
use sha2::Sha256;
use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};
use zeroize::Zeroizing;

type DeliveryCall = (Vec<(String, String)>, Vec<u8>);
type TestSetup = (
    tempfile::TempDir,
    AuthConfig,
    Db,
    Arc<Auth>,
    Arc<Mail>,
    Arc<Receiver>,
    Arc<Events>,
);

#[derive(Default)]
pub struct Mail {
    pub state: Mutex<BTreeMap<String, (u32, u32)>>,
    pub snapshots: AtomicUsize,
    pub scans: AtomicUsize,
    pub fail_snapshot: AtomicBool,
    pub fail_available: AtomicBool,
}
impl Mail {
    pub fn set(&self, a: &str, v: u32, next: u32) {
        self.state.lock().unwrap().insert(a.into(), (v, next));
    }
}
impl Source for Mail {
    fn available(&self, a: &str) -> Result<bool> {
        if self.fail_available.load(Ordering::SeqCst) {
            return Err(mail_bridge_core::Error::Rejected(
                "Synthetic source lookup failure",
            ));
        }
        Ok(self.state.lock().unwrap().contains_key(a))
    }
    fn snapshot<'a>(&'a self, f: &'a Filters) -> BoxFuture<'a, Result<Snapshot>> {
        Box::pin(async move {
            self.snapshots.fetch_add(1, Ordering::SeqCst);
            if self.fail_snapshot.load(Ordering::SeqCst) {
                return Err(mail_bridge_core::Error::Baseline(
                    mail_bridge_core::BaselineFailure::MissingValidity,
                ));
            }
            let (validity, next_uid) = self.state.lock().unwrap()[f.account_id.as_str()];
            Ok(Snapshot { validity, next_uid })
        })
    }
    fn scan<'a>(&'a self, f: &'a Filters, v: u32, uid: u32) -> BoxFuture<'a, Result<Scan>> {
        Box::pin(async move {
            self.scans.fetch_add(1, Ordering::SeqCst);
            let (validity, next_uid) = self.state.lock().unwrap()[f.account_id.as_str()];
            Ok(Scan {
                validity,
                next_uid,
                messages: if v == validity {
                    ((uid + 1)..next_uid).map(|id| MessageSummary::parse(id, b"Subject: =?utf-8?b?5Lit5paH?=\r\nFrom: Sender <sender@example.com>\r\nDate: Mon, 19 Oct 2026 12:00:00 +0800\r\n\r\n")).collect()
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
pub struct Receiver {
    pub calls: Mutex<Vec<DeliveryCall>>,
    pub statuses: Mutex<Vec<u16>>,
    pub bad_echo: Mutex<bool>,
}
pub fn header<'a>(h: &'a [(String, String)], name: &str) -> &'a str {
    &h.iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .unwrap()
        .1
}
pub fn mock_secret() -> String {
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
pub fn request(account: &str) -> Subscribe {
    serde_json::from_value(json!({"name":"message.created","arguments":{"account_id":account,"mailbox":"INBOX"},"delivery":{"mode":"webhook","url":format!("https://{account}.example.com/events"),"secret":mock_secret()},"cursor":null})).unwrap()
}
pub fn setup() -> TestSetup {
    let dir = tempfile::tempdir().unwrap();
    let db = Db::open(&dir.path().join("events.db")).unwrap();
    let settings = AuthConfig {
        owner_password: Arc::new(Zeroizing::new(
            "test-owner-placeholder-0000000000000000".into(),
        )),
        public_url: "https://mail.example.com".into(),
        redirects: vec![].into(),
    };
    let auth = Arc::new(Auth::new(&settings, db.clone()).unwrap());
    connection(&db)
        .execute(
            "INSERT INTO tokens VALUES (?,'refresh','owner',?,'mail:read',?)",
            params![hash("mock-refresh"), auth.resource(), now() + 86400],
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

pub fn connection(db: &Db) -> rusqlite::Connection {
    rusqlite::Connection::open(db.path()).unwrap()
}
