mod support;
use base64::{Engine, engine::general_purpose::STANDARD};
use mail_bridge_events::{Events, webhook};
use mail_bridge_store::Db;
use serde_json::Value;
use std::sync::atomic::Ordering;
use support::*;
fn accepted(
    result: std::result::Result<Value, mail_bridge_events::subscription::EventError>,
) -> Value {
    result.unwrap_or_else(|e| panic!("event error {} {}", e.code, e.message))
}
fn pending(db: &Db) -> i64 {
    connection(db)
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
    connection(&db)
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
    assert_eq!(q["data"].as_object().unwrap().len(), 8);
    assert_eq!(q["data"]["subject"], "中文");
    assert_eq!(q["data"]["from"][0]["address"], "sender@example.com");
    assert_eq!(q["data"]["date"], "2026-10-19T12:00:00+08:00");
    assert!(q["data"].get("body").is_none());
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
    connection(&db)
        .execute("UPDATE event_subscriptions SET expires=0", [])
        .unwrap();
    accepted(events.subscribe("owner", request("qq")).await);
    assert_eq!(pending(&db), 0);
    assert_eq!(events.get(&id).unwrap().unwrap().uid, 502);
    connection(&db)
        .execute("UPDATE event_subscriptions SET expires=0", [])
        .unwrap();
    events.scan_once(&id).await.unwrap();
    assert!(events.get(&id).unwrap().is_none());
    accepted(events.subscribe("owner", request("qq")).await);
    connection(&db).execute("DELETE FROM tokens", []).unwrap();
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
    let proofs: i64 = connection(&db)
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
        connection(&db)
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

#[tokio::test(start_paused = true)]
async fn two_trigger_task_paces_distinct_callbacks_on_one_platform_host() {
    let (_dir, _settings, _db, _auth, _mail, receiver, events) = setup();
    for account in ["qq", "zju"] {
        let mut subscription = request(account);
        subscription.delivery.url = format!("https://receiver.example.com/events/{account}");
        accepted(events.subscribe("owner", subscription).await);
    }
    assert_eq!(events.active().unwrap().len(), 2);
    assert_eq!(receiver.calls.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn failed_baseline_leaves_no_subscription_and_retry_reuses_callback_proof() {
    let (_dir, _settings, db, _auth, mail, receiver, events) = setup();
    mail.fail_snapshot.store(true, Ordering::SeqCst);
    let error = events
        .subscribe("owner", request("zju"))
        .await
        .err()
        .unwrap();
    assert_eq!(error.reason, Some("imap_uidvalidity_missing"));
    assert!(events.active().unwrap().is_empty());
    assert_eq!(pending(&db), 0);
    mail.fail_snapshot.store(false, Ordering::SeqCst);
    let id = accepted(events.subscribe("owner", request("zju")).await)["id"].clone();
    assert_eq!(events.active().unwrap().len(), 1);
    assert_eq!(receiver.calls.lock().unwrap().len(), 1);
    assert_eq!(
        accepted(events.subscribe("owner", request("zju")).await)["id"],
        id
    );
}
