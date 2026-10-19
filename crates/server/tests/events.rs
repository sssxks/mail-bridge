#[path = "../../events/tests/support/mod.rs"]
mod support;
use mail_bridge_store::{hash, now};
use rusqlite::params;
use serde_json::{Value, json};
use std::sync::Arc;
use support::*;
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
    let (_dir, _config, db, auth, _mail, _receiver, events) = setup();
    for (token, scope) in [("read", "mail:read"), ("send", "mail:send")] {
        connection(&db)
            .execute(
                "INSERT INTO tokens VALUES (?,'access','owner',?,?,?)",
                params![hash(token), auth.resource(), scope, now() + 3600],
            )
            .unwrap();
    }
    let mail = Arc::new(mail_bridge_mail::service::MailService::from_store(db.clone()).unwrap());
    let app = mail_bridge_rust::http::router(auth.clone(), mail.clone(), Some(events.clone()));
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
    let secret = request("qq").delivery.secret.unwrap();
    let args = json!({"name":"message.created","arguments":{"account_id":"qq","mailbox":"INBOX"},"delivery":{"mode":"webhook","url":"https://qq.example.com/events","secret":secret},"cursor":null});
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
    let off = mail_bridge_rust::http::router(auth, mail, None);
    let (_, _, discover) = rpc(off.clone(), "server/discover", json!({}), "read").await;
    assert!(discover["result"]["capabilities"].get("events").is_none());
    let (_, _, catalog) = rpc(off, "events/list", json!({}), "read").await;
    assert_eq!(catalog["error"]["code"], -32601);
}
