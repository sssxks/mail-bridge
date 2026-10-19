//! Standard Webhooks delivery with per-connection DNS validation and pinning.
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD},
};
use futures_util::{StreamExt, future::BoxFuture};
use hmac::{Hmac, Mac};
use mail_bridge_core::{Error, Result, clean};
use sha2::Sha256;
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::Duration,
};

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct CallbackError(pub &'static str);
pub struct Reply {
    pub status: u16,
    pub body: Vec<u8>,
}
pub trait Transport: Send + Sync {
    fn post<'a>(
        &'a self,
        url: &'a str,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    ) -> BoxFuture<'a, std::result::Result<Reply, CallbackError>>;
}
pub fn key(secret: &str) -> Result<Vec<u8>> {
    let raw = secret
        .strip_prefix("whsec_")
        .ok_or(Error("Invalid webhook signing secret"))?;
    let bytes = STANDARD
        .decode(raw)
        .or_else(|_| STANDARD_NO_PAD.decode(raw))
        .map_err(|_| Error("Invalid webhook signing secret"))?;
    if !(24..=64).contains(&bytes.len()) {
        return Err(Error("Invalid webhook signing secret"));
    }
    Ok(bytes)
}
pub fn signature(secret: &str, id: &str, timestamp: i64, body: &[u8]) -> Result<String> {
    let mut mac = Hmac::<Sha256>::new_from_slice(&key(secret)?).map_err(mail_bridge_core::safe)?;
    mac.update(format!("{id}.{timestamp}.").as_bytes());
    mac.update(body);
    Ok(format!(
        "v1,{}",
        STANDARD.encode(mac.finalize().into_bytes())
    ))
}
pub fn headers(
    secret: &str,
    previous: Option<&str>,
    id: &str,
    subscription: &str,
    body: &[u8],
) -> Result<Vec<(String, String)>> {
    let timestamp = mail_bridge_store::now();
    let mut signed = signature(secret, id, timestamp, body)?;
    if let Some(previous) = previous {
        signed.push(' ');
        signed.push_str(&signature(previous, id, timestamp, body)?);
    }
    Ok(vec![
        ("Content-Type".into(), "application/json".into()),
        ("webhook-id".into(), id.into()),
        ("webhook-timestamp".into(), timestamp.to_string()),
        ("webhook-signature".into(), signed),
        ("X-MCP-Subscription-Id".into(), subscription.into()),
    ])
}
pub fn callback_url(raw: &str) -> Result<url::Url> {
    clean(raw, 2048)?;
    let url = url::Url::parse(raw).map_err(|_| Error("Invalid callback URL"))?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || url.port_or_known_default() != Some(443)
    {
        return Err(Error(
            "Callback must be an HTTPS URL on port 443 without credentials or fragment",
        ));
    }
    if let Some(host) = url.host_str()
        && let Ok(ip) = host.trim_matches(['[', ']']).parse::<IpAddr>()
        && !public_ip(ip)
    {
        return Err(Error("Callback is not publicly routable"));
    }
    Ok(url)
}
fn v4_prefix(ip: Ipv4Addr, base: [u8; 4], bits: u32) -> bool {
    u32::from(ip) >> (32 - bits) == u32::from(Ipv4Addr::from(base)) >> (32 - bits)
}
fn v6_prefix(ip: Ipv6Addr, base: u128, bits: u32) -> bool {
    u128::from(ip) >> (128 - bits) == base >> (128 - bits)
}
pub fn public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ![
            ([0, 0, 0, 0], 8),
            ([10, 0, 0, 0], 8),
            ([100, 64, 0, 0], 10),
            ([127, 0, 0, 0], 8),
            ([169, 254, 0, 0], 16),
            ([172, 16, 0, 0], 12),
            ([192, 0, 0, 0], 24),
            ([192, 0, 2, 0], 24),
            ([192, 88, 99, 0], 24),
            ([192, 168, 0, 0], 16),
            ([198, 18, 0, 0], 15),
            ([198, 51, 100, 0], 24),
            ([203, 0, 113, 0], 24),
            ([224, 0, 0, 0], 4),
            ([240, 0, 0, 0], 4),
        ]
        .iter()
        .any(|(base, bits)| v4_prefix(ip, *base, *bits)),
        IpAddr::V6(ip) => {
            v6_prefix(ip, 0x2000u128 << 112, 3)
                && !v6_prefix(ip, 0x2001u128 << 112, 23)
                && !v6_prefix(ip, 0x20010db8u128 << 96, 32)
                && !v6_prefix(ip, 0x2002u128 << 112, 16)
                && !v6_prefix(ip, 0x3fff0u128 << 108, 20)
        }
    }
}
pub struct HttpsTransport;
impl Transport for HttpsTransport {
    fn post<'a>(
        &'a self,
        raw: &'a str,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    ) -> BoxFuture<'a, std::result::Result<Reply, CallbackError>> {
        Box::pin(async move {
            let url = callback_url(raw).map_err(|_| CallbackError("invalid_url"))?;
            let host = url
                .host_str()
                .ok_or(CallbackError("invalid_url"))?
                .trim_matches(['[', ']'])
                .to_owned();
            let addresses: Vec<_> = tokio::time::timeout(
                Duration::from_secs(5),
                tokio::net::lookup_host((host.as_str(), 443)),
            )
            .await
            .map_err(|_| CallbackError("timeout"))?
            .map_err(|_| CallbackError("connection_refused"))?
            .collect();
            if addresses.is_empty()
                || addresses.len() > 16
                || addresses.iter().any(|a| !public_ip(a.ip()))
            {
                return Err(CallbackError("invalid_url"));
            }
            // Fresh client, no proxy, no redirects and no cached connections. Only the
            // validated addresses are dialed while URL Host and TLS SNI stay unchanged.
            let client = reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .pool_max_idle_per_host(0)
                .connect_timeout(Duration::from_secs(5))
                .timeout(Duration::from_secs(10))
                .resolve_to_addrs(&host, &addresses)
                .build()
                .map_err(|_| CallbackError("tls_error"))?;
            let mut request = client.post(url).body(body);
            for (name, value) in headers {
                request = request.header(name, value);
            }
            let response = request.send().await.map_err(|e| {
                CallbackError(if e.is_timeout() {
                    "timeout"
                } else {
                    "connection_refused"
                })
            })?;
            let status = response.status().as_u16();
            let mut stream = response.bytes_stream();
            let mut body = Vec::new();
            while let Some(chunk) = stream.next().await {
                let chunk = chunk.map_err(|_| CallbackError("connection_refused"))?;
                if body.len() + chunk.len() > 8192 {
                    body.clear();
                    break;
                }
                body.extend_from_slice(&chunk);
            }
            Ok(Reply { status, body })
        })
    }
}
