use crate::{
    form::form,
    mcp::{Mcp, Principal, Scopes},
};
use axum::{
    Json, Router,
    body::{Body, Bytes},
    extract::{DefaultBodyLimit, RawQuery, Request, State},
    http::{HeaderMap, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use mail_bridge_auth::Auth;
use mail_bridge_mail::service::MailService;
use rmcp::transport::streamable_http_server::{
    StreamableHttpServerConfig, StreamableHttpService, session::never::NeverSessionManager,
};
use serde_json::json;
use std::{
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::{TcpListener, TcpStream},
    sync::{OwnedSemaphorePermit, Semaphore},
};

/// HTTP application dependency product plus bounded admission and login-attempt state.
/// Private fields prevent adapters from replacing runtime services or budgets.
#[derive(Clone)]
struct App {
    /// Shared private account-setup invitation service.
    setup: Arc<crate::account_setup::AccountSetup>,
    /// Mail service used by HTTP and MCP adapters.
    mail: Arc<MailService>,
    /// Authorization service used to resolve current grants.
    auth: Arc<Auth>,
    /// Global HTTP request admission budget.
    requests: Arc<Semaphore>,
    /// Completed delivery failures or bounded callback-attempt history.
    attempts: Arc<Mutex<Vec<Instant>>>,
    /// Optional event service; absence disables event discovery and operations.
    events: Option<Arc<mail_bridge_events::Events>>,
}
/// Owned MCP method inspected by middleware before scope enforcement.
#[derive(Clone)]
struct EventMethod(String);
/// Create a generic credential-safe HTTP rejection.
fn error(status: StatusCode) -> Response {
    (
        status,
        Json(json!({"error":"Request rejected; private details suppressed"})),
    )
        .into_response()
}
/// Attach cache, referrer and content-type privacy headers to a response.
fn private(mut response: Response) -> Response {
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store"),
    );
    response
        .headers_mut()
        .entry(header::REFERRER_POLICY)
        .or_insert(header::HeaderValue::from_static("no-referrer"));
    response.headers_mut().insert(
        header::X_CONTENT_TYPE_OPTIONS,
        header::HeaderValue::from_static("nosniff"),
    );
    response
}
/// Apply privacy headers to successful responses and middleware rejections.
async fn privacy_headers(request: Request, next: Next) -> Response {
    private(next.run(request).await)
}

/// Report that the HTTP process is running without accessing providers.
async fn health() -> Json<serde_json::Value> {
    Json(json!({"status": "ok"}))
}

/// Probe local account persistence without waiting on a busy store mutex.
async fn ready(State(state): State<App>) -> Response {
    // Never wait for a busy database mutex on the single-threaded runtime.
    // Check the account store without reading credentials or contacting providers.
    let available = state.mail.ready();
    if available {
        health().await.into_response()
    } else {
        error(StatusCode::SERVICE_UNAVAILABLE)
    }
}
/// Bound HTTP work and adapt event discovery around the MCP transport.
async fn limits(State(state): State<App>, mut request: Request, next: Next) -> Response {
    let Ok(_permit) = state.requests.clone().try_acquire_owned() else {
        return error(StatusCode::TOO_MANY_REQUESTS);
    };
    let mut discover = false;
    if state.events.is_some()
        && request.uri().path() == "/mcp"
        && request.method() == axum::http::Method::POST
    {
        let token = request
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "));
        if token.is_some_and(|token| state.auth.token_access(token).ok().flatten().is_some()) {
            let (parts, body) = request.into_parts();
            let bytes = match tokio::time::timeout(
                Duration::from_secs(15),
                axum::body::to_bytes(body, 65536),
            )
            .await
            {
                Ok(Ok(bytes)) => bytes,
                _ => return error(StatusCode::BAD_REQUEST),
            };
            let method = serde_json::from_slice::<serde_json::Value>(&bytes)
                .ok()
                .and_then(|v| {
                    v.get("method")
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_owned)
                });
            discover = method.as_deref() == Some("server/discover");
            request = Request::from_parts(parts, Body::from(bytes));
            if let Some(method) = method {
                request.extensions_mut().insert(EventMethod(method));
            }
        }
    }
    let response = match tokio::time::timeout(Duration::from_secs(55), next.run(request)).await {
        Ok(response) => response,
        Err(_) => error(StatusCode::REQUEST_TIMEOUT),
    };
    // rmcp handles MCP 2.0 validation and discovery. Its current typed
    // capability struct predates Events, so add only that extension field.
    if discover && response.status() == StatusCode::OK {
        let (mut parts, body) = response.into_parts();
        let bytes = match axum::body::to_bytes(body, 65536).await {
            Ok(v) => v,
            Err(_) => return error(StatusCode::INTERNAL_SERVER_ERROR),
        };
        if let Ok(mut value) = serde_json::from_slice::<serde_json::Value>(&bytes) {
            if value.get("result").is_some() {
                value["result"]["capabilities"]["events"] = json!({});
                value["result"]["supportedVersions"] = json!(["2026-07-28"]);
            }
            let body = serde_json::to_vec(&value).expect("JSON response");
            parts.headers.remove(header::CONTENT_LENGTH);
            return private(Response::from_parts(parts, Body::from(body)));
        }
        return private(Response::from_parts(parts, Body::from(bytes)));
    }
    private(response)
}
/// Resolve Bearer authorization and attach the client and compact scope set.
async fn authenticated(State(state): State<App>, mut request: Request, next: Next) -> Response {
    if request.headers().contains_key(header::ORIGIN) {
        return error(StatusCode::FORBIDDEN);
    }
    let token = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "));
    let access = token.and_then(|token| state.auth.token_access(token).ok().flatten());
    if let Some((client, scopes)) = access {
        if request
            .extensions()
            .get::<EventMethod>()
            .is_some_and(|m| m.0 == "events/subscribe")
            && !scopes.contains(mail_bridge_core::scope::Scope::Read)
        {
            let mut response = error(StatusCode::FORBIDDEN);
            if let Ok(value) = format!(
                "{}, error=\"insufficient_scope\"",
                state.auth.challenge("mail:read")
            )
            .parse()
            {
                response
                    .headers_mut()
                    .insert(header::WWW_AUTHENTICATE, value);
            }
            return response;
        }
        request.extensions_mut().insert(Scopes(scopes));
        request.extensions_mut().insert(Principal(client));
        next.run(request).await
    } else {
        let mut response = error(StatusCode::UNAUTHORIZED);
        if let Ok(challenge) = state.auth.challenge("mail:read").parse() {
            response
                .headers_mut()
                .insert(header::WWW_AUTHENTICATE, challenge);
        }
        response
    }
}
/// Build OAuth authorization-server or protected-resource discovery metadata.
async fn metadata(State(state): State<App>) -> Json<serde_json::Value> {
    Json(state.auth.metadata(false))
}
/// Serve protected-resource metadata for the canonical MCP resource.
async fn resource(State(state): State<App>) -> Json<serde_json::Value> {
    Json(state.auth.metadata(true))
}
/// Register a bounded set of policy-approved client callbacks.
async fn register(State(state): State<App>, headers: HeaderMap, body: Bytes) -> Response {
    if body.len() > 16384
        || headers.contains_key(header::ORIGIN)
        || headers
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.split(';').next())
            != Some("application/json")
    {
        return error(StatusCode::BAD_REQUEST);
    }
    match serde_json::from_slice(&body)
        .map_err(mail_bridge_core::safe)
        .and_then(|v| state.auth.register(v))
    {
        Ok(v) => (StatusCode::CREATED, Json(v)).into_response(),
        Err(_) => error(StatusCode::BAD_REQUEST),
    }
}
/// Prepare signed authorization data and render the private browser consent response.
async fn consent(State(state): State<App>, RawQuery(query): RawQuery) -> Response {
    let result = form(query.unwrap_or_default().as_bytes()).and_then(|params| {
        let consent = state.auth.consent(&params)?;
        let page = render_consent(&consent.fields);
        let cookie = format!(
            "__Host-mail-bridge={}; Secure; HttpOnly; SameSite=Lax; Path=/",
            consent.csrf
        );
        Ok((
            page,
            cookie,
            consent.callback.origin().ascii_serialization(),
        ))
    });
    match result {
        Ok((page, cookie, callback_origin)) => {
            let mut response = Response::new(Body::from(page));
            let headers = response.headers_mut();
            headers.insert(
                header::CONTENT_TYPE,
                header::HeaderValue::from_static("text/html; charset=utf-8"),
            );
            headers.insert(header::SET_COOKIE, cookie.parse().expect("random cookie"));
            // no-referrer makes browser form navigations serialize Origin as
            // null. strict-origin preserves same-origin POST verification while
            // keeping authorization query parameters out of Referer headers.
            headers.insert(
                header::REFERRER_POLICY,
                header::HeaderValue::from_static("strict-origin"),
            );
            headers.insert(
                header::CONTENT_SECURITY_POLICY,
                format!(
                    "default-src 'none'; form-action 'self' {callback_origin}; frame-ancestors 'none'; base-uri 'none'"
                )
                .parse()
                .expect("validated HTTP callback origin"),
            );
            headers.insert(
                header::X_FRAME_OPTIONS,
                header::HeaderValue::from_static("DENY"),
            );
            response
        }
        Err(_) => error(StatusCode::BAD_REQUEST),
    }
}
/// Recognize the required URL-encoded form content type.
fn is_form(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|s| s.split(';').next() == Some("application/x-www-form-urlencoded"))
}
/// Render an isolated private setup response with its required browser headers.
fn setup_response(page: String) -> Response {
    let mut response = Response::new(Body::from(page));
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("text/html; charset=utf-8"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        header::HeaderValue::from_static("strict-origin"),
    );
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        header::HeaderValue::from_static(
            "default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
        ),
    );
    headers.insert(
        header::X_FRAME_OPTIONS,
        header::HeaderValue::from_static("DENY"),
    );
    response
}
/// Open one client-bound setup invitation and issue its current browser cookie.
async fn setup_page(State(state): State<App>, RawQuery(query): RawQuery) -> Response {
    let result = form(query.unwrap_or_default().as_bytes()).and_then(|params| {
        if params.len() != 1 {
            return Err(mail_bridge_core::Error::Rejected("Invalid setup link"));
        }
        state
            .setup
            .page(mail_bridge_auth::val(&params, "ticket")?, &state.auth)
    });
    match result {
        Ok((page, cookie)) => {
            let mut response = setup_response(page);
            response.headers_mut().insert(
                header::SET_COOKIE,
                cookie.parse().expect("random setup cookie"),
            );
            response
        }
        Err(_) => error(StatusCode::BAD_REQUEST),
    }
}
/// Verify same-origin private form submission and commit one account through the setup state machine.
async fn setup_save(State(state): State<App>, headers: HeaderMap, body: Bytes) -> Response {
    if body.len() > 16384
        || !is_form(&headers)
        || headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) != Some(state.auth.base())
    {
        return error(StatusCode::FORBIDDEN);
    }
    {
        let mut attempts = state.attempts.lock().unwrap_or_else(|e| e.into_inner());
        attempts.retain(|t| t.elapsed() < Duration::from_secs(60));
        if attempts.len() >= 10 {
            return error(StatusCode::TOO_MANY_REQUESTS);
        }
        attempts.push(Instant::now());
    }
    let cookie = headers
        .get(header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| {
            s.split(';')
                .find_map(|c| c.trim().strip_prefix("__Host-mail-bridge-setup="))
        })
        .unwrap_or("");
    match form(&body).and_then(|params| state.setup.submit(params, cookie, &state.auth, &state.mail)) {
        Ok(id) => {
            let mut response = setup_response(format!("<!doctype html><html lang=\"zh-CN\"><meta charset=\"utf-8\"><title>邮箱已添加</title><h1>邮箱已添加</h1><p>账户 {} 的配置已保存并立即生效，无需重启。</p><p>尚未验证邮箱登录，发信保持关闭。你可以返回聊天检查配置或请求读取邮件。</p></html>", html_escape::encode_text(&id)));
            response.headers_mut().insert(header::SET_COOKIE, header::HeaderValue::from_static("__Host-mail-bridge-setup=; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age=0"));
            response
        },
        Err(e) => (StatusCode::BAD_REQUEST, setup_response(format!("<!doctype html><meta charset=\"utf-8\"><title>添加未完成</title><h1>添加未完成</h1><p>{}</p><p>请返回上一页重新填写；不要将密码粘贴到聊天。</p>", html_escape::encode_text(e.message())))).into_response(),
    }
}
/// Verify browser confirmation and owner approval, then issue a short-lived code.
async fn authorize(State(state): State<App>, headers: HeaderMap, body: Bytes) -> Response {
    if body.len() > 16384
        || !is_form(&headers)
        || headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) != Some(state.auth.base())
    {
        return error(StatusCode::FORBIDDEN);
    }
    {
        let mut attempts = state.attempts.lock().unwrap_or_else(|e| e.into_inner());
        attempts.retain(|t| t.elapsed() < Duration::from_secs(60));
        if attempts.len() >= 10 {
            return error(StatusCode::TOO_MANY_REQUESTS);
        }
        attempts.push(Instant::now());
    }
    let cookie = headers
        .get(header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| {
            s.split(';')
                .find_map(|c| c.trim().strip_prefix("__Host-mail-bridge="))
        })
        .unwrap_or("");
    match form(&body).and_then(|params| state.auth.authorize(params, cookie)) {
        Ok(target) => {
            let mut response = StatusCode::SEE_OTHER.into_response();
            if let Ok(location) = target.parse() {
                response.headers_mut().insert(header::LOCATION, location);
            } else {
                return error(StatusCode::BAD_REQUEST);
            }
            response
        }
        Err(_) => error(StatusCode::BAD_REQUEST),
    }
}
/// Apply client, resource and PKCE policy to an atomic one-use grant exchange.
async fn exchange(State(state): State<App>, headers: HeaderMap, body: Bytes) -> Response {
    if body.len() > 16384 || !is_form(&headers) {
        return error(StatusCode::BAD_REQUEST);
    }
    match form(&body).and_then(|params| state.auth.exchange(&params)) {
        Ok(tokens) => Json(tokens).into_response(),
        Err(_) => (
            StatusCode::BAD_REQUEST,
            Json(json!({"error":"invalid_grant"})),
        )
            .into_response(),
    }
}
/// Assemble HTTP, OAuth, private setup and authenticated MCP routes.
pub fn router(
    auth: Arc<Auth>,
    mail: Arc<MailService>,
    events: Option<Arc<mail_bridge_events::Events>>,
) -> Router {
    let state = App {
        setup: Arc::new(crate::account_setup::AccountSetup::default()),
        mail: mail.clone(),
        auth: auth.clone(),
        requests: Arc::new(Semaphore::new(16)),
        attempts: Arc::new(Mutex::new(Vec::new())),
        events: events.clone(),
    };
    let [host, authority] = auth.hosts().map(str::to_owned);
    let mcp = Mcp::new(state.setup.clone(), mail, auth, events);
    let mut config = StreamableHttpServerConfig::default()
        .with_json_response(true)
        .with_max_request_body_bytes(65536)
        .with_allowed_hosts([host, authority, "127.0.0.1".into(), "localhost".into()]);
    config.legacy_session_mode = false;
    let service = StreamableHttpService::new(
        move || Ok(mcp.clone()),
        Arc::new(NeverSessionManager::default()),
        config,
    );
    let mcp_routes = Router::new()
        .route_service("/mcp", service)
        .route_layer(middleware::from_fn_with_state(state.clone(), authenticated));
    Router::new()
        .route("/healthz", get(health))
        .route("/readyz", get(ready))
        .route("/.well-known/oauth-protected-resource", get(resource))
        .route("/.well-known/oauth-protected-resource/mcp", get(resource))
        .route("/.well-known/oauth-authorization-server", get(metadata))
        .route("/oauth/register", post(register))
        .route("/oauth/authorize", get(consent).post(authorize))
        .route("/oauth/token", post(exchange))
        .route("/accounts/setup", get(setup_page).post(setup_save))
        .with_state(state.clone())
        .merge(mcp_routes)
        .layer(DefaultBodyLimit::max(65536))
        .layer(middleware::from_fn_with_state(state, limits))
        // Outermost: include overload, timeout, extraction and routing errors.
        .layer(middleware::from_fn(privacy_headers))
}

/// A permit lives for the entire TCP connection, including idle keepalive time.
pub struct LimitedListener {
    /// Owned underlying connection or IO object.
    inner: TcpListener,
    /// Shared fixed-capacity admission budget; permits live for the entire operation.
    gate: Arc<Semaphore>,
}
impl LimitedListener {
    /// Bind a listener to a fixed nonzero connection budget.
    pub fn new(inner: TcpListener, capacity: std::num::NonZeroUsize) -> Self {
        Self {
            inner,
            gate: Arc::new(Semaphore::new(capacity.get())),
        }
    }
}
/// Owned TCP stream paired with exactly one connection permit.
/// Dropping the connection releases its budget even when a request is cancelled.
pub struct Connection {
    /// Owned underlying connection or IO object.
    inner: TcpStream,
    /// Owned connection permit released when this connection is dropped.
    _permit: OwnedSemaphorePermit,
}
impl AsyncRead for Connection {
    /// Read into a bounded scratch buffer and inspect bytes before exposing them upstream.
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}
impl AsyncWrite for Connection {
    /// Delegate writing to the owned underlying IO object.
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    /// Flush the owned underlying IO object.
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    /// Shut down the owned underlying IO object.
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
impl axum::serve::Listener for LimitedListener {
    /// Accepted connection type retaining its lifetime permit.
    type Io = Connection;
    /// Socket address reported by the underlying TCP listener.
    type Addr = std::net::SocketAddr;
    /// Acquire a connection permit before accepting a socket; retain it for the connection lifetime.
    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            let permit = self
                .gate
                .clone()
                .acquire_owned()
                .await
                .expect("connection gate open");
            match self.inner.accept().await {
                Ok((inner, addr)) => {
                    return (
                        Connection {
                            inner,
                            _permit: permit,
                        },
                        addr,
                    );
                }
                Err(_) => tokio::time::sleep(Duration::from_millis(100)).await,
            }
        }
    }
    /// Return the bound address of the owned TCP listener.
    fn local_addr(&self) -> io::Result<Self::Addr> {
        self.inner.local_addr()
    }
}

/// Render signed authorization fields without interpreting authorization policy.
fn render_consent(params: &mail_bridge_auth::Params) -> String {
    use std::fmt::Write;
    let mut inputs = String::new();
    for (key, value) in params {
        write!(
            &mut inputs,
            "<input type=\"hidden\" name=\"{}\" value=\"{}\">",
            html_escape::encode_double_quoted_attribute(key),
            html_escape::encode_double_quoted_attribute(value)
        )
        .expect("string writes are infallible");
    }
    format!(
        "<!doctype html><meta charset=\"utf-8\"><title>Mail Bridge authorization</title><h1>Authorize Mail Bridge</h1><p>Requested permissions: {}</p><p>Client callback: {}</p><p>Only authorize your own ChatGPT connection. Enter your independent service owner password, never your mailbox authorization code.</p><form method=\"post\" action=\"/oauth/authorize\">{}<label>Owner password <input type=\"password\" name=\"owner_password\" required autocomplete=\"off\"></label><button type=\"submit\">Authorize</button></form>",
        html_escape::encode_text(&params["scope"]),
        html_escape::encode_text(&params["redirect_uri"]),
        inputs
    )
}
