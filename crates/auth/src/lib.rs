//! Single-owner authorization policy; oauth2 supplies PKCE primitives.
//! Axum owns HTTP parsing, RustCrypto supplies HMAC and constant-time checks.
//!
//! | Operation | Frequency | Complexity | Storage | Forbidden implementation |
//! | --- | --- | --- | --- | --- |
//! | Parse policy | Startup | O(origin + redirect bytes) | Immutable parsed URLs | Reparse allowlist per request |
//! | Check consent | Authorization request | O(request + allowlist bytes + SQL) | Typed authorization product | HTML or cookies in this crate |
//! | Resolve access | Authenticated request | O(log tokens + metadata bytes) | Two-bit scope set | Allocate scope strings |
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use mail_bridge_core::random;
use mail_bridge_core::scope::Scopes;
use mail_bridge_core::{Error, Result, safe};
use mail_bridge_store::oauth::{
    CodeGrant, ExchangeGrant, ExchangeSecret, GrantUse, TokenGrant, TokenPair,
};
use mail_bridge_store::{Db, now};
use oauth2::{PkceCodeChallenge, PkceCodeVerifier};
use serde_json::{Value, json};
use sha2::Sha256;
use std::{collections::BTreeMap, sync::Arc};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// External OAuth/form fields keyed by name; bounded decoding rejects duplicate keys.
pub type Params = BTreeMap<String, String>;
/// Compare credential bytes in constant time.
fn eq(a: &str, b: &str) -> bool {
    bool::from(a.as_bytes().ct_eq(b.as_bytes()))
}
/// Borrow a required nonempty request field or reject the external request.
pub fn val<'a>(params: &'a Params, key: &str) -> Result<&'a str> {
    params
        .get(key)
        .map(String::as_str)
        .filter(|s| !s.is_empty())
        .ok_or(Error::Rejected("invalid_request"))
}
/// Immutable authorization policy and its store handle.
///
/// Semantically `Origin × RedirectPolicies × OwnerCredential × Store`. Construction parses
/// the origin and callback policies; private fields preserve them for all requests.
pub struct Auth {
    /// Canonical public HTTPS origin.
    origin: url::Url,
    /// Exact MCP resource bound to this authorization server.
    resource: Box<str>,
    /// Explicit callback allowlist; registration must match its policy.
    redirects: Box<[Redirect]>,
    /// Shared handle to the private SQLite persistence boundary.
    db: Db,
    /// Immutable independent owner credential; never serialized.
    owner: Arc<Zeroizing<Box<str>>>,
}
impl Auth {
    /// Check the submitted independent owner password without exposing its contents.
    pub fn verify_owner(&self, password: &str) -> bool {
        eq(password, &self.owner)
    }
    /// Check whether the originating client retains a live read grant for setup.
    pub fn setup_grant_active(&self, client: &str) -> Result<bool> {
        self.db
            .has_read_grant(client, &self.resource, GrantUse::Setup)
    }
    /// Parse an external callback and apply the configured exact/loopback policy.
    pub fn redirect_allowed(&self, redirect: &str) -> bool {
        let Ok(candidate) = validate_oauth_redirect(redirect) else {
            return false;
        };
        self.redirect_matches(redirect, &candidate)
    }
    /// Apply the pre-parsed callback allowlist to a parsed candidate.
    fn redirect_matches(&self, redirect: &str, candidate: &url::Url) -> bool {
        self.redirects.iter().any(|allowed| {
            if allowed.literal.as_ref() == redirect {
                return true;
            }
            let template = &allowed.url;
            template.scheme() == "http"
                && template.port().is_none()
                && candidate.scheme() == "http"
                && template.host() == candidate.host()
                && template.path() == candidate.path()
        })
    }
    /// Parse immutable authorization policy before constructing the service.
    pub fn new(settings: &AuthConfig, db: Db) -> Result<Self> {
        let url = url::Url::parse(&settings.public_url).map_err(safe)?;
        if url.scheme() != "https"
            || url.host_str().is_none()
            || url.path() != "/"
            || url.query().is_some()
            || url.fragment().is_some()
            || !url.username().is_empty()
            || url.password().is_some()
        {
            return Err(Error::Rejected(
                "Public URL must be an HTTPS origin without a path or credentials",
            ));
        }
        let base: Box<str> = url.origin().ascii_serialization().into();
        let redirects = settings
            .redirects
            .iter()
            .map(|literal| {
                Ok(Redirect {
                    url: validate_oauth_redirect(literal)?,
                    literal: literal.clone(),
                })
            })
            .collect::<Result<Box<[_]>>>()?;
        Ok(Self {
            resource: format!("{base}/mcp").into(),
            origin: url,
            redirects,
            db,
            owner: settings.owner_password.clone(),
        })
    }
    /// Canonical public HTTPS origin.
    pub fn base(&self) -> &str {
        self.origin.as_str().trim_end_matches('/')
    }
    /// Borrow both accepted host spellings from the parsed origin.
    /// The constructor guarantees a host, HTTPS and an empty root path.
    pub fn hosts(&self) -> [&str; 2] {
        [
            self.origin
                .host_str()
                .expect("authorization origin has a host"),
            &self.origin[url::Position::BeforeHost..url::Position::AfterPort],
        ]
    }
    /// MCP resource bound to this authorization server.
    pub fn resource(&self) -> &str {
        &self.resource
    }
    /// Build OAuth authorization-server or protected-resource discovery metadata.
    pub fn metadata(&self, resource: bool) -> Value {
        if resource {
            json!({"resource":self.resource,"authorization_servers":[self.base()],"scopes_supported":["mail:read"]})
        } else {
            // Some native clients request every advertised scope by default.
            // RFC 8414 permits not advertising optional scopes; send/events
            // remain available only when explicitly requested and authorized.
            json!({"issuer":self.base(),"authorization_endpoint":format!("{}/oauth/authorize",self.base()),"token_endpoint":format!("{}/oauth/token",self.base()),"registration_endpoint":format!("{}/oauth/register",self.base()),"response_types_supported":["code"],"grant_types_supported":["authorization_code","refresh_token"],"token_endpoint_auth_methods_supported":["none"],"code_challenge_methods_supported":["S256"],"scopes_supported":["mail:read"],"authorization_response_iss_parameter_supported":true})
        }
    }
    /// Build the Bearer challenge for the requested mail permission.
    pub fn challenge(&self, scope: &str) -> String {
        format!(
            "Bearer resource_metadata=\"{}/.well-known/oauth-protected-resource\", scope=\"{}\"",
            self.base(),
            scope
        )
    }
    /// Register a bounded set of policy-approved client callbacks.
    pub fn register(&self, request: Value) -> Result<Value> {
        let uris: Vec<String> = serde_json::from_value(
            request
                .get("redirect_uris")
                .cloned()
                .ok_or(Error::Rejected("invalid_redirect_uri"))?,
        )
        .map_err(|_| Error::Rejected("invalid_redirect_uri"))?;
        if uris.is_empty() || uris.len() > 5 || uris.iter().any(|uri| !self.redirect_allowed(uri)) {
            return Err(Error::Rejected("invalid_redirect_uri"));
        }
        if request
            .get("token_endpoint_auth_method")
            .and_then(Value::as_str)
            .unwrap_or("none")
            != "none"
        {
            return Err(Error::Rejected("invalid_client_metadata"));
        }
        let id = random();
        self.db.register_client(&id, &uris)?;
        Ok(
            json!({"client_id":id,"redirect_uris":uris,"token_endpoint_auth_method":"none","grant_types":["authorization_code","refresh_token"],"response_types":["code"]}),
        )
    }
    /// Parse and bind an external request to its registered account/callback policy.
    fn checked(&self, params: &Params) -> Result<Authorization> {
        for key in [
            "client_id",
            "redirect_uri",
            "response_type",
            "code_challenge",
            "code_challenge_method",
            "resource",
            "state",
        ] {
            if val(params, key)?.len() > 2048 {
                return Err(Error::Rejected("invalid_request"));
            }
        }
        let client = val(params, "client_id")?;
        let redirect = val(params, "redirect_uri")?;
        let callback = validate_oauth_redirect(redirect)?;
        let redirects = self
            .db
            .client_redirects(client)?
            .ok_or(Error::Rejected("invalid_client"))?;
        if !redirects.iter().any(|r| r == redirect) || !self.redirect_matches(redirect, &callback) {
            return Err(Error::Rejected("invalid_redirect_uri"));
        }
        if val(params, "resource")? != self.resource() {
            return Err(Error::Rejected("invalid_target"));
        }
        let challenge = val(params, "code_challenge")?;
        if val(params, "response_type")? != "code"
            || val(params, "code_challenge_method")? != "S256"
            || challenge.len() != 43
            || !challenge
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        {
            return Err(Error::Rejected("invalid_request"));
        }
        Ok(Authorization {
            client: client.into(),
            redirect: redirect.into(),
            callback,
            challenge: challenge.into(),
            state: val(params, "state")?.into(),
            scope: Scopes::parse(
                params
                    .get("scope")
                    .map(String::as_str)
                    .unwrap_or("mail:read"),
            )?,
        })
    }
    /// Sign canonical authorization fields or exact webhook bytes with the selected key.
    fn signature(&self, params: &Params) -> Result<String> {
        let mut mac = Hmac::<Sha256>::new_from_slice(self.owner.as_bytes()).map_err(safe)?;
        mac.update(&serde_json::to_vec(params).map_err(safe)?);
        Ok(URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes()))
    }
    /// Prepare signed consent fields; HTTP rendering and cookies belong to the host.
    pub fn consent(&self, params: &Params) -> Result<Consent> {
        let authorization = self.checked(params)?;
        let mut params = Params::from([
            ("client_id".into(), authorization.client.into_string()),
            ("redirect_uri".into(), authorization.redirect.into_string()),
            ("response_type".into(), "code".into()),
            (
                "code_challenge".into(),
                authorization.challenge.into_string(),
            ),
            ("code_challenge_method".into(), "S256".into()),
            ("resource".into(), self.resource().to_owned()),
            ("state".into(), authorization.state.into_string()),
            ("scope".into(), authorization.scope.as_str().into()),
        ]);
        let callback = authorization.callback;
        let csrf: Box<str> = random().into();
        params.insert("_csrf".into(), csrf.to_string());
        params.insert("_time".into(), now().to_string());
        params.insert("_sig".into(), self.signature(&params)?);
        Ok(Consent {
            fields: params,
            csrf,
            callback,
        })
    }
    /// Verify browser confirmation and owner approval, then issue a short-lived code.
    pub fn authorize(&self, mut params: Params, cookie: &str) -> Result<String> {
        let password = Zeroizing::new(params.remove("owner_password").unwrap_or_default());
        let signature = params.remove("_sig").unwrap_or_default();
        let time = val(&params, "_time")?
            .parse::<i64>()
            .map_err(|_| Error::Rejected("invalid_request"))?;
        if !eq(&signature, &self.signature(&params)?)
            || !eq(val(&params, "_csrf")?, cookie)
            || !(0..=300).contains(&(now() - time))
        {
            return Err(Error::Rejected("invalid_request"));
        }
        if !eq(&password, &self.owner) {
            return Err(Error::Rejected("access_denied"));
        }
        let authorization = self.checked(&params)?;
        let code = random();
        self.db.save_code(
            &code,
            &CodeGrant {
                token: TokenGrant {
                    client: authorization.client,
                    resource: self.resource.as_ref().into(),
                    scope: authorization.scope.as_str().into(),
                    expires: now() + 120,
                },
                redirect: authorization.redirect,
                challenge: authorization.challenge,
            },
        )?;
        let mut target = authorization.callback;
        target
            .query_pairs_mut()
            .append_pair("code", &code)
            .append_pair("state", &authorization.state)
            .append_pair("iss", self.base());
        Ok(target.to_string())
    }
    /// Apply client, resource and PKCE policy to an atomic one-use grant exchange.
    pub fn exchange(&self, params: &Params) -> Result<Value> {
        if val(params, "resource")? != self.resource.as_ref() {
            return Err(Error::Rejected("invalid_target"));
        }
        let client = val(params, "client_id")?;
        let code = match val(params, "grant_type")? {
            "authorization_code" => true,
            "refresh_token" => false,
            _ => return Err(Error::Rejected("unsupported_grant_type")),
        };
        let secret = val(params, if code { "code" } else { "refresh_token" })?;
        let access = random();
        let refresh = random();
        let scope = self.db.exchange_grant(
            if code {
                ExchangeSecret::Code(secret)
            } else {
                ExchangeSecret::Refresh(secret)
            },
            TokenPair {
                access: &access,
                refresh: &refresh,
            },
            |grant| {
                let token = grant.token();
                if token.client.as_ref() != client
                    || token.resource.as_ref() != self.resource.as_ref()
                    || token.expires <= now()
                {
                    return Err(Error::Rejected("invalid_grant"));
                }
                if let ExchangeGrant::Code(grant) = grant {
                    let verifier = val(params, "code_verifier")?;
                    if !(43..=128).contains(&verifier.len())
                        || !verifier
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b"-._~".contains(&b))
                    {
                        return Err(Error::Rejected("invalid_grant"));
                    }
                    let expected = PkceCodeChallenge::from_code_verifier_sha256(
                        &PkceCodeVerifier::new(verifier.to_owned()),
                    );
                    if grant.redirect.as_ref() != val(params, "redirect_uri")?
                        || !eq(&grant.challenge, expected.as_str())
                    {
                        return Err(Error::Rejected("invalid_grant"));
                    }
                }
                Ok(())
            },
        )?;
        Ok(
            json!({"access_token":access,"token_type":"Bearer","expires_in":3600,"refresh_token":refresh,"scope":scope}),
        )
    }
    /// Resolve an access token into its owning client and compact permission set.
    pub fn token_access(&self, token: &str) -> Result<Option<(Box<str>, Scopes)>> {
        self.db
            .access_grant(token)?
            .filter(|grant| {
                grant.resource.as_ref() == self.resource.as_ref() && grant.expires > now()
            })
            .map(|grant| Ok((grant.client, Scopes::parse(&grant.scope)?)))
            .transpose()
    }
    /// Check whether the client retains a live refresh grant permitting events.
    pub fn event_grant_active(&self, client: &str) -> Result<bool> {
        self.db
            .has_read_grant(client, &self.resource, GrantUse::Events)
    }
}

/// Authorization policy supplied by the host process.
#[derive(Clone)]
pub struct AuthConfig {
    /// Configured public HTTPS origin.
    pub public_url: Box<str>,
    /// Explicit callback allowlist; registration must match its policy.
    pub redirects: Box<[Box<str>]>,
    /// Independent owner credential, separate from mailbox credentials.
    pub owner_password: Arc<Zeroizing<Box<str>>>,
}

/// HTTPS callbacks are exact. Native callbacks require an explicit loopback IP;
/// a configured HTTP URI without a port permits an ephemeral client port.
pub fn validate_oauth_redirect(redirect: &str) -> Result<url::Url> {
    let u = url::Url::parse(redirect).map_err(safe)?;
    let loopback = matches!(u.host(), Some(url::Host::Ipv4(ip)) if ip == std::net::Ipv4Addr::LOCALHOST)
        || matches!(u.host(), Some(url::Host::Ipv6(ip)) if ip == std::net::Ipv6Addr::LOCALHOST);
    if redirect.len() > 2048
        || redirect.trim() != redirect
        || u.host_str().is_none()
        || u.fragment().is_some()
        || !u.username().is_empty()
        || u.password().is_some()
        || (u.scheme() != "https"
            && !(u.scheme() == "http"
                && loopback
                && u.query().is_none()
                && u.port() != Some(0)
                && u.as_str() == redirect))
    {
        return Err(Error::Rejected(
            "Use exact HTTPS callbacks or canonical HTTP loopback IP callbacks",
        ));
    }
    Ok(u)
}

/// An exact registered callback plus its parsed URL for loopback policy checks.
struct Redirect {
    /// Exact original spelling used for registered-callback equality.
    literal: Box<str>,
    /// Callback URL used for subscription identity and delivery.
    url: url::Url,
}
/// Signed consent data, independent of its HTTP presentation.
pub struct Consent {
    /// Signed hidden authorization fields sent back by the browser.
    pub fields: Params,
    /// Random browser-verification token whose hash/signature is checked on submit.
    pub csrf: Box<str>,
    /// Parsed registered callback used for navigation policy.
    pub callback: url::Url,
}

/// `Client × RegisteredRedirect × S256Challenge × State × Scopes` after policy checks.
/// Only `Auth::checked` constructs this private product; the URL and its exact
/// registered spelling are retained for separate navigation and equality semantics.
struct Authorization {
    /// OAuth client identity bound to this grant or setup invitation.
    client: Box<str>,
    /// Exact registered callback URI required during code exchange.
    redirect: Box<str>,
    /// Parsed registered callback used for navigation policy.
    callback: url::Url,
    /// S256 PKCE challenge bound to the authorization code.
    challenge: Box<str>,
    /// Opaque client state preserved unchanged through authorization.
    state: Box<str>,
    /// Canonical scope text or parsed permission set.
    scope: Scopes,
}
