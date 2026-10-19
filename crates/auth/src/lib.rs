//! Single-owner authorization policy; oauth2 supplies PKCE primitives.
//! Axum owns HTTP parsing, RustCrypto supplies HMAC and constant-time checks.
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use mail_bridge_core::random;
use mail_bridge_core::{Error, Result, safe};
use mail_bridge_store::oauth::{Grant, TokenPair};
use mail_bridge_store::{Db, now};
use oauth2::{PkceCodeChallenge, PkceCodeVerifier};
use serde_json::{Value, json};
use sha2::Sha256;
use std::{collections::BTreeMap, sync::Arc};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

pub type Params = BTreeMap<String, String>;
fn eq(a: &str, b: &str) -> bool {
    bool::from(a.as_bytes().ct_eq(b.as_bytes()))
}
pub fn val<'a>(params: &'a Params, key: &str) -> Result<&'a str> {
    params
        .get(key)
        .map(String::as_str)
        .filter(|s| !s.is_empty())
        .ok_or(Error("invalid_request"))
}
fn scopes(value: &str) -> Result<String> {
    let mut v: Vec<&str> = value.split_whitespace().collect();
    v.sort_unstable();
    v.dedup();
    if v.is_empty() || v.iter().any(|s| !matches!(*s, "mail:read" | "mail:send")) {
        return Err(Error("invalid_scope"));
    }
    Ok(v.join(" "))
}

#[derive(Clone)]
pub struct Auth {
    pub base: String,
    pub resource: String,
    pub redirects: Vec<String>,
    pub db: Db,
    owner: Arc<Zeroizing<String>>,
}
impl Auth {
    pub fn verify_owner(&self, password: &str) -> bool {
        eq(password, &self.owner)
    }
    pub fn setup_grant_active(&self, client: &str) -> Result<bool> {
        Ok(self
            .db
            .grant_scopes(client, &self.resource, false)?
            .iter()
            .any(|scope| scope.split_whitespace().any(|s| s == "mail:read")))
    }
    pub fn redirect_allowed(&self, redirect: &str) -> bool {
        let Ok(candidate) = validate_oauth_redirect(redirect) else {
            return false;
        };
        self.redirects.iter().any(|allowed| {
            if allowed == redirect {
                return true;
            }
            let Ok(template) = validate_oauth_redirect(allowed) else {
                return false;
            };
            // Port flexibility is opt-in through a portless loopback allowlist
            // entry. The registered full URI remains exact for this client.
            template.scheme() == "http"
                && template.port().is_none()
                && candidate.scheme() == "http"
                && template.host() == candidate.host()
                && template.path() == candidate.path()
        })
    }
    pub fn new(settings: &AuthConfig, db: Db) -> Self {
        Self {
            base: settings.public_url.clone(),
            resource: format!("{}/mcp", settings.public_url),
            redirects: settings.redirects.clone(),
            db,
            owner: settings.owner_password.clone(),
        }
    }
    pub fn metadata(&self, resource: bool) -> Value {
        if resource {
            json!({"resource":self.resource,"authorization_servers":[self.base],"scopes_supported":["mail:read"]})
        } else {
            // Some native clients request every advertised scope by default.
            // RFC 8414 permits not advertising optional scopes; send/events
            // remain available only when explicitly requested and authorized.
            json!({"issuer":self.base,"authorization_endpoint":format!("{}/oauth/authorize",self.base),"token_endpoint":format!("{}/oauth/token",self.base),"registration_endpoint":format!("{}/oauth/register",self.base),"response_types_supported":["code"],"grant_types_supported":["authorization_code","refresh_token"],"token_endpoint_auth_methods_supported":["none"],"code_challenge_methods_supported":["S256"],"scopes_supported":["mail:read"],"authorization_response_iss_parameter_supported":true})
        }
    }
    pub fn challenge(&self, scope: &str) -> String {
        format!(
            "Bearer resource_metadata=\"{}/.well-known/oauth-protected-resource\", scope=\"{}\"",
            self.base, scope
        )
    }
    pub fn register(&self, request: Value) -> Result<Value> {
        let uris: Vec<String> = serde_json::from_value(
            request
                .get("redirect_uris")
                .cloned()
                .ok_or(Error("invalid_redirect_uri"))?,
        )
        .map_err(|_| Error("invalid_redirect_uri"))?;
        if uris.is_empty() || uris.len() > 5 || uris.iter().any(|uri| !self.redirect_allowed(uri)) {
            return Err(Error("invalid_redirect_uri"));
        }
        if request
            .get("token_endpoint_auth_method")
            .and_then(Value::as_str)
            .unwrap_or("none")
            != "none"
        {
            return Err(Error("invalid_client_metadata"));
        }
        let id = random();
        self.db.register_client(&id, &uris)?;
        Ok(
            json!({"client_id":id,"redirect_uris":uris,"token_endpoint_auth_method":"none","grant_types":["authorization_code","refresh_token"],"response_types":["code"]}),
        )
    }
    fn checked(&self, params: &Params) -> Result<Params> {
        let mut checked = Params::new();
        for key in [
            "client_id",
            "redirect_uri",
            "response_type",
            "code_challenge",
            "code_challenge_method",
            "resource",
            "state",
        ] {
            let value = val(params, key)?;
            if value.len() > 2048 {
                return Err(Error("invalid_request"));
            }
            checked.insert(key.to_owned(), value.to_owned());
        }
        let redirects = self
            .db
            .client_redirects(&checked["client_id"])?
            .ok_or(Error("invalid_client"))?;
        if !redirects.contains(&checked["redirect_uri"])
            || !self.redirect_allowed(&checked["redirect_uri"])
        {
            return Err(Error("invalid_redirect_uri"));
        }
        if checked["resource"] != self.resource {
            return Err(Error("invalid_target"));
        }
        if checked["response_type"] != "code"
            || checked["code_challenge_method"] != "S256"
            || checked["code_challenge"].len() != 43
            || !checked["code_challenge"]
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        {
            return Err(Error("invalid_request"));
        }
        checked.insert(
            "scope".into(),
            scopes(
                params
                    .get("scope")
                    .map(String::as_str)
                    .unwrap_or("mail:read"),
            )?,
        );
        Ok(checked)
    }
    fn signature(&self, params: &Params) -> Result<String> {
        let mut mac = Hmac::<Sha256>::new_from_slice(self.owner.as_bytes()).map_err(safe)?;
        mac.update(&serde_json::to_vec(params).map_err(safe)?);
        Ok(URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes()))
    }
    pub fn consent_form(&self, params: &Params) -> Result<(String, String)> {
        let mut params = self.checked(params)?;
        let csrf = random();
        params.insert("_csrf".into(), csrf.clone());
        params.insert("_time".into(), now().to_string());
        params.insert("_sig".into(), self.signature(&params)?);
        let mut inputs = String::new();
        for (key, value) in &params {
            inputs.push_str(&format!(
                "<input type=\"hidden\" name=\"{}\" value=\"{}\">",
                html_escape::encode_double_quoted_attribute(key),
                html_escape::encode_double_quoted_attribute(value)
            ));
        }
        let page = format!(
            "<!doctype html><meta charset=\"utf-8\"><title>Mail Bridge authorization</title><h1>Authorize Mail Bridge</h1><p>Requested permissions: {}</p><p>Client callback: {}</p><p>Only authorize your own ChatGPT connection. Enter your independent service owner password, never your mailbox authorization code.</p><form method=\"post\" action=\"/oauth/authorize\">{}<label>Owner password <input type=\"password\" name=\"owner_password\" required autocomplete=\"off\"></label><button type=\"submit\">Authorize</button></form>",
            html_escape::encode_text(&params["scope"]),
            html_escape::encode_text(&params["redirect_uri"]),
            inputs
        );
        Ok((
            page,
            format!("__Host-mail-bridge={csrf}; Secure; HttpOnly; SameSite=Lax; Path=/"),
        ))
    }
    pub fn authorize(&self, mut params: Params, cookie: &str) -> Result<String> {
        let password = Zeroizing::new(params.remove("owner_password").unwrap_or_default());
        let signature = params.remove("_sig").unwrap_or_default();
        let time = val(&params, "_time")?
            .parse::<i64>()
            .map_err(|_| Error("invalid_request"))?;
        if !eq(&signature, &self.signature(&params)?)
            || !eq(val(&params, "_csrf")?, cookie)
            || !(0..=300).contains(&(now() - time))
        {
            return Err(Error("invalid_request"));
        }
        if !eq(&password, &self.owner) {
            return Err(Error("access_denied"));
        }
        let params = self.checked(&params)?;
        let code = random();
        self.db.save_code(
            &code,
            &Grant {
                client: params["client_id"].clone(),
                redirect: Some(params["redirect_uri"].clone()),
                challenge: Some(params["code_challenge"].clone()),
                resource: self.resource.clone(),
                scope: params["scope"].clone(),
                expires: now() + 120,
            },
        )?;
        let mut target = url::Url::parse(&params["redirect_uri"]).map_err(safe)?;
        target
            .query_pairs_mut()
            .append_pair("code", &code)
            .append_pair("state", &params["state"])
            .append_pair("iss", &self.base);
        Ok(target.to_string())
    }
    pub fn exchange(&self, params: &Params) -> Result<Value> {
        if val(params, "resource")? != self.resource {
            return Err(Error("invalid_target"));
        }
        let client = val(params, "client_id")?;
        let code = match val(params, "grant_type")? {
            "authorization_code" => true,
            "refresh_token" => false,
            _ => return Err(Error("unsupported_grant_type")),
        };
        let secret = val(params, if code { "code" } else { "refresh_token" })?;
        let access = random();
        let refresh = random();
        let scope = self.db.exchange_grant(
            secret,
            code,
            TokenPair {
                access: &access,
                refresh: &refresh,
            },
            |grant| {
                if grant.client != client
                    || grant.resource != self.resource
                    || grant.expires <= now()
                {
                    return Err(Error("invalid_grant"));
                }
                if code {
                    let verifier = val(params, "code_verifier")?;
                    if !(43..=128).contains(&verifier.len())
                        || !verifier
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b"-._~".contains(&b))
                    {
                        return Err(Error("invalid_grant"));
                    }
                    let expected = PkceCodeChallenge::from_code_verifier_sha256(
                        &PkceCodeVerifier::new(verifier.to_owned()),
                    );
                    if grant.redirect.as_deref() != Some(val(params, "redirect_uri")?)
                        || !grant
                            .challenge
                            .as_deref()
                            .is_some_and(|challenge| eq(challenge, expected.as_str()))
                    {
                        return Err(Error("invalid_grant"));
                    }
                }
                Ok(())
            },
        )?;
        Ok(
            json!({"access_token":access,"token_type":"Bearer","expires_in":3600,"refresh_token":refresh,"scope":scope}),
        )
    }
    pub fn token_access(&self, token: &str) -> Result<Option<(String, Vec<String>)>> {
        Ok(self
            .db
            .access_grant(token)?
            .filter(|grant| grant.resource == self.resource && grant.expires > now())
            .map(|grant| {
                (
                    grant.client,
                    grant.scope.split_whitespace().map(str::to_owned).collect(),
                )
            }))
    }
    pub fn event_grant_active(&self, client: &str) -> Result<bool> {
        Ok(self
            .db
            .grant_scopes(client, &self.resource, true)?
            .iter()
            .any(|scope| scope.split_whitespace().any(|s| s == "mail:read")))
    }
}

/// Authorization policy supplied by the host process.
#[derive(Clone)]
pub struct AuthConfig {
    pub public_url: String,
    pub redirects: Vec<String>,
    pub owner_password: Arc<Zeroizing<String>>,
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
        return Err(Error(
            "Use exact HTTPS callbacks or canonical HTTP loopback IP callbacks",
        ));
    }
    Ok(u)
}
