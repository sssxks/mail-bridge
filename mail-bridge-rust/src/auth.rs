//! Single-owner authorization policy; oauth2 supplies PKCE primitives.
//! Axum owns HTTP parsing, RustCrypto supplies HMAC and constant-time checks.
use crate::{
    Error, Result,
    config::Settings,
    db::{Db, hash, now},
    safe,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use oauth2::{PkceCodeChallenge, PkceCodeVerifier};
use rand::RngCore;
use rusqlite::{OptionalExtension, params};
use serde_json::{Value, json};
use sha2::Sha256;
use std::{collections::BTreeMap, sync::Arc};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

pub type Params = BTreeMap<String, String>;
pub fn random() -> String {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}
fn eq(a: &str, b: &str) -> bool {
    bool::from(a.as_bytes().ct_eq(b.as_bytes()))
}
pub fn form(raw: &[u8]) -> Result<Params> {
    let pairs: Vec<(String, String)> =
        serde_urlencoded::from_bytes(raw).map_err(|_| Error("invalid_request"))?;
    if pairs.len() > 30 {
        return Err(Error("invalid_request"));
    }
    let mut result = Params::new();
    for (k, v) in pairs {
        if v.len() > 8192 || result.insert(k, v).is_some() {
            return Err(Error("invalid_request"));
        }
    }
    Ok(result)
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
    if v.is_empty()
        || v.iter()
            .any(|s| !matches!(*s, "mail:read" | "mail:send" | "mail:events"))
    {
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
    pub fn new(settings: &Settings, db: Db) -> Self {
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
            json!({"resource":self.resource,"authorization_servers":[self.base],"scopes_supported":["mail:read","mail:send","mail:events"]})
        } else {
            json!({"issuer":self.base,"authorization_endpoint":format!("{}/oauth/authorize",self.base),"token_endpoint":format!("{}/oauth/token",self.base),"registration_endpoint":format!("{}/oauth/register",self.base),"response_types_supported":["code"],"grant_types_supported":["authorization_code","refresh_token"],"token_endpoint_auth_methods_supported":["none"],"code_challenge_methods_supported":["S256"],"scopes_supported":["mail:read","mail:send","mail:events"],"authorization_response_iss_parameter_supported":true})
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
        if uris.is_empty() || uris.len() > 5 || uris.iter().any(|uri| !self.redirects.contains(uri))
        {
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
        let db = self.db.0.lock().map_err(safe)?;
        let count: i64 = db
            .query_row("SELECT count(*) FROM clients", [], |r| r.get(0))
            .map_err(safe)?;
        if count >= 1000 {
            return Err(Error("registration_limit_reached"));
        }
        let id = random();
        db.execute(
            "INSERT INTO clients VALUES (?,?)",
            params![id, serde_json::to_string(&uris).map_err(safe)?],
        )
        .map_err(safe)?;
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
        let db = self.db.0.lock().map_err(safe)?;
        let stored: Option<String> = db
            .query_row(
                "SELECT redirects FROM clients WHERE id=?",
                [&checked["client_id"]],
                |r| r.get(0),
            )
            .optional()
            .map_err(safe)?;
        let redirects: Vec<String> =
            serde_json::from_str(&stored.ok_or(Error("invalid_client"))?).map_err(safe)?;
        if !redirects.contains(&checked["redirect_uri"])
            || !self.redirects.contains(&checked["redirect_uri"])
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
        let db = self.db.0.lock().map_err(safe)?;
        db.execute("DELETE FROM codes WHERE expires<?", [now()])
            .map_err(safe)?;
        db.execute(
            "INSERT INTO codes VALUES (?,?,?,?,?,?,?)",
            params![
                hash(&code),
                params["client_id"],
                params["redirect_uri"],
                params["code_challenge"],
                self.resource,
                params["scope"],
                now() + 120
            ],
        )
        .map_err(safe)?;
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
        let mut db = self.db.0.lock().map_err(safe)?;
        let tx = db
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(safe)?;
        let scope = match val(params, "grant_type")? {
            "authorization_code" => {
                let code = val(params, "code")?;
                let row:Option<(String,String,String,String,String,i64)>=tx.query_row("SELECT client,redirect,challenge,resource,scope,expires FROM codes WHERE hash=?",[hash(code)],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?))).optional().map_err(safe)?;
                let (stored_client, redirect, challenge, resource, scope, expires) =
                    row.ok_or(Error("invalid_grant"))?;
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
                if stored_client != client
                    || redirect != val(params, "redirect_uri")?
                    || !eq(&challenge, expected.as_str())
                    || resource != self.resource
                    || expires <= now()
                {
                    return Err(Error("invalid_grant"));
                }
                tx.execute("DELETE FROM codes WHERE hash=?", [hash(code)])
                    .map_err(safe)?;
                scope
            }
            "refresh_token" => {
                let refresh = val(params, "refresh_token")?;
                let row:Option<(String,String,String,i64)>=tx.query_row("SELECT client,resource,scope,expires FROM tokens WHERE hash=? AND kind='refresh'",[hash(refresh)],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).optional().map_err(safe)?;
                let (stored_client, resource, scope, expires) =
                    row.ok_or(Error("invalid_grant"))?;
                if stored_client != client || resource != self.resource || expires <= now() {
                    return Err(Error("invalid_grant"));
                }
                tx.execute("DELETE FROM tokens WHERE hash=?", [hash(refresh)])
                    .map_err(safe)?;
                scope
            }
            _ => return Err(Error("unsupported_grant_type")),
        };
        let access = random();
        let refresh = random();
        tx.execute("DELETE FROM tokens WHERE expires<?", [now()])
            .map_err(safe)?;
        for (token, kind, expiry) in [
            (&access, "access", now() + 3600),
            (&refresh, "refresh", now() + 30 * 86400),
        ] {
            tx.execute(
                "INSERT INTO tokens VALUES (?,?,?,?,?,?)",
                params![hash(token), kind, client, self.resource, scope, expiry],
            )
            .map_err(safe)?;
        }
        tx.commit().map_err(safe)?;
        Ok(
            json!({"access_token":access,"token_type":"Bearer","expires_in":3600,"refresh_token":refresh,"scope":scope}),
        )
    }
    pub fn token_scopes(&self, token: &str) -> Result<Option<Vec<String>>> {
        Ok(self.token_access(token)?.map(|(_, scopes)| scopes))
    }
    pub fn token_access(&self, token: &str) -> Result<Option<(String, Vec<String>)>> {
        let db = self.db.0.lock().map_err(safe)?;
        let row: Option<(String, String, String, i64)> = db
            .query_row(
                "SELECT client,resource,scope,expires FROM tokens WHERE hash=? AND kind='access'",
                [hash(token)],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .optional()
            .map_err(safe)?;
        Ok(row
            .filter(|(_, resource, _, expires)| resource == &self.resource && *expires > now())
            .map(|(client, _, scope, _)| {
                (
                    client,
                    scope.split_whitespace().map(str::to_owned).collect(),
                )
            }))
    }
    pub fn event_grant_active(&self, client: &str) -> Result<bool> {
        let db = self.db.0.lock().map_err(safe)?;
        let mut query=db.prepare("SELECT scope FROM tokens WHERE client=? AND resource=? AND kind='refresh' AND expires>?").map_err(safe)?;
        let scopes = query
            .query_map(params![client, self.resource, now()], |r| {
                r.get::<_, String>(0)
            })
            .map_err(safe)?;
        for scope in scopes {
            let scope = scope.map_err(safe)?;
            let fields: Vec<_> = scope.split_whitespace().collect();
            if fields.contains(&"mail:read") && fields.contains(&"mail:events") {
                return Ok(true);
            }
        }
        Ok(false)
    }
}
