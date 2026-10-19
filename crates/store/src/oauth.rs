//! OAuth persistence with typed grant variants and atomic one-use exchanges.
//!
//! | Operation | Frequency | Complexity | Storage | Forbidden implementation |
//! | --- | --- | --- | --- | --- |
//! | Exchange | OAuth refresh/login | O(log n + expired rows + grant bytes) | One immediate transaction | Consume before policy checks |
//! | Read grant | Authenticated operation | O(log n + metadata bytes) | Hashed primary key | Store token plaintext |
//! | Read permission | Setup/worker check | O(token rows until match) | Streaming SQL rows | Collect scopes into a vector |
use crate::{Db, hash, now};
use mail_bridge_core::{
    Error, Result, safe,
    scope::{Scope, Scopes},
};
use rusqlite::{OptionalExtension, params};

/// `Client × Resource × ScopeText × Expiry`, owned immutable token metadata.
pub struct TokenGrant {
    /// OAuth client identity bound to this grant or setup invitation.
    pub client: Box<str>,
    /// Exact MCP resource bound to this authorization server.
    pub resource: Box<str>,
    /// Canonical scope text or parsed permission set.
    pub scope: Box<str>,
    /// Unix expiry time checked before granting or starting work.
    pub expires: i64,
}
/// An authorization code necessarily owns both its redirect URI and PKCE challenge.
pub struct CodeGrant {
    /// Common client/resource/scope/expiry metadata for the code.
    pub token: TokenGrant,
    /// Exact registered callback URI required during code exchange.
    pub redirect: Box<str>,
    /// S256 PKCE challenge bound to the authorization code.
    pub challenge: Box<str>,
}
/// `Code(metadata,redirect,challenge) | Refresh(metadata)`; optional code fields are impossible.
pub enum ExchangeGrant {
    /// An authorization code with its required redirect and PKCE binding.
    Code(CodeGrant),
    /// A refresh grant with its client/resource/scope binding.
    Refresh(TokenGrant),
}
impl ExchangeGrant {
    /// Common metadata checked by the authorization policy.
    pub fn token(&self) -> &TokenGrant {
        match self {
            Self::Code(c) => &c.token,
            Self::Refresh(t) => t,
        }
    }
}
/// Secret plus its grant kind, selected before opening the exchange transaction.
pub enum ExchangeSecret<'a> {
    /// An authorization code with its required redirect and PKCE binding.
    Code(&'a str),
    /// A refresh grant with its client/resource/scope binding.
    Refresh(&'a str),
}
/// The grant kinds accepted by each service operation.
pub enum GrantUse {
    /// Setup accepts either an active access or refresh read grant.
    Setup,
    /// Events require a live refresh grant with read permission.
    Events,
}
/// Newly generated secrets; persistence only retains their hashes.
pub struct TokenPair<'a> {
    /// Fresh access-token secret; only its hash enters persistent state.
    pub access: &'a str,
    /// Fresh refresh-token secret; only its hash enters persistent state.
    pub refresh: &'a str,
}

/// Decode the common token columns; scope policy remains with the caller.
fn token_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<TokenGrant> {
    Ok(TokenGrant {
        client: r.get::<_, String>(0)?.into(),
        resource: r.get::<_, String>(1)?.into(),
        scope: r.get::<_, String>(2)?.into(),
        expires: r.get(3)?,
    })
}
impl Db {
    /// Register one client under the global registration bound.
    pub fn register_client(&self, id: &str, redirects: &[String]) -> Result<()> {
        let db = self.0.lock().map_err(safe)?;
        let count: i64 = db
            .query_row("SELECT count(*) FROM clients", [], |r| r.get(0))
            .map_err(safe)?;
        if count >= 1000 {
            return Err(Error::Rejected("registration_limit_reached"));
        }
        db.execute(
            "INSERT INTO clients VALUES (?,?)",
            params![id, serde_json::to_string(redirects).map_err(safe)?],
        )
        .map_err(safe)?;
        Ok(())
    }

    /// Read the exact callbacks registered by a client.
    pub fn client_redirects(&self, id: &str) -> Result<Option<Vec<String>>> {
        let db = self.0.lock().map_err(safe)?;
        let row: Option<String> = db
            .query_row("SELECT redirects FROM clients WHERE id=?", [id], |r| {
                r.get(0)
            })
            .optional()
            .map_err(safe)?;
        row.map(|s| serde_json::from_str(&s).map_err(safe))
            .transpose()
    }

    /// Persist an approved code with its required callback and challenge.
    pub fn save_code(&self, code: &str, grant: &CodeGrant) -> Result<()> {
        let db = self.0.lock().map_err(safe)?;
        db.execute("DELETE FROM codes WHERE expires<?", [now()])
            .map_err(safe)?;
        db.execute(
            "INSERT INTO codes VALUES (?,?,?,?,?,?,?)",
            params![
                hash(code),
                grant.token.client,
                grant.redirect,
                grant.challenge,
                grant.token.resource,
                grant.token.scope,
                grant.token.expires
            ],
        )
        .map_err(safe)?;
        Ok(())
    }
    /// Check, consume and replace a grant atomically. Policy failure rolls back the exchange.
    pub fn exchange_grant(
        &self,
        secret: ExchangeSecret<'_>,
        pair: TokenPair<'_>,
        check: impl FnOnce(&ExchangeGrant) -> Result<()>,
    ) -> Result<Box<str>> {
        let mut db = self.0.lock().map_err(safe)?;
        let tx = db
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(safe)?;
        let grant=match secret {
            ExchangeSecret::Code(code)=>tx.query_row("SELECT client,resource,scope,expires,redirect,challenge FROM codes WHERE hash=?",[hash(code)],|r|Ok(ExchangeGrant::Code(CodeGrant{token:token_row(r)?,redirect:r.get::<_,String>(4)?.into(),challenge:r.get::<_,String>(5)?.into()}))).optional().map_err(safe)?,
            ExchangeSecret::Refresh(refresh)=>tx.query_row("SELECT client,resource,scope,expires FROM tokens WHERE hash=? AND kind='refresh'",[hash(refresh)],|r|Ok(ExchangeGrant::Refresh(token_row(r)?))).optional().map_err(safe)?,
        }.ok_or(Error::Rejected("invalid_grant"))?;
        check(&grant)?;
        match secret {
            ExchangeSecret::Code(code) => {
                tx.execute("DELETE FROM codes WHERE hash=?", [hash(code)])
                    .map_err(safe)?;
            }
            ExchangeSecret::Refresh(refresh) => {
                tx.execute("DELETE FROM tokens WHERE hash=?", [hash(refresh)])
                    .map_err(safe)?;
            }
        }
        let grant = grant.token();
        tx.execute("DELETE FROM tokens WHERE expires<?", [now()])
            .map_err(safe)?;
        for (token, kind, expiry) in [
            (pair.access, "access", now() + 3600),
            (pair.refresh, "refresh", now() + 30 * 86400),
        ] {
            tx.execute(
                "INSERT INTO tokens VALUES (?,?,?,?,?,?)",
                params![
                    hash(token),
                    kind,
                    grant.client,
                    grant.resource,
                    grant.scope,
                    expiry
                ],
            )
            .map_err(safe)?;
        }
        tx.commit().map_err(safe)?;
        Ok(grant.scope.clone())
    }
    /// Load access-token metadata by its secret hash.
    pub fn access_grant(&self, token: &str) -> Result<Option<TokenGrant>> {
        self.0
            .lock()
            .map_err(safe)?
            .query_row(
                "SELECT client,resource,scope,expires FROM tokens WHERE hash=? AND kind='access'",
                [hash(token)],
                token_row,
            )
            .optional()
            .map_err(safe)
    }
    /// Check read authorization while streaming scope rows; no temporary vector is built.
    pub fn has_read_grant(&self, client: &str, resource: &str, usage: GrantUse) -> Result<bool> {
        let db = self.0.lock().map_err(safe)?;
        let mut query=db.prepare("SELECT scope FROM tokens WHERE client=? AND resource=? AND expires>? AND (?=0 OR kind='refresh')").map_err(safe)?;
        let rows = query
            .query_map(
                params![client, resource, now(), matches!(usage, GrantUse::Events)],
                |r| r.get::<_, String>(0),
            )
            .map_err(safe)?;
        for scope in rows {
            if Scopes::parse(&scope.map_err(safe)?)?.contains(Scope::Read) {
                return Ok(true);
            }
        }
        Ok(false)
    }
}
