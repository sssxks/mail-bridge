//! OAuth records and atomic one-use grant exchange.
use crate::{Db, hash, now};
use mail_bridge_core::{Error, Result, safe};
use rusqlite::{OptionalExtension, params};

/// Stored code or token, before authorization policy is applied.
pub struct Grant {
    pub client: String,
    pub resource: String,
    pub scope: String,
    pub expires: i64,
    pub redirect: Option<String>,
    pub challenge: Option<String>,
}

/// Fresh token secrets; only their hashes are persisted.
pub struct TokenPair<'a> {
    pub access: &'a str,
    pub refresh: &'a str,
}

impl Db {
    /// Register one client under the global registration bound.
    pub fn register_client(&self, id: &str, redirects: &[String]) -> Result<()> {
        let db = self.0.lock().map_err(safe)?;
        let count: i64 = db
            .query_row("SELECT count(*) FROM clients", [], |r| r.get(0))
            .map_err(safe)?;
        if count >= 1000 {
            return Err(Error("registration_limit_reached"));
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

    /// Persist a short-lived authorization code after owner approval.
    pub fn save_code(&self, code: &str, grant: &Grant) -> Result<()> {
        let db = self.0.lock().map_err(safe)?;
        db.execute("DELETE FROM codes WHERE expires<?", [now()])
            .map_err(safe)?;
        db.execute(
            "INSERT INTO codes VALUES (?,?,?,?,?,?,?)",
            params![
                hash(code),
                grant.client,
                grant.redirect,
                grant.challenge,
                grant.resource,
                grant.scope,
                grant.expires
            ],
        )
        .map_err(safe)?;
        Ok(())
    }

    /// Validate and consume a grant, then issue both tokens in one transaction.
    /// A failed policy callback rolls the transaction back without consuming the grant.
    pub fn exchange_grant(
        &self,
        secret: &str,
        code: bool,
        pair: TokenPair<'_>,
        check: impl FnOnce(&Grant) -> Result<()>,
    ) -> Result<String> {
        let mut db = self.0.lock().map_err(safe)?;
        let tx = db
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(safe)?;
        let grant = if code {
            tx.query_row(
                "SELECT client,resource,scope,expires,redirect,challenge FROM codes WHERE hash=?",
                [hash(secret)],
                |r| {
                    Ok(Grant {
                        client: r.get(0)?,
                        resource: r.get(1)?,
                        scope: r.get(2)?,
                        expires: r.get(3)?,
                        redirect: r.get(4)?,
                        challenge: r.get(5)?,
                    })
                },
            )
            .optional()
            .map_err(safe)?
        } else {
            tx.query_row(
                "SELECT client,resource,scope,expires FROM tokens WHERE hash=? AND kind='refresh'",
                [hash(secret)],
                |r| {
                    Ok(Grant {
                        client: r.get(0)?,
                        resource: r.get(1)?,
                        scope: r.get(2)?,
                        expires: r.get(3)?,
                        redirect: None,
                        challenge: None,
                    })
                },
            )
            .optional()
            .map_err(safe)?
        }
        .ok_or(Error("invalid_grant"))?;
        check(&grant)?;
        if code {
            tx.execute("DELETE FROM codes WHERE hash=?", [hash(secret)])
                .map_err(safe)?;
        } else {
            tx.execute("DELETE FROM tokens WHERE hash=?", [hash(secret)])
                .map_err(safe)?;
        }
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
        Ok(grant.scope)
    }

    /// Read an access token record by its secret hash.
    pub fn access_grant(&self, token: &str) -> Result<Option<Grant>> {
        self.0
            .lock()
            .map_err(safe)?
            .query_row(
                "SELECT client,resource,scope,expires FROM tokens WHERE hash=? AND kind='access'",
                [hash(token)],
                |r| {
                    Ok(Grant {
                        client: r.get(0)?,
                        resource: r.get(1)?,
                        scope: r.get(2)?,
                        expires: r.get(3)?,
                        redirect: None,
                        challenge: None,
                    })
                },
            )
            .optional()
            .map_err(safe)
    }

    /// Read active grant scopes; events require a refresh grant, setup accepts either kind.
    pub fn grant_scopes(
        &self,
        client: &str,
        resource: &str,
        refresh_only: bool,
    ) -> Result<Vec<String>> {
        let db = self.0.lock().map_err(safe)?;
        let mut query = db.prepare("SELECT scope FROM tokens WHERE client=? AND resource=? AND expires>? AND (?=0 OR kind='refresh')").map_err(safe)?;
        query
            .query_map(params![client, resource, now(), refresh_only], |r| r.get(0))
            .map_err(safe)?
            .collect::<rusqlite::Result<_>>()
            .map_err(safe)
    }
}
