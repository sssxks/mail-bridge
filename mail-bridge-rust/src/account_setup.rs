//! Short-lived, client-bound invitations to an owner-confirmed private form.
use crate::{
    Error, Result,
    auth::{Auth, Params, random, val},
    db::{hash, now},
    mail::MailService,
    safe,
};
use serde_json::{Value, json};
use std::{collections::BTreeMap, sync::Mutex};
use zeroize::Zeroizing;

const TTL: i64 = 600;
const MAX_SESSIONS: usize = 8;
struct Session {
    client: String,
    ticket_hash: String,
    csrf_hash: String,
    expires: i64,
    account_id: Option<String>,
}
#[derive(Default)]
pub struct AccountSetup {
    sessions: Mutex<BTreeMap<String, Session>>,
}
impl AccountSetup {
    pub fn begin(&self, client: &str, base: &str) -> Result<Value> {
        let mut sessions = self.sessions.lock().map_err(safe)?;
        sessions.retain(|_, s| s.expires > now());
        if sessions.len() >= MAX_SESSIONS {
            return Err(Error("Too many setup invitations; try after they expire"));
        }
        let setup_id = random();
        let ticket = random();
        let expires = now() + TTL;
        sessions.insert(
            setup_id.clone(),
            Session {
                client: client.into(),
                ticket_hash: hash(&ticket),
                csrf_hash: String::new(),
                expires,
                account_id: None,
            },
        );
        Ok(
            json!({"setup_id": setup_id, "setup_url": format!("{base}/accounts/setup?ticket={ticket}"), "expires_at": expires,
            "status": "pending", "instructions": "Open the private link and enter the owner password and mailbox credential there. Never paste credentials into chat. Saving activates configuration without testing login or enabling SMTP/events."}),
        )
    }
    pub fn status(&self, client: &str, setup_id: &str) -> Result<Value> {
        let sessions = self.sessions.lock().map_err(safe)?;
        let session = sessions.get(setup_id).filter(|s| s.client == client && s.expires > now()).ok_or(Error("Setup invitation unavailable or expired; use list_accounts to inspect saved accounts"))?;
        Ok(
            json!({"setup_id":setup_id,"status":if session.account_id.is_some(){"saved"}else{"pending"},"account_id":session.account_id,"connection_tested":false,"restart_required":false}),
        )
    }
    pub fn page(&self, ticket: &str, auth: &Auth) -> Result<(String, String)> {
        let mut sessions = self.sessions.lock().map_err(safe)?;
        let session = sessions
            .values_mut()
            .find(|s| s.ticket_hash == hash(ticket) && s.expires > now() && s.account_id.is_none())
            .ok_or(Error("Setup invitation unavailable or expired"))?;
        if !auth.setup_grant_active(&session.client)? {
            return Err(Error("Connection authorization no longer active"));
        }
        let csrf = random();
        session.csrf_hash = hash(&csrf);
        let page = include_str!("account_setup.html")
            .replace(
                "{{ticket}}",
                &html_escape::encode_double_quoted_attribute(ticket),
            )
            .replace("{{csrf}}", &csrf);
        Ok((
            page,
            format!(
                "__Host-mail-bridge-setup={csrf}; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age={TTL}"
            ),
        ))
    }
    pub fn submit(
        &self,
        mut params: Params,
        cookie: &str,
        auth: &Auth,
        mail: &MailService,
    ) -> Result<String> {
        let owner = Zeroizing::new(params.remove("owner_password").unwrap_or_default());
        let ticket = params.remove("ticket").unwrap_or_default();
        let csrf = params.remove("_csrf").unwrap_or_default();
        let mut sessions = self.sessions.lock().map_err(safe)?;
        let session = sessions
            .values_mut()
            .find(|s| s.ticket_hash == hash(&ticket) && s.expires > now() && s.account_id.is_none())
            .ok_or(Error("Setup invitation unavailable or expired"))?;
        if csrf.is_empty()
            || csrf != cookie
            || session.csrf_hash != hash(&csrf)
            || !auth.verify_owner(&owner)
            || !auth.setup_grant_active(&session.client)?
        {
            return Err(Error("Owner confirmation or browser verification failed"));
        }
        if params.keys().any(|k| {
            !matches!(
                k.as_str(),
                "account_id"
                    | "name"
                    | "email"
                    | "username"
                    | "imap_host"
                    | "imap_port"
                    | "imap_security"
                    | "smtp_host"
                    | "smtp_port"
                    | "smtp_security"
                    | "password"
            )
        }) {
            return Err(Error("Unexpected setup field"));
        }
        // Reject password reuse before removing it into the account's zeroizing storage.
        if auth.verify_owner(val(&params, "password")?) {
            return Err(Error(
                "Mailbox credential must differ from the owner password",
            ));
        }
        let account = crate::accounts::from_form(params)?;
        let id = account.id.clone();
        mail.add_account(account)?;
        session.account_id = Some(id.clone());
        session.csrf_hash.clear();
        Ok(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn expired_invitations_are_rejected_and_reclaimed() {
        let setup = AccountSetup::default();
        let invitation = setup.begin("client", "https://mail.example.com").unwrap();
        let id = invitation["setup_id"].as_str().unwrap();
        setup.sessions.lock().unwrap().get_mut(id).unwrap().expires = now() - 1;
        assert!(setup.status("client", id).is_err());
        setup.begin("client", "https://mail.example.com").unwrap();
        assert_eq!(setup.sessions.lock().unwrap().len(), 1);
    }
}
