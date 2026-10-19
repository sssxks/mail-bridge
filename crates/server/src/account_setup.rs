//! Short-lived, client-bound invitations to an owner-confirmed private form.
//!
//! | Operation | Frequency | Complexity | Storage | Forbidden implementation |
//! | --- | --- | --- | --- | --- |
//! | Find ticket | Page/submit | O(n + ticket bytes), n <= 8 | Vec | Hash ticket per candidate |
//! | Transition | Page/save | O(1) excluding IO | Inline enum | Empty-string state sentinel |
use mail_bridge_auth::{Auth, Params, val};
use mail_bridge_core::random;
use mail_bridge_core::{Error, Result, safe};
use mail_bridge_mail::MailService;
use mail_bridge_store::{hash, now};
use serde_json::{Value, json};
use std::sync::Mutex;
use zeroize::Zeroizing;

const TTL: i64 = 600;
const MAX_SESSIONS: usize = 8;
/// `Invited | Opened(csrf_hash) | Saved`.
///
/// Each variant owns only its relevant immutable payload. A saved invitation
/// cannot retain a CSRF token, and an unopened invitation cannot authorize POST.
enum Progress {
    Invited,
    Opened { csrf_hash: Box<str> },
    Saved,
}

/// `Client × TicketHash × Expiry × Progress`. Identity and expiry are fixed;
/// only progress changes while the registry lock is held.
struct Session {
    client: Box<str>,
    ticket_hash: Box<str>,
    expires: i64,
    progress: Progress,
}
/// At most eight live invitations stored in insertion order.
/// The mutex serializes form opening, owner confirmation and commit/publication,
/// so two submissions cannot activate the same invitation twice.
#[derive(Default)]
pub struct AccountSetup {
    sessions: Mutex<Vec<Session>>,
}
impl AccountSetup {
    /// Reclaim expired entries and issue a client-bound, ten-minute invitation.
    pub fn begin(&self, client: &str, base: &str) -> Result<Value> {
        let mut sessions = self.sessions.lock().map_err(safe)?;
        sessions.retain(|s| s.expires > now());
        if sessions.len() >= MAX_SESSIONS {
            return Err(Error("Too many setup invitations; try after they expire"));
        }
        let ticket = random();
        let expires = now() + TTL;
        sessions.push(Session {
            client: client.into(),
            ticket_hash: hash(&ticket).into(),
            expires,
            progress: Progress::Invited,
        });
        Ok(
            json!({"setup_url": format!("{base}/accounts/setup?ticket={ticket}"), "expires_at": expires}),
        )
    }
    /// Open or reopen a pending invitation, replacing its browser CSRF token.
    pub fn page(&self, ticket: &str, auth: &Auth) -> Result<(String, String)> {
        let mut sessions = self.sessions.lock().map_err(safe)?;
        let ticket_hash = hash(ticket);
        let session = sessions
            .iter_mut()
            .find(|s| {
                s.ticket_hash.as_ref() == ticket_hash
                    && s.expires > now()
                    && !matches!(s.progress, Progress::Saved)
            })
            .ok_or(Error("Setup invitation unavailable or expired"))?;
        if !auth.setup_grant_active(&session.client)? {
            return Err(Error("Connection authorization no longer active"));
        }
        let csrf = random();
        session.progress = Progress::Opened {
            csrf_hash: hash(&csrf).into(),
        };
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
    /// Confirm an opened form, then mark saved only after persistence/activation
    /// succeeds. Failure leaves the invitation available for a corrected submit.
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
        let ticket_hash = hash(&ticket);
        let session = sessions
            .iter_mut()
            .find(|s| {
                s.ticket_hash.as_ref() == ticket_hash
                    && s.expires > now()
                    && !matches!(s.progress, Progress::Saved)
            })
            .ok_or(Error("Setup invitation unavailable or expired"))?;
        let Progress::Opened { csrf_hash } = &session.progress else {
            return Err(Error("Owner confirmation or browser verification failed"));
        };
        if csrf.is_empty()
            || csrf != cookie
            || csrf_hash.as_ref() != hash(&csrf)
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
        let account = crate::form::from_form(params)?;
        let id = account.id.clone();
        mail.add_account(account)?;
        session.progress = Progress::Saved;
        Ok(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn expired_invitations_are_reclaimed() {
        let setup = AccountSetup::default();
        setup.begin("client", "https://mail.example.com").unwrap();
        setup.sessions.lock().unwrap()[0].expires = now() - 1;
        setup.begin("client", "https://mail.example.com").unwrap();
        assert_eq!(setup.sessions.lock().unwrap().len(), 1);
    }
}
