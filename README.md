# Mail Bridge Rust 0.4

A single-owner, multi-account IMAP/SMTP service using authenticated HTTP MCP.
Mailbox accounts are runtime data in one SQLite store. There is no account JSON
startup configuration, password-directory fallback, or account credential mount.

## Add an account from chat

1. Ask to add a mailbox. `begin_account_setup` returns a private link and expiry time.
2. Open the link within ten minutes. Enter the account ID, display name, address,
   IMAP hostname/port, TLS or STARTTLS, mailbox client password, and independent
   service owner password in the private page. A separate login username and SMTP
   server settings are optional. SMTP remains disabled for every newly added account.
3. Saving commits the account to SQLite and publishes it to the shared registry.
   The current process can immediately use it; no restart is needed.
4. After the page reports success, use `list_accounts` to find the new account.
   `configuration_status` also inspects accounts without connecting.
   Saving or reporting `ready` does not prove login. Mail actions take an account ID.

Only the owner-confirmed private form receives passwords. Neither MCP tool accepts
credentials. Links require an active originating OAuth grant, owner confirmation,
CSRF token, secure HttpOnly cookie and same-origin POST. They expire after ten
minutes, are single use after saving, and are capped at eight invitations. New
accounts cannot overwrite existing IDs. The combined account limit is eight.

## Persistent state and authorization

`MAIL_BRIDGE_DATA_DIR/mail-bridge.sqlite3` is the sole account source. It contains
mailbox credentials, OAuth state, send deduplication and optional event state.
SQLite is not encrypted. Protect its directory with 0700, files with 0600, and
all backups as secrets. Unix creation uses private permissions before opening
SQLite. The supplied systemd unit provides a private writable StateDirectory.
Never paste, attach, log or commit the database or mailbox credentials.

Startup settings describe the service, not its mailboxes:

```text
MAIL_BRIDGE_OWNER_PASSWORD_FILE=/private/path/owner_password
MAIL_BRIDGE_PUBLIC_URL=https://your-mail.example.com
MAIL_BRIDGE_OAUTH_REDIRECT_URIS=["https://chatgpt.com/connector_platform_oauth_redirect"]
MAIL_BRIDGE_DATA_DIR=/private/path/state
MAIL_BRIDGE_BIND=127.0.0.1:18765
MAIL_BRIDGE_EVENTS_ENABLED=false
```

The owner enters a separate 32-256 character ASCII owner password privately. It
protects authorization and account changes and must differ from mailbox passwords.
QQ uses a client authorization code; ZJU with two-factor authentication uses a
client-specific password. This release accepts password-based IMAP authentication;
provider-specific mailbox OAuth is not implemented.

Use the platform's actual callback. HTTPS callbacks are exact; native desktop
callbacks require an explicit literal loopback IP, e.g. `http://127.0.0.1/callback`.
A portless loopback policy allows ephemeral ports on that IP and exact path.
Registration and token exchange still require the exact registered redirect and
PKCE S256. Default discovery advertises `mail:read`; sending and events require
separate scopes and feature controls. Connect the deployed `/mcp` endpoint directly
in ChatGPT using OAuth; no separate plugin ZIP is required. Adding the connection
does not host or start the service.

## Mail behavior

`list_folders`, `list_messages`, `search_messages` and `read_message` require an
explicit account ID. IMAP uses EXAMINE and BODY.PEEK. UIDs are scoped to account,
mailbox and UIDVALIDITY. MIME, Chinese encodings and modified UTF-7 are supported.
Bodies, searches, pagination, request sizes and timeouts are bounded. HTML is
converted to text without loading remote content. Email content is untrusted data.

`prepare_draft` previews the selected sender and exact content without writing
IMAP Drafts. `send_email` requires `mail:send`, an enabled account, explicit
recipients/subject/body and one preserved request ID.
The durable `(account_id, request_id)` journal commits before an SMTP attempt.
Repeating a request ID returns its recorded status without resending. SMTP acceptance does not prove
final delivery or create a Sent-folder copy. No test email is required for setup.

The registry takes a short lock to clone an account, then releases it before
network I/O. Saving commits before activation; failed writes activate nothing.
Existing calls keep their snapshot. Account IDs are stable and cannot be replaced
by the add flow. On process restart all accounts are restored from the same store.
Existing migrated SMTP flags are preserved; new accounts start disabled.

## Build, test and deploy

```bash
cargo test --locked
cargo build --locked --release
```

Browser and migration regression from the repository root:

```powershell
cargo build --locked
uv run scripts/test-oauth-browser.py --browser "C:/Program Files/BraveSoftware/Brave-Browser/Application/brave.exe"
uv run --no-project python -X utf8 scripts/test-account-migration.py
```

The browser test uses an isolated profile, synthetic credentials and local-only
services. It verifies actual browser OAuth, private-form POST, immediate account
visibility, restart persistence and preservation of the original OAuth connection.
It never connects to a real mailbox or sends email.

Build Linux amd64 on a larger builder, not a small deployment server:

```bash
docker buildx build --platform linux/amd64 --target binary --output type=local,dest=dist .
```

The Debian 12 binary requires glibc >=2.34 and libgcc_s; Rust, Python and OpenSSL
are not runtime dependencies. See [deployment and one-time migration](deploy/SETUP.md).
Reverse-proxy `/mcp`, `/accounts/setup`, the OAuth endpoints and discovery metadata
to the loopback listener. Preserve Host, Authorization, Cookie and Origin; disable
body/query/auth logging, caching, buffering to disk and automatic upstream retries.
The HTTPS page needs no external assets or JavaScript.

## Events, upgrades and revocation

Events default off. New account setup never creates a subscription or starts an
IMAP watcher. If events are enabled and explicitly subscribed, the event source
and catalog resolve accounts from the same runtime store without a restart.
See [event contract](EVENTS.md) for platform signing and delivery requirements.

Back up private state before upgrades. Preserve the database and account IDs to
retain OAuth grants, subscriptions and send deduplication. Account updates no
longer need service restarts; upgrading the executable or changing service-wide
settings still does. Stop the service before `--revoke-oauth`; this removes grants,
clients, subscriptions and outbox, preserving mailbox accounts and the send journal.

Limits: eight TCP connections, four HTTP requests, one ordinary mail operation,
eight accounts, two event subscriptions, 128 queued events per subscription;
64 KiB MCP request, 16 KiB private/OAuth form, 2 MiB mail/literal and 4 MiB IMAP input.
The supplied service memory cap is 160 MiB.
