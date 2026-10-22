# Mail Bridge Rust 0.4

A single-owner, multi-account IMAP/SMTP server for MCP clients. Run it behind
HTTPS, connect your client through OAuth, then add mailboxes from a private web
form. Accounts persist in SQLite and become available without restarting.

## What you need

- A host reachable by your MCP client and browser, a domain with working DNS,
  and a reverse proxy with a valid HTTPS certificate.
- Outbound access to your provider's IMAP server; SMTP access if sending is enabled.
- An independent **owner password**: 32–256 ASCII characters, different from
  every mailbox password. You enter it when authorizing a client and adding accounts.
- Your provider's IMAP settings and mailbox client password or authorization code.
  Provider-specific mailbox OAuth is not implemented.

The service can start with zero accounts. Its HTTP listener defaults to
`127.0.0.1:18765`; the reverse proxy terminates TLS. The public URL must be an
HTTPS origin such as `https://mail.example.com`, with no `/mcp` or other path.
The client connects to `https://mail.example.com/mcp`.

## Install on Linux with systemd

Run these commands from the repository root unless stated otherwise. Build on
a development machine with Docker Buildx, especially when deploying to a small VPS:

```bash
docker buildx build --platform linux/amd64 --target binary --output type=local,dest=dist .
```

This exports `dist/mail-bridge-rust`, a Debian 12 x86-64 executable. The runtime
needs glibc >= 2.34 and `libgcc_s`; Rust, Python and OpenSSL are not runtime
dependencies. Copy the executable and the `deploy/` examples to your server.
The following commands assume those files are available there:

```bash
sudo install -d -m 755 /opt/mail-bridge-rust
sudo install -m 755 dist/mail-bridge-rust /opt/mail-bridge-rust/mail-bridge-rust
sudo install -d -m 700 /etc/mail-bridge-rust
sudo install -m 600 deploy/service.env.example /etc/mail-bridge-rust/service.env
sudo install -m 600 /dev/null /etc/mail-bridge-rust/owner_password
sudoedit /etc/mail-bridge-rust/owner_password
sudoedit /etc/mail-bridge-rust/service.env
sudo install -m 644 deploy/mail-bridge-rust.service /etc/systemd/system/mail-bridge-rust.service
```

Use the password editor to enter your independent owner password on one line.
In `service.env`, replace the example domain and set the OAuth callback used by
your client:

```ini
MAIL_BRIDGE_PUBLIC_URL=https://mail.example.com
MAIL_BRIDGE_OAUTH_REDIRECT_URIS='["https://chatgpt.com/connector_platform_oauth_redirect"]'
MAIL_BRIDGE_EVENTS_ENABLED=true
```

The supplied unit imports the password with systemd `LoadCredential`, runs as a
`DynamicUser`, and creates a private state directory at `/var/lib/mail-bridge-rust`
(backed by `/var/lib/private/mail-bridge-rust`). It sets the loopback listener
and a 160 MiB memory cap. An optional `/etc/mail-bridge-rust/safety.env` is loaded
after `service.env` and can override its settings.

### Configure HTTPS routing

Adapt [the nginx location example](deploy/nginx-location.example.conf) inside
your existing HTTPS virtual host. The example assumes nginx and Mail Bridge run
on the same host. Route all of these paths to `http://127.0.0.1:18765`:

| Path | Purpose |
| --- | --- |
| `/mcp` | Authenticated MCP transport |
| `/accounts/setup` | Private mailbox setup page and form submission |
| `/oauth/register`, `/oauth/authorize`, `/oauth/token` | Client registration, owner authorization and tokens |
| `/.well-known/oauth-protected-resource` and `/.well-known/oauth-protected-resource/mcp` | Protected-resource discovery |
| `/.well-known/oauth-authorization-server` | Authorization-server discovery |

Preserve `Host`, `Authorization`, `Cookie` and `Origin`. Disable caching, request
body buffering to disk, automatic upstream retries, and logging of request bodies,
OAuth query strings or authorization headers on these routes. The setup form
uses same-origin POST and a secure cookie; serve it through the configured HTTPS
origin. It needs no JavaScript or external assets.

After installing the proxy configuration, validate and reload it, then start the
service:

```bash
sudo nginx -t
sudo systemctl reload nginx
sudo systemctl daemon-reload
sudo systemctl enable --now mail-bridge-rust.service
sudo systemctl status mail-bridge-rust.service --no-pager
```

### Check the installation

On the server:

```bash
curl --fail http://127.0.0.1:18765/healthz
curl --fail http://127.0.0.1:18765/readyz
curl --fail https://mail.example.com/.well-known/oauth-authorization-server
curl -i https://mail.example.com/mcp
```

Both local probes return `{"status":"ok"}` when healthy. `/healthz` checks the
HTTP process; `/readyz` checks the local account store. The public metadata should
contain endpoints under your configured HTTPS origin. An unauthenticated request
to `/mcp` should return **401** with `WWW-Authenticate` discovery metadata.
Mailbox connections begin when you request a mail operation or subscribe to events.

## Connect an MCP client

Add `https://mail.example.com/mcp` as a remote HTTP MCP server using OAuth.
Complete authorization in the browser with the independent owner password.
The service supports dynamic client registration and PKCE S256; a separate
plugin ZIP is unnecessary. Start the hosted service before adding the connection.

Set `MAIL_BRIDGE_OAUTH_REDIRECT_URIS` to a JSON array containing the actual callback
shown by the client. HTTPS callbacks must match exactly. The example above is
the default ChatGPT callback; replace or extend it for other clients.

Native desktop clients can use literal loopback IP callbacks, for example:

```ini
MAIL_BRIDGE_OAUTH_REDIRECT_URIS='["https://chatgpt.com/connector_platform_oauth_redirect","http://127.0.0.1/callback"]'
```

A portless loopback entry permits ephemeral ports on that IP and exact path.
Use `127.0.0.1` or `[::1]` for HTTP loopback callbacks. Client registration and
token exchange must still use the exact registered redirect URI.

Discovery advertises `mail:read`, which covers mailbox reading, account setup,
draft previews and event subscriptions. Sending requires a separate `mail:send`
grant and an SMTP-enabled account.

## Add a mailbox from chat

1. Ask to add a mailbox. `begin_account_setup` returns a private link valid for
   ten minutes. Open it in your browser.
2. Enter the account ID, display name, email address, IMAP host, port, encryption
   mode and mailbox client password. The login username defaults to the email
   address. Enter the independent owner password to confirm.
3. Save the form, then ask the agent to run `list_accounts`. The account is
   immediately available and survives service restarts.
4. Ask to list that account's folders to check the provider connection. Account
   listing reports stored configuration; the first mail operation checks login.

Account IDs use 1–32 lowercase letters, digits, underscores or hyphens, must be
unique, and are supplied as `account_id` in mail tools. The service supports up
to eight accounts. Setup links are single use after saving; request a new link
if one expires.

The form supports TLS (normally IMAP port 993) and STARTTLS (normally port 143).
QQ uses a mailbox client authorization code; ZJU with two-factor authentication
uses a client-specific password. Enter credentials only in the private form;
MCP tools never accept passwords.

Optional SMTP settings can be saved, but **new accounts always have sending
disabled**. This release's setup form has no switch to enable it. Existing accounts
retain their SMTP flags when migrated. Adding an account creates no event subscription.

## Configuration reference

Settings are environment variables read at startup. Restart after changing them.
The server does not load a `.env` file automatically; systemd and Docker Compose
load their own configuration files.

| Variable | Default | Meaning |
| --- | --- | --- |
| `MAIL_BRIDGE_OWNER_PASSWORD_FILE` | Unset | File containing the independent owner password; takes precedence over the inline variable. Trailing CR/LF is stripped. |
| `MAIL_BRIDGE_OWNER_PASSWORD` | Unset | Inline alternative when no password file is configured. Prefer the file for deployment. |
| `MAIL_BRIDGE_PUBLIC_URL` | Required | Public HTTPS origin, without a path, query, fragment or credentials. |
| `MAIL_BRIDGE_OAUTH_REDIRECT_URIS` | `["https://chatgpt.com/connector_platform_oauth_redirect"]` | JSON array of 1–10 allowed callbacks. |
| `MAIL_BRIDGE_DATA_DIR` | `./data` | Directory containing `mail-bridge.sqlite3`; relative to the process working directory. |
| `MAIL_BRIDGE_BIND` | `127.0.0.1:18765` | Listener IP and port. The container image sets `0.0.0.0:18765` inside the container. |
| `MAIL_BRIDGE_EVENTS_ENABLED` | Enabled when unset | If set, only `true` or `1` enables events; `false` disables them. |

For a foreground run, export these variables in your shell and run
`cargo run --locked --release`. Use the same HTTPS proxy and callback configuration
as a deployed service.

## Run with Docker Compose

As an alternative to systemd, build and load the runtime image on your builder:

```bash
docker buildx build --platform linux/amd64 --load -t mail-bridge-rust:0.4.0 .
```

If deploying to another host, transfer the image with `docker save` / `docker load`.
[The Compose example](compose.example.yaml) expects this local tag and performs no
build. Set these variables in your shell or Compose's `.env`:

```dotenv
MAIL_BRIDGE_PUBLIC_URL=https://mail.example.com
MAIL_BRIDGE_PRIVATE_DIR=/absolute/private/mail-bridge
MAIL_BRIDGE_OAUTH_REDIRECT_URIS='["https://chatgpt.com/connector_platform_oauth_redirect"]'
```

Create `owner_password` in that private directory. On Linux, make the file readable
by container UID/GID `10001:10001`, with mode `0600`; keep the directory private.
Then start the container:

```bash
docker compose -f compose.example.yaml up -d
docker compose -f compose.example.yaml logs --tail 50
```

The Compose file publishes port 18765 on host loopback, mounts the password read
only, and persists SQLite in the named `journal` volume at `/data`. Configure HTTPS
on the host as described above. Keep the volume across container replacements.
To change event enablement, edit the Compose environment entry, which explicitly
sets it to `true` in the example.

## Using the mail tools

`list_folders`, `list_messages`, `search_messages` and `read_message` take an
explicit account ID. Reads use IMAP EXAMINE and BODY.PEEK to preserve read flags.
Message UIDs belong to an account, folder and UIDVALIDITY; retain the returned
UIDVALIDITY and pagination cursor for subsequent requests, including empty pages
with a continuation cursor. Search results expose provider-index limitations in
`search_warning`.

`read_message` decodes MIME and Chinese encodings, converts HTML to text without
loading remote content, and excludes attachments. Body output is limited to
20,000 characters; inspect `body_source` and `body_truncated`.

`prepare_draft` previews content locally. `send_email` uses a durable
`(account_id, request_id)` journal: reuse the same request ID for the same message
to get its recorded status without resending. SMTP acceptance is recorded; the
service does not create a Sent-folder copy.

Events are enabled by default, but mailbox watching starts only after an explicit
authorized subscription. See [the event contract](EVENTS.md) for callback verification,
subscription renewal and payloads.

## State, upgrades and troubleshooting

`MAIL_BRIDGE_DATA_DIR/mail-bridge.sqlite3` is the sole account source and also
stores OAuth state, send deduplication and event state. It contains **unencrypted
mailbox credentials**. Keep the directory at `0700`, files at `0600`, and protect
backups the same way. Stop the service before copying its state for a backup;
preserve the database when replacing the executable or container.

See [deployment, upgrades and one-time migration from 0.3](deploy/SETUP.md) for
the upgrade utility and legacy import procedure. Runtime account JSON files and
password directories are no longer used. To revoke all client connections, stop
the service and run the executable with `--revoke-oauth` using the same startup
environment and data directory. This removes OAuth clients, grants, subscriptions
and outbox entries while preserving mailbox accounts and the send journal.

| Symptom | Check |
| --- | --- |
| Startup exits immediately | Owner password length/ASCII, readable password file, valid HTTPS origin and JSON callback array. Inspect `journalctl -u mail-bridge-rust.service -n 50 --no-pager`. |
| OAuth reports `invalid_redirect_uri` | Copy the client's actual callback into the allowlist, restart, then reconnect. |
| Setup page fails or cannot save | Proxy `/accounts/setup`, preserve Cookie/Origin, use the configured HTTPS hostname, and request a fresh link. |
| Accounts disappear after restart | Confirm the same persistent data directory or Docker volume is mounted. |
| Sending is unavailable | Check both the `mail:send` grant and `smtp_enabled` in `list_accounts`; new accounts start disabled. |

## Development

With Rust and Cargo installed, build and test from the repository root:

```bash
cargo build --locked --release
cargo test --workspace --locked
```

The executable is `target/release/mail-bridge-rust` (`.exe` on Windows).
See [crate boundaries and development checks](docs/architecture.md) for the
six-crate workspace, focused tests, Clippy and Rustdoc.

For browser OAuth/account setup and offline migration regressions, install `uv`
and supply a Chromium-based browser executable:

```powershell
cargo build --locked
uv run scripts/test-oauth-browser.py --browser "C:/Program Files/BraveSoftware/Brave-Browser/Application/brave.exe"
uv run --no-project python -X utf8 scripts/test-account-migration.py
```

These checks use synthetic credentials and repository-local test state. The browser
test uses an isolated profile and checks OAuth, private-form submission, immediate
account visibility and restart persistence without connecting to a real mailbox
or sending email.

For Codex, request an additional send grant with:

```bash
uv run scripts/authorize-mail-send.py --server-url https://mail.example.com/mcp
```

The helper finds Codex on PATH or in the Windows desktop installation; use
`--codex PATH` to select an executable. Complete consent in the browser. Private
CLI output stays in the ignored `.research/send-authorization/` directory.

## License and history

Licensed under the [MIT License](LICENSE).

Before initial publication, Git history was rewritten to remove private deployment
records and replace personal email addresses and service identifiers. Development
commits, their order and timestamps were retained. Some commits containing only
private records are now empty.
