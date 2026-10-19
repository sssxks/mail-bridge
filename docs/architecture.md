# Crate boundaries

Mail Bridge is a six-crate workspace with a single deployed executable.
The root manifest owns shared dependency versions and release settings;
`crates/server` is the default member and retains the `mail-bridge-rust` binary name.

| Crate | Responsibility | Internal dependencies |
| --- | --- | --- |
| `mail-bridge-core` | Account model, mailbox credentials, validation and shared errors | None |
| `mail-bridge-store` | SQLite schema, accounts, OAuth records, send journal and event outbox | core |
| `mail-bridge-mail` | IMAP/SMTP, MIME, search, drafts and bounded multi-account operations | core, store |
| `mail-bridge-auth` | Owner authorization, redirect policy, PKCE and token/grant policy | core, store |
| `mail-bridge-events` | Subscription lifecycle, IMAP observation and webhook delivery | core, store, mail, auth |
| `mail-bridge-rust` | HTTP/MCP, private account setup, environment configuration and process lifecycle | All five libraries |

SQLite connections are private to `store`. Its public operations express persistence
actions rather than expose connections, SQL or transaction guards. OAuth grant
exchange validates and consumes the grant and issues both tokens in one transaction;
the authorization crate supplies a policy callback over a stored record. Event scans
check the expected cursor, insert bounded outbox entries and advance the cursor in
one transaction. Delivery acknowledgement/retry updates are also transactional.

Account setup decodes HTTP forms in `server`, persists through the mail service,
and publishes an account only after a successful database write. Protocol DTOs and
MCP error conversion live with their adapters. Database records do not depend on
OAuth, HTTP, MCP or event service types.

The mail library exposes `backend`, `imap`, `mime`, `page` and `service` modules;
SMTP submission and draft construction remain internal. The events library exposes
`source`, `subscription`, `message` and `webhook`, with worker scheduling kept internal.
Callers import types from their owning modules directly; there is no compatibility
facade for the former monolithic library.

Run all Rust tests and lint checks from the repository root:

```bash
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo build --locked --release
```

Use `cargo test -p mail-bridge-mail --locked` for mail-specific tests. Cross-crate
HTTP/MCP and account setup regressions run under the server crate. Browser OAuth
and offline migration checks retain their root-level commands documented in the README.
Event lifecycle tests run with `cargo test -p mail-bridge-events --locked`. Their
synthetic source and webhook receiver are shared with the server's event protocol
test through `crates/events/tests/support`; they do not introduce production dependencies.
