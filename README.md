# Mail Bridge

Private email connector with a Rust HTTP MCP service, OAuth, independent QQ/ZJU
account configuration, read-only IMAP operations, draft previews and explicit
SMTP sending. Optional signed new-mail events are implemented and default off.

| Directory | Purpose |
|---|---|
| `mail-bridge-rust/` | Main Rust 0.3 implementation, Cargo.lock, tests and deployment templates |
| `mail-bridge-private/` | Private plugin source, remote MCP configuration and manual setup script |
| `docs/` | Deployment/connection handoff and release index |
| `releases/` | Local ZIP deliverables; intentionally excluded from Git |

Start with [the Rust instructions](mail-bridge-rust/README.md) and
[the handoff](docs/STATUS.md). Test the main implementation with:

```bash
cd mail-bridge-rust
cargo test --locked
```

Never commit real mailbox client passwords, the OAuth owner password, runtime
configuration, tokens or the private SQLite state. Example configuration contains
no secrets. The manual setup script must only be run by the owner in a private
interactive terminal; do not execute its secret-entry path during automated work.

Plugin package creation does not register or authorize a cloud MCP connection.
Read the connection status before assuming the email tools are usable.
