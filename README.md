# Mail Bridge

IMAP/SMTP MCP backend for ChatGPT, connected directly over Streamable HTTP with OAuth.

The backend is in [`mail-bridge-rust/`](mail-bridge-rust/README.md). This repository
does not distribute a separate ChatGPT plugin package. See the backend README
for account setup, authorization, and deployment.

```bash
cd mail-bridge-rust
cargo test --locked
```
