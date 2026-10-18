# Accordion Gateway

TLS, certificates, the host name check, and remote access for Accordion. The `accordion` repo builds this crate into the server, where every client request passes through it.

This repo is part of [Accordion](https://github.com/accordion-suite/accordion), a self-hosted, zero-telemetry replacement for Google Workspace. Please open issues in the [main repo](https://github.com/accordion-suite/accordion/issues).

## What's here

| Module | Contents |
|---|---|
| `name` | `ServerName`, the server's public name, which is also the passkey relying party ID |
| `host` | Middleware that answers only requests for the server's own names, which blocks DNS rebinding |
| `tls` | TLS 1.3 serving with a certificate that can be replaced without a restart |
| `redirect` | The port 80 redirect to the HTTPS name |

Getting certificates from Let's Encrypt and WireGuard remote access are planned. [Decision 5](https://github.com/accordion-suite/accordion/blob/main/docs/decisions/0005-server-name-and-certificates.md) explains how the name and certificates work.

## Building

Install Rust with [rustup](https://rustup.rs), then run these commands from the repo root:

```sh
cargo build --workspace
cargo test --workspace
```

CI also checks formatting with `cargo fmt`, lints with `cargo clippy`, and checks dependency licenses and advisories with `cargo deny`.

## License

[AGPL-3.0 or later](LICENSE)
