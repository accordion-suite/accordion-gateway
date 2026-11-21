# Accordion Gateway

TLS, certificates, the host name check, and remote access for Accordion. The `accordion` repo builds this crate into the server, where every client request passes through it.

This repo is part of [Accordion](https://github.com/accordion-suite/accordion), a self-hosted, zero-telemetry replacement for Google Workspace. Please open issues in the [main repo](https://github.com/accordion-suite/accordion/issues).

## What's here

| Module | Contents |
|---|---|
| `name` | `ServerName`, the server's public name, which is also the passkey relying party ID |
| `host` | Middleware that answers only requests for the server's own names, which blocks DNS rebinding |
| `tls` | TLS 1.3 serving, with TLS 1.2 for older clients, and a certificate that can be replaced without a restart |
| `redirect` | The port 80 redirect to the HTTPS name |
| `acme` | Getting certificates from Let's Encrypt with the DNS challenge, including the wildcard certificate for link sharing ([decision 22](https://github.com/accordion-suite/accordion/blob/main/docs/decisions/0022-link-sharing.md)), and reading when they expire and when to renew them |
| `certificates` | Storing the server's name, DNS settings, and certificate, renewing the certificate in the background, and reporting how renewal is going |
| `dns` | DNS providers that publish the challenge and address records: deSEC and Cloudflare |
| `address` | Pointing the server's name at its address on the home network, and updating it when the address changes |
| `peer` | Both ends of a connection, and whether the client is on the home network |
| `local_name` | Announcing `accordion.local` on the home network with multicast DNS, so people can find the setup wizard |
| `propagation` | Waiting until every nameserver serves the challenge record, before the certificate authority looks |
| `tunnel` | Remote access: a WireGuard server inside Accordion, in user space, with its own TCP/IP stack, so the machine needs no network interface, route, or firewall rule |
| `port_mapping` | Asking the home router to forward a port, through PCP, NAT-PMP, or UPnP, renewing it, and noticing carrier-grade NAT from the public address the router reports |
| `endpoint` | The address record that devices away from home find the tunnel at, under a random label of the server's name so certificate logs don't reveal the home's address |

An RFC 2136 provider is planned. [Decision 5](https://github.com/accordion-suite/accordion/blob/main/docs/decisions/0005-server-name-and-certificates.md) explains how the name and certificates work, and [decision 21](https://github.com/accordion-suite/accordion/blob/main/docs/decisions/0021-remote-access.md) explains remote access.

## Building

Install Rust with [rustup](https://rustup.rs), then run these commands from the repo root:

```sh
cargo build --workspace
cargo test --workspace
```

The ACME tests need Pebble, Let's Encrypt's test certificate authority, so `cargo test` skips them. To run them, use:

```sh
scripts/test-acme.sh
```

The script downloads a pinned Pebble release into `target/pebble`, checks its checksums, and starts it before running the tests.

CI runs that script too. It also checks formatting with `cargo fmt`, lints with `cargo clippy`, and checks dependency licenses and advisories with `cargo deny`.

## License

[AGPL-3.0 or later](LICENSE)
