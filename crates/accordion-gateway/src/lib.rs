//! The gateway: TLS, certificates, the host name check, and the redirect from
//! HTTP to HTTPS.
//!
//! Every client request reaches the server through this crate. It's a library
//! in the server binary, like the modules, rather than a separate process.
//! See decisions 1 and 5 in the `accordion` repo's `docs/decisions`.

pub mod acme;
pub mod address;
pub mod certificates;
pub mod dns;
pub mod host;
mod http;
pub mod local_name;
pub mod name;
pub mod peer;
pub mod propagation;
pub mod redirect;
mod retry;
pub mod tls;

pub use host::AllowedHosts;
pub use name::ServerName;
pub use peer::Peer;
pub use propagation::PropagationCheck;
