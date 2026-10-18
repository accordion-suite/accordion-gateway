//! Publishing the DNS records that prove the server controls its name.
//!
//! To issue a certificate, the certificate authority looks up a TXT record at
//! `_acme-challenge.<name>`. Each DNS host Accordion supports has a provider
//! here that sets and removes that record through the host's API. See
//! decision 5 in the `accordion` repo's `docs/decisions`.

pub mod desec;

use std::error::Error;
use std::future::Future;
use std::time::Duration;

pub use desec::Desec;

pub trait DnsProvider: Send + Sync {
    /// Makes `value` the only TXT record at `record`, such as
    /// `_acme-challenge.accordion.example.com`.
    fn set_txt(
        &self,
        record: &str,
        value: &str,
    ) -> impl Future<Output = Result<(), DnsError>> + Send;

    /// Removes the TXT records at `record`. Removing a record that doesn't
    /// exist isn't an error.
    fn clear_txt(&self, record: &str) -> impl Future<Output = Result<(), DnsError>> + Send;

    /// How long to wait after `set_txt` before the certificate authority
    /// looks for the record. If it looks too early, the request fails and
    /// counts against the authority's limits.
    fn propagation_delay(&self) -> Duration;
}

#[derive(Debug, thiserror::Error)]
pub enum DnsError {
    #[error(
        "{provider} didn't accept the API token. Check that the token is correct and hasn't \
         been deleted."
    )]
    Unauthorized { provider: &'static str },
    #[error(
        "{provider} doesn't let this API token change {record}. Give the token permission to \
         change TXT records at that name."
    )]
    Forbidden {
        provider: &'static str,
        record: String,
    },
    #[error(
        "None of the domains in your {provider} account contain {name}. Check the server's \
         name, or add its domain to {provider}."
    )]
    NoZone {
        provider: &'static str,
        name: String,
    },
    #[error("{provider} refused the change (HTTP {status}): {detail}")]
    Rejected {
        provider: &'static str,
        status: u16,
        detail: String,
    },
    #[error(
        "Accordion couldn't reach {provider}. Check the server's internet connection, then try \
         again. ({source})"
    )]
    Unreachable {
        provider: &'static str,
        source: Box<dyn Error + Send + Sync>,
    },
}
