//! Publishing the DNS records that prove the server controls its name.
//!
//! To issue a certificate, the certificate authority looks up a TXT record at
//! `_acme-challenge.<name>`. Each DNS host Accordion supports has a provider
//! here that sets and removes that record through the host's API. See
//! decision 5 in the `accordion` repo's `docs/decisions`.

pub mod cloudflare;
pub mod desec;

use std::error::Error;
use std::future::Future;
use std::time::Duration;

pub use cloudflare::Cloudflare;
pub use desec::Desec;

/// The longest part of a provider's error reply worth showing to the admin.
const MAX_DETAIL_LEN: usize = 300;

fn short_detail(detail: &str) -> String {
    if detail.len() <= MAX_DETAIL_LEN {
        return detail.to_owned();
    }
    let end = detail.floor_char_boundary(MAX_DETAIL_LEN);
    format!("{}…", &detail[..end])
}

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

    /// Extra time to wait after the provider's nameservers serve the record,
    /// before the certificate authority looks for it. Each nameserver runs in
    /// many places, and Accordion can only ask the copy nearest to it, while
    /// the authority asks from several places that may update later.
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
        "{provider} has no domain for {name} that this API token can use. Check the server's \
         name, and that its domain is in your {provider} account and allowed for the token."
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
