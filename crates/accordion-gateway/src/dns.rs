//! Publishing the server's DNS records through the DNS host's API.
//!
//! To issue a certificate, the certificate authority looks up a TXT record at
//! `_acme-challenge.<name>`. Clients look up the name's address record to
//! find the server. Each DNS host Accordion supports has a provider here that
//! sets those records. See decision 5 in the `accordion` repo's
//! `docs/decisions`.

pub mod cloudflare;
pub mod desec;

use std::error::Error;
use std::fmt;
use std::future::Future;
use std::net::IpAddr;
use std::str::FromStr;
use std::time::Duration;

pub use cloudflare::Cloudflare;
pub use desec::Desec;
use serde::{Deserialize, Serialize};

use crate::http::BoxError;

/// The longest part of a provider's error reply worth showing to the admin.
const MAX_DETAIL_LEN: usize = 300;

/// The TTL for the server's address record, where the provider allows it.
/// Five minutes lets clients follow an address change quickly without asking
/// the nameservers on every connection.
const ADDRESS_TTL: u32 = 300;

/// The record type that holds `address`.
fn address_type(address: IpAddr) -> &'static str {
    match address {
        IpAddr::V4(_) => "A",
        IpAddr::V6(_) => "AAAA",
    }
}

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

    /// Points `name` at `address`, replacing the name's other records of
    /// the same type: A for IPv4, or AAAA for IPv6.
    fn set_address(
        &self,
        name: &str,
        address: IpAddr,
    ) -> impl Future<Output = Result<(), DnsError>> + Send;

    /// Removes `name`'s address records of the type that `ipv6` picks: A
    /// for IPv4, or AAAA for IPv6. Removing records that don't exist isn't
    /// an error.
    fn clear_address(
        &self,
        name: &str,
        ipv6: bool,
    ) -> impl Future<Output = Result<(), DnsError>> + Send;

    /// Extra time to wait after the provider's nameservers serve the record,
    /// before the certificate authority looks for it. Each nameserver runs in
    /// many places, and Accordion can only ask the copy nearest to it, while
    /// the authority asks from several places that may update later.
    fn propagation_delay(&self) -> Duration;
}

/// The DNS hosts Accordion supports, as the admin names them in settings.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProviderKind {
    Desec,
    Cloudflare,
}

impl ProviderKind {
    const ALL: [Self; 2] = [Self::Desec, Self::Cloudflare];

    /// The host of the provider's API, for the Network page.
    pub fn api_host(self) -> &'static str {
        match self {
            Self::Desec => "desec.io",
            Self::Cloudflare => "api.cloudflare.com",
        }
    }

    /// Where Accordion learns the home's public address when the router
    /// doesn't say, for the Network page.
    pub fn public_address_host(self) -> &'static str {
        match self {
            Self::Desec => desec::UPDATE_HOST,
            Self::Cloudflare => cloudflare::TRACE_HOST,
        }
    }

    fn id(self) -> &'static str {
        match self {
            Self::Desec => "desec",
            Self::Cloudflare => "cloudflare",
        }
    }
}

impl fmt::Display for ProviderKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Desec => "deSEC",
            Self::Cloudflare => "Cloudflare",
        })
    }
}

#[derive(Debug, thiserror::Error)]
#[error("Accordion doesn't support the DNS provider \"{0}\". Use desec or cloudflare.")]
pub struct UnknownProvider(String);

impl FromStr for ProviderKind {
    type Err = UnknownProvider;

    fn from_str(input: &str) -> Result<Self, UnknownProvider> {
        Self::ALL
            .into_iter()
            .find(|kind| kind.id().eq_ignore_ascii_case(input.trim()))
            .ok_or_else(|| UnknownProvider(input.to_owned()))
    }
}

/// Any supported provider, for when settings choose it at runtime.
#[derive(Clone, Debug)]
pub enum Provider {
    Desec(Desec),
    Cloudflare(Cloudflare),
}

impl Provider {
    pub fn new(kind: ProviderKind, token: impl Into<String>) -> Result<Self, BoxError> {
        Ok(match kind {
            ProviderKind::Desec => Self::Desec(Desec::new(token)?),
            ProviderKind::Cloudflare => Self::Cloudflare(Cloudflare::new(token)?),
        })
    }
}

impl Provider {
    /// Points `name`'s A record at the address the server reaches the
    /// internet from, for when the router doesn't say what it is. deSEC's
    /// update service sets it from where the update comes from, and says
    /// nothing back. For Cloudflare, its trace page says what the address
    /// is. Returns the address, if Accordion learned it.
    pub async fn set_public_address(&self, name: &str) -> Result<Option<IpAddr>, DnsError> {
        match self {
            Self::Desec(dns) => dns.set_address_from_source(name).await.map(|()| None),
            Self::Cloudflare(dns) => {
                let address = dns.public_address().await?;
                dns.set_address(name, address).await?;
                Ok(Some(address))
            }
        }
    }

    pub fn kind(&self) -> ProviderKind {
        match self {
            Self::Desec(_) => ProviderKind::Desec,
            Self::Cloudflare(_) => ProviderKind::Cloudflare,
        }
    }
}

impl DnsProvider for Provider {
    async fn set_txt(&self, record: &str, value: &str) -> Result<(), DnsError> {
        match self {
            Self::Desec(dns) => dns.set_txt(record, value).await,
            Self::Cloudflare(dns) => dns.set_txt(record, value).await,
        }
    }

    async fn clear_txt(&self, record: &str) -> Result<(), DnsError> {
        match self {
            Self::Desec(dns) => dns.clear_txt(record).await,
            Self::Cloudflare(dns) => dns.clear_txt(record).await,
        }
    }

    async fn set_address(&self, name: &str, address: IpAddr) -> Result<(), DnsError> {
        match self {
            Self::Desec(dns) => dns.set_address(name, address).await,
            Self::Cloudflare(dns) => dns.set_address(name, address).await,
        }
    }

    async fn clear_address(&self, name: &str, ipv6: bool) -> Result<(), DnsError> {
        match self {
            Self::Desec(dns) => dns.clear_address(name, ipv6).await,
            Self::Cloudflare(dns) => dns.clear_address(name, ipv6).await,
        }
    }

    fn propagation_delay(&self) -> Duration {
        match self {
            Self::Desec(dns) => dns.propagation_delay(),
            Self::Cloudflare(dns) => dns.propagation_delay(),
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_provider_names() {
        assert_eq!(
            "desec".parse::<ProviderKind>().unwrap(),
            ProviderKind::Desec
        );
        assert_eq!(
            " Cloudflare ".parse::<ProviderKind>().unwrap(),
            ProviderKind::Cloudflare
        );
        assert!("route53".parse::<ProviderKind>().is_err());
    }
}
