//! Confirming that a challenge record is live before the certificate
//! authority looks for it.
//!
//! A DNS provider accepts a change before its nameservers serve it. If the
//! authority looks too early, the challenge fails and counts against its
//! limits, and its resolvers may remember the missing record for up to an
//! hour. So Accordion asks each of the zone's nameservers directly, with no
//! cache in between, until they all serve the new value.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use hickory_resolver::config::{NameServerConfig, ResolveHosts, ResolverConfig};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::proto::rr::{RData, RecordType};
use hickory_resolver::{Resolver, TokioResolver};
use tokio::time::Instant;

/// deSEC took about 3 minutes to serve a new record on both of its
/// nameservers in a test on October 19, 2026, so this leaves room for slower
/// days.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10 * 60);
const POLL_INTERVAL: Duration = Duration::from_secs(5);
const QUERY_TIMEOUT: Duration = Duration::from_secs(3);

/// How to confirm that a challenge record is live.
#[derive(Clone, Debug)]
pub struct PropagationCheck {
    nameservers: Nameservers,
    timeout: Duration,
}

#[derive(Clone, Debug)]
enum Nameservers {
    /// Look up the zone's nameservers with the system resolver.
    Lookup,
    Fixed(Vec<SocketAddr>),
    Skip,
}

#[derive(Debug, thiserror::Error)]
pub enum PropagationError {
    #[error(
        "Accordion couldn't find the nameservers for {record}. Check that the server can look \
         up names on the internet, then try again."
    )]
    NoNameservers { record: String },
    #[error(
        "The DNS record {record} didn't appear on all of its nameservers within {minutes} \
         minutes. These hadn't served it yet: {waiting}. Check the DNS provider's status, then \
         try again."
    )]
    NotPropagated {
        record: String,
        minutes: u64,
        waiting: String,
    },
    #[error(
        "Accordion couldn't reach these nameservers to check {record}: {waiting}. Check that the \
         server can make DNS queries to the internet (port 53), then try again."
    )]
    Unreachable { record: String, waiting: String },
}

/// What one nameserver said in the latest round.
#[derive(Clone, Copy, PartialEq)]
enum Answer {
    Serves,
    NotYet,
    Unreachable,
}

impl PropagationCheck {
    /// Looks up the zone's nameservers and waits up to 10 minutes.
    pub fn new() -> Self {
        Self {
            nameservers: Nameservers::Lookup,
            timeout: DEFAULT_TIMEOUT,
        }
    }

    /// Asks these nameservers instead, such as a test DNS server.
    pub fn with_nameservers(nameservers: Vec<SocketAddr>) -> Self {
        Self {
            nameservers: Nameservers::Fixed(nameservers),
            timeout: DEFAULT_TIMEOUT,
        }
    }

    /// Doesn't check at all. Only for tests that need the certificate
    /// authority's own error about a missing record.
    pub fn skip() -> Self {
        Self {
            nameservers: Nameservers::Skip,
            timeout: DEFAULT_TIMEOUT,
        }
    }

    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Waits until every nameserver serves `value` as a TXT record at
    /// `record`.
    pub async fn wait_for_txt(&self, record: &str, value: &str) -> Result<(), PropagationError> {
        let servers = match &self.nameservers {
            Nameservers::Skip => return Ok(()),
            Nameservers::Fixed(servers) => servers.clone(),
            Nameservers::Lookup => find_nameservers(record).await?,
        };
        let no_nameservers = || PropagationError::NoNameservers {
            record: record.to_owned(),
        };
        if servers.is_empty() {
            return Err(no_nameservers());
        }
        let mut waiting = Vec::new();
        for server in servers {
            let resolver = direct_resolver(server).map_err(|_| no_nameservers())?;
            waiting.push((server, resolver, Answer::NotYet));
        }

        // An absolute name, so the system's search domains never apply.
        let fqdn = format!("{}.", record.trim_end_matches('.'));
        let deadline = Instant::now() + self.timeout;
        loop {
            for (_, resolver, answer) in &mut waiting {
                *answer = ask(resolver, &fqdn, value).await;
            }
            waiting.retain(|(_, _, answer)| *answer != Answer::Serves);
            if waiting.is_empty() {
                return Ok(());
            }
            if Instant::now() + POLL_INTERVAL > deadline {
                let names = waiting
                    .iter()
                    .map(|(server, _, _)| server.ip().to_string())
                    .collect::<Vec<_>>()
                    .join(", ");
                let all_unreachable = waiting
                    .iter()
                    .all(|(_, _, answer)| *answer == Answer::Unreachable);
                return Err(if all_unreachable {
                    PropagationError::Unreachable {
                        record: record.to_owned(),
                        waiting: names,
                    }
                } else {
                    PropagationError::NotPropagated {
                        record: record.to_owned(),
                        minutes: self.timeout.as_secs().div_ceil(60),
                        waiting: names,
                    }
                });
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    }
}

impl Default for PropagationCheck {
    fn default() -> Self {
        Self::new()
    }
}

async fn ask(resolver: &TokioResolver, fqdn: &str, value: &str) -> Answer {
    match resolver.lookup(fqdn, RecordType::TXT).await {
        Ok(lookup) => {
            let serves = lookup.answers().iter().any(|record| match &record.data {
                RData::TXT(txt) => txt.txt_data.concat() == value.as_bytes(),
                _ => false,
            });
            if serves {
                Answer::Serves
            } else {
                Answer::NotYet
            }
        }
        // The nameserver answered, but not with the record yet.
        Err(err) if err.is_no_records_found() || err.is_nx_domain() => Answer::NotYet,
        Err(_) => Answer::Unreachable,
    }
}

/// Finds the zone that holds `record` by asking for NS records at each name
/// from `record` upward, then looks up those nameservers' addresses.
async fn find_nameservers(record: &str) -> Result<Vec<SocketAddr>, PropagationError> {
    let no_nameservers = || PropagationError::NoNameservers {
        record: record.to_owned(),
    };
    let system = TokioResolver::builder_tokio()
        .and_then(|builder| builder.build())
        .map_err(|_| no_nameservers())?;

    let mut name = record.trim_end_matches('.');
    loop {
        if let Ok(lookup) = system.lookup(format!("{name}."), RecordType::NS).await {
            let hosts: Vec<_> = lookup
                .answers()
                .iter()
                .filter_map(|record| match &record.data {
                    RData::NS(ns) => Some(ns.0.clone()),
                    _ => None,
                })
                .collect();
            if !hosts.is_empty() {
                let addresses = addresses(&system, &hosts, RecordType::A).await;
                // Fall back to IPv6 only when the nameservers have no IPv4
                // address, because many home connections lack IPv6.
                let addresses = if addresses.is_empty() {
                    self::addresses(&system, &hosts, RecordType::AAAA).await
                } else {
                    addresses
                };
                return if addresses.is_empty() {
                    Err(no_nameservers())
                } else {
                    Ok(addresses)
                };
            }
        }
        match name.split_once('.') {
            Some((_, parent)) if parent.contains('.') => name = parent,
            _ => return Err(no_nameservers()),
        }
    }
}

async fn addresses(
    system: &TokioResolver,
    hosts: &[hickory_resolver::proto::rr::Name],
    record_type: RecordType,
) -> Vec<SocketAddr> {
    let mut addresses = Vec::new();
    for host in hosts {
        let Ok(lookup) = system.lookup(host.clone(), record_type).await else {
            continue;
        };
        for record in lookup.answers() {
            let ip = match &record.data {
                RData::A(a) => IpAddr::V4(a.0),
                RData::AAAA(aaaa) => IpAddr::V6(aaaa.0),
                _ => continue,
            };
            let address = SocketAddr::new(ip, 53);
            if !addresses.contains(&address) {
                addresses.push(address);
            }
        }
    }
    addresses
}

/// A resolver that asks only `server`, without caching, and without asking
/// it to recurse, so the answer comes from the server's own copy of the zone.
fn direct_resolver(server: SocketAddr) -> Result<TokioResolver, hickory_resolver::net::NetError> {
    let mut nameserver = NameServerConfig::udp_and_tcp(server.ip());
    for connection in &mut nameserver.connections {
        connection.port = server.port();
    }
    let mut builder = Resolver::builder_with_config(
        ResolverConfig::from_name_servers(vec![nameserver]),
        TokioRuntimeProvider::default(),
    );
    let options = builder.options_mut();
    options.cache_size = 0;
    options.recursion_desired = false;
    options.attempts = 1;
    options.timeout = QUERY_TIMEOUT;
    options.use_hosts_file = ResolveHosts::Never;
    builder.build()
}
