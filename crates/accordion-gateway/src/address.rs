//! Keeping the server's name pointed at the server.
//!
//! Clients find the server by looking up its name, so the name's address
//! record has to hold the server's address on the home network. Routers can
//! hand out a different address after a restart, so Accordion checks its
//! address every minute and updates the record when it changes. This is the
//! spec's dynamic DNS helper (decision 5 in the `accordion` repo's
//! `docs/decisions`).

use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr, UdpSocket};
use std::time::{Duration, SystemTime};

use tokio::sync::watch;
use tracing::{error, info, warn};

use crate::ServerName;
use crate::certificates::{CertificateError, Settings};
use crate::dns::{DnsProvider, Provider};
use crate::retry;

const CHECK_INTERVAL: Duration = Duration::from_secs(60);

/// After a failed update, the first retry waits this long, and each later one
/// waits twice as long as the one before, up to an hour.
const FIRST_RETRY_DELAY: Duration = Duration::from_secs(60);
const MAX_RETRY_DELAY: Duration = Duration::from_secs(60 * 60);

/// Where the server's address comes from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddressSource {
    /// The address the machine uses to reach the internet.
    Detect,
    /// Always this address, such as when the server runs in a container
    /// and can't see the machine's own address.
    Fixed(IpAddr),
}

impl AddressSource {
    fn address(self) -> io::Result<IpAddr> {
        match self {
            Self::Detect => detect_address().map(IpAddr::V4),
            Self::Fixed(address) => Ok(address),
        }
    }
}

/// The IPv4 address the machine uses to reach the internet, which on a home
/// network is its address on that network.
///
/// Connecting a UDP socket sends nothing. It only asks the system which
/// local address it would send from. 192.0.2.1 is reserved for
/// documentation (RFC 5737), so it's never a real host, but the system still
/// picks the route it would use for any internet address.
pub fn detect_address() -> io::Result<Ipv4Addr> {
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
    socket.connect((Ipv4Addr::new(192, 0, 2, 1), 9))?;
    match socket.local_addr()?.ip() {
        IpAddr::V4(address) if !address.is_unspecified() && !address.is_loopback() => Ok(address),
        _ => Err(io::Error::new(
            io::ErrorKind::NotFound,
            "the machine has no network address that reaches the internet",
        )),
    }
}

/// How the name's address record is doing, for the health page.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AddressStatus {
    /// The address the name points at, once Accordion has published it.
    pub published: Option<IpAddr>,
    /// Why Accordion can't find its own address, while it can't.
    pub not_found: Option<String>,
    /// How many updates in a row have failed. A success resets it.
    pub failures: u32,
    /// Why the last update failed, until one succeeds.
    pub last_error: Option<String>,
    /// When Accordion tries again after a failure.
    pub retry_at: Option<SystemTime>,
}

/// Keeps one name's address record up to date.
pub struct AddressPublisher<D> {
    name: ServerName,
    dns: D,
    source: AddressSource,
    status: watch::Sender<AddressStatus>,
}

impl AddressPublisher<Provider> {
    /// A publisher that uses the DNS provider in the saved settings.
    pub fn from_settings(
        settings: &Settings,
        source: AddressSource,
    ) -> Result<Self, CertificateError> {
        let dns = Provider::new(settings.provider, settings.token.clone())
            .map_err(CertificateError::Dns)?;
        Ok(Self::new(settings.name.clone(), dns, source))
    }
}

impl<D: DnsProvider> AddressPublisher<D> {
    pub fn new(name: ServerName, dns: D, source: AddressSource) -> Self {
        Self {
            name,
            dns,
            source,
            status: watch::Sender::default(),
        }
    }

    /// Follows the record's status as the publisher works.
    pub fn status(&self) -> watch::Receiver<AddressStatus> {
        self.status.subscribe()
    }

    /// Publishes the address at startup, then again whenever it changes,
    /// until `shutdown` completes.
    pub async fn run(self, shutdown: impl Future<Output = ()>) {
        let mut shutdown = std::pin::pin!(shutdown);
        let mut published = None;
        let mut failures = 0;
        // Warn once when the address can't be found, not every minute.
        let mut warned = false;
        loop {
            let wait = match self.source.address() {
                Err(err) => {
                    self.status
                        .send_modify(|status| status.not_found = Some(err.to_string()));
                    if !warned {
                        warn!(
                            name = %self.name,
                            "Accordion couldn't find its network address ({err}), so it can't \
                             update the name's DNS record. It'll keep checking."
                        );
                        warned = true;
                    }
                    CHECK_INTERVAL
                }
                Ok(address) if published == Some(address) => {
                    self.status.send_modify(|status| status.not_found = None);
                    CHECK_INTERVAL
                }
                Ok(address) => {
                    warned = false;
                    self.status.send_modify(|status| status.not_found = None);
                    let result = tokio::select! {
                        () = &mut shutdown => return,
                        result = self.dns.set_address(self.name.as_str(), address) => result,
                    };
                    match result {
                        Ok(()) => {
                            info!(name = %self.name, %address, "pointed the name at the server");
                            published = Some(address);
                            failures = 0;
                            self.status.send_replace(AddressStatus {
                                published,
                                ..AddressStatus::default()
                            });
                            CHECK_INTERVAL
                        }
                        Err(err) => {
                            failures += 1;
                            let delay = retry::delay(failures, FIRST_RETRY_DELAY, MAX_RETRY_DELAY);
                            error!(
                                name = %self.name,
                                "{err} Accordion will try again in {} minutes.",
                                delay.as_secs() / 60
                            );
                            self.status.send_modify(|status| {
                                status.failures = failures;
                                status.last_error = Some(err.to_string());
                                status.retry_at = Some(SystemTime::now() + delay);
                            });
                            delay
                        }
                    }
                }
            };
            tokio::select! {
                () = &mut shutdown => return,
                () = tokio::time::sleep(wait) => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use crate::dns::DnsError;

    use super::*;

    /// Records each address it's asked to publish, and fails the first time.
    #[derive(Clone, Default)]
    struct FlakyDns {
        published: Arc<Mutex<Vec<(String, IpAddr)>>>,
    }

    impl DnsProvider for FlakyDns {
        async fn set_txt(&self, _: &str, _: &str) -> Result<(), DnsError> {
            unreachable!()
        }

        async fn clear_txt(&self, _: &str) -> Result<(), DnsError> {
            unreachable!()
        }

        async fn set_address(&self, name: &str, address: IpAddr) -> Result<(), DnsError> {
            let mut published = self.published.lock().unwrap();
            published.push((name.to_owned(), address));
            if published.len() == 1 {
                return Err(DnsError::Rejected {
                    provider: "test",
                    status: 429,
                    detail: "Throttled.".into(),
                });
            }
            Ok(())
        }

        fn propagation_delay(&self) -> Duration {
            Duration::ZERO
        }
    }

    #[tokio::test(start_paused = true)]
    async fn retries_a_failure_then_publishes_only_changes() {
        let dns = FlakyDns::default();
        let address: IpAddr = "192.168.1.20".parse().unwrap();
        let publisher = AddressPublisher::new(
            "accordion.example.com".parse().unwrap(),
            dns.clone(),
            AddressSource::Fixed(address),
        );
        let mut status = publisher.status();
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let running = tokio::spawn(publisher.run(async {
            let _ = stopped.await;
        }));

        let failed = status
            .wait_for(|status| status.failures == 1)
            .await
            .unwrap()
            .clone();
        assert_eq!(failed.published, None);
        assert!(failed.last_error.unwrap().contains("Throttled."));

        // Time is paused, so these 10 minutes pass at once: a retry a
        // minute after the failure, then checks that find nothing new.
        tokio::time::sleep(Duration::from_secs(10 * 60)).await;
        assert_eq!(
            *status.borrow(),
            AddressStatus {
                published: Some(address),
                ..AddressStatus::default()
            }
        );
        stop.send(()).unwrap();
        running.await.unwrap();

        let name = "accordion.example.com".to_owned();
        assert_eq!(
            *dns.published.lock().unwrap(),
            [(name.clone(), address), (name, address)]
        );
    }
}
