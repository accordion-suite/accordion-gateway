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

/// The machine's IPv4 addresses on the networks it's part of, with the
/// address from [`detect_address`] first. A server can be on more than one,
/// such as a Raspberry Pi that's also a Wi-Fi access point, and the setup
/// wizard is reachable on each. Only private addresses are added after the
/// first, because the wizard only answers devices on private networks.
pub fn network_addresses() -> Vec<Ipv4Addr> {
    let interfaces = if_addrs::get_if_addrs().unwrap_or_default();
    pick_network_addresses(
        detect_address().ok(),
        interfaces
            .iter()
            .filter_map(|interface| match &interface.addr {
                if_addrs::IfAddr::V4(addr) if interface.is_oper_up() => {
                    Some((interface.name.as_str(), addr.ip))
                }
                _ => None,
            }),
    )
}

/// Interface names that other devices can't reach: loopback, which WSL also
/// gives a private address, and the networks that containers and virtual
/// machines use.
const SKIPPED_INTERFACES: &[&str] = &[
    "lo", "docker", "br-", "veth", "virbr", "vmnet", "vboxnet", "cni", "flannel", "podman", "lxc",
];

fn pick_network_addresses<'a>(
    main: Option<Ipv4Addr>,
    interfaces: impl Iterator<Item = (&'a str, Ipv4Addr)>,
) -> Vec<Ipv4Addr> {
    let mut addresses: Vec<Ipv4Addr> = main.into_iter().collect();
    for (name, address) in interfaces {
        let skipped = SKIPPED_INTERFACES
            .iter()
            .any(|prefix| name.starts_with(prefix));
        if !skipped && address.is_private() && !addresses.contains(&address) {
            addresses.push(address);
        }
    }
    addresses
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
    /// When Accordion last asked the DNS provider to update the record,
    /// since it started. `failures` says whether that worked.
    pub last_attempt: Option<SystemTime>,
    /// The admin turned updates off, so Accordion leaves the record alone.
    pub turned_off: bool,
}

/// Keeps one name's address record up to date.
pub struct AddressPublisher<D> {
    name: ServerName,
    dns: D,
    source: AddressSource,
    on: Option<watch::Receiver<bool>>,
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
            on: None,
            status: watch::Sender::default(),
        }
    }

    /// Updates the record only while `on` holds `true`. Turning it back on
    /// publishes the address again right away.
    #[must_use]
    pub fn with_switch(mut self, on: watch::Receiver<bool>) -> Self {
        self.on = Some(on);
        self
    }

    /// Follows the record's status as the publisher works.
    pub fn status(&self) -> watch::Receiver<AddressStatus> {
        self.status.subscribe()
    }

    /// Publishes the address at startup, then again whenever it changes,
    /// until `shutdown` completes.
    pub async fn run(self, shutdown: impl Future<Output = ()>) {
        let mut shutdown = std::pin::pin!(shutdown);
        let mut on = self.on.clone();
        let mut published = None;
        let mut failures = 0;
        // Warn once when the address can't be found, not every minute.
        let mut warned = false;
        loop {
            if let Some(switch) = &mut on
                && !*switch.borrow_and_update()
            {
                // Start fresh when it's turned back on, in case the address
                // or the record changed in the meantime.
                published = None;
                failures = 0;
                warned = false;
                self.status.send_modify(|status| {
                    *status = AddressStatus {
                        turned_off: true,
                        last_attempt: status.last_attempt,
                        ..AddressStatus::default()
                    };
                });
                info!(name = %self.name, "address updates are turned off");
                tokio::select! {
                    () = &mut shutdown => return,
                    () = switched(&mut on) => continue,
                }
            }
            self.status
                .send_if_modified(|status| std::mem::replace(&mut status.turned_off, false));
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
                                last_attempt: Some(SystemTime::now()),
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
                                status.last_attempt = Some(SystemTime::now());
                            });
                            delay
                        }
                    }
                }
            };
            tokio::select! {
                () = &mut shutdown => return,
                () = tokio::time::sleep(wait) => {}
                () = switched(&mut on) => {}
            }
        }
    }
}

/// Waits for the switch to change. Without a switch, or once its sender is
/// gone, it never changes.
async fn switched(on: &mut Option<watch::Receiver<bool>>) {
    let Some(switch) = on else {
        return std::future::pending().await;
    };
    if switch.changed().await.is_err() {
        *on = None;
        std::future::pending::<()>().await;
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use crate::dns::DnsError;

    use super::*;

    #[test]
    fn lists_the_main_address_first_and_leaves_out_unreachable_ones() {
        let address = |text: &str| text.parse::<Ipv4Addr>().unwrap();
        let interfaces = [
            ("lo", address("127.0.0.1")),
            ("lo", address("10.255.255.254")),
            ("wlan0", address("10.42.0.1")),
            ("end0", address("192.168.1.57")),
            ("docker0", address("172.17.0.1")),
            ("br-5f2a", address("10.21.0.1")),
            ("tailscale0", address("100.64.0.7")),
        ];
        assert_eq!(
            pick_network_addresses(Some(address("192.168.1.57")), interfaces.into_iter()),
            [address("192.168.1.57"), address("10.42.0.1")]
        );
        assert!(
            pick_network_addresses(None, [("lo", address("127.0.0.1"))].into_iter()).is_empty()
        );
    }

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
        let now = status.borrow().clone();
        assert!(now.last_attempt.is_some());
        assert_eq!(
            now,
            AddressStatus {
                published: Some(address),
                last_attempt: now.last_attempt,
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

    #[tokio::test(start_paused = true)]
    async fn leaves_the_record_alone_while_turned_off() {
        let dns = FlakyDns::default();
        // FlakyDns fails its first update. Count one already, so the update
        // after turning it on works.
        dns.published
            .lock()
            .unwrap()
            .push(("earlier".into(), "192.168.1.1".parse().unwrap()));
        let address: IpAddr = "192.168.1.20".parse().unwrap();
        let (switch, on) = watch::channel(false);
        let publisher = AddressPublisher::new(
            "accordion.example.com".parse().unwrap(),
            dns.clone(),
            AddressSource::Fixed(address),
        )
        .with_switch(on);
        let mut status = publisher.status();
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let running = tokio::spawn(publisher.run(async {
            let _ = stopped.await;
        }));

        status.wait_for(|status| status.turned_off).await.unwrap();
        tokio::time::sleep(Duration::from_secs(10 * 60)).await;
        assert_eq!(dns.published.lock().unwrap().len(), 1);

        switch.send(true).unwrap();
        let published = status
            .wait_for(|status| status.published.is_some())
            .await
            .unwrap()
            .clone();
        assert!(!published.turned_off);
        assert_eq!(published.published, Some(address));

        switch.send(false).unwrap();
        let off = status
            .wait_for(|status| status.turned_off)
            .await
            .unwrap()
            .clone();
        assert_eq!(off.published, None);
        assert_eq!(off.last_attempt, published.last_attempt);
        tokio::time::sleep(Duration::from_secs(10 * 60)).await;
        assert_eq!(dns.published.lock().unwrap().len(), 2);

        stop.send(()).unwrap();
        running.await.unwrap();
    }
}
