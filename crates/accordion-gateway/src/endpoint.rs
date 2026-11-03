//! The name devices find home at, away from home (decision 21).
//!
//! The server's name points at its address on the home network, which
//! devices reach through the tunnel. To reach the tunnel itself, they need
//! the home's public address. That goes in a second address record, under
//! a random label of the server's name, such as
//! `k3x9q2wm7f.ourhome.dedyn.io`. Certificate logs list the server's name,
//! and the random label keeps the home's address from being found through
//! them.
//!
//! The router says what the public address is when it forwards the port.
//! Otherwise, the DNS provider's own service sets or finds it. If the
//! machine has a public IPv6 address, the record gets that too.

use std::future::Future;
use std::net::{IpAddr, Ipv6Addr, UdpSocket};
use std::time::{Duration, SystemTime};

use tokio::sync::watch;
use tracing::{info, warn};

use crate::dns::{DnsError, DnsProvider, Provider};
use crate::port_mapping::is_shared;

/// How often Accordion checks that the record still has the home's address.
/// Home addresses change rarely, often only when the router restarts.
const CHECK_INTERVAL: Duration = Duration::from_secs(10 * 60);

/// What the publisher needs to know.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EndpointInput {
    /// The record, such as `k3x9q2wm7f.ourhome.dedyn.io`.
    pub name: String,
    /// The public address the router reported, if it forwards the port.
    pub router_address: Option<IpAddr>,
}

/// How the record is doing, for the remote access and Network pages.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EndpointStatus {
    /// The record, while remote access is on.
    pub name: Option<String>,
    /// The IPv4 address in the record, when Accordion knows it.
    pub ipv4: Option<IpAddr>,
    /// deSEC set the IPv4 address from where its update came from, so
    /// Accordion doesn't know what it is.
    pub ipv4_set_by_provider: bool,
    /// The router's address is shared with other homes, so there's no IPv4
    /// address worth publishing.
    pub ipv4_shared: bool,
    pub ipv6: Option<Ipv6Addr>,
    /// Why the last update failed, until one works.
    pub problem: Option<String>,
    /// When Accordion last asked the DNS provider, or looked up the
    /// address, since it started.
    pub last_attempt: Option<SystemTime>,
}

/// The DNS provider's part: setting records, and the public address when
/// the router doesn't say.
pub trait EndpointDns: DnsProvider {
    fn set_public_address(
        &self,
        name: &str,
    ) -> impl Future<Output = Result<Option<IpAddr>, DnsError>> + Send;
}

impl EndpointDns for Provider {
    async fn set_public_address(&self, name: &str) -> Result<Option<IpAddr>, DnsError> {
        Provider::set_public_address(self, name).await
    }
}

/// Keeps the record current while there's an input.
pub struct EndpointPublisher<D> {
    dns: D,
    input: watch::Receiver<Option<EndpointInput>>,
    ipv6: fn() -> Option<Ipv6Addr>,
    status: watch::Sender<EndpointStatus>,
}

impl<D: EndpointDns> EndpointPublisher<D> {
    pub fn new(dns: D, input: watch::Receiver<Option<EndpointInput>>) -> Self {
        Self {
            dns,
            input,
            ipv6: public_ipv6,
            status: watch::Sender::default(),
        }
    }

    pub fn status(&self) -> watch::Receiver<EndpointStatus> {
        self.status.subscribe()
    }

    /// Publishes the addresses, then checks them every few minutes and
    /// whenever the input changes, until `shutdown` completes. With no
    /// input, it removes the record.
    pub async fn run(mut self, shutdown: impl Future<Output = ()>) {
        let mut shutdown = std::pin::pin!(shutdown);
        // What's in the record, as far as Accordion knows, so unchanged
        // addresses don't call the provider again.
        let mut published: Option<(String, Option<IpAddr>, Option<Ipv6Addr>)> = None;
        loop {
            let input = self.input.borrow_and_update().clone();
            let update = async {
                match &input {
                    None => {
                        if let Some((name, ..)) = &published {
                            self.clear(name).await?;
                        }
                        Ok(None)
                    }
                    Some(input) => self.publish(input, published.as_ref()).await.map(Some),
                }
            };
            let result = tokio::select! {
                () = &mut shutdown => return,
                result = update => result,
            };
            let now = SystemTime::now();
            match result {
                Ok(None) => {
                    if published.take().is_some() {
                        info!("removed the remote access address record");
                    }
                    self.status.send_replace(EndpointStatus::default());
                }
                Ok(Some(status)) => {
                    let name = status.name.clone().unwrap_or_default();
                    published = Some((name, status.ipv4, status.ipv6));
                    self.status.send_replace(EndpointStatus {
                        last_attempt: Some(now),
                        ..status
                    });
                }
                Err(err) => {
                    warn!("Accordion couldn't update the remote access address record: {err}");
                    self.status.send_modify(|status| {
                        status.name = input.as_ref().map(|input| input.name.clone());
                        status.problem = Some(err.to_string());
                        status.last_attempt = Some(now);
                    });
                }
            }
            let on = self.input.borrow().is_some();
            let wait = async {
                if on {
                    tokio::time::sleep(CHECK_INTERVAL).await;
                } else {
                    std::future::pending::<()>().await;
                }
            };
            tokio::select! {
                () = &mut shutdown => return,
                () = wait => {}
                changed = self.input.changed() => {
                    if changed.is_err() {
                        return;
                    }
                }
            }
        }
    }

    async fn publish(
        &self,
        input: &EndpointInput,
        published: Option<&(String, Option<IpAddr>, Option<Ipv6Addr>)>,
    ) -> Result<EndpointStatus, DnsError> {
        let name = &input.name;
        let (old_v4, old_v6) = match published {
            Some((old_name, v4, v6)) if old_name == name => (*v4, *v6),
            Some((old_name, ..)) => {
                self.clear(old_name).await?;
                (None, None)
            }
            None => (None, None),
        };
        let mut status = EndpointStatus {
            name: Some(name.clone()),
            ..EndpointStatus::default()
        };
        match input.router_address {
            Some(address) if is_shared(address) => {
                // Devices can't reach that address, so leave it out.
                status.ipv4_shared = true;
                self.dns.clear_address(name, false).await?;
            }
            Some(address) => {
                if old_v4 != Some(address) {
                    self.dns.set_address(name, address).await?;
                }
                status.ipv4 = Some(address);
            }
            None => {
                status.ipv4 = self.dns.set_public_address(name).await?;
                status.ipv4_set_by_provider = status.ipv4.is_none();
            }
        }
        match (self.ipv6)() {
            Some(address) => {
                if old_v6 != Some(address) {
                    self.dns.set_address(name, IpAddr::V6(address)).await?;
                }
                status.ipv6 = Some(address);
            }
            None if old_v6.is_some() || published.is_none() => {
                self.dns.clear_address(name, true).await?;
            }
            None => {}
        }
        Ok(status)
    }

    async fn clear(&self, name: &str) -> Result<(), DnsError> {
        self.dns.clear_address(name, false).await?;
        self.dns.clear_address(name, true).await
    }
}

/// The machine's public IPv6 address, if it has one. Like
/// [`crate::address::detect_address`], connecting a UDP socket sends
/// nothing: it only asks which address the machine would send from.
pub fn public_ipv6() -> Option<Ipv6Addr> {
    let socket = UdpSocket::bind((Ipv6Addr::UNSPECIFIED, 0)).ok()?;
    // 2001:db8::/32 is for documentation, so it's never a real host.
    socket.connect(("2001:db8::1", 9)).ok()?;
    match socket.local_addr().ok()?.ip() {
        // Global unicast addresses are in 2000::/3.
        IpAddr::V6(address) if address.segments()[0] & 0xe000 == 0x2000 => Some(address),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;

    /// Records each change, and answers the public address lookup with
    /// `lookup`.
    #[derive(Clone, Default)]
    struct FakeDns {
        changes: Arc<Mutex<Vec<String>>>,
        lookup: Option<IpAddr>,
    }

    impl DnsProvider for FakeDns {
        async fn set_txt(&self, _: &str, _: &str) -> Result<(), DnsError> {
            unreachable!()
        }

        async fn clear_txt(&self, _: &str) -> Result<(), DnsError> {
            unreachable!()
        }

        async fn set_address(&self, name: &str, address: IpAddr) -> Result<(), DnsError> {
            self.changes
                .lock()
                .unwrap()
                .push(format!("set {name} {address}"));
            Ok(())
        }

        async fn clear_address(&self, name: &str, ipv6: bool) -> Result<(), DnsError> {
            let kind = if ipv6 { "AAAA" } else { "A" };
            self.changes
                .lock()
                .unwrap()
                .push(format!("clear {name} {kind}"));
            Ok(())
        }

        fn propagation_delay(&self) -> Duration {
            Duration::ZERO
        }
    }

    impl EndpointDns for FakeDns {
        async fn set_public_address(&self, name: &str) -> Result<Option<IpAddr>, DnsError> {
            self.changes
                .lock()
                .unwrap()
                .push(format!("set {name} from where the update came from"));
            Ok(self.lookup)
        }
    }

    const NAME: &str = "k3x9q2wm7f.ourhome.example.com";

    async fn run(
        dns: FakeDns,
        router_address: Option<&str>,
        ipv6: fn() -> Option<Ipv6Addr>,
    ) -> (
        watch::Sender<Option<EndpointInput>>,
        watch::Receiver<EndpointStatus>,
    ) {
        let (input, receiver) = watch::channel(Some(EndpointInput {
            name: NAME.into(),
            router_address: router_address.map(|address| address.parse().unwrap()),
        }));
        let mut publisher = EndpointPublisher::new(dns, receiver);
        publisher.ipv6 = ipv6;
        let mut status = publisher.status();
        tokio::spawn(publisher.run(std::future::pending()));
        status
            .wait_for(|status| status.last_attempt.is_some())
            .await
            .unwrap();
        (input, status)
    }

    #[tokio::test]
    async fn publishes_the_routers_address_and_removes_it() {
        let dns = FakeDns::default();
        let (input, mut status) = run(dns.clone(), Some("203.0.113.7"), || {
            Some("2001:db8:5::20".parse().unwrap())
        })
        .await;
        assert_eq!(status.borrow().ipv4, Some("203.0.113.7".parse().unwrap()));
        input.send_replace(None);
        status
            .wait_for(|status| status.name.is_none())
            .await
            .unwrap();
        assert_eq!(
            *dns.changes.lock().unwrap(),
            [
                format!("set {NAME} 203.0.113.7"),
                format!("set {NAME} 2001:db8:5::20"),
                format!("clear {NAME} A"),
                format!("clear {NAME} AAAA"),
            ]
        );
    }

    #[tokio::test]
    async fn asks_the_provider_when_the_router_doesnt_say() {
        let dns = FakeDns::default();
        let (_input, status) = run(dns.clone(), None, || None).await;
        assert!(status.borrow().ipv4_set_by_provider);
        assert_eq!(
            *dns.changes.lock().unwrap(),
            [
                format!("set {NAME} from where the update came from"),
                format!("clear {NAME} AAAA"),
            ]
        );
    }

    #[tokio::test]
    async fn leaves_out_a_shared_address() {
        let dns = FakeDns::default();
        let (_input, status) = run(dns.clone(), Some("100.72.9.14"), || None).await;
        assert!(status.borrow().ipv4_shared);
        assert_eq!(status.borrow().ipv4, None);
        assert_eq!(
            *dns.changes.lock().unwrap(),
            [format!("clear {NAME} A"), format!("clear {NAME} AAAA")]
        );
    }
}
