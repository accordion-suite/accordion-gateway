//! Asking the home router to forward remote access's UDP port (decision 21).
//!
//! Most home routers accept requests from the home network to forward a
//! port: through the Port Control Protocol (PCP), its older form NAT-PMP,
//! or UPnP. Accordion tries them in that order, renews the mapping before
//! it expires, and removes it when remote access is turned off. Routers
//! keep a mapping only while it's renewed, so a server that's unplugged
//! doesn't leave the port open for long.
//!
//! The answer also says what the home's public address is. An address in
//! 100.64.0.0/10, or a private one, means the internet provider shares one
//! address among many homes (carrier-grade NAT), or there's a second router
//! in the way, and devices can't reach home through it.

mod pcp;
mod upnp;

use std::fmt;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, SystemTime};

use tokio::sync::watch;
use tracing::{info, warn};

use pcp::Answer;

/// How long each mapping lasts before it's renewed. An hour, so an
/// unplugged server's port closes within the hour, and renewing at half
/// that is a handful of small packets an hour.
const LIFETIME: Duration = Duration::from_secs(60 * 60);

/// After no router agreed, Accordion asks again this often, since routers
/// restart and admins change their settings.
const RETRY: Duration = Duration::from_secs(10 * 60);

/// Where the router answers each protocol. Tests point these at stand-ins.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Router {
    /// PCP and NAT-PMP: UDP port 5351 on the router.
    pub pcp: SocketAddr,
    /// UPnP's search: its multicast address on a real network.
    pub ssdp: SocketAddr,
}

impl Router {
    /// The router for the machine's default route, from Linux's routing
    /// table.
    pub fn find() -> Option<Self> {
        let routes = std::fs::read_to_string("/proc/net/route").ok()?;
        let address = default_gateway(&routes)?;
        Some(Self {
            pcp: SocketAddr::from((address, 5351)),
            ssdp: SocketAddr::from((Ipv4Addr::new(239, 255, 255, 250), 1900)),
        })
    }
}

/// The gateway of the default route in `/proc/net/route`, whose addresses
/// are hexadecimal in the machine's byte order.
fn default_gateway(routes: &str) -> Option<Ipv4Addr> {
    routes.lines().skip(1).find_map(|line| {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let (destination, gateway) = (*fields.get(1)?, *fields.get(2)?);
        if destination != "00000000" {
            return None;
        }
        let gateway = u32::from_str_radix(gateway, 16).ok()?;
        (gateway != 0).then(|| Ipv4Addr::from(gateway.to_ne_bytes()))
    })
}

/// How a router agreed to forward the port.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    Pcp,
    NatPmp,
    Upnp,
}

impl fmt::Display for Method {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Pcp => "PCP",
            Self::NatPmp => "NAT-PMP",
            Self::Upnp => "UPnP",
        })
    }
}

/// A port the router forwards.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Mapping {
    pub method: Method,
    /// The home's public address, as the router sees it.
    pub external_address: Option<IpAddr>,
    /// The port devices reach home on, which some routers pick themselves.
    pub external_port: u16,
    pub lifetime: Duration,
}

/// Why a router said no.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Refused {
    /// The router has port forwarding requests turned off.
    NotAllowed,
    /// The router has no room for another mapping.
    NoRoom,
    /// Another device on the network already has the port.
    PortTaken,
    Other(String),
}

impl fmt::Display for Refused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotAllowed => f.write_str("the router has port forwarding requests turned off"),
            Self::NoRoom => f.write_str("the router has no room for another forwarded port"),
            Self::PortTaken => f.write_str("another device already uses that port on the router"),
            Self::Other(detail) => f.write_str(detail),
        }
    }
}

/// Whether `address` can't be reached from the internet: the provider's
/// shared range, 100.64.0.0/10, or a private range behind another router.
pub fn is_shared(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            let [a, b, ..] = address.octets();
            (a == 100 && (64..128).contains(&b)) || address.is_private() || address.is_link_local()
        }
        IpAddr::V6(_) => false,
    }
}

/// How the port mapping is doing, for the remote access and health pages.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct PortStatus {
    /// The port Accordion wants forwarded, while remote access is on.
    pub port: Option<u16>,
    /// What the router agreed to.
    pub mapping: Option<Mapping>,
    /// Why no router agreed, after asking.
    pub problem: Option<String>,
    /// No router answered any of the protocols at all.
    pub no_answer: bool,
    /// The router's public address is shared or private, so devices can't
    /// reach home through it.
    pub shared_address: bool,
    /// When Accordion last asked the router, since it started.
    pub last_attempt: Option<SystemTime>,
}

/// Keeps one UDP port forwarded while `port` holds one.
pub struct PortMapper {
    router: Option<Router>,
    port: watch::Receiver<Option<u16>>,
    status: watch::Sender<PortStatus>,
    nonce: [u8; 12],
}

impl PortMapper {
    pub fn new(router: Option<Router>, port: watch::Receiver<Option<u16>>) -> Self {
        use ring::rand::{SecureRandom, SystemRandom};
        let mut nonce = [0; 12];
        SystemRandom::new()
            .fill(&mut nonce)
            .expect("the operating system's random number generator works");
        Self {
            router,
            port,
            status: watch::Sender::default(),
            nonce,
        }
    }

    pub fn status(&self) -> watch::Receiver<PortStatus> {
        self.status.subscribe()
    }

    /// Asks for the port, renews it, and removes it when the port changes
    /// or remote access is turned off, until `shutdown` completes. The
    /// mapping stays at shutdown, so a restart doesn't close the port, and
    /// it ends on its own if the server doesn't come back.
    pub async fn run(mut self, shutdown: impl Future<Output = ()>) {
        let mut shutdown = std::pin::pin!(shutdown);
        let mut mapped: Option<(u16, Mapping, Option<upnp::Gateway>)> = None;
        loop {
            let wanted = *self.port.borrow_and_update();
            if let Some((port, mapping, gateway)) =
                mapped.take_if(|(port, ..)| Some(*port) != wanted)
            {
                self.unmap(port, mapping.method, gateway.as_ref()).await;
                info!(port, "removed the router's port mapping");
            }
            let wait = match wanted {
                None => {
                    self.status.send_replace(PortStatus::default());
                    None
                }
                Some(port) => {
                    self.status.send_modify(|status| status.port = Some(port));
                    let attempt = self.map(port).await;
                    let now = SystemTime::now();
                    match attempt {
                        Ok((mapping, gateway)) => {
                            let shared = mapping.external_address.is_some_and(is_shared);
                            if mapped.is_none() {
                                info!(
                                    port,
                                    external_port = mapping.external_port,
                                    method = %mapping.method,
                                    "the router forwards remote access's port"
                                );
                            }
                            if shared {
                                warn!(
                                    "The router's public address is shared or private, so \
                                     devices away from home can't reach it."
                                );
                            }
                            self.status.send_replace(PortStatus {
                                port: Some(port),
                                mapping: Some(mapping),
                                shared_address: shared,
                                last_attempt: Some(now),
                                ..PortStatus::default()
                            });
                            mapped = Some((port, mapping, gateway));
                            Some((mapping.lifetime / 2).clamp(Duration::from_secs(60), LIFETIME))
                        }
                        Err((problem, no_answer)) => {
                            if self.status.borrow().problem.as_ref() != Some(&problem) {
                                warn!(
                                    "Accordion couldn't get the router to forward UDP port {port}: {problem}"
                                );
                            }
                            self.status.send_replace(PortStatus {
                                port: Some(port),
                                problem: Some(problem),
                                no_answer,
                                last_attempt: Some(now),
                                ..PortStatus::default()
                            });
                            Some(RETRY)
                        }
                    }
                }
            };
            let wait = async {
                match wait {
                    Some(wait) => tokio::time::sleep(wait).await,
                    None => std::future::pending().await,
                }
            };
            tokio::select! {
                () = &mut shutdown => return,
                () = wait => {}
                changed = self.port.changed() => {
                    if changed.is_err() {
                        return;
                    }
                }
            }
        }
    }

    /// Asks each protocol in turn. On failure, returns why, and whether no
    /// router answered at all.
    async fn map(&self, port: u16) -> Result<(Mapping, Option<upnp::Gateway>), (String, bool)> {
        let Some(router) = self.router else {
            return Err((
                "Accordion couldn't find the router: the machine has no default route.".into(),
                true,
            ));
        };
        let lifetime = u32::try_from(LIFETIME.as_secs()).unwrap_or(u32::MAX);
        let mut refusals = Vec::new();
        match pcp::map_pcp(router.pcp, port, lifetime, self.nonce).await {
            Some(Answer::Mapped(mapping)) => return Ok((mapping, None)),
            Some(Answer::Refused(refused)) => refusals.push(format!("PCP: {refused}")),
            Some(Answer::WrongVersion) => {
                match pcp::map_nat_pmp(router.pcp, port, lifetime).await {
                    Some(Answer::Mapped(mapping)) => return Ok((mapping, None)),
                    Some(Answer::Refused(refused)) => refusals.push(format!("NAT-PMP: {refused}")),
                    Some(Answer::WrongVersion) | None => {}
                }
            }
            None => {}
        }
        if let Some(gateway) = upnp::find(router.ssdp).await {
            match upnp::map(&gateway, port, LIFETIME).await {
                Ok(mapping) => return Ok((mapping, Some(gateway))),
                Err(refused) => refusals.push(format!("UPnP: {refused}")),
            }
        }
        if refusals.is_empty() {
            Err((
                "The router didn't answer requests to forward a port (PCP, NAT-PMP, or UPnP). \
                 It may have them turned off."
                    .into(),
                true,
            ))
        } else {
            Err((
                format!("The router said no. {}.", refusals.join("; ")),
                false,
            ))
        }
    }

    async fn unmap(&self, port: u16, method: Method, gateway: Option<&upnp::Gateway>) {
        let Some(router) = self.router else { return };
        match method {
            Method::Pcp => {
                pcp::map_pcp(router.pcp, port, 0, self.nonce).await;
            }
            Method::NatPmp => {
                pcp::map_nat_pmp(router.pcp, port, 0).await;
            }
            Method::Upnp => {
                if let Some(gateway) = gateway {
                    upnp::unmap(gateway, port).await;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests;
