//! Remote access: a WireGuard server inside Accordion (decision 21).
//!
//! WireGuard runs here, in user space, on one UDP port. The packets it opens
//! go to the tunnel's own TCP/IP stack ([`stack`]), which hands connections
//! for the gateway's ports to the gateway's servers and drops everything
//! else. Nothing on the machine changes: there's no network interface, no
//! route, and no firewall rule, and the server needs no privileges.
//!
//! Each device gets its own key pair and one address in the tunnel's /24.
//! Its tunnel carries only the server's home address and its tunnel
//! address, so the server's name means the same address at home and away.

#[cfg(test)]
mod end_to_end;
mod stack;

use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::net::Ipv4Addr;
use std::time::{Duration, SystemTime};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use gotatun::device::{self, Device, Peer as WgPeer};
use gotatun::udp::socket::UdpSocketFactory;
use gotatun::x25519;
use ipnetwork::{IpNetwork, Ipv4Network};
use tokio::sync::watch;
use tracing::{info, warn};

pub use stack::{Accepted, Addresses, Listeners, MTU, TunnelStream};

/// The UDP port the tunnel listens on, unless the admin picks another.
pub const DEFAULT_PORT: u16 = 51820;

/// How often devices send a packet while they're connected, in seconds, so
/// the networks they're on keep their way back open. 25 is what the
/// WireGuard apps suggest.
const KEEPALIVE: u16 = 25;

/// How often the status learns when devices last connected.
const HANDSHAKE_CHECK: Duration = Duration::from_secs(30);

/// A WireGuard private key: the server's, or a device's while its setup is
/// made.
#[derive(Clone)]
pub struct Key(x25519::StaticSecret);

/// A WireGuard public key, which names a device.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PublicKey(x25519::PublicKey);

#[derive(Debug, thiserror::Error)]
#[error("That isn't a WireGuard key. Keys are 44 characters of base64.")]
pub struct BadKey;

impl Key {
    /// A new random key.
    pub fn generate() -> Self {
        use ring::rand::{SecureRandom, SystemRandom};
        let mut bytes = [0; 32];
        SystemRandom::new()
            .fill(&mut bytes)
            .expect("the operating system's random number generator works");
        Self(x25519::StaticSecret::from(bytes))
    }

    pub fn public(&self) -> PublicKey {
        PublicKey(x25519::PublicKey::from(&self.0))
    }

    /// The key as WireGuard writes it, in base64.
    pub fn to_base64(&self) -> String {
        BASE64.encode(self.0.to_bytes())
    }

    pub fn from_base64(text: &str) -> Result<Self, BadKey> {
        Ok(Self(x25519::StaticSecret::from(decode(text)?)))
    }
}

impl fmt::Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Key(..)")
    }
}

impl PartialEq for Key {
    fn eq(&self, other: &Self) -> bool {
        self.public() == other.public()
    }
}

impl PublicKey {
    pub fn to_base64(&self) -> String {
        BASE64.encode(self.0.as_bytes())
    }

    pub fn from_base64(text: &str) -> Result<Self, BadKey> {
        Ok(Self(x25519::PublicKey::from(decode(text)?)))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(x25519::PublicKey::from(bytes))
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey({})", self.to_base64())
    }
}

fn decode(text: &str) -> Result<[u8; 32], BadKey> {
    BASE64
        .decode(text.trim())
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(BadKey)
}

/// The tunnel's /24 in 10.0.0.0/8. The server is `.1`, and devices get
/// `.2` to `.254`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Network(Ipv4Addr);

impl Network {
    /// The first address of each device's /24.
    pub const FIRST_DEVICE: u8 = 2;
    pub const LAST_DEVICE: u8 = 254;

    /// A random /24, so it's unlikely to match a network a device joins.
    /// It skips 10.0.0.0/16 and 10.1.1.0/24, which home routers use most.
    pub fn random() -> Self {
        use ring::rand::{SecureRandom, SystemRandom};
        loop {
            let mut bytes = [0; 2];
            SystemRandom::new()
                .fill(&mut bytes)
                .expect("the operating system's random number generator works");
            if bytes[0] != 0 && bytes != [1, 1] && bytes[0] != 255 {
                return Self(Ipv4Addr::new(10, bytes[0], bytes[1], 0));
            }
        }
    }

    /// The /24 that `address` is in, if it's in 10.0.0.0/8.
    pub fn containing(address: Ipv4Addr) -> Option<Self> {
        let [a, b, c, _] = address.octets();
        (a == 10).then(|| Self(Ipv4Addr::new(a, b, c, 0)))
    }

    pub fn server(self) -> Ipv4Addr {
        self.host(1)
    }

    pub fn host(self, number: u8) -> Ipv4Addr {
        let [a, b, c, _] = self.0.octets();
        Ipv4Addr::new(a, b, c, number)
    }
}

impl fmt::Display for Network {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/24", self.0)
    }
}

/// What the tunnel needs to run.
#[derive(Clone, Debug, PartialEq)]
pub struct TunnelConfig {
    pub key: Key,
    /// The UDP port WireGuard listens on.
    pub port: u16,
    pub network: Network,
    /// The server's address on the home network, which its name points at.
    pub home: Ipv4Addr,
}

/// A device that may connect.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DevicePeer {
    pub public_key: PublicKey,
    /// Its address in the tunnel's /24.
    pub address: Ipv4Addr,
}

impl DevicePeer {
    fn to_peer(self) -> WgPeer {
        let mut peer = WgPeer::new(self.public_key.0);
        // The only address it may send from, so one device can't pretend
        // to be another.
        peer.allowed_ips = vec![IpNetwork::V4(
            Ipv4Network::new(self.address, 32).expect("32 is a valid prefix"),
        )];
        peer
    }
}

/// A device's setup, as the WireGuard apps read it from a file or QR code.
pub struct DeviceSetup<'a> {
    pub key: &'a Key,
    pub address: Ipv4Addr,
    pub server: PublicKey,
    pub network: Network,
    pub home: Ipv4Addr,
    /// Where the device finds home, such as the server's endpoint name.
    pub endpoint_host: &'a str,
    pub endpoint_port: u16,
}

impl DeviceSetup<'_> {
    /// The setup in the WireGuard apps' format. It sets no DNS server, so
    /// the device keeps its own, and the tunnel carries only the server's
    /// two addresses.
    pub fn to_config(&self) -> String {
        format!(
            "[Interface]\n\
             PrivateKey = {key}\n\
             Address = {address}/32\n\
             MTU = {MTU}\n\
             \n\
             [Peer]\n\
             PublicKey = {server}\n\
             AllowedIPs = {home}/32, {tunnel}/32\n\
             Endpoint = {host}:{port}\n\
             PersistentKeepalive = {KEEPALIVE}\n",
            key = self.key.to_base64(),
            address = self.address,
            server = self.server.to_base64(),
            home = self.home,
            tunnel = self.network.server(),
            host = self.endpoint_host,
            port = self.endpoint_port,
        )
    }
}

type Transports = (UdpSocketFactory, stack::Inbound, stack::Outbound);

/// How the tunnel is doing, for the health and remote access pages.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct TunnelStatus {
    /// The UDP port it's listening on, while it runs.
    pub listening: Option<u16>,
    /// Why it couldn't start, until it does.
    pub problem: Option<String>,
    /// When each device last connected, since the server started.
    pub connected: HashMap<PublicKey, SystemTime>,
}

/// Runs the tunnel while there's a config, and keeps its devices current.
pub struct RemoteTunnel {
    config: watch::Receiver<Option<TunnelConfig>>,
    peers: watch::Receiver<Vec<DevicePeer>>,
    listeners: Listeners,
    status: watch::Sender<TunnelStatus>,
}

/// The tunnel while it runs.
struct Running {
    config: TunnelConfig,
    device: Device<Transports>,
    /// The peer that keeps the socket open.
    placeholder: PublicKey,
    addresses: watch::Sender<Addresses>,
    stop_stack: tokio::sync::oneshot::Sender<()>,
    stack: tokio::task::JoinHandle<()>,
}

impl RemoteTunnel {
    pub fn new(
        config: watch::Receiver<Option<TunnelConfig>>,
        peers: watch::Receiver<Vec<DevicePeer>>,
        listeners: Listeners,
    ) -> Self {
        Self {
            config,
            peers,
            listeners,
            status: watch::Sender::default(),
        }
    }

    pub fn status(&self) -> watch::Receiver<TunnelStatus> {
        self.status.subscribe()
    }

    /// Starts, changes, and stops the tunnel as its config and devices
    /// change, until `shutdown` completes.
    pub async fn run(mut self, shutdown: impl Future<Output = ()>) {
        let mut shutdown = std::pin::pin!(shutdown);
        let mut running: Option<Running> = None;
        let mut check = tokio::time::interval(HANDSHAKE_CHECK);
        check.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // Whether each sender is still there to change anything.
        let (mut config_open, mut peers_open) = (true, true);
        loop {
            let config = self.config.borrow_and_update().clone();
            let peers = self.peers.borrow_and_update().clone();
            running = self.apply(running, config, &peers).await;

            loop {
                tokio::select! {
                    () = &mut shutdown => {
                        if let Some(running) = running {
                            running.stop().await;
                        }
                        return;
                    }
                    changed = self.config.changed(), if config_open => {
                        config_open = changed.is_ok();
                        break;
                    }
                    changed = self.peers.changed(), if peers_open => {
                        peers_open = changed.is_ok();
                        break;
                    }
                    _ = check.tick(), if running.is_some() => {
                        if let Some(running) = &running {
                            let connected = running.connected().await;
                            self.status.send_if_modified(|status| {
                                let changed = status.connected != connected;
                                status.connected.extend(connected);
                                changed
                            });
                        }
                    }
                }
            }
        }
    }

    async fn apply(
        &self,
        running: Option<Running>,
        config: Option<TunnelConfig>,
        peers: &[DevicePeer],
    ) -> Option<Running> {
        let Some(config) = config else {
            if let Some(running) = running {
                running.stop().await;
                info!("remote access is off");
            }
            self.status.send_modify(|status| {
                status.listening = None;
                status.problem = None;
            });
            return None;
        };
        let running = match running {
            Some(running)
                if running.config.key == config.key
                    && running.config.port == config.port
                    && running.config.network == config.network =>
            {
                if running.config.home != config.home {
                    running.addresses.send_replace(Addresses {
                        home: config.home,
                        tunnel: config.network.server(),
                    });
                }
                Running { config, ..running }
            }
            other => {
                if let Some(running) = other {
                    running.stop().await;
                }
                match Running::start(config.clone(), self.listeners.clone()).await {
                    Ok(running) => {
                        info!(port = config.port, "remote access is on");
                        self.status.send_modify(|status| {
                            status.listening = Some(config.port);
                            status.problem = None;
                        });
                        running
                    }
                    Err(problem) => {
                        warn!("{problem}");
                        self.status.send_modify(|status| {
                            status.listening = None;
                            status.problem = Some(problem);
                        });
                        return None;
                    }
                }
            }
        };
        running.set_peers(peers).await;
        Some(running)
    }
}

impl Running {
    async fn start(config: TunnelConfig, listeners: Listeners) -> Result<Self, String> {
        let (addresses, receiver) = watch::channel(Addresses {
            home: config.home,
            tunnel: config.network.server(),
        });
        let (stack, inbound, outbound) = stack::new(receiver, listeners);
        let problem = |err: device::Error| {
            format!(
                "Accordion couldn't start remote access on UDP port {}: {err}. If another \
                 program uses that port, choose a different one.",
                config.port
            )
        };
        // GotaTun opens its socket only when it's built with a peer, and
        // not when one is added later. This one keeps it open from the
        // start, so a port that's taken shows up at once and the first
        // device can connect. Nobody has its private key, and it may send
        // from no address.
        let placeholder = Key::generate().public();
        let device = device::build()
            .with_default_udp()
            .with_ip_pair(inbound, outbound)
            .with_private_key(config.key.0.clone())
            .with_listen_port(config.port)
            .with_peer(WgPeer::new(placeholder.0))
            .build()
            .await
            .map_err(problem)?;
        let (stop_stack, stopped) = tokio::sync::oneshot::channel();
        let stack = tokio::spawn(stack.run(async {
            let _ = stopped.await;
        }));
        Ok(Self {
            config,
            device,
            placeholder,
            addresses,
            stop_stack,
            stack,
        })
    }

    /// Makes the device's peers exactly `peers`. A removed device's next
    /// packet finds no peer, so its tunnel ends at once.
    async fn set_peers(&self, peers: &[DevicePeer]) {
        let wanted: HashMap<PublicKey, DevicePeer> =
            peers.iter().map(|peer| (peer.public_key, *peer)).collect();
        let current = self.device.peers().await;
        let result = self
            .device
            .write(async |device| {
                for existing in &current {
                    let key = PublicKey(existing.peer.public_key);
                    if key == self.placeholder {
                        continue;
                    }
                    let same = wanted.get(&key).is_some_and(|peer| {
                        existing.peer.allowed_ips == peer.to_peer().allowed_ips
                    });
                    if !same {
                        device.remove_peer(&existing.peer.public_key).await;
                    }
                }
                for peer in wanted.values() {
                    let present = current.iter().any(|existing| {
                        PublicKey(existing.peer.public_key) == peer.public_key
                            && existing.peer.allowed_ips == peer.to_peer().allowed_ips
                    });
                    if !present {
                        device.add_peer(peer.to_peer());
                    }
                }
            })
            .await;
        if let Err(err) = result {
            warn!(%err, "couldn't update the remote access devices");
        }
    }

    /// When each device last finished a handshake, which it does every two
    /// minutes while it's connected.
    async fn connected(&self) -> HashMap<PublicKey, SystemTime> {
        let now = SystemTime::now();
        self.device
            .peers()
            .await
            .into_iter()
            .filter_map(|peer| {
                let since = peer.stats.last_handshake?;
                Some((PublicKey(peer.peer.public_key), now - since))
            })
            .collect()
    }

    async fn stop(self) {
        self.device.stop().await;
        let _ = self.stop_stack.send(());
        let _ = self.stack.await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_round_trip_through_base64() {
        let key = Key::generate();
        let text = key.to_base64();
        assert_eq!(text.len(), 44);
        assert_eq!(Key::from_base64(&text).unwrap().public(), key.public());
        let public = key.public();
        assert_eq!(PublicKey::from_base64(&public.to_base64()).unwrap(), public);
        assert!(PublicKey::from_base64("not a key").is_err());
        assert_eq!(format!("{key:?}"), "Key(..)");
    }

    #[test]
    fn picks_networks_away_from_common_ones() {
        for _ in 0..1000 {
            let network = Network::random();
            let [a, b, c, d] = network.server().octets();
            assert_eq!((a, d), (10, 1));
            assert_ne!(b, 0);
            assert_ne!((b, c), (1, 1));
        }
        let network = Network::containing(Ipv4Addr::new(10, 42, 7, 9)).unwrap();
        assert_eq!(network.to_string(), "10.42.7.0/24");
        assert_eq!(network.host(2), Ipv4Addr::new(10, 42, 7, 2));
        assert!(Network::containing(Ipv4Addr::new(192, 168, 1, 1)).is_none());
    }

    #[test]
    fn writes_a_setup_the_wireguard_apps_read() {
        let key = Key::from_base64("yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=").unwrap();
        let server =
            PublicKey::from_base64("xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=").unwrap();
        let setup = DeviceSetup {
            key: &key,
            address: Ipv4Addr::new(10, 42, 7, 2),
            server,
            network: Network::containing(Ipv4Addr::new(10, 42, 7, 0)).unwrap(),
            home: Ipv4Addr::new(192, 168, 1, 20),
            endpoint_host: "k3x9q2wm7f.ourhome.dedyn.io",
            endpoint_port: 51820,
        };
        assert_eq!(
            setup.to_config(),
            "[Interface]\n\
             PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=\n\
             Address = 10.42.7.2/32\n\
             MTU = 1420\n\
             \n\
             [Peer]\n\
             PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\n\
             AllowedIPs = 192.168.1.20/32, 10.42.7.1/32\n\
             Endpoint = k3x9q2wm7f.ourhome.dedyn.io:51820\n\
             PersistentKeepalive = 25\n"
        );
    }
}
