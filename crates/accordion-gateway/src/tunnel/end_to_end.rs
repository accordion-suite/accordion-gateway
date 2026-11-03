//! A real WireGuard client, in the test, connecting through the tunnel to
//! the gateway's TLS server: the same path a phone away from home takes.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::extract::ConnectInfo;
use axum::routing::get;
use gotatun::device::{self, Peer as WgPeer};
use ipnetwork::{IpNetwork, Ipv4Network};
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot, watch};
use tokio_rustls::TlsConnector;

use super::stack::client;
use super::*;
use crate::Peer;
use crate::tls::{self, CertStore};

const NAME: &str = "accordion.example.com";
const HOME: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 20);

struct Server {
    port: u16,
    public: PublicKey,
    network: Network,
    peers: watch::Sender<Vec<DevicePeer>>,
    status: watch::Receiver<TunnelStatus>,
    trusted: CertificateDer<'static>,
    _stop: oneshot::Sender<()>,
}

/// A UDP port that was free a moment ago.
fn free_port() -> u16 {
    std::net::UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// The tunnel and a TLS server behind it that says who connected.
async fn start(devices: &[DevicePeer]) -> Server {
    let certified = rcgen::generate_simple_self_signed(vec![NAME.to_owned()]).unwrap();
    let certs = CertStore::new();
    certs
        .set_pem(
            certified.cert.pem().as_bytes(),
            certified.signing_key.serialize_pem().as_bytes(),
        )
        .unwrap();
    let router = Router::new().route(
        "/",
        get(|ConnectInfo(peer): ConnectInfo<Peer>| async move {
            format!(
                "hello {} at {}, home {}",
                peer.remote.ip(),
                peer.local,
                peer.on_home_network()
            )
        }),
    );

    let key = Key::generate();
    let network = Network::containing(Ipv4Addr::new(10, 77, 3, 0)).unwrap();
    let port = free_port();
    let (https, https_incoming) = mpsc::channel(16);
    let (http, _http_incoming) = mpsc::channel(16);
    let (_config, config) = watch::channel(Some(TunnelConfig {
        key: key.clone(),
        port,
        network,
        home: HOME,
    }));
    let (peers, peers_receiver) = watch::channel(devices.to_vec());
    let tunnel = RemoteTunnel::new(
        config,
        peers_receiver,
        Listeners(vec![(443, https), (80, http)]),
    );
    let mut status = tunnel.status();
    let (stop, stopped) = oneshot::channel::<()>();
    let (stop_tls, tls_stopped) = oneshot::channel::<()>();
    tokio::spawn(async move {
        tokio::join!(
            tunnel.run(async {
                let _ = stopped.await;
                let _ = stop_tls.send(());
                let _ = _config;
            }),
            tls::serve_tunnel(
                https_incoming,
                Some(tls::server_config(certs)),
                router,
                async {
                    let _ = tls_stopped.await;
                },
            ),
        );
    });
    status
        .wait_for(|status| status.listening.is_some())
        .await
        .unwrap();
    Server {
        port,
        public: key.public(),
        network,
        peers,
        status,
        trusted: certified.cert.der().clone(),
        _stop: stop,
    }
}

/// A device: its key, and its address on the tunnel.
fn device(network: Network, number: u8) -> (Key, DevicePeer) {
    let key = Key::generate();
    let peer = DevicePeer {
        public_key: key.public(),
        address: network.host(number),
    };
    (key, peer)
}

/// Brings up a WireGuard client for `key` at `address`, and opens a TCP
/// connection through it to `to`.
async fn connect(
    server: &Server,
    key: &Key,
    address: Ipv4Addr,
    to: SocketAddr,
) -> (
    TunnelStream,
    gotatun::device::Device<impl gotatun::device::DeviceTransports>,
) {
    let (to_device, from_device, stream, run) = client::connect(address, to);
    let mut peer = WgPeer::new(server.public.0);
    peer.endpoint = Some(SocketAddr::from((Ipv4Addr::LOCALHOST, server.port)));
    peer.allowed_ips = vec![
        IpNetwork::V4(Ipv4Network::new(HOME, 32).unwrap()),
        IpNetwork::V4(Ipv4Network::new(server.network.server(), 32).unwrap()),
    ];
    let device = device::build()
        .with_default_udp()
        .with_ip_pair(to_device, from_device)
        .with_private_key(key.0.clone())
        .with_peer(peer)
        .build()
        .await
        .unwrap();
    tokio::spawn(run);
    (stream, device)
}

fn tls_connector(trusted: &CertificateDer<'static>) -> TlsConnector {
    let mut roots = RootCertStore::empty();
    roots.add(trusted.clone()).unwrap();
    let config =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
    TlsConnector::from(Arc::new(config))
}

/// Sends one HTTPS request over `stream` and returns the response.
async fn get_root(
    stream: TunnelStream,
    trusted: &CertificateDer<'static>,
) -> std::io::Result<String> {
    let mut tls = tls_connector(trusted)
        .connect(ServerName::try_from(NAME).unwrap(), stream)
        .await?;
    tls.write_all(
        format!("GET / HTTP/1.1\r\nHost: {NAME}\r\nConnection: close\r\n\r\n").as_bytes(),
    )
    .await?;
    let mut response = String::new();
    tls.read_to_string(&mut response).await?;
    Ok(response)
}

#[tokio::test(flavor = "multi_thread")]
async fn serves_a_device_through_the_tunnel() {
    let network = Network::containing(Ipv4Addr::new(10, 77, 3, 0)).unwrap();
    let (key, phone) = device(network, 2);
    let mut server = start(&[phone]).await;

    let (stream, _client) = connect(&server, &key, phone.address, (HOME, 443).into()).await;
    let response = tokio::time::timeout(Duration::from_secs(10), get_root(stream, &server.trusted))
        .await
        .expect("the request finished")
        .unwrap();
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    assert!(
        response.ends_with("hello 10.77.3.2 at 192.168.1.20:443, home true"),
        "{response}"
    );

    // The server's tunnel address works too.
    let (stream, _client) =
        connect(&server, &key, phone.address, (network.server(), 443).into()).await;
    let response = get_root(stream, &server.trusted).await.unwrap();
    assert!(
        response.ends_with("at 10.77.3.1:443, home true"),
        "{response}"
    );

    // The status learns that the device connected.
    tokio::time::timeout(
        Duration::from_secs(40),
        server
            .status
            .wait_for(|status| status.connected.contains_key(&phone.public_key)),
    )
    .await
    .expect("the status shows the connection")
    .unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn drops_packets_for_anything_but_the_gateway() {
    let network = Network::containing(Ipv4Addr::new(10, 77, 3, 0)).unwrap();
    let (key, phone) = device(network, 2);
    let server = start(&[phone]).await;

    // SSH on the server, and the router, get no answer at all: not even
    // a reset.
    for to in [(HOME, 22), (Ipv4Addr::new(192, 168, 1, 1), 443)] {
        let (mut stream, _client) = connect(&server, &key, phone.address, to.into()).await;
        let mut byte = [0];
        let read = tokio::time::timeout(Duration::from_secs(3), stream.read(&mut byte)).await;
        assert!(read.is_err(), "{to:?} answered: {read:?}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn ignores_unknown_and_removed_devices() {
    let network = Network::containing(Ipv4Addr::new(10, 77, 3, 0)).unwrap();
    let (key, phone) = device(network, 2);
    let (laptop_key, laptop) = device(network, 3);
    let server = start(&[phone, laptop]).await;

    // A device the server doesn't know.
    let (stranger, _) = device(network, 4);
    let (mut stream, _client) =
        connect(&server, &stranger, network.host(4), (HOME, 443).into()).await;
    let mut byte = [0];
    assert!(
        tokio::time::timeout(Duration::from_secs(3), stream.read(&mut byte))
            .await
            .is_err()
    );

    // A device can't use another device's address.
    let (mut stream, _client) =
        connect(&server, &laptop_key, phone.address, (HOME, 443).into()).await;
    assert!(
        tokio::time::timeout(Duration::from_secs(3), stream.read(&mut byte))
            .await
            .is_err()
    );

    // Removing a device ends its tunnel at once.
    let (stream, _client) = connect(&server, &key, phone.address, (HOME, 443).into()).await;
    get_root(stream, &server.trusted).await.unwrap();
    server.peers.send_replace(vec![laptop]);
    let (stream, _client) = connect(&server, &key, phone.address, (HOME, 443).into()).await;
    let request =
        tokio::time::timeout(Duration::from_secs(3), get_root(stream, &server.trusted)).await;
    assert!(
        request.is_err(),
        "the removed device connected: {request:?}"
    );

    // The other device still works.
    let (stream, _client) = connect(&server, &laptop_key, laptop.address, (HOME, 443).into()).await;
    get_root(stream, &server.trusted).await.unwrap();
}
