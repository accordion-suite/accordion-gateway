//! Serves real TLS connections on a local port and connects to them.

use std::net::SocketAddr;
use std::sync::Arc;

use accordion_gateway::Peer;
use accordion_gateway::tls::{self, CertError, CertStore};
use axum::Router;
use axum::extract::ConnectInfo;
use axum::routing::get;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, ProtocolVersion, RootCertStore, SupportedProtocolVersion};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tokio_rustls::TlsConnector;

const NAME: &str = "accordion.example.com";

struct TestCert {
    chain_pem: String,
    key_pem: String,
    der: CertificateDer<'static>,
}

fn new_cert() -> TestCert {
    let certified = rcgen::generate_simple_self_signed(vec![NAME.to_owned()]).unwrap();
    TestCert {
        chain_pem: certified.cert.pem(),
        key_pem: certified.signing_key.serialize_pem(),
        der: certified.cert.der().clone(),
    }
}

struct TestServer {
    address: SocketAddr,
    stop: oneshot::Sender<()>,
    task: JoinHandle<()>,
}

async fn start(certs: Arc<CertStore>) -> TestServer {
    let router =
        Router::new().route(
            "/",
            get(
                |ConnectInfo(remote): ConnectInfo<SocketAddr>,
                 ConnectInfo(peer): ConnectInfo<Peer>| async move {
                    assert_eq!(peer.remote, remote);
                    assert!(peer.on_home_network());
                    format!("hello {} at {}", remote.ip(), peer.local.ip())
                },
            ),
        );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (stop, stopped) = oneshot::channel();
    let task = tokio::spawn(tls::serve(
        listener,
        tls::server_config(certs),
        router,
        async {
            let _ = stopped.await;
        },
    ));
    TestServer {
        address,
        stop,
        task,
    }
}

/// Sends one HTTP/1.1 request, trusting only `trusted`, and returns the
/// whole response.
async fn get_root(
    address: SocketAddr,
    trusted: &CertificateDer<'static>,
) -> std::io::Result<String> {
    get_root_with(address, trusted, &[&rustls::version::TLS13])
        .await
        .map(|(_, response)| response)
}

/// Like [`get_root`], from a client that offers only `versions`. Also
/// returns the TLS version the server chose.
async fn get_root_with(
    address: SocketAddr,
    trusted: &CertificateDer<'static>,
    versions: &[&'static SupportedProtocolVersion],
) -> std::io::Result<(ProtocolVersion, String)> {
    let mut roots = RootCertStore::empty();
    roots.add(trusted.clone()).unwrap();
    let config =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(versions)
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));

    let stream = TcpStream::connect(address).await?;
    let mut tls = connector
        .connect(ServerName::try_from(NAME).unwrap(), stream)
        .await?;
    let version = tls.get_ref().1.protocol_version().unwrap();
    tls.write_all(
        format!("GET / HTTP/1.1\r\nHost: {NAME}\r\nConnection: close\r\n\r\n").as_bytes(),
    )
    .await?;
    let mut response = String::new();
    tls.read_to_string(&mut response).await?;
    Ok((version, response))
}

#[tokio::test]
async fn serves_requests_over_tls_with_the_client_address() {
    let cert = new_cert();
    let certs = CertStore::new();
    certs
        .set_pem(cert.chain_pem.as_bytes(), cert.key_pem.as_bytes())
        .unwrap();
    let server = start(certs).await;

    let response = get_root(server.address, &cert.der).await.unwrap();
    assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
    assert!(
        response.ends_with("hello 127.0.0.1 at 127.0.0.1"),
        "{response}"
    );

    server.stop.send(()).unwrap();
    server.task.await.unwrap();
}

#[tokio::test]
async fn prefers_tls_1_3_and_serves_tls_1_2_for_windows() {
    let cert = new_cert();
    let certs = CertStore::new();
    certs
        .set_pem(cert.chain_pem.as_bytes(), cert.key_pem.as_bytes())
        .unwrap();
    let server = start(certs).await;

    let both = [&rustls::version::TLS13, &rustls::version::TLS12];
    let (version, _) = get_root_with(server.address, &cert.der, &both)
        .await
        .unwrap();
    assert_eq!(version, ProtocolVersion::TLSv1_3);

    // Like File Explorer's WebDAV client on many Windows PCs.
    let (version, response) = get_root_with(server.address, &cert.der, &[&rustls::version::TLS12])
        .await
        .unwrap();
    assert_eq!(version, ProtocolVersion::TLSv1_2);
    assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");

    server.stop.send(()).unwrap();
    server.task.await.unwrap();
}

#[tokio::test]
async fn uses_a_replaced_certificate_without_restarting() {
    let first = new_cert();
    let second = new_cert();
    let certs = CertStore::new();
    certs
        .set_pem(first.chain_pem.as_bytes(), first.key_pem.as_bytes())
        .unwrap();
    let server = start(certs.clone()).await;
    assert!(get_root(server.address, &first.der).await.is_ok());

    certs
        .set_pem(second.chain_pem.as_bytes(), second.key_pem.as_bytes())
        .unwrap();
    assert!(get_root(server.address, &second.der).await.is_ok());
    assert!(get_root(server.address, &first.der).await.is_err());

    server.stop.send(()).unwrap();
    server.task.await.unwrap();
}

#[tokio::test]
async fn refuses_connections_until_there_is_a_certificate() {
    let cert = new_cert();
    let certs = CertStore::new();
    assert!(!certs.has_certificate());
    let server = start(certs).await;

    assert!(get_root(server.address, &cert.der).await.is_err());

    server.stop.send(()).unwrap();
    server.task.await.unwrap();
}

#[test]
fn keeps_the_current_certificate_when_the_new_one_is_bad() {
    let first = new_cert();
    let second = new_cert();
    let certs = CertStore::new();
    certs
        .set_pem(first.chain_pem.as_bytes(), first.key_pem.as_bytes())
        .unwrap();

    let mismatched = certs.set_pem(first.chain_pem.as_bytes(), second.key_pem.as_bytes());
    assert!(
        matches!(mismatched, Err(CertError::Key(_))),
        "{mismatched:?}"
    );
    let empty = certs.set_pem(b"", first.key_pem.as_bytes());
    assert!(matches!(empty, Err(CertError::NoCertificate)), "{empty:?}");
    assert!(certs.has_certificate());
}
