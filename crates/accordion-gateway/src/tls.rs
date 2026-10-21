//! TLS for every HTTP connection.
//!
//! The certificate can be replaced while the server runs, so renewing it
//! doesn't need a restart. Connections that are already open keep the
//! certificate they started with.

use std::future::Future;
use std::net::SocketAddr;
use std::sync::{Arc, PoisonError, RwLock};
use std::time::Duration;

use axum::Router;
use axum::extract::ConnectInfo;
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto;
use hyper_util::service::TowerToHyperService;
use rustls::ServerConfig;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::pem::{self, PemObject};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::task::JoinSet;
use tokio_rustls::TlsAcceptor;
use tower::ServiceExt;
use tracing::{debug, warn};

use crate::peer::Peer;

/// How long a client gets to finish the TLS handshake, and then to send its
/// request headers. Without a limit, slow clients could hold connections open
/// until the server runs out.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// How long open connections get to finish when the server stops. WebSocket
/// connections don't end on their own, so they're closed after this.
const DRAIN_TIMEOUT: Duration = Duration::from_secs(10);

/// Holds the server's current certificate.
#[derive(Debug, Default)]
pub struct CertStore {
    current: RwLock<Option<Arc<CertifiedKey>>>,
}

#[derive(Debug, thiserror::Error)]
pub enum CertError {
    #[error("The certificate file doesn't contain a certificate.")]
    NoCertificate,
    #[error("Accordion couldn't read the certificate or key file: {0}")]
    Pem(#[from] pem::Error),
    #[error("The private key doesn't work with this certificate: {0}")]
    Key(#[from] rustls::Error),
}

impl CertStore {
    pub fn new() -> Arc<Self> {
        Arc::default()
    }

    /// Replaces the certificate with a PEM certificate chain, server
    /// certificate first, and its PEM private key. On error, the current
    /// certificate stays in place.
    pub fn set_pem(&self, chain_pem: &[u8], key_pem: &[u8]) -> Result<(), CertError> {
        let chain = CertificateDer::pem_slice_iter(chain_pem).collect::<Result<Vec<_>, _>>()?;
        if chain.is_empty() {
            return Err(CertError::NoCertificate);
        }
        let key = PrivateKeyDer::from_pem_slice(key_pem)?;
        let certified = CertifiedKey::from_der(chain, key, &provider())?;
        *self.current.write().unwrap_or_else(PoisonError::into_inner) = Some(Arc::new(certified));
        Ok(())
    }

    pub fn has_certificate(&self) -> bool {
        self.current
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .is_some()
    }
}

impl ResolvesServerCert for CertStore {
    // The server has one name, so every client gets the same certificate.
    // Without one, the handshake fails.
    fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.current
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

fn provider() -> CryptoProvider {
    rustls::crypto::ring::default_provider()
}

/// TLS settings for the server: TLS 1.3, and HTTP/2 with a fallback to
/// HTTP/1.1.
///
/// TLS 1.2 is there for Windows, whose WebDAV client behind File Explorer
/// often allows nothing newer. rustls only offers forward-secret AEAD cipher
/// suites for TLS 1.2, and clients that support TLS 1.3 can't be pushed down
/// to 1.2.
pub fn server_config(certs: Arc<CertStore>) -> Arc<ServerConfig> {
    let mut config = ServerConfig::builder_with_provider(Arc::new(provider()))
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .expect("ring supports TLS 1.2 and 1.3")
        .with_no_client_auth()
        .with_cert_resolver(certs);
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Arc::new(config)
}

/// Serves `router` over TLS on `listener` until `shutdown` completes, then
/// waits briefly for open connections to finish.
///
/// Handlers can read both ends of the connection with `ConnectInfo<Peer>`,
/// or only the client's address with `ConnectInfo<SocketAddr>`.
pub async fn serve(
    listener: TcpListener,
    config: Arc<ServerConfig>,
    router: Router,
    shutdown: impl Future<Output = ()>,
) {
    let acceptor = TlsAcceptor::from(config);
    let (stop_sender, stop) = watch::channel(false);
    let mut connections = JoinSet::new();
    let mut shutdown = std::pin::pin!(shutdown);

    loop {
        tokio::select! {
            () = &mut shutdown => break,
            accepted = listener.accept() => match accepted {
                Ok((stream, peer)) => {
                    connections.spawn(serve_connection(
                        acceptor.clone(),
                        stream,
                        peer,
                        router.clone(),
                        stop.clone(),
                    ));
                }
                Err(err) => {
                    // Usually the process is out of file handles. Pause
                    // rather than retrying in a tight loop.
                    warn!(%err, "couldn't accept a connection");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            },
            // Collect finished connections so the set doesn't keep growing.
            Some(_) = connections.join_next(), if !connections.is_empty() => {}
        }
    }

    let _ = stop_sender.send(true);
    if tokio::time::timeout(DRAIN_TIMEOUT, connections.join_all())
        .await
        .is_err()
    {
        debug!("closed connections that were still open at shutdown");
    }
}

async fn serve_connection(
    acceptor: TlsAcceptor,
    stream: tokio::net::TcpStream,
    peer: SocketAddr,
    router: Router,
    mut stop: watch::Receiver<bool>,
) {
    let connection = Peer {
        local: stream.local_addr().unwrap_or(peer),
        remote: peer,
    };
    let tls = match tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await {
        Ok(Ok(tls)) => tls,
        Ok(Err(err)) => {
            debug!(%peer, %err, "TLS handshake failed");
            return;
        }
        Err(_) => {
            debug!(%peer, "TLS handshake timed out");
            return;
        }
    };

    let service = router.map_request(move |mut request: hyper::Request<Incoming>| {
        request.extensions_mut().insert(ConnectInfo(peer));
        request.extensions_mut().insert(ConnectInfo(connection));
        request
    });

    let mut builder = auto::Builder::new(TokioExecutor::new());
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(HEADER_READ_TIMEOUT);
    builder.http2().timer(TokioTimer::new());
    let connection = builder
        .serve_connection_with_upgrades(TokioIo::new(tls), TowerToHyperService::new(service));
    let mut connection = std::pin::pin!(connection);

    let result = tokio::select! {
        result = connection.as_mut() => result,
        _ = stop.changed() => {
            connection.as_mut().graceful_shutdown();
            connection.await
        }
    };
    if let Err(err) = result {
        debug!(%peer, %err, "connection ended with an error");
    }
}
