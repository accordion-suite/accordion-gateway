//! Gets real certificates from Pebble, Let's Encrypt's test certificate
//! authority. `scripts/test-acme.sh` downloads and starts Pebble, then runs
//! these tests.

use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

use accordion_gateway::acme::{AcmeAccount, AcmeError, Directory, renew_after};
use accordion_gateway::certificates::Renewer;
use accordion_gateway::dns::{DnsError, DnsProvider};
use accordion_gateway::propagation::PropagationError;
use accordion_gateway::tls::CertStore;
use accordion_gateway::{PropagationCheck, ServerName};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Waits for records on Pebble's test DNS server, the way the server waits
/// for a real zone's nameservers.
fn check() -> PropagationCheck {
    let address = std::env::var("CHALLTESTSRV_DNS").unwrap_or("127.0.0.1:8053".into());
    PropagationCheck::with_nameservers(vec![address.parse().unwrap()])
}

fn directory() -> Directory {
    let url = std::env::var("PEBBLE_DIRECTORY").unwrap_or("https://localhost:14000/dir".into());
    let root =
        std::env::var("PEBBLE_ROOT").expect("PEBBLE_ROOT names Pebble's HTTPS root certificate");
    Directory::custom(url, Some(root.into()))
}

/// Publishes records through the management API of `pebble-challtestsrv`,
/// the DNS server that Pebble checks challenges against.
#[derive(Default)]
struct ChallTestSrv {
    cleared: Mutex<Vec<String>>,
}

impl ChallTestSrv {
    async fn post(&self, path: &str, body: String) -> Result<(), DnsError> {
        let address = std::env::var("CHALLTESTSRV").unwrap_or("127.0.0.1:8055".into());
        let unreachable = |err: std::io::Error| DnsError::Unreachable {
            provider: "challtestsrv",
            source: err.into(),
        };
        let mut stream = TcpStream::connect(&address).await.map_err(unreachable)?;
        let request = format!(
            "POST {path} HTTP/1.1\r\nHost: {address}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream
            .write_all(request.as_bytes())
            .await
            .map_err(unreachable)?;
        let mut response = String::new();
        stream
            .read_to_string(&mut response)
            .await
            .map_err(unreachable)?;
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        Ok(())
    }
}

impl DnsProvider for ChallTestSrv {
    async fn set_txt(&self, record: &str, value: &str) -> Result<(), DnsError> {
        let body = serde_json::json!({ "host": format!("{record}."), "value": value });
        self.post("/set-txt", body.to_string()).await
    }

    async fn clear_txt(&self, record: &str) -> Result<(), DnsError> {
        self.cleared.lock().unwrap().push(record.to_owned());
        let body = serde_json::json!({ "host": format!("{record}.") });
        self.post("/clear-txt", body.to_string()).await
    }

    async fn set_address(&self, name: &str, address: IpAddr) -> Result<(), DnsError> {
        let path = if address.is_ipv4() {
            "/add-a"
        } else {
            "/add-aaaa"
        };
        let body = serde_json::json!({ "host": format!("{name}."), "addresses": [address] });
        self.post(path, body.to_string()).await
    }

    fn propagation_delay(&self) -> Duration {
        Duration::ZERO
    }
}

/// A provider that claims success without publishing anything, so the
/// challenge fails.
struct Forgetful;

impl DnsProvider for Forgetful {
    async fn set_txt(&self, _record: &str, _value: &str) -> Result<(), DnsError> {
        Ok(())
    }

    async fn clear_txt(&self, _record: &str) -> Result<(), DnsError> {
        Ok(())
    }

    async fn set_address(&self, _name: &str, _address: IpAddr) -> Result<(), DnsError> {
        Ok(())
    }

    fn propagation_delay(&self) -> Duration {
        Duration::ZERO
    }
}

#[tokio::test]
#[ignore = "needs Pebble; run scripts/test-acme.sh"]
async fn issues_a_certificate_through_the_dns_challenge() {
    let directory = directory();
    let (account, credentials) = AcmeAccount::create(&directory).await.unwrap();
    let dns = ChallTestSrv::default();
    let name: ServerName = "accordion.example.com".parse().unwrap();

    let cert = account.issue(&name, &dns, &check()).await.unwrap();

    // The TLS server accepts it, which also checks that the key matches.
    let certs = CertStore::new();
    certs
        .set_pem(cert.chain_pem.as_bytes(), cert.key_pem.as_bytes())
        .unwrap();
    assert!(renew_after(&cert.chain_pem).unwrap() > SystemTime::now());
    assert_eq!(
        *dns.cleared.lock().unwrap(),
        ["_acme-challenge.accordion.example.com"]
    );

    // Saved credentials work for the next renewal.
    let saved = serde_json::to_string(&credentials).unwrap();
    let restored = AcmeAccount::from_credentials(&directory, serde_json::from_str(&saved).unwrap())
        .await
        .unwrap();
    let renewed = restored
        .issue(&name, &ChallTestSrv::default(), &check())
        .await
        .unwrap();
    certs
        .set_pem(renewed.chain_pem.as_bytes(), renewed.key_pem.as_bytes())
        .unwrap();
}

#[tokio::test]
#[ignore = "needs Pebble; run scripts/test-acme.sh"]
async fn explains_a_failed_challenge() {
    let (account, _) = AcmeAccount::create(&directory()).await.unwrap();
    let name: ServerName = "missing-record.example.com".parse().unwrap();

    // Skip the check, so the authority itself looks for the missing record.
    let result = account
        .issue(&name, &Forgetful, &PropagationCheck::skip())
        .await;

    match result {
        Err(AcmeError::Validation { name, detail }) => {
            assert_eq!(name, "missing-record.example.com");
            assert!(!detail.is_empty());
        }
        other => panic!("expected a validation error, got {other:?}"),
    }
}

#[tokio::test]
#[ignore = "needs Pebble; run scripts/test-acme.sh"]
async fn stops_before_the_authority_looks_if_the_record_never_appears() {
    let (account, _) = AcmeAccount::create(&directory()).await.unwrap();
    let name: ServerName = "never-published.example.com".parse().unwrap();

    let check = check().timeout(Duration::from_secs(6));
    let result = account.issue(&name, &Forgetful, &check).await;

    match result {
        Err(AcmeError::Propagation(PropagationError::NotPropagated { record, .. })) => {
            assert_eq!(record, "_acme-challenge.never-published.example.com");
        }
        other => panic!("expected the record not to appear, got {other:?}"),
    }
}

#[tokio::test]
#[ignore = "needs Pebble; run scripts/test-acme.sh"]
async fn keeps_the_certificate_across_restarts() {
    let dir = tempfile::tempdir().unwrap();
    let name: ServerName = "renewal.example.com".parse().unwrap();
    let renewer = |store| {
        Renewer::new(
            dir.path(),
            name.clone(),
            ChallTestSrv::default(),
            directory(),
            check(),
            store,
        )
    };

    // With nothing saved, the loop gets a certificate right away.
    let first = CertStore::new();
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let running = tokio::spawn(renewer(first.clone()).run(async {
        let _ = stopped.await;
    }));
    tokio::time::timeout(Duration::from_secs(60), async {
        while !first.has_certificate() {
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    })
    .await
    .expect("the renewal loop didn't get a certificate within a minute");
    stop.send(()).unwrap();
    running.await.unwrap();

    // After a restart, the saved certificate is served without asking the
    // certificate authority, and the saved account renews it.
    let second = CertStore::new();
    let restarted = renewer(second.clone());
    let due = restarted
        .load()
        .unwrap()
        .expect("the certificate was saved");
    assert!(due > SystemTime::now());
    assert!(second.has_certificate());
    restarted.renew().await.unwrap();
}
