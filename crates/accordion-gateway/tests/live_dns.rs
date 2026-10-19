//! Gets a certificate from Let's Encrypt's staging service through a real DNS
//! provider account. Browsers don't trust staging certificates, so a test run
//! can't affect anything.
//!
//! The `_record_appears` tests only publish a record and wait for the
//! provider's nameservers to serve it, without involving Let's Encrypt.
//!
//! Each test reads the name and a file that holds the provider's API token:
//!
//! ```sh
//! LIVE_NAME=accordion.example.com LIVE_TOKEN_FILE=~/.config/accordion/cloudflare-token \
//!     cargo test --test live_dns cloudflare -- --ignored --nocapture
//!
//! LIVE_NAME=ourhome.dedyn.io LIVE_TOKEN_FILE=~/.config/accordion/desec-token \
//!     cargo test --test live_dns desec -- --ignored --nocapture
//! ```

use accordion_gateway::acme::{AcmeAccount, Directory, renew_after};
use accordion_gateway::dns::{Cloudflare, Desec, DnsProvider};
use accordion_gateway::tls::CertStore;
use accordion_gateway::{PropagationCheck, ServerName};

fn name() -> ServerName {
    std::env::var("LIVE_NAME")
        .expect("LIVE_NAME is the name to get a certificate for")
        .parse()
        .unwrap()
}

fn token() -> String {
    let path =
        std::env::var("LIVE_TOKEN_FILE").expect("LIVE_TOKEN_FILE names a file holding the token");
    let token = std::fs::read_to_string(path).expect("couldn't read LIVE_TOKEN_FILE");
    token.trim().to_owned()
}

async fn issue_staging_certificate(dns: &impl DnsProvider) {
    let name = name();
    let (account, _) = AcmeAccount::create(&Directory::lets_encrypt_staging())
        .await
        .unwrap();
    println!(
        "Publishing the challenge record for {name}, waiting until its nameservers serve it, \
         then {} seconds more.",
        dns.propagation_delay().as_secs()
    );
    let cert = account
        .issue(&name, dns, &PropagationCheck::new())
        .await
        .unwrap();

    CertStore::new()
        .set_pem(cert.chain_pem.as_bytes(), cert.key_pem.as_bytes())
        .unwrap();
    println!(
        "Got a staging certificate for {name}. Renew after {:?}.",
        renew_after(&cert.chain_pem).unwrap()
    );
}

/// Publishes a record and waits until every nameserver serves it, without
/// involving the certificate authority.
async fn publish_and_wait(dns: &impl DnsProvider) {
    let record = format!("_acme-challenge.{}", name());
    let value = "accordion-propagation-test";
    dns.set_txt(&record, value).await.unwrap();
    let started = std::time::Instant::now();
    let result = PropagationCheck::new().wait_for_txt(&record, value).await;
    let waited = started.elapsed().as_secs();
    dns.clear_txt(&record).await.unwrap();
    result.unwrap();
    println!("Every nameserver served {record} after about {waited} seconds.");
}

#[tokio::test]
#[ignore = "needs a Cloudflare account; see the comment at the top of this file"]
async fn cloudflare_record_appears() {
    publish_and_wait(&Cloudflare::new(token()).unwrap()).await;
}

#[tokio::test]
#[ignore = "needs a deSEC account; see the comment at the top of this file"]
async fn desec_record_appears() {
    publish_and_wait(&Desec::new(token()).unwrap()).await;
}

#[tokio::test]
#[ignore = "needs a Cloudflare account; see the comment at the top of this file"]
async fn cloudflare() {
    issue_staging_certificate(&Cloudflare::new(token()).unwrap()).await;
}

#[tokio::test]
#[ignore = "needs a deSEC account; see the comment at the top of this file"]
async fn desec() {
    issue_staging_certificate(&Desec::new(token()).unwrap()).await;
}
