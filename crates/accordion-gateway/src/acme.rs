//! Getting certificates from Let's Encrypt with the ACME DNS challenge.
//!
//! The DNS challenge needs no inbound connection, so the server can get a
//! certificate without any open ports. See decision 5 in the `accordion`
//! repo's `docs/decisions`.

use std::fmt;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use instant_acme::{
    Account, AccountBuilder, AuthorizationStatus, ChallengeType, Identifier, LetsEncrypt,
    NewAccount, NewOrder, Order, OrderStatus, RetryPolicy,
};
use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject;
use tracing::warn;

pub use instant_acme::AccountCredentials;

use crate::ServerName;
use crate::dns::{DnsError, DnsProvider};

/// How long to wait for the certificate authority to check the DNS record,
/// and then to issue the certificate.
const VALIDATION_TIMEOUT: Duration = Duration::from_secs(120);
const ISSUE_TIMEOUT: Duration = Duration::from_secs(60);

/// A certificate authority's ACME directory.
#[derive(Clone, Debug)]
pub struct Directory {
    url: String,
    root: Option<PathBuf>,
}

impl Directory {
    pub fn lets_encrypt() -> Self {
        Self {
            url: LetsEncrypt::Production.url().to_owned(),
            root: None,
        }
    }

    /// Let's Encrypt's staging service, whose certificates browsers don't
    /// trust. Its limits are much higher, so use it for testing.
    pub fn lets_encrypt_staging() -> Self {
        Self {
            url: LetsEncrypt::Staging.url().to_owned(),
            root: None,
        }
    }

    /// Another directory. `root` is a PEM file with the root certificate of
    /// the directory's own HTTPS server, for test servers such as Pebble.
    pub fn custom(url: impl Into<String>, root: Option<PathBuf>) -> Self {
        Self {
            url: url.into(),
            root,
        }
    }

    fn builder(&self) -> Result<AccountBuilder, AcmeError> {
        Ok(match &self.root {
            Some(root) => Account::builder_with_root(root)?,
            None => Account::builder()?,
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AcmeError {
    #[error("The certificate authority returned an error: {0}")]
    Acme(#[from] instant_acme::Error),
    #[error(transparent)]
    Dns(#[from] DnsError),
    #[error("The certificate authority didn't offer a DNS challenge for {0}.")]
    NoDnsChallenge(String),
    #[error(
        "The certificate authority couldn't confirm the DNS record for {name}: {detail} Check \
         that the DNS provider settings are for this name, then try again."
    )]
    Validation { name: String, detail: String },
    #[error("Accordion couldn't read the certificate: {0}")]
    Certificate(String),
}

/// A certificate and its private key, both PEM.
pub struct IssuedCert {
    pub chain_pem: String,
    pub key_pem: String,
}

// Keeps the private key out of logs.
impl fmt::Debug for IssuedCert {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IssuedCert").finish_non_exhaustive()
    }
}

/// The server's account with a certificate authority.
pub struct AcmeAccount {
    account: Account,
}

impl AcmeAccount {
    /// Creates an account with no contact details, so the certificate
    /// authority learns nothing about the household.
    ///
    /// Creating an account agrees to the authority's terms of service, so
    /// show the owner the terms first. Store the returned credentials on the
    /// data volume and use them from then on.
    pub async fn create(directory: &Directory) -> Result<(Self, AccountCredentials), AcmeError> {
        let new_account = NewAccount {
            contact: &[],
            terms_of_service_agreed: true,
            only_return_existing: false,
        };
        let (account, credentials) = directory
            .builder()?
            .create(&new_account, directory.url.clone(), None)
            .await?;
        Ok((Self { account }, credentials))
    }

    pub async fn from_credentials(
        directory: &Directory,
        credentials: AccountCredentials,
    ) -> Result<Self, AcmeError> {
        let account = directory.builder()?.from_credentials(credentials).await?;
        Ok(Self { account })
    }

    /// Gets a certificate for `name`, proving control of it with a TXT
    /// record that `dns` publishes. The record is removed afterward, whether
    /// or not issuing succeeds.
    pub async fn issue<D: DnsProvider>(
        &self,
        name: &ServerName,
        dns: &D,
    ) -> Result<IssuedCert, AcmeError> {
        let identifiers = [Identifier::Dns(name.to_string())];
        let mut order = self.account.new_order(&NewOrder::new(&identifiers)).await?;

        let mut records = Vec::new();
        let result = match publish_challenges(&mut order, dns, &mut records).await {
            Ok(()) => finish(&mut order, name).await,
            Err(err) => Err(err),
        };

        for record in records {
            if let Err(err) = dns.clear_txt(&record).await {
                warn!(%record, %err, "couldn't remove the challenge record");
            }
        }
        result
    }
}

/// Publishes the TXT record for each pending authorization, waits for it to
/// reach the provider's nameservers, then tells the authority to check.
async fn publish_challenges<D: DnsProvider>(
    order: &mut Order,
    dns: &D,
    records: &mut Vec<String>,
) -> Result<(), AcmeError> {
    let mut authorizations = order.authorizations();
    while let Some(authorization) = authorizations.next().await {
        let mut authorization = authorization?;
        if authorization.status == AuthorizationStatus::Valid {
            continue;
        }
        let identifier = authorization.identifier().to_string();
        let mut challenge = authorization
            .challenge(ChallengeType::Dns01)
            .ok_or_else(|| AcmeError::NoDnsChallenge(identifier.clone()))?;

        let record = format!("_acme-challenge.{identifier}");
        dns.set_txt(&record, &challenge.key_authorization().dns_value())
            .await?;
        records.push(record);
        tokio::time::sleep(dns.propagation_delay()).await;
        challenge.set_ready().await?;
    }
    Ok(())
}

async fn finish(order: &mut Order, name: &ServerName) -> Result<IssuedCert, AcmeError> {
    let ready = order
        .poll_ready(&RetryPolicy::new().timeout(VALIDATION_TIMEOUT))
        .await;
    match ready {
        Ok(OrderStatus::Ready) => {}
        // A failed challenge makes the order invalid, and the authority
        // usually attaches the reason to the order, which instant-acme returns
        // as an error. Other errors, such as rate limits, pass through as is.
        Ok(_) => return Err(validation_error(order, name, None).await),
        Err(instant_acme::Error::Api(problem)) if order.state().status == OrderStatus::Invalid => {
            return Err(validation_error(order, name, problem.detail).await);
        }
        Err(err) => return Err(err.into()),
    }
    let key_pem = order.finalize().await?;
    let chain_pem = order
        .poll_certificate(&RetryPolicy::new().timeout(ISSUE_TIMEOUT))
        .await?;
    Ok(IssuedCert { chain_pem, key_pem })
}

/// Explains why the authority couldn't confirm the record, preferring the
/// challenge's own reason over the order's.
async fn validation_error(
    order: &mut Order,
    name: &ServerName,
    order_detail: Option<String>,
) -> AcmeError {
    let mut detail = None;
    let mut authorizations = order.authorizations();
    while let Some(Ok(authorization)) = authorizations.next().await {
        detail = authorization
            .challenges
            .iter()
            .find_map(|challenge| challenge.error.as_ref()?.detail.clone());
        if detail.is_some() {
            break;
        }
    }
    let detail = match detail.or(order_detail) {
        Some(detail) => format!("{}.", detail.trim_end_matches('.')),
        None => "It didn't say why.".to_owned(),
    };
    AcmeError::Validation {
        name: name.to_string(),
        detail,
    }
}

/// When to renew the certificate: after two-thirds of its lifetime, as Let's
/// Encrypt recommends. For a 90-day certificate, that's 30 days before it
/// expires, which leaves time to retry if renewal fails.
pub fn renew_after(chain_pem: &str) -> Result<SystemTime, AcmeError> {
    let der = CertificateDer::from_pem_slice(chain_pem.as_bytes())
        .map_err(|err| AcmeError::Certificate(err.to_string()))?;
    let (_, cert) = x509_parser::parse_x509_certificate(&der)
        .map_err(|err| AcmeError::Certificate(err.to_string()))?;
    let validity = cert.validity();
    let start = validity.not_before.timestamp();
    let end = validity.not_after.timestamp();
    let renew_at = start + (end - start) * 2 / 3;
    let seconds = u64::try_from(renew_at)
        .map_err(|_| AcmeError::Certificate("it was issued before 1970".into()))?;
    Ok(UNIX_EPOCH + Duration::from_secs(seconds))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renews_after_two_thirds_of_the_lifetime() {
        let mut params =
            rcgen::CertificateParams::new(vec!["accordion.example.com".to_owned()]).unwrap();
        params.not_before = rcgen::date_time_ymd(2026, 1, 1);
        params.not_after = rcgen::date_time_ymd(2026, 3, 31);
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();

        let start = UNIX_EPOCH + Duration::from_secs(1_767_225_600); // January 1, 2026
        let lifetime = Duration::from_secs(89 * 24 * 60 * 60); // to March 31
        assert_eq!(renew_after(&cert.pem()).unwrap(), start + lifetime * 2 / 3);
    }

    #[test]
    fn explains_unreadable_certificates() {
        assert!(matches!(
            renew_after("not a certificate"),
            Err(AcmeError::Certificate(_))
        ));
    }

    #[test]
    fn debug_output_hides_the_key() {
        let cert = IssuedCert {
            chain_pem: "chain".into(),
            key_pem: "secret".into(),
        };
        assert!(!format!("{cert:?}").contains("secret"));
    }
}
