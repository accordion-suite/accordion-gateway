//! Keeping the server's certificate current.
//!
//! The server's name, its DNS provider settings, its certificate authority
//! account, and its certificate live in one folder on the data volume. The
//! server loads the certificate at startup, then renews it in the background
//! after two-thirds of its lifetime. See decision 5 in the `accordion` repo's
//! `docs/decisions`.

use std::fmt;
use std::fs::{self, DirBuilder, OpenOptions};
use std::future::Future;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tokio::sync::watch;
use tracing::{error, info, warn};

use crate::acme::{AccountCredentials, AcmeAccount, AcmeError, Directory, Validity, validity};
use crate::dns::{DnsProvider, Provider, ProviderKind};
use crate::http::BoxError;
use crate::retry;
use crate::tls::CertStore;
use crate::{PropagationCheck, ServerName};

const SETTINGS_FILE: &str = "settings.json";
const ACCOUNT_FILE: &str = "account.json";
const CERTIFICATE_FILE: &str = "certificate.json";

/// The longest the renewal loop sleeps at once. It checks the clock again
/// each time it wakes, because the clock can jump, such as after the machine
/// sleeps.
const MAX_SLEEP: Duration = Duration::from_secs(6 * 60 * 60);

/// After a failed renewal, the first retry waits this long, and each later
/// one waits twice as long as the one before. Let's Encrypt allows five
/// failed validations per name per hour, and renewal starts 30 days before
/// expiry, so there's no need to hurry.
const FIRST_RETRY_DELAY: Duration = Duration::from_secs(15 * 60);
const MAX_RETRY_DELAY: Duration = Duration::from_secs(12 * 60 * 60);

/// Which certificate authority to use.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Authority {
    #[default]
    LetsEncrypt,
    /// Let's Encrypt's staging service, for testing. Browsers don't trust
    /// its certificates.
    LetsEncryptStaging,
}

impl Authority {
    pub fn directory(self) -> Directory {
        match self {
            Self::LetsEncrypt => Directory::lets_encrypt(),
            Self::LetsEncryptStaging => Directory::lets_encrypt_staging(),
        }
    }
}

/// How the server gets its certificate. The setup wizard will write these.
#[derive(Clone, Serialize, Deserialize)]
pub struct Settings {
    pub name: ServerName,
    pub provider: ProviderKind,
    pub token: String,
    #[serde(default)]
    pub authority: Authority,
}

impl Settings {
    /// Reads the settings saved in `dir`, or returns `None` if the server's
    /// name hasn't been set.
    pub fn load(dir: &Path) -> Result<Option<Self>, CertificateError> {
        read_json(&dir.join(SETTINGS_FILE))
    }

    /// Saves the settings in `dir`, readable only by the server's user
    /// because they hold the DNS token.
    pub fn save(&self, dir: &Path) -> Result<(), CertificateError> {
        write_private_json(&dir.join(SETTINGS_FILE), self)
    }
}

// Keeps the token out of logs.
impl fmt::Debug for Settings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Settings")
            .field("name", &self.name)
            .field("provider", &self.provider)
            .field("authority", &self.authority)
            .finish_non_exhaustive()
    }
}

/// The account is tied to one certificate authority, so the file records
/// which one.
#[derive(Serialize, Deserialize)]
struct SavedAccount {
    directory: String,
    credentials: AccountCredentials,
}

/// The chain and key are saved together in one file, so a crash between two
/// writes can't leave a key that doesn't match its certificate.
#[derive(Serialize, Deserialize)]
struct SavedCertificate {
    name: ServerName,
    directory: String,
    chain_pem: String,
    key_pem: String,
}

#[derive(Debug, thiserror::Error)]
pub enum CertificateError {
    #[error(transparent)]
    Acme(#[from] AcmeError),
    #[error(
        "Accordion couldn't set up its connection to the DNS provider ({0}). Check that the \
         server has its system's root certificates installed."
    )]
    Dns(BoxError),
    #[error(
        "Accordion couldn't read {}: {source}. Check that Accordion can read its data folder.",
        path.display()
    )]
    Read { path: PathBuf, source: io::Error },
    #[error(
        "Accordion couldn't understand {}: {detail}. Restore the file from a backup, or set the \
         server's name again.",
        path.display()
    )]
    Damaged { path: PathBuf, detail: String },
    #[error(
        "Accordion couldn't save {}: {source}. Check that the data folder has free space and \
         that Accordion can write to it.",
        path.display()
    )]
    Save { path: PathBuf, source: io::Error },
}

/// How the certificate is doing, for the health page.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CertificateStatus {
    /// When the certificate being served expires and when Accordion renews
    /// it, or `None` until there's a certificate.
    pub validity: Option<Validity>,
    /// Whether Accordion is getting a certificate now.
    pub renewing: bool,
    /// How many renewals in a row have failed. A success resets it.
    pub failures: u32,
    /// Why the last renewal failed, until one succeeds.
    pub last_error: Option<String>,
    /// When Accordion tries again after a failure.
    pub retry_at: Option<SystemTime>,
}

/// Gets, stores, and renews the certificate for one name.
pub struct Renewer<D> {
    dir: PathBuf,
    name: ServerName,
    dns: D,
    directory: Directory,
    check: PropagationCheck,
    store: Arc<CertStore>,
    status: watch::Sender<CertificateStatus>,
}

impl Renewer<Provider> {
    /// A renewer for the saved settings, keeping its files in `dir` and
    /// serving the certificate from `store`.
    pub fn from_settings(
        dir: impl Into<PathBuf>,
        settings: &Settings,
        store: Arc<CertStore>,
    ) -> Result<Self, CertificateError> {
        let dns = Provider::new(settings.provider, settings.token.clone())
            .map_err(CertificateError::Dns)?;
        Ok(Self::new(
            dir,
            settings.name.clone(),
            dns,
            settings.authority.directory(),
            PropagationCheck::new(),
            store,
        ))
    }
}

impl<D: DnsProvider> Renewer<D> {
    pub fn new(
        dir: impl Into<PathBuf>,
        name: ServerName,
        dns: D,
        directory: Directory,
        check: PropagationCheck,
        store: Arc<CertStore>,
    ) -> Self {
        Self {
            dir: dir.into(),
            name,
            dns,
            directory,
            check,
            store,
            status: watch::Sender::default(),
        }
    }

    /// Follows the certificate's status as the renewer works.
    pub fn status(&self) -> watch::Receiver<CertificateStatus> {
        self.status.subscribe()
    }

    /// Loads the saved certificate into the store and returns when to renew
    /// it. Returns `None` if there's no certificate for this name and
    /// certificate authority, so the server needs to get one now.
    pub fn load(&self) -> Result<Option<SystemTime>, CertificateError> {
        let path = self.dir.join(CERTIFICATE_FILE);
        let Some(saved) = read_json::<SavedCertificate>(&path)? else {
            return Ok(None);
        };
        if saved.name != self.name || saved.directory != self.directory.url() {
            return Ok(None);
        }
        let damaged = |detail: String| CertificateError::Damaged {
            path: path.clone(),
            detail,
        };
        let validity = validity(&saved.chain_pem).map_err(|err| damaged(err.to_string()))?;
        self.store
            .set_pem(saved.chain_pem.as_bytes(), saved.key_pem.as_bytes())
            .map_err(|err| damaged(err.to_string()))?;
        self.status
            .send_modify(|status| status.validity = Some(validity));
        Ok(Some(validity.renew_at))
    }

    /// Gets a new certificate, saves it, and starts serving it. Returns when
    /// to renew it.
    pub async fn renew(&self) -> Result<SystemTime, CertificateError> {
        let account = self.account().await?;
        let cert = account.issue(&self.name, &self.dns, &self.check).await?;
        let validity = validity(&cert.chain_pem)?;
        self.store
            .set_pem(cert.chain_pem.as_bytes(), cert.key_pem.as_bytes())
            .map_err(|err| AcmeError::Certificate(err.to_string()))?;
        self.status
            .send_modify(|status| status.validity = Some(validity));
        let saved = SavedCertificate {
            name: self.name.clone(),
            directory: self.directory.url().to_owned(),
            chain_pem: cert.chain_pem,
            key_pem: cert.key_pem,
        };
        write_private_json(&self.dir.join(CERTIFICATE_FILE), &saved)?;
        Ok(validity.renew_at)
    }

    /// Keeps the certificate current until `shutdown` completes. Loads the
    /// saved certificate, gets a new one when it's due or missing, and
    /// retries failures with growing delays.
    pub async fn run(self, shutdown: impl Future<Output = ()>) {
        let mut shutdown = std::pin::pin!(shutdown);
        let mut due = match self.load() {
            Ok(Some(due)) => {
                info!(name = %self.name, "loaded the saved certificate");
                due
            }
            Ok(None) => SystemTime::now(),
            Err(err) => {
                warn!("{err} Accordion will get a new certificate.");
                SystemTime::now()
            }
        };
        let mut failures = 0;
        loop {
            let wait = due.duration_since(SystemTime::now()).unwrap_or_default();
            if !wait.is_zero() {
                tokio::select! {
                    () = &mut shutdown => return,
                    () = tokio::time::sleep(wait.min(MAX_SLEEP)) => continue,
                }
            }

            info!(name = %self.name, "getting a certificate");
            self.status.send_modify(|status| status.renewing = true);
            let result = tokio::select! {
                () = &mut shutdown => return,
                result = self.renew() => result,
            };
            match result {
                Ok(next) => {
                    failures = 0;
                    due = next;
                    self.status.send_modify(|status| {
                        status.renewing = false;
                        status.failures = 0;
                        status.last_error = None;
                        status.retry_at = None;
                    });
                    info!(
                        name = %self.name,
                        "got a certificate; Accordion will renew it in {} days",
                        days_until(next)
                    );
                }
                Err(err) => {
                    failures += 1;
                    let delay = retry::delay(failures, FIRST_RETRY_DELAY, MAX_RETRY_DELAY);
                    error!(
                        name = %self.name,
                        "{err} Accordion will try again in {} minutes.",
                        delay.as_secs() / 60
                    );
                    due = SystemTime::now() + delay;
                    self.status.send_modify(|status| {
                        status.renewing = false;
                        status.failures = failures;
                        status.last_error = Some(err.to_string());
                        status.retry_at = Some(due);
                    });
                }
            }
        }
    }

    async fn account(&self) -> Result<AcmeAccount, CertificateError> {
        let path = self.dir.join(ACCOUNT_FILE);
        if let Some(saved) = read_json::<SavedAccount>(&path)?
            && saved.directory == self.directory.url()
        {
            return Ok(AcmeAccount::from_credentials(&self.directory, saved.credentials).await?);
        }
        // Accounts hold no details about the household, so replacing one,
        // such as after switching from staging, loses nothing.
        let (account, credentials) = AcmeAccount::create(&self.directory).await?;
        let saved = SavedAccount {
            directory: self.directory.url().to_owned(),
            credentials,
        };
        write_private_json(&path, &saved)?;
        Ok(account)
    }
}

fn days_until(time: SystemTime) -> u64 {
    time.duration_since(SystemTime::now())
        .unwrap_or_default()
        .as_secs()
        / (24 * 60 * 60)
}

fn read_json<T: DeserializeOwned>(path: &Path) -> Result<Option<T>, CertificateError> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(CertificateError::Read {
                path: path.to_owned(),
                source,
            });
        }
    };
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|err| CertificateError::Damaged {
            path: path.to_owned(),
            detail: err.to_string(),
        })
}

fn write_private_json(path: &Path, value: &impl Serialize) -> Result<(), CertificateError> {
    let contents = serde_json::to_vec_pretty(value).expect("these types always serialize");
    write_private(path, &contents).map_err(|source| CertificateError::Save {
        path: path.to_owned(),
        source,
    })
}

/// Writes to a temporary file and renames it over `path`, so a crash leaves
/// either the old file or the new one, never half of one. Only the server's
/// user can read the file, because these files hold keys and tokens.
fn write_private(path: &Path, contents: &[u8]) -> io::Result<()> {
    if let Some(dir) = path.parent() {
        let mut builder = DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
        builder.create(dir)?;
    }
    let temp = path.with_extension("tmp");
    // A leftover from a crash might have other permissions, and the mode
    // below applies only to new files.
    match fs::remove_file(&temp) {
        Err(err) if err.kind() != io::ErrorKind::NotFound => return Err(err),
        _ => {}
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut file = options.open(&temp)?;
    file.write_all(contents)?;
    file.sync_all()?;
    fs::rename(&temp, path)
}

#[cfg(test)]
mod tests {
    use crate::dns::DnsError;

    use super::*;

    /// A provider for tests that never reach a certificate authority.
    struct NoDns;

    impl DnsProvider for NoDns {
        async fn set_txt(&self, _: &str, _: &str) -> Result<(), DnsError> {
            unreachable!()
        }

        async fn clear_txt(&self, _: &str) -> Result<(), DnsError> {
            unreachable!()
        }

        async fn set_address(&self, _: &str, _: std::net::IpAddr) -> Result<(), DnsError> {
            unreachable!()
        }

        fn propagation_delay(&self) -> Duration {
            Duration::ZERO
        }
    }

    fn renewer(dir: &Path, name: &str, directory: Directory) -> Renewer<NoDns> {
        Renewer::new(
            dir,
            name.parse().unwrap(),
            NoDns,
            directory,
            PropagationCheck::skip(),
            CertStore::new(),
        )
    }

    fn save_certificate(dir: &Path, name: &str, directory: &Directory) {
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::new(vec![name.to_owned()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let saved = SavedCertificate {
            name: name.parse().unwrap(),
            directory: directory.url().to_owned(),
            chain_pem: cert.pem(),
            key_pem: key.serialize_pem(),
        };
        write_private_json(&dir.join(CERTIFICATE_FILE), &saved).unwrap();
    }

    #[test]
    fn saves_settings_where_only_the_server_can_read_them() {
        let dir = tempfile::tempdir().unwrap();
        let gateway = dir.path().join("gateway");
        assert!(Settings::load(&gateway).unwrap().is_none());

        let settings = Settings {
            name: "accordion.example.com".parse().unwrap(),
            provider: ProviderKind::Desec,
            token: "secret".into(),
            authority: Authority::LetsEncryptStaging,
        };
        settings.save(&gateway).unwrap();
        let loaded = Settings::load(&gateway).unwrap().unwrap();
        assert_eq!(loaded.name, settings.name);
        assert_eq!(loaded.token, "secret");
        assert_eq!(loaded.authority, Authority::LetsEncryptStaging);
        assert!(!format!("{loaded:?}").contains("secret"));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = |path: &Path| fs::metadata(path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(&gateway), 0o700);
            assert_eq!(mode(&gateway.join(SETTINGS_FILE)), 0o600);
        }
    }

    #[test]
    fn explains_a_damaged_settings_file() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join(SETTINGS_FILE),
            r#"{"name": "accordion.local"}"#,
        )
        .unwrap();
        let err = Settings::load(dir.path()).unwrap_err();
        assert!(matches!(err, CertificateError::Damaged { .. }), "{err:?}");
        assert!(err.to_string().contains("private network"), "{err}");
    }

    #[test]
    fn loads_a_saved_certificate_for_the_same_name_and_authority() {
        let dir = tempfile::tempdir().unwrap();
        let staging = Directory::lets_encrypt_staging();
        save_certificate(dir.path(), "accordion.example.com", &staging);

        let same = renewer(dir.path(), "accordion.example.com", staging.clone());
        let status = same.status();
        assert!(same.load().unwrap().is_some());
        assert!(same.store.has_certificate());
        assert!(status.borrow().validity.is_some());

        let renamed = renewer(dir.path(), "home.example.com", staging);
        assert!(renamed.load().unwrap().is_none());
        assert!(!renamed.store.has_certificate());

        let production = renewer(
            dir.path(),
            "accordion.example.com",
            Directory::lets_encrypt(),
        );
        assert!(production.load().unwrap().is_none());
    }

    #[tokio::test]
    async fn reports_a_failed_renewal_and_when_it_retries() {
        let dir = tempfile::tempdir().unwrap();
        // Nothing listens on port 1, so getting an account fails at once.
        let unreachable = Directory::custom("https://127.0.0.1:1/dir", None);
        let renewer = renewer(dir.path(), "accordion.example.com", unreachable);
        let mut status = renewer.status();
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let running = tokio::spawn(renewer.run(async {
            let _ = stopped.await;
        }));

        let failed = status
            .wait_for(|status| status.failures == 1 && !status.renewing)
            .await
            .unwrap()
            .clone();
        stop.send(()).unwrap();
        running.await.unwrap();

        assert!(failed.validity.is_none());
        assert!(failed.last_error.is_some());
        let retry_in = failed
            .retry_at
            .unwrap()
            .duration_since(SystemTime::now())
            .unwrap();
        assert!(retry_in > FIRST_RETRY_DELAY - Duration::from_secs(60));
    }
}
