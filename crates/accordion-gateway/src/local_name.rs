//! Announcing `accordion.local` on the home network.
//!
//! People find the setup wizard at `http://accordion.local`, and after setup
//! that address redirects to the server's name (decision 5 in the `accordion`
//! repo's `docs/decisions`). Names ending in `.local` have no DNS server.
//! Devices look them up with multicast DNS (mDNS): they ask everyone on the
//! network, and the device that owns the name answers. Accordion answers for
//! `accordion.local` with its address on each network it's connected to.
//!
//! Two Accordion servers on one network can't both own the name. The one
//! that starts second finds the first and renames itself `accordion-2.local`,
//! as RFC 6762 describes.

use std::future::Future;
use std::time::Duration;

use mdns_sd::{DaemonEvent, RRType, ServiceDaemon, ServiceInfo};
use tokio::sync::watch;
use tracing::{info, warn};

/// The name Accordion announces, unless another device already uses it.
pub const LOCAL_NAME: &str = "accordion.local";

/// The standard port for multicast DNS.
const MDNS_PORT: u16 = 5353;

/// Accordion also announces itself as a website, so it shows up in apps
/// that list the services on a network.
const SERVICE_TYPE: &str = "_http._tcp.local.";
const INSTANCE_NAME: &str = "Accordion";

/// How long to wait for the goodbye message at shutdown, which tells other
/// devices to forget the name now rather than when their caches expire.
const GOODBYE_TIMEOUT: Duration = Duration::from_secs(2);

/// Whether `host` is a name this server may announce: `accordion.local`, or
/// `accordion-2.local` and so on after a conflict. Names ending in `.local`
/// resolve only on the home network, so a website can't point one at the
/// server.
pub fn is_local_name(host: &str) -> bool {
    let host = host.to_ascii_lowercase();
    let Some(label) = host.strip_suffix(".local") else {
        return false;
    };
    match label.strip_prefix("accordion") {
        Some("") => true,
        Some(suffix) => suffix
            .strip_prefix('-')
            .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit())),
        None => false,
    }
}

/// How the announcement is doing, for the health page.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LocalNameStatus {
    /// Answering for `name`.
    Announcing { name: String },
    /// Multicast DNS isn't working, for this reason.
    Failed { error: String },
}

/// Announces the name until it's stopped.
pub struct LocalName {
    daemon: ServiceDaemon,
    service: String,
    events: mdns_sd::Receiver<DaemonEvent>,
    status: watch::Sender<LocalNameStatus>,
}

impl LocalName {
    /// Starts announcing `accordion.local`, and a website on `http_port`.
    pub fn announce(http_port: u16) -> Result<Self, mdns_sd::Error> {
        Self::announce_on(MDNS_PORT, http_port)
    }

    fn announce_on(mdns_port: u16, http_port: u16) -> Result<Self, mdns_sd::Error> {
        let daemon = ServiceDaemon::new_with_port(mdns_port)?;
        // Subscribe before registering, so no name change is missed.
        let events = daemon.monitor()?;
        let service = ServiceInfo::new(
            SERVICE_TYPE,
            INSTANCE_NAME,
            &format!("{LOCAL_NAME}."),
            "",
            http_port,
            None,
        )?
        // Answer with the address of the network each question came from,
        // and follow the machine's addresses as they change.
        .enable_addr_auto();
        let fullname = service.get_fullname().to_owned();
        daemon.register(service)?;
        Ok(Self {
            daemon,
            service: fullname,
            events,
            status: watch::Sender::new(LocalNameStatus::Announcing {
                name: LOCAL_NAME.to_owned(),
            }),
        })
    }

    /// Follows the announcement's status.
    pub fn status(&self) -> watch::Receiver<LocalNameStatus> {
        self.status.subscribe()
    }

    /// Keeps announcing until `shutdown` completes, then says goodbye.
    pub async fn run(self, shutdown: impl Future<Output = ()>) {
        let mut shutdown = std::pin::pin!(shutdown);
        let mut name = LOCAL_NAME.to_owned();
        loop {
            let event = tokio::select! {
                () = &mut shutdown => break,
                event = self.events.recv_async() => event,
            };
            match event {
                Ok(DaemonEvent::NameChange(change))
                    if matches!(change.rr_type, RRType::A | RRType::AAAA) =>
                {
                    let new_name = change.new_name.trim_end_matches('.').to_owned();
                    if new_name != name {
                        info!(
                            "Another device on the network already uses {name}, so Accordion \
                             is using {new_name} instead."
                        );
                        name = new_name;
                    }
                    self.status
                        .send_replace(LocalNameStatus::Announcing { name: name.clone() });
                }
                Ok(DaemonEvent::Announce(..)) => {
                    // The first announcement after a failure means it works
                    // again.
                    self.status.send_if_modified(|status| {
                        let announcing = LocalNameStatus::Announcing { name: name.clone() };
                        let changed = *status != announcing;
                        *status = announcing;
                        changed
                    });
                }
                Ok(DaemonEvent::Error(err)) => {
                    warn!(
                        "Accordion couldn't announce {name} on the network ({err}). Devices can \
                         still reach the server by its address."
                    );
                    self.status.send_replace(LocalNameStatus::Failed {
                        error: err.to_string(),
                    });
                }
                Ok(_) => {}
                // The daemon stopped on its own, so there's nothing left to
                // say goodbye with.
                Err(_) => return,
            }
        }

        if let Ok(goodbye) = self.daemon.unregister(&self.service) {
            let _ = tokio::time::timeout(GOODBYE_TIMEOUT, goodbye.recv_async()).await;
        }
        if let Ok(stopped) = self.daemon.shutdown() {
            let _ = tokio::time::timeout(GOODBYE_TIMEOUT, stopped.recv_async()).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use mdns_sd::HostnameResolutionEvent;

    use super::*;

    #[test]
    fn knows_its_own_names() {
        for name in ["accordion.local", "Accordion.Local", "accordion-2.local"] {
            assert!(is_local_name(name), "{name}");
        }
        for name in [
            "accordion",
            "accordion.example.com",
            "accordion-.local",
            "accordion-x.local",
            "accordionx.local",
            "evil.accordion.local",
            "printer.local",
        ] {
            assert!(!is_local_name(name), "{name}");
        }
    }

    /// Announces and looks up the name on a spare port, so the test doesn't
    /// disturb the machine's own mDNS service. The system loops multicast
    /// back to the machine that sent it, so this works on networks that
    /// don't carry multicast.
    #[tokio::test]
    async fn answers_for_accordion_local() {
        let port = 15353;
        let local = LocalName::announce_on(port, 80).unwrap();
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let running = tokio::spawn(local.run(async {
            let _ = stopped.await;
        }));

        let client = ServiceDaemon::new_with_port(port).unwrap();
        let events = client
            .resolve_hostname(&format!("{LOCAL_NAME}."), Some(5000))
            .unwrap();
        let found = loop {
            match events.recv_async().await.unwrap() {
                HostnameResolutionEvent::AddressesFound(_, addresses) => break addresses,
                HostnameResolutionEvent::SearchTimeout(_) => panic!("nothing answered"),
                _ => {}
            }
        };
        assert!(!found.is_empty());

        let _ = client.shutdown();
        stop.send(()).unwrap();
        running.await.unwrap();
    }
}
