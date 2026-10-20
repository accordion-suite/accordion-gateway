//! deSEC (desec.io), a DNS host run by a nonprofit. It offered free
//! subdomains under `dedyn.io`, but has suspended new ones.
//!
//! API reference: <https://desec.readthedocs.io/en/latest/dns/rrsets.html>.
//! The admin guide should explain how to limit the token with token policies
//! to two records: the `_acme-challenge` TXT record and the name's A record.

use std::fmt;
use std::net::IpAddr;
use std::time::Duration;

use hyper::{Method, StatusCode};
use serde::Deserialize;
use serde_json::json;

use super::{ADDRESS_TTL, DnsError, DnsProvider, address_type, short_detail};
use crate::http::{BoxError, Client, Reply};

const PROVIDER: &str = "deSEC";
const API: &str = "https://desec.io/api/v1";

/// Both nameservers are anycast, so Accordion's check reaches the copies near
/// the server, while Let's Encrypt checks from other places whose copies can
/// lag behind. Accordion waits for both nameservers, then this long more. On
/// October 20, 2026, 30 seconds wasn't enough: Let's Encrypt still got
/// NXDOMAIN. Other deSEC users report that waits of 2–5 minutes work.
const PROPAGATION_DELAY: Duration = Duration::from_secs(120);

#[derive(Clone)]
pub struct Desec {
    client: Client,
    api: String,
    token: String,
}

/// The deSEC domain that a record belongs to.
#[derive(Debug, Deserialize)]
struct Domain {
    name: String,
    minimum_ttl: u32,
}

/// The parts of an RRset that Accordion compares.
#[derive(Debug, Deserialize)]
struct Rrset {
    ttl: u32,
    records: Vec<String>,
}

impl Desec {
    pub fn new(token: impl Into<String>) -> Result<Self, BoxError> {
        Ok(Self {
            client: Client::new()?,
            api: API.to_owned(),
            token: token.into(),
        })
    }

    #[cfg(test)]
    fn with_api(api: &str, token: &str) -> Self {
        Self {
            client: Client::allowing_http(),
            api: api.to_owned(),
            token: token.to_owned(),
        }
    }

    async fn domain_for(&self, record: &str) -> Result<Domain, DnsError> {
        let url = format!("{}/domains/?owns_qname={record}", self.api);
        let reply = self.send(Method::GET, &url, None).await?;
        check(&reply, record)?;
        let mut domains: Vec<Domain> =
            serde_json::from_slice(&reply.body).map_err(|err| DnsError::Rejected {
                provider: PROVIDER,
                status: reply.status.as_u16(),
                detail: format!("unexpected reply: {err}"),
            })?;
        domains.pop().ok_or_else(|| DnsError::NoZone {
            provider: PROVIDER,
            name: record.to_owned(),
        })
    }

    /// The RRset at `subname` with this type, or `None` if there isn't one.
    async fn rrset(
        &self,
        domain: &str,
        subname: &str,
        kind: &str,
        record: &str,
    ) -> Result<Option<Rrset>, DnsError> {
        // deSEC names the domain's own RRsets "@" in URLs.
        let subname = if subname.is_empty() { "@" } else { subname };
        let url = format!("{}/domains/{domain}/rrsets/{subname}/{kind}/", self.api);
        let reply = self.send(Method::GET, &url, None).await?;
        if reply.status == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        check(&reply, record)?;
        serde_json::from_slice(&reply.body)
            .map(Some)
            .map_err(|err| DnsError::Rejected {
                provider: PROVIDER,
                status: reply.status.as_u16(),
                detail: format!("unexpected reply: {err}"),
            })
    }

    /// Changes one RRset with the bulk endpoint, which creates the RRset if
    /// it's missing.
    async fn write_rrset(
        &self,
        method: Method,
        domain: &str,
        rrset: serde_json::Value,
        record: &str,
    ) -> Result<(), DnsError> {
        let url = format!("{}/domains/{domain}/rrsets/", self.api);
        let reply = self.send(method, &url, Some(json!([rrset]))).await?;
        check(&reply, record)
    }

    async fn send(
        &self,
        method: Method,
        url: &str,
        body: Option<serde_json::Value>,
    ) -> Result<Reply, DnsError> {
        let authorization = format!("Token {}", self.token);
        self.client
            .send_json(method, url, &authorization, body.as_ref())
            .await
            .map_err(|source| DnsError::Unreachable {
                provider: PROVIDER,
                source,
            })
    }
}

/// The part of `record` below the domain, or an empty string for the
/// domain itself.
fn subname<'a>(record: &'a str, domain: &str) -> &'a str {
    if record == domain {
        return "";
    }
    record
        .strip_suffix(domain)
        .and_then(|rest| rest.strip_suffix('.'))
        .unwrap_or(record)
}

fn check(reply: &Reply, record: &str) -> Result<(), DnsError> {
    match reply.status {
        status if status.is_success() => Ok(()),
        StatusCode::UNAUTHORIZED => Err(DnsError::Unauthorized { provider: PROVIDER }),
        StatusCode::FORBIDDEN => Err(DnsError::Forbidden {
            provider: PROVIDER,
            record: record.to_owned(),
        }),
        StatusCode::NOT_FOUND => Err(DnsError::NoZone {
            provider: PROVIDER,
            name: record.to_owned(),
        }),
        status => Err(DnsError::Rejected {
            provider: PROVIDER,
            status: status.as_u16(),
            detail: short_detail(&String::from_utf8_lossy(&reply.body)),
        }),
    }
}

impl DnsProvider for Desec {
    async fn set_txt(&self, record: &str, value: &str) -> Result<(), DnsError> {
        let domain = self.domain_for(record).await?;
        let rrset = json!({
            "subname": subname(record, &domain.name),
            "type": "TXT",
            // Challenge records are short-lived, so use the lowest TTL the
            // domain allows.
            "ttl": domain.minimum_ttl,
            // deSEC wants TXT contents in quotes. ACME values are base64url,
            // so they never contain quotes or backslashes.
            "records": [format!("\"{value}\"")],
        });
        self.write_rrset(Method::PUT, &domain.name, rrset, record)
            .await
    }

    async fn clear_txt(&self, record: &str) -> Result<(), DnsError> {
        let domain = self.domain_for(record).await?;
        let rrset =
            json!({ "subname": subname(record, &domain.name), "type": "TXT", "records": [] });
        self.write_rrset(Method::PATCH, &domain.name, rrset, record)
            .await
    }

    async fn set_address(&self, name: &str, address: IpAddr) -> Result<(), DnsError> {
        let domain = self.domain_for(name).await?;
        let subname = subname(name, &domain.name);
        let kind = address_type(address);
        let ttl = ADDRESS_TTL.max(domain.minimum_ttl);
        // Leave a correct record alone, so a restart doesn't write to DNS or
        // count against deSEC's limits on changes.
        if let Some(current) = self.rrset(&domain.name, subname, kind, name).await? {
            let same_address = match current.records.as_slice() {
                [record] => record.parse() == Ok(address),
                _ => false,
            };
            if same_address && current.ttl == ttl {
                return Ok(());
            }
        }
        let rrset = json!({
            "subname": subname,
            "type": kind,
            "ttl": ttl,
            "records": [address.to_string()],
        });
        self.write_rrset(Method::PUT, &domain.name, rrset, name)
            .await
    }

    fn propagation_delay(&self) -> Duration {
        PROPAGATION_DELAY
    }
}

// Keeps the token out of logs.
impl fmt::Debug for Desec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Desec")
            .field("api", &self.api)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use axum::Router;
    use axum::extract::{Path, Query, State};
    use axum::http::HeaderMap;
    use axum::http::header::AUTHORIZATION;
    use axum::routing::{get, put};
    use serde_json::Value;

    use super::*;

    /// A stand-in for the deSEC API that owns `example.com` and records
    /// every write.
    #[derive(Clone, Default)]
    struct FakeDesec {
        writes: Arc<Mutex<Vec<(String, Value)>>>,
    }

    async fn start(status: StatusCode) -> (Desec, FakeDesec) {
        let fake = FakeDesec::default();
        let app = Router::new()
            .route(
                "/domains/",
                get(move |headers: HeaderMap, Query(query): Query<Vec<(String, String)>>| async move {
                    if headers[AUTHORIZATION] != "Token secret" {
                        return (StatusCode::UNAUTHORIZED, "[]".to_owned());
                    }
                    let qname = &query.iter().find(|(key, _)| key == "owns_qname").unwrap().1;
                    let owned = qname == "example.com" || qname.ends_with(".example.com");
                    let body = if owned { r#"[{"name": "example.com", "minimum_ttl": 3600}]"# } else { "[]" };
                    (StatusCode::OK, body.to_owned())
                }),
            )
            .route(
                "/domains/example.com/rrsets/",
                put(record_write).patch(record_write),
            )
            .route(
                "/domains/example.com/rrsets/{subname}/{kind}/",
                get(read_rrset),
            )
            .with_state((fake.clone(), status));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let api = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (Desec::with_api(&api, "secret"), fake)
    }

    async fn record_write(
        State((fake, status)): State<(FakeDesec, StatusCode)>,
        method: Method,
        body: String,
    ) -> (StatusCode, &'static str) {
        fake.writes
            .lock()
            .unwrap()
            .push((method.to_string(), serde_json::from_str(&body).unwrap()));
        (status, r#"{"detail": "Throttled."}"#)
    }

    /// Answers with the latest write to the RRset, as deSEC would.
    async fn read_rrset(
        State((fake, _)): State<(FakeDesec, StatusCode)>,
        Path((subname, kind)): Path<(String, String)>,
    ) -> (StatusCode, String) {
        let subname = if subname == "@" { "" } else { &subname };
        let writes = fake.writes.lock().unwrap();
        let latest = writes
            .iter()
            .rev()
            .map(|(_, body)| &body[0])
            .find(|rrset| rrset["subname"] == subname && rrset["type"] == kind.as_str());
        match latest {
            Some(rrset) => (StatusCode::OK, rrset.to_string()),
            None => (
                StatusCode::NOT_FOUND,
                r#"{"detail": "Not found."}"#.to_owned(),
            ),
        }
    }

    #[tokio::test]
    async fn sets_and_clears_the_challenge_record() {
        let (desec, fake) = start(StatusCode::OK).await;
        let record = "_acme-challenge.accordion.example.com";

        desec.set_txt(record, "abc123").await.unwrap();
        desec.clear_txt(record).await.unwrap();

        let writes = fake.writes.lock().unwrap();
        assert_eq!(writes[0].0, "PUT");
        assert_eq!(
            writes[0].1,
            json!([{ "subname": "_acme-challenge.accordion", "type": "TXT", "ttl": 3600, "records": ["\"abc123\""] }])
        );
        assert_eq!(writes[1].0, "PATCH");
        assert_eq!(
            writes[1].1,
            json!([{ "subname": "_acme-challenge.accordion", "type": "TXT", "records": [] }])
        );
    }

    #[tokio::test]
    async fn points_the_name_at_the_server() {
        let (desec, fake) = start(StatusCode::OK).await;

        desec
            .set_address("accordion.example.com", "192.168.1.20".parse().unwrap())
            .await
            .unwrap();
        desec
            .set_address("example.com", "fd00::20".parse().unwrap())
            .await
            .unwrap();

        let writes = fake.writes.lock().unwrap();
        assert_eq!(writes.len(), 2);
        assert_eq!(
            writes[0],
            (
                "PUT".into(),
                json!([{ "subname": "accordion", "type": "A", "ttl": 3600, "records": ["192.168.1.20"] }])
            )
        );
        assert_eq!(
            writes[1].1,
            json!([{ "subname": "", "type": "AAAA", "ttl": 3600, "records": ["fd00::20"] }])
        );
    }

    #[tokio::test]
    async fn leaves_a_correct_address_alone() {
        let (desec, fake) = start(StatusCode::OK).await;
        let name = "accordion.example.com";

        desec
            .set_address(name, "192.168.1.20".parse().unwrap())
            .await
            .unwrap();
        desec
            .set_address(name, "192.168.1.20".parse().unwrap())
            .await
            .unwrap();
        desec
            .set_address(name, "192.168.1.21".parse().unwrap())
            .await
            .unwrap();

        let writes = fake.writes.lock().unwrap();
        let addresses: Vec<_> = writes
            .iter()
            .map(|(_, body)| &body[0]["records"][0])
            .collect();
        assert_eq!(addresses, ["192.168.1.20", "192.168.1.21"]);
    }

    #[tokio::test]
    async fn explains_problems() {
        let (desec, _) = start(StatusCode::TOO_MANY_REQUESTS).await;
        let throttled = desec.set_txt("_acme-challenge.example.com", "abc").await;
        assert!(
            matches!(throttled, Err(DnsError::Rejected { status: 429, .. })),
            "{throttled:?}"
        );

        let missing = desec.set_txt("_acme-challenge.example.org", "abc").await;
        assert!(
            matches!(missing, Err(DnsError::NoZone { .. })),
            "{missing:?}"
        );

        let wrong_token = Desec {
            token: "wrong".into(),
            ..desec
        };
        let refused = wrong_token
            .set_txt("_acme-challenge.example.com", "abc")
            .await;
        assert!(
            matches!(refused, Err(DnsError::Unauthorized { .. })),
            "{refused:?}"
        );
    }

    #[test]
    fn finds_the_subname() {
        assert_eq!(
            subname("_acme-challenge.ourhome.dedyn.io", "ourhome.dedyn.io"),
            "_acme-challenge"
        );
        assert_eq!(
            subname("_acme-challenge.a.example.com", "example.com"),
            "_acme-challenge.a"
        );
        assert_eq!(subname("example.com", "example.com"), "");
    }

    #[test]
    fn debug_output_hides_the_token() {
        let desec = Desec::with_api("http://localhost", "secret");
        assert!(!format!("{desec:?}").contains("secret"));
    }
}
