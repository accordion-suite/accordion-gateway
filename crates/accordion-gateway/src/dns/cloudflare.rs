//! Cloudflare, where many households already keep their domain's DNS.
//!
//! API reference: <https://developers.cloudflare.com/api/resources/dns/>.
//! The token needs **Zone > DNS > Edit** and **Zone > Zone > Read**, limited to
//! the one domain. Account API tokens and user API tokens both work. Cloudflare
//! recommends account tokens for servers, because they don't belong to one
//! person. Cloudflare can't limit a token to a single record, so the
//! token can change any record in that domain. Households who want a narrower
//! token can point `_acme-challenge` at a deSEC name with a CNAME instead.

use std::fmt;
use std::time::Duration;

use hyper::{Method, StatusCode};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::json;

use super::{DnsError, DnsProvider, short_detail};
use crate::http::{BoxError, Client, Reply};

const PROVIDER: &str = "Cloudflare";
const API: &str = "https://api.cloudflare.com/client/v4";

/// The shortest TTL Cloudflare allows on most plans. Challenge records are
/// short-lived, so there's no reason to cache them longer.
const TTL: u32 = 60;

/// Cloudflare says changes usually reach all of its nameservers within
/// seconds. Accordion waits for the nearest ones, then this long more.
const PROPAGATION_DELAY: Duration = Duration::from_secs(10);

/// Cloudflare error codes that mean the token itself is wrong, rather than
/// missing a permission: an invalid token, and a malformed one.
const BAD_TOKEN_CODES: &[u32] = &[9109, 6003, 6111];

#[derive(Clone)]
pub struct Cloudflare {
    client: Client,
    api: String,
    token: String,
}

/// Every Cloudflare reply has this shape.
#[derive(Deserialize)]
struct Envelope<T> {
    success: bool,
    #[serde(default)]
    errors: Vec<ApiError>,
    result: Option<T>,
}

#[derive(Deserialize)]
struct ApiError {
    code: u32,
    message: String,
}

#[derive(Deserialize)]
struct Zone {
    id: String,
}

#[derive(Deserialize)]
struct Record {
    id: String,
}

impl Cloudflare {
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

    /// Finds the zone that holds `record` by trying each parent name, from
    /// the longest down to two labels, since a zone is never a bare
    /// top-level domain.
    async fn zone_for(&self, record: &str) -> Result<Zone, DnsError> {
        let mut candidate = record;
        while let Some((_, parent)) = candidate.split_once('.') {
            if !parent.contains('.') {
                break;
            }
            let url = format!("{}/zones?name={parent}", self.api);
            let zones: Vec<Zone> = self.call(Method::GET, &url, None, record).await?;
            if let Some(zone) = zones.into_iter().next() {
                return Ok(zone);
            }
            candidate = parent;
        }
        Err(DnsError::NoZone {
            provider: PROVIDER,
            name: record.to_owned(),
        })
    }

    async fn delete_txt(&self, zone: &Zone, record: &str) -> Result<(), DnsError> {
        let url = format!(
            "{}/zones/{}/dns_records?type=TXT&name={record}",
            self.api, zone.id
        );
        let existing: Vec<Record> = self.call(Method::GET, &url, None, record).await?;
        for old in existing {
            let url = format!("{}/zones/{}/dns_records/{}", self.api, zone.id, old.id);
            self.call::<serde_json::Value>(Method::DELETE, &url, None, record)
                .await?;
        }
        Ok(())
    }

    async fn call<T: DeserializeOwned>(
        &self,
        method: Method,
        url: &str,
        body: Option<serde_json::Value>,
        record: &str,
    ) -> Result<T, DnsError> {
        let authorization = format!("Bearer {}", self.token);
        let reply = self
            .client
            .send_json(method, url, &authorization, body.as_ref())
            .await
            .map_err(|source| DnsError::Unreachable {
                provider: PROVIDER,
                source,
            })?;
        parse(&reply, record)
    }
}

fn parse<T: DeserializeOwned>(reply: &Reply, record: &str) -> Result<T, DnsError> {
    let envelope: Option<Envelope<T>> = serde_json::from_slice(&reply.body).ok();
    let (success, errors, result) = match envelope {
        Some(envelope) => (envelope.success, envelope.errors, envelope.result),
        None => (false, Vec::new(), None),
    };
    if reply.status.is_success()
        && success
        && let Some(result) = result
    {
        return Ok(result);
    }

    let bad_token = errors
        .iter()
        .any(|error| BAD_TOKEN_CODES.contains(&error.code));
    match reply.status {
        StatusCode::UNAUTHORIZED => Err(DnsError::Unauthorized { provider: PROVIDER }),
        _ if bad_token => Err(DnsError::Unauthorized { provider: PROVIDER }),
        StatusCode::FORBIDDEN => Err(DnsError::Forbidden {
            provider: PROVIDER,
            record: record.to_owned(),
        }),
        status => {
            let detail = if errors.is_empty() {
                String::from_utf8_lossy(&reply.body).into_owned()
            } else {
                errors
                    .iter()
                    .map(|error| format!("{} (code {})", error.message, error.code))
                    .collect::<Vec<_>>()
                    .join("; ")
            };
            Err(DnsError::Rejected {
                provider: PROVIDER,
                status: status.as_u16(),
                detail: short_detail(&detail),
            })
        }
    }
}

impl DnsProvider for Cloudflare {
    async fn set_txt(&self, record: &str, value: &str) -> Result<(), DnsError> {
        let zone = self.zone_for(record).await?;
        // Remove leftovers from an earlier attempt, so the authority sees
        // only the current value.
        self.delete_txt(&zone, record).await?;
        let url = format!("{}/zones/{}/dns_records", self.api, zone.id);
        let body = json!({
            "type": "TXT",
            "name": record,
            // Cloudflare recommends quoting TXT content. ACME values are
            // base64url, so they never contain quotes or backslashes.
            "content": format!("\"{value}\""),
            "ttl": TTL,
        });
        self.call::<serde_json::Value>(Method::POST, &url, Some(body), record)
            .await?;
        Ok(())
    }

    async fn clear_txt(&self, record: &str) -> Result<(), DnsError> {
        let zone = self.zone_for(record).await?;
        self.delete_txt(&zone, record).await
    }

    fn propagation_delay(&self) -> Duration {
        PROPAGATION_DELAY
    }
}

// Keeps the token out of logs.
impl fmt::Debug for Cloudflare {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Cloudflare")
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
    use axum::routing::{delete, get};
    use serde_json::Value;

    use super::*;

    /// A stand-in for the Cloudflare API with one zone, `example.com`, that
    /// already has a stale challenge record. It records every change.
    #[derive(Clone, Default)]
    struct FakeCloudflare {
        changes: Arc<Mutex<Vec<String>>>,
        created: Arc<Mutex<Vec<Value>>>,
    }

    fn ok(result: Value) -> (StatusCode, String) {
        let body = json!({ "success": true, "errors": [], "result": result });
        (StatusCode::OK, body.to_string())
    }

    fn authorized(headers: &HeaderMap) -> Result<(), (StatusCode, String)> {
        if headers[AUTHORIZATION] == "Bearer secret" {
            return Ok(());
        }
        let body = json!({
            "success": false,
            "errors": [{ "code": 9109, "message": "Invalid access token" }],
            "result": null,
        });
        Err((StatusCode::FORBIDDEN, body.to_string()))
    }

    async fn start() -> (Cloudflare, FakeCloudflare) {
        let fake = FakeCloudflare::default();
        let app = Router::new()
            .route(
                "/zones",
                get(
                    |headers: HeaderMap, Query(query): Query<Vec<(String, String)>>| async move {
                        if let Err(denied) = authorized(&headers) {
                            return denied;
                        }
                        match query.iter().find(|(key, _)| key == "name") {
                            Some((_, name)) if name == "example.com" => {
                                ok(json!([{ "id": "zone1", "name": "example.com" }]))
                            }
                            _ => ok(json!([])),
                        }
                    },
                ),
            )
            .route(
                "/zones/zone1/dns_records",
                get(|| async { ok(json!([{ "id": "stale" }])) }).post(
                    |State(fake): State<FakeCloudflare>, body: String| async move {
                        fake.changes.lock().unwrap().push("create".into());
                        fake.created
                            .lock()
                            .unwrap()
                            .push(serde_json::from_str(&body).unwrap());
                        ok(json!({ "id": "new" }))
                    },
                ),
            )
            .route(
                "/zones/zone1/dns_records/{id}",
                delete(
                    |State(fake): State<FakeCloudflare>, Path(id): Path<String>| async move {
                        fake.changes.lock().unwrap().push(format!("delete {id}"));
                        ok(json!({ "id": id }))
                    },
                ),
            )
            .with_state(fake.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let api = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (Cloudflare::with_api(&api, "secret"), fake)
    }

    #[tokio::test]
    async fn replaces_and_clears_the_challenge_record() {
        let (cloudflare, fake) = start().await;
        let record = "_acme-challenge.accordion.example.com";

        cloudflare.set_txt(record, "abc123").await.unwrap();
        cloudflare.clear_txt(record).await.unwrap();

        assert_eq!(
            *fake.changes.lock().unwrap(),
            ["delete stale", "create", "delete stale"]
        );
        assert_eq!(
            fake.created.lock().unwrap()[0],
            json!({ "type": "TXT", "name": record, "content": "\"abc123\"", "ttl": 60 })
        );
    }

    #[tokio::test]
    async fn explains_problems() {
        let (cloudflare, _) = start().await;
        let missing = cloudflare
            .set_txt("_acme-challenge.example.org", "abc")
            .await;
        assert!(
            matches!(missing, Err(DnsError::NoZone { .. })),
            "{missing:?}"
        );

        let wrong_token = Cloudflare {
            token: "wrong".into(),
            ..cloudflare
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
    fn reports_cloudflare_errors() {
        let reply = Reply {
            status: StatusCode::BAD_REQUEST,
            body: json!({
                "success": false,
                "errors": [{ "code": 81058, "message": "An identical record already exists." }],
                "result": null,
            })
            .to_string()
            .into(),
        };
        let result = parse::<Value>(&reply, "_acme-challenge.example.com");
        match result {
            Err(DnsError::Rejected { status, detail, .. }) => {
                assert_eq!(status, 400);
                assert_eq!(detail, "An identical record already exists. (code 81058)");
            }
            other => panic!("expected a rejection, got {other:?}"),
        }
    }

    #[test]
    fn debug_output_hides_the_token() {
        let cloudflare = Cloudflare::with_api("http://localhost", "secret");
        assert!(!format!("{cloudflare:?}").contains("secret"));
    }
}
