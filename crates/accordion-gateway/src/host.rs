//! Answers only requests for the server's own names.
//!
//! In a DNS rebinding attack, a website the owner visits points its own name
//! at the server's address. The owner's browser then reaches Accordion while
//! treating it as that website, so the site's scripts can read the replies.
//! The browser still sends the website's name in the `Host` header, so
//! refusing unknown names blocks the attack. See decision 5.

use std::net::Ipv6Addr;
use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::http::header::HOST;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

/// The host names and addresses the server answers to.
///
/// After setup, that's the server's name. During setup, it's
/// `accordion.local` and the server's address on the home network.
#[derive(Clone, Debug)]
pub struct AllowedHosts {
    hosts: Arc<[String]>,
}

impl AllowedHosts {
    /// Each host is a name or an IP address, without a port.
    pub fn new<I, S>(hosts: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let hosts = hosts
            .into_iter()
            .map(|host| normalize_allowed(host.as_ref()))
            .collect();
        Self { hosts }
    }

    /// Whether a request for `authority` (a `Host` header value, with or
    /// without a port) is for this server.
    pub fn allows(&self, authority: &str) -> bool {
        host_without_port(authority).is_some_and(|host| self.hosts.contains(&host))
    }

    fn allows_request(&self, request: &Request) -> bool {
        // HTTP/2 carries the name in the URI's authority, and HTTP/1.1 in the
        // Host header. When both are present, both must match.
        let from_uri = request
            .uri()
            .authority()
            .map(|authority| authority.as_str());
        let from_header = request
            .headers()
            .get(HOST)
            .map(|value| value.to_str().unwrap_or(""));
        if from_uri.is_none() && from_header.is_none() {
            return false;
        }
        from_uri.is_none_or(|authority| self.allows(authority))
            && from_header.is_none_or(|authority| self.allows(authority))
    }
}

/// Middleware that refuses requests for any other host.
pub async fn reject_unknown_hosts(
    State(allowed): State<AllowedHosts>,
    request: Request,
    next: Next,
) -> Response {
    if !allowed.allows_request(&request) {
        return (
            StatusCode::MISDIRECTED_REQUEST,
            "Accordion only answers to its own name. Open it using that name, \
             not a network address or another name.",
        )
            .into_response();
    }
    next.run(request).await
}

/// Lowercase, without a trailing dot, and with IPv6 addresses in brackets,
/// which is how they appear in a Host header.
fn normalize_allowed(host: &str) -> String {
    match host.parse::<Ipv6Addr>() {
        Ok(address) => format!("[{address}]"),
        Err(_) => normalize_name(host),
    }
}

fn normalize_name(host: &str) -> String {
    host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase()
}

/// Splits off the port, if any. Returns `None` for values that aren't a valid
/// authority, such as an IPv6 address without brackets.
fn host_without_port(authority: &str) -> Option<String> {
    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        let (address, after) = rest.split_once(']')?;
        let address: Ipv6Addr = address.parse().ok()?;
        let port = match after {
            "" => None,
            _ => Some(after.strip_prefix(':')?),
        };
        (format!("[{address}]"), port)
    } else {
        match authority.split_once(':') {
            // A second colon means an IPv6 address without brackets, which
            // isn't valid in a Host header.
            Some((_, port)) if port.contains(':') => return None,
            Some((host, port)) => (normalize_name(host), Some(port)),
            None => (normalize_name(authority), None),
        }
    };
    let valid_port = |port: &str| !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit());
    if host.is_empty() || port.is_some_and(|port| !valid_port(port)) {
        return None;
    }
    Some(host)
}

#[cfg(test)]
mod tests {
    use axum::Router;
    use axum::body::Body;
    use axum::routing::get;
    use tower::ServiceExt;

    use super::*;

    fn allowed() -> AllowedHosts {
        AllowedHosts::new(["accordion.example.com", "192.168.1.10", "fd00::10"])
    }

    #[test]
    fn matches_names_with_or_without_a_port() {
        let allowed = allowed();
        assert!(allowed.allows("accordion.example.com"));
        assert!(allowed.allows("accordion.example.com:443"));
        assert!(allowed.allows("Accordion.Example.com."));
        assert!(allowed.allows("192.168.1.10:8443"));
        assert!(allowed.allows("[fd00::10]"));
        assert!(allowed.allows("[FD00:0::10]:443"));
    }

    #[test]
    fn refuses_other_hosts() {
        let allowed = allowed();
        assert!(!allowed.allows("evil.example.com"));
        assert!(!allowed.allows("accordion.example.com.evil.example"));
        assert!(!allowed.allows("192.168.1.11"));
        assert!(!allowed.allows(""));
        assert!(!allowed.allows("fd00::10"));
        assert!(!allowed.allows("accordion.example.com:"));
        assert!(!allowed.allows("accordion.example.com:https"));
        assert!(!allowed.allows("[fd00::10]x"));
    }

    async fn status_for(host: Option<&str>) -> StatusCode {
        let app = Router::new().route("/", get(|| async { "ok" })).layer(
            axum::middleware::from_fn_with_state(allowed(), reject_unknown_hosts),
        );
        let mut request = Request::builder().uri("/");
        if let Some(host) = host {
            request = request.header(HOST, host);
        }
        app.oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap()
            .status()
    }

    #[tokio::test]
    async fn middleware_passes_only_known_hosts() {
        assert_eq!(
            status_for(Some("accordion.example.com")).await,
            StatusCode::OK
        );
        assert_eq!(
            status_for(Some("evil.example.com")).await,
            StatusCode::MISDIRECTED_REQUEST
        );
        assert_eq!(status_for(None).await, StatusCode::MISDIRECTED_REQUEST);
    }

    #[tokio::test]
    async fn checks_the_uri_authority_too() {
        let app = Router::new().route("/", get(|| async { "ok" })).layer(
            axum::middleware::from_fn_with_state(allowed(), reject_unknown_hosts),
        );
        let request = Request::builder()
            .uri("https://evil.example.com/")
            .header(HOST, "accordion.example.com")
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::MISDIRECTED_REQUEST);
    }
}
