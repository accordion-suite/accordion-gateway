//! A small HTTPS client for DNS provider APIs.

use std::error::Error;
use std::sync::Arc;
use std::time::Duration;

use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::header::{AUTHORIZATION, CONTENT_TYPE};
use hyper::{Method, Request, StatusCode};
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::client::legacy::Client as LegacyClient;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;

/// A provider that doesn't answer in this time is treated as unreachable, so
/// a hung connection can't stall certificate renewal.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

pub(crate) type BoxError = Box<dyn Error + Send + Sync>;

#[derive(Clone)]
pub(crate) struct Client {
    inner: LegacyClient<HttpsConnector<HttpConnector>, Full<Bytes>>,
}

pub(crate) struct Reply {
    pub status: StatusCode,
    pub body: Bytes,
}

impl Client {
    /// Trusts the operating system's certificate authorities, like the ACME
    /// client does.
    pub fn new() -> Result<Self, BoxError> {
        let connector = HttpsConnectorBuilder::new()
            .with_provider_and_platform_verifier(
                Arc::new(rustls::crypto::ring::default_provider()),
            )?
            .https_only()
            .enable_http1()
            .enable_http2()
            .build();
        Ok(Self::with_connector(connector))
    }

    /// For tests against a local plain HTTP server.
    #[cfg(test)]
    pub fn allowing_http() -> Self {
        let connector = HttpsConnectorBuilder::new()
            .with_provider_and_platform_verifier(Arc::new(rustls::crypto::ring::default_provider()))
            .unwrap()
            .https_or_http()
            .enable_http1()
            .build();
        Self::with_connector(connector)
    }

    fn with_connector(connector: HttpsConnector<HttpConnector>) -> Self {
        Self {
            inner: LegacyClient::builder(TokioExecutor::new()).build(connector),
        }
    }

    /// Sends a request with an `Authorization` header and, if given, a JSON
    /// body. That's the shape of every DNS provider API call.
    pub async fn send_json(
        &self,
        method: Method,
        url: &str,
        authorization: &str,
        body: Option<&serde_json::Value>,
    ) -> Result<Reply, BoxError> {
        let mut request = Request::builder()
            .method(method)
            .uri(url)
            .header(AUTHORIZATION, authorization);
        let body = match body {
            Some(body) => {
                request = request.header(CONTENT_TYPE, "application/json");
                Bytes::from(body.to_string())
            }
            None => Bytes::new(),
        };
        self.send(request.body(Full::new(body))?).await
    }

    async fn send(&self, request: Request<Full<Bytes>>) -> Result<Reply, BoxError> {
        let exchange = async {
            let response = self.inner.request(request).await?;
            let status = response.status();
            let body = response.into_body().collect().await?.to_bytes();
            Ok::<_, BoxError>(Reply { status, body })
        };
        tokio::time::timeout(REQUEST_TIMEOUT, exchange)
            .await
            .map_err(|_| format!("no answer within {} seconds", REQUEST_TIMEOUT.as_secs()))?
    }
}
