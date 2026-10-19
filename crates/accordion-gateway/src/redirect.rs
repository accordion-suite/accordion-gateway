//! Sends plain HTTP requests to the server's HTTPS name.
//!
//! After setup, port 80 serves only this redirect. It ignores the name the
//! request used, so `http://accordion.local` keeps working as a way to find
//! the server.

use axum::Router;
use axum::http::Uri;
use axum::response::Redirect;

use crate::ServerName;

/// Redirects to `name` on HTTPS `port`, which is 443 except in testing.
pub fn redirect_to_https(name: ServerName, port: u16) -> Router {
    let origin = if port == 443 {
        format!("https://{name}")
    } else {
        format!("https://{name}:{port}")
    };
    Router::new().fallback(move |uri: Uri| {
        let target = format!(
            "{origin}{}",
            uri.path_and_query().map_or("/", |path| path.as_str())
        );
        async move { Redirect::permanent(&target) }
    })
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::header::LOCATION;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    use super::*;

    #[tokio::test]
    async fn keeps_the_path_and_query() {
        let app = redirect_to_https("accordion.example.com".parse().unwrap(), 443);
        let request = Request::builder()
            .uri("/drive/files?sort=name")
            .header("host", "accordion.local")
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::PERMANENT_REDIRECT);
        assert_eq!(
            response.headers()[LOCATION],
            "https://accordion.example.com/drive/files?sort=name"
        );
    }

    #[tokio::test]
    async fn keeps_a_port_other_than_443() {
        let app = redirect_to_https("accordion.example.com".parse().unwrap(), 8443);
        let request = Request::builder()
            .uri("/")
            .header("host", "accordion.local:8080")
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(
            response.headers()[LOCATION],
            "https://accordion.example.com:8443/"
        );
    }
}
