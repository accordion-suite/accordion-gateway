//! Sends plain HTTP requests to the server's HTTPS name.
//!
//! After setup, port 80 serves only this redirect. It ignores the name the
//! request used, so `http://accordion.local` keeps working as a way to find
//! the server.

use axum::Router;
use axum::http::Uri;
use axum::response::Redirect;

use crate::ServerName;

pub fn redirect_to_https(name: ServerName) -> Router {
    Router::new().fallback(move |uri: Uri| {
        let target = format!(
            "https://{name}{}",
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
        let app = redirect_to_https("accordion.example.com".parse().unwrap());
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
}
