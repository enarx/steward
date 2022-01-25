use std::net::SocketAddr;

use axum::extract::TypedHeader;
use axum::headers::ContentType;
use axum::routing::post;
use axum::Router;
use hyper::StatusCode;
use mime::Mime;

const PKCS10: &str = "application/pkcs10";

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    tracing::debug!("listening on {}", addr);
    axum::Server::bind(&addr)
        .serve(app().into_make_service())
        .await
        .unwrap();
}

fn app() -> Router {
    Router::new().route("/attest", post(attest))
}

async fn attest(TypedHeader(ct): TypedHeader<ContentType>) -> Result<Vec<u8>, StatusCode> {
    let mime: Mime = PKCS10.parse().unwrap();
    if ct != ContentType::from(mime) {
        return Err(StatusCode::BAD_REQUEST);
    }

    Ok(Vec::new())
}

#[cfg(test)]
mod tests {
    mod attest {
        use super::super::*;

        use http::{header::CONTENT_TYPE, Request};
        use hyper::Body;
        use tower::ServiceExt; // for `app.oneshot()`

        #[tokio::test]
        async fn ok() {
            let request = Request::builder()
                .method("POST")
                .uri("/attest")
                .header(CONTENT_TYPE, PKCS10)
                .body(Body::empty())
                .unwrap();

            let response = app().oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);

            let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
            assert_eq!(&body[..], b"");
        }

        #[tokio::test]
        async fn err_no_content_type() {
            let request = Request::builder()
                .method("POST")
                .uri("/attest")
                .body(Body::empty())
                .unwrap();

            let response = app().oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }

        #[tokio::test]
        async fn err_bad_content_type() {
            let request = Request::builder()
                .method("POST")
                .header(CONTENT_TYPE, "text/plain")
                .uri("/attest")
                .body(Body::empty())
                .unwrap();

            let response = app().oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }
    }
}
