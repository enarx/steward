mod crypto;

use crypto::*;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use axum::body::Bytes;
use axum::extract::{Extension, TypedHeader};
use axum::headers::ContentType;
use axum::routing::post;
use axum::{AddExtensionLayer, Router};
use der::asn1::UIntBytes;
use hyper::StatusCode;
use mime::Mime;

use der::Decodable;
use pkcs8::PrivateKeyInfo;
use x509::time::{Time, Validity};
use x509::TbsCertificate;

use clap::Parser;
use zeroize::Zeroizing;

const PKCS10: &str = "application/pkcs10";

#[derive(Clone, Debug, Parser)]
struct Args {
    #[clap(short, long)]
    key: PathBuf,

    #[clap(short, long)]
    crt: PathBuf,
}

impl Args {
    fn load(self) -> std::io::Result<State> {
        Ok(State {
            key: std::fs::read(self.key)?.into(),
            crt: std::fs::read(self.crt)?,
            ord: AtomicUsize::default(),
        })
    }
}

#[derive(Debug)]
struct State {
    key: Zeroizing<Vec<u8>>,
    crt: Vec<u8>,
    ord: AtomicUsize,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let state = Args::parse().load().unwrap();
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    tracing::debug!("listening on {}", addr);
    axum::Server::bind(&addr)
        .serve(app(state).into_make_service())
        .await
        .unwrap();
}

fn app(state: State) -> Router {
    Router::new()
        .route("/attest", post(attest))
        .layer(AddExtensionLayer::new(Arc::new(state)))
}

async fn attest(
    TypedHeader(ct): TypedHeader<ContentType>,
    body: Bytes,
    Extension(state): Extension<Arc<State>>,
) -> Result<Vec<u8>, StatusCode> {
    // Ensure the correct mime type.
    let mime: Mime = PKCS10.parse().unwrap();
    if ct != ContentType::from(mime) {
        return Err(StatusCode::BAD_REQUEST);
    }

    // Decode and verify the certification request.
    let cr = CertReq::from_der(body.as_ref()).or(Err(StatusCode::BAD_REQUEST))?;
    let cr = cr
        .verify(&cr.body().public_key)
        .or(Err(StatusCode::BAD_REQUEST))?;
    if cr.version != x509::request::Version::V1 {
        return Err(StatusCode::BAD_REQUEST);
    }

    // TODO: validate attestation
    // TODO: validate other CSR fields

    // Get the current time and the expiration of the cert.
    let now = SystemTime::now();
    let end = now + Duration::from_secs(60 * 60 * 24);
    let validity = Validity {
        not_before: Time::try_from(now).or(Err(StatusCode::INTERNAL_SERVER_ERROR))?,
        not_after: Time::try_from(end).or(Err(StatusCode::INTERNAL_SERVER_ERROR))?,
    };

    // Get the next serial number.
    let serial = state.ord.fetch_add(1, Ordering::SeqCst).to_be_bytes();
    let serial = UIntBytes::new(&serial).or(Err(StatusCode::INTERNAL_SERVER_ERROR))?;

    // Decode the signing certificate and key.
    let issuer = Certificate::from_der(&state.crt).or(Err(StatusCode::INTERNAL_SERVER_ERROR))?;
    let isskey = PrivateKeyInfo::from_der(&state.key).or(Err(StatusCode::INTERNAL_SERVER_ERROR))?;

    // Create the new certificate.
    let tbs = TbsCertificate {
        version: x509::Version::V3,
        serial_number: serial,
        signature: isskey
            .signs_with()
            .or(Err(StatusCode::INTERNAL_SERVER_ERROR))?,
        issuer: issuer.body().subject.clone(),
        validity,
        subject: issuer.body().subject.clone(), // FIXME
        subject_public_key_info: cr.public_key,
        issuer_unique_id: issuer.body().subject_unique_id,
        subject_unique_id: None,
        extensions: None,
    };

    Ok(tbs
        .sign(&isskey)
        .or(Err(StatusCode::INTERNAL_SERVER_ERROR))?)
}

#[cfg(test)]
mod tests {
    mod attest {
        use super::super::*;

        use der::asn1::{SetOfVec, Utf8String};
        use der::Encodable;

        use x509::attr::AttributeTypeAndValue;
        use x509::name::RelativeDistinguishedName;
        use x509::request::CertReqInfo;

        use http::{header::CONTENT_TYPE, Request};
        use hyper::Body;
        use tower::ServiceExt; // for `app.oneshot()`

        const CRT: &[u8] = include_bytes!("../crt.der");
        const KEY: &[u8] = include_bytes!("../key.der");

        fn state() -> State {
            State {
                key: KEY.to_owned().into(),
                crt: CRT.into(),
                ord: Default::default(),
            }
        }

        fn cr() -> Vec<u8> {
            let pki = PrivateKeyInfo::generate(NISTP256).unwrap();
            let pki = PrivateKeyInfo::from_der(pki.as_ref()).unwrap();
            let spki = pki.public_key().unwrap();

            // Create a relative distinguished name.
            let mut rdn = RelativeDistinguishedName::new();
            rdn.add(AttributeTypeAndValue {
                oid: x509::ext::pkix::oids::AT_COMMON_NAME,
                value: Utf8String::new("foo").unwrap().into(),
            })
            .unwrap();

            // Create a certification request information structure.
            let cri = CertReqInfo {
                version: x509::request::Version::V1,
                attributes: SetOfVec::new(), // Extension requests go here.
                subject: [rdn].into(),
                public_key: spki,
            };

            // Sign the request.
            cri.sign(&pki).unwrap()
        }

        #[test]
        fn reencode() {
            let encoded = cr();

            for byte in &encoded {
                eprint!("{:02X}", byte);
            }
            eprintln!();

            let decoded = CertReq::from_der(&encoded).unwrap();
            let reencoded = decoded.to_vec().unwrap();
            assert_eq!(encoded, reencoded);
        }

        #[tokio::test]
        async fn ok() {
            let request = Request::builder()
                .method("POST")
                .uri("/attest")
                .header(CONTENT_TYPE, PKCS10)
                .body(Body::from(cr()))
                .unwrap();

            let response = app(state()).oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);

            let body = hyper::body::to_bytes(response.into_body()).await.unwrap();

            let sub = Certificate::from_der(&body).unwrap();
            let iss = Certificate::from_der(CRT).unwrap();
            sub.verify(&iss.body().subject_public_key_info).unwrap();
        }

        #[tokio::test]
        async fn err_no_content_type() {
            let request = Request::builder()
                .method("POST")
                .uri("/attest")
                .body(Body::from(cr()))
                .unwrap();

            let response = app(state()).oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }

        #[tokio::test]
        async fn err_bad_content_type() {
            let request = Request::builder()
                .method("POST")
                .header(CONTENT_TYPE, "text/plain")
                .uri("/attest")
                .body(Body::from(cr()))
                .unwrap();

            let response = app(state()).oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }

        #[tokio::test]
        async fn err_empty_body() {
            let request = Request::builder()
                .method("POST")
                .header(CONTENT_TYPE, PKCS10)
                .uri("/attest")
                .body(Body::empty())
                .unwrap();

            let response = app(state()).oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }

        #[tokio::test]
        async fn err_bad_body() {
            let request = Request::builder()
                .method("POST")
                .header(CONTENT_TYPE, PKCS10)
                .uri("/attest")
                .body(Body::from(vec![0x01, 0x02, 0x03, 0x04]))
                .unwrap();

            let response = app(state()).oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }

        #[tokio::test]
        async fn err_bad_csr_sig() {
            let mut cr = cr();
            *cr.last_mut().unwrap() = 0; // Modify the signature...

            let request = Request::builder()
                .method("POST")
                .header(CONTENT_TYPE, PKCS10)
                .uri("/attest")
                .body(Body::from(cr))
                .unwrap();

            let response = app(state()).oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }
    }
}
