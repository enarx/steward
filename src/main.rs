use std::net::SocketAddr;

use axum::body::Bytes;
use axum::extract::TypedHeader;
use axum::headers::ContentType;
use axum::routing::post;
use axum::Router;
use hyper::StatusCode;
use mime::Mime;

use der::{asn1::ObjectIdentifier, Decodable, Encodable};
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use pkcs10::{CertReq, Version};

const PKCS10: &str = "application/pkcs10";

const ECPUBKEY: ObjectIdentifier = ObjectIdentifier::new("1.2.840.10045.2.1");
const NISTP256: ObjectIdentifier = ObjectIdentifier::new("1.2.840.10045.3.1.7");
//const ECDSA_SHA224: ObjectIdentifier = ObjectIdentifier::new("1.2.840.10045.4.3.1");
const ECDSA_SHA256: ObjectIdentifier = ObjectIdentifier::new("1.2.840.10045.4.3.2");
//const ECDSA_SHA384: ObjectIdentifier = ObjectIdentifier::new("1.2.840.10045.4.3.3");
//const ECDSA_SHA512: ObjectIdentifier = ObjectIdentifier::new("1.2.840.10045.4.3.4");

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

async fn attest(
    TypedHeader(ct): TypedHeader<ContentType>,
    body: Bytes,
) -> Result<Vec<u8>, StatusCode> {
    // Ensure the correct mime type.
    let mime: Mime = PKCS10.parse().unwrap();
    if ct != ContentType::from(mime) {
        return Err(StatusCode::BAD_REQUEST);
    }

    // Decode the certification request.
    let cr = CertReq::from_der(body.as_ref()).or(Err(StatusCode::BAD_REQUEST))?;
    if cr.info.version != Version::V1 {
        return Err(StatusCode::BAD_REQUEST);
    }

    // Ensure supported signature algorithm.
    match cr.algorithm.oid {
        ECDSA_SHA256 => (),
        _ => return Err(StatusCode::BAD_REQUEST),
    }

    // Ensure supported signature parameters.
    match cr.algorithm.parameters {
        None => (),
        Some(x) if x.is_null() => (),
        _ => return Err(StatusCode::BAD_REQUEST),
    }

    // Ensure the public key is supported.
    if cr.info.public_key.algorithm.oid != ECPUBKEY {
        return Err(StatusCode::BAD_REQUEST);
    }

    // Ensure the curve is supported.
    let curve = cr
        .info
        .public_key
        .algorithm
        .parameters
        .ok_or(StatusCode::BAD_REQUEST)?
        .oid()
        .or(Err(StatusCode::BAD_REQUEST))?;
    if curve != NISTP256 {
        return Err(StatusCode::BAD_REQUEST);
    }

    // Decode the signature.
    let sig = cr.signature.as_bytes().ok_or(StatusCode::BAD_REQUEST)?;
    let sig = Signature::from_der(sig).or(Err(StatusCode::BAD_REQUEST))?;

    // Decode the key.
    let key = cr.info.public_key.subject_public_key.to_vec();
    let key = VerifyingKey::from_sec1_bytes(&key).or(Err(StatusCode::BAD_REQUEST))?;

    // Verify the body.
    let body = cr.info.to_vec().or(Err(StatusCode::BAD_REQUEST))?;
    key.verify(&body, &sig).or(Err(StatusCode::BAD_REQUEST))?;

    // TODO: validate attestation
    // TODO: validate other CSR fields
    // TODO: generate certificate

    Ok(Vec::new())
}

#[cfg(test)]
mod tests {
    mod attest {
        use super::super::*;

        use der::asn1::{BitString, SetOfVec, Utf8String};
        use der::{Any, Encodable};
        use p256::ecdsa::signature::Signer;
        use p256::ecdsa::SigningKey;
        use p256::elliptic_curve::sec1::ToEncodedPoint;
        use pkcs10::CertReqInfo;
        use x509::*;

        use http::{header::CONTENT_TYPE, Request};
        use hyper::Body;
        use tower::ServiceExt; // for `app.oneshot()`

        fn cr() -> Vec<u8> {
            // Create a keypair.
            let rng = rand::thread_rng();
            let prv = p256::SecretKey::random(rng);
            let pbl = prv.public_key();
            let enc = pbl.to_encoded_point(true);

            // Create a relative distinguished name.
            let mut rdn = RelativeDistinguishedName::new();
            rdn.add(AttributeTypeAndValue {
                oid: x509::PKIX_AT_COMMON_NAME,
                value: Utf8String::new("foo").unwrap().into(),
            })
            .unwrap();

            // Create a certification request information structure.
            let cri = CertReqInfo {
                version: pkcs10::Version::V1,
                attributes: SetOfVec::new(), // Extension requests go here.
                subject: [rdn].into(),
                public_key: SubjectPublicKeyInfo {
                    subject_public_key: enc.as_ref(),
                    algorithm: AlgorithmIdentifier {
                        oid: ECPUBKEY,
                        parameters: Some(Any::from(&NISTP256)),
                    },
                },
            };

            // Sign the body.
            let bdy = cri.to_vec().unwrap();
            let sig = SigningKey::try_from(prv).unwrap().sign(&bdy).to_der();

            // Create the certificate request.
            let csr = CertReq {
                info: cri,
                algorithm: AlgorithmIdentifier {
                    oid: ECDSA_SHA256,
                    parameters: None,
                },
                signature: BitString::from_bytes(sig.as_ref()).unwrap(),
            };

            // Encode the certificate request.
            csr.to_vec().unwrap()
        }

        #[tokio::test]
        async fn ok() {
            let request = Request::builder()
                .method("POST")
                .uri("/attest")
                .header(CONTENT_TYPE, PKCS10)
                .body(Body::from(cr()))
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
                .body(Body::from(cr()))
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
                .body(Body::from(cr()))
                .unwrap();

            let response = app().oneshot(request).await.unwrap();
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

            let response = app().oneshot(request).await.unwrap();
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

            let response = app().oneshot(request).await.unwrap();
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

            let response = app().oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }
    }
}
