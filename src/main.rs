mod crypto;

use crypto::*;
use x509::request::CertReq;

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
use x509::{Certificate, TbsCertificate};

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
    let cr = cr.verify().or(Err(StatusCode::BAD_REQUEST))?;

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
        issuer: issuer.tbs_certificate.subject.clone(),
        validity,
        subject: issuer.tbs_certificate.subject.clone(), // FIXME
        subject_public_key_info: cr.public_key,
        issuer_unique_id: issuer.tbs_certificate.subject_unique_id,
        subject_unique_id: None,
        extensions: None,
    };

    // Sign the certificate.
    Ok(tbs
        .sign(&isskey)
        .or(Err(StatusCode::INTERNAL_SERVER_ERROR))?)
}

#[cfg(test)]
mod tests {
    mod attest {
        use crate::crypto::oids::ECDSA_SHA384;
        use crate::*;

        use der::asn1::{SetOfVec, Utf8String};
        use der::{Any, Encodable, Sequence};

        use x509::attr::AttributeTypeAndValue;
        use x509::name::RelativeDistinguishedName;
        use x509::request::CertReqInfo;

        use http::{header::CONTENT_TYPE, Request};
        use hyper::Body;
        use ring::signature::Signature;
        use spki::PublicKeyDocument;
        use tower::ServiceExt; // for `app.oneshot()`

        const CRT: &[u8] = include_bytes!("../certs/test/crt.der");
        const KEY: &[u8] = include_bytes!("../certs/test/key.der");

        fn state() -> State {
            State {
                key: KEY.to_owned().into(),
                crt: CRT.into(),
                ord: Default::default(),
            }
        }

        fn cr() -> Vec<u8> {
            let pki = PrivateKeyInfo::generate(oids::NISTP256).unwrap();
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
        fn test_milan_validation() {
            // ECDSA-Sig-Value ::= SEQUENCE {
            //    r INTEGER,
            //    s INTEGER
            //}
            #[derive(Clone, Debug, Sequence)]
            struct EcdsaSig<'a> {
                r: UIntBytes<'a>,
                s: UIntBytes<'a>,
            }

            use crate::crypto;
            use der::Document;
            use sha2::{Digest, Sha384};
            use std::fs;
            let test_file = fs::read("tests/test1_le.bin").unwrap();
            assert_eq!(test_file.len(), 0x4A0, "attestation blob size");

            let test_message = &test_file[..0x2A0];

            let test_signature = &test_file[0x2A0..];
            assert_eq!(test_signature.len(), 0x0200, "attestation signature size");

            let mut r = test_signature[..0x48].to_vec();
            r.reverse();

            let mut s = test_signature[0x48..0x90].to_vec();
            s.reverse();

            let ecdsa = EcdsaSig {
                r: UIntBytes::new(&r).unwrap(),
                s: UIntBytes::new(&s).unwrap(),
            };

            let der = ecdsa.to_vec().unwrap();

            //eprintln!("R={:?}", r_value);
            //eprintln!("S={:?}", s_value);
            //panic!("");

            let data_hash_value = Sha384::digest(&test_file[..0x2A0]);
            assert_eq!(data_hash_value.len(), 48, "sha-384 is 48 bytes long");

            const MILAN_VCEK: &str = include_str!("../certs/amd/milan_vcek.pem");
            let veck = PkiPath::parse_pem(MILAN_VCEK).unwrap();
            let vcek_path = PkiPath::from_ders(&veck).unwrap();
            assert_eq!(vcek_path.len(), 1, "The SNP cert is just one cert");
            let the_cert = vcek_path.first().unwrap();

            println!(
                "Signing algorithm {:?}",
                the_cert.tbs_certificate.subject_public_key_info.algorithm
            );

            println!(
                "algo.oid: {:?}",
                the_cert
                    .tbs_certificate
                    .subject_public_key_info
                    .algorithm
                    .oid
            );

            println!(
                "algo.oid = {:?}",
                the_cert
                    .tbs_certificate
                    .subject_public_key_info
                    .algorithm
                    .oids()
                    .unwrap()
            );
            println!(
                "algo.parameters = {:?}",
                the_cert
                    .tbs_certificate
                    .subject_public_key_info
                    .algorithm
                    .parameters
            );

            /*

            algo.oid = (ObjectIdentifier(1.2.840.10045.2.1), Some(ObjectIdentifier(1.3.132.0.34)))
            algo.parameters = Some(Any { tag: Tag(0x06: OBJECT IDENTIFIER), value: ByteSlice { length: Length(5), inner: [43, 129, 4, 0, 34] } })

             */

            match the_cert.tbs_certificate.verify_raw(
                test_message,
                pkcs8::AlgorithmIdentifier {
                    oid: ECDSA_SHA384,
                    parameters: None,
                },
                &der,
            ) {
                Ok(_) => {
                    assert!(true, "Message passed");
                }
                Err(e) => {
                    assert!(false, "Message invalid {}", e);
                }
            }
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
            iss.tbs_certificate.verify_crt(&sub).unwrap();
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
