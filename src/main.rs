mod crypto;
mod ext;

use crypto::*;
use ext::{kvm::Kvm, sgx::Sgx, snp::Snp, ExtVerifier};

use std::env::var;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use axum::body::Bytes;
use axum::extract::{Extension, TypedHeader};
use axum::headers::ContentType;
use axum::routing::post;
use axum::Router;
use hyper::StatusCode;
use mime::Mime;

use const_oid::db::rfc5280::{ID_CE_BASIC_CONSTRAINTS, ID_CE_KEY_USAGE};
use const_oid::db::rfc5912::ID_EXTENSION_REQ;
use der::asn1::{GeneralizedTime, UIntBytes};
use der::{Decodable, Encodable};
use pkcs8::PrivateKeyInfo;
use x509::ext::pkix::{BasicConstraints, KeyUsage, KeyUsages};
use x509::name::RdnSequence;
use x509::request::{CertReq, ExtensionReq};
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

impl State {
    pub fn generate(hostname: &str) -> anyhow::Result<Self> {
        use const_oid::db::rfc5912::SECP_256_R_1 as P256;

        // Generate the private key.
        let key = PrivateKeyInfo::generate(P256)?;
        let pki = PrivateKeyInfo::from_der(key.as_ref())?;

        // Create a relative distinguished name.
        let rdns = RdnSequence::parse(&format!("CN={}", hostname))?;
        let rdns = RdnSequence::from_der(&rdns)?;

        // Create the extensions.
        let ku = KeyUsage::from(KeyUsages::KeyCertSign).to_vec()?;
        let bc = BasicConstraints {
            ca: true,
            path_len_constraint: Some(0),
        }
        .to_vec()?;

        // Create the certificate duration.
        let now = SystemTime::now();
        let dur = Duration::from_secs(60 * 60 * 24 * 365);
        let validity = Validity {
            not_before: Time::GeneralTime(GeneralizedTime::from_system_time(now)?),
            not_after: Time::GeneralTime(GeneralizedTime::from_system_time(now + dur)?),
        };

        // Create the certificate body.
        let tbs = TbsCertificate {
            version: x509::Version::V3,
            serial_number: UIntBytes::new(&[0u8])?,
            signature: pki.signs_with()?,
            issuer: rdns.clone(),
            validity,
            subject: rdns,
            subject_public_key_info: pki.public_key()?,
            issuer_unique_id: None,
            subject_unique_id: None,
            extensions: Some(vec![
                x509::ext::Extension {
                    extn_id: ID_CE_KEY_USAGE,
                    critical: true,
                    extn_value: &ku,
                },
                x509::ext::Extension {
                    extn_id: ID_CE_BASIC_CONSTRAINTS,
                    critical: true,
                    extn_value: &bc,
                },
            ]),
        };

        // Self-sign the certificate.
        let crt = tbs.sign(&pki)?;
        Ok(Self {
            key,
            crt,
            ord: AtomicUsize::default(),
        })
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let (state, host, port) = match (var("RENDER_EXTERNAL_HOSTNAME"), var("ROCKET_PORT")) {
        (Ok(host), Ok(port)) => (State::generate(&host)?, "::".parse()?, port.parse()?),
        _ => (Args::parse().load()?, IpAddr::from_str("127.0.0.1")?, 3000),
    };

    let addr = SocketAddr::from((host, port));
    tracing::debug!("listening on {}", addr);
    axum::Server::bind(&addr)
        .serve(app(state).into_make_service())
        .await?;

    Ok(())
}

fn app(state: State) -> Router {
    Router::new()
        .route("/attest", post(attest))
        .layer(Extension(Arc::new(state)))
}

async fn attest(
    TypedHeader(ct): TypedHeader<ContentType>,
    body: Bytes,
    Extension(state): Extension<Arc<State>>,
) -> Result<Vec<u8>, StatusCode> {
    // Decode the signing certificate and key.
    let issuer = Certificate::from_der(&state.crt).or(Err(StatusCode::INTERNAL_SERVER_ERROR))?;
    let isskey = PrivateKeyInfo::from_der(&state.key).or(Err(StatusCode::INTERNAL_SERVER_ERROR))?;

    // Ensure the correct mime type.
    let mime: Mime = PKCS10.parse().unwrap();
    if ct != ContentType::from(mime) {
        return Err(StatusCode::BAD_REQUEST);
    }

    // Decode and verify the certification request.
    let cr = CertReq::from_der(body.as_ref()).or(Err(StatusCode::BAD_REQUEST))?;
    let cri = cr.verify().or(Err(StatusCode::BAD_REQUEST))?;

    // Validate requested extensions.
    let mut attested = false;
    let mut extensions = Vec::new();
    for attr in cri.attributes.iter() {
        if attr.oid != ID_EXTENSION_REQ {
            return Err(StatusCode::BAD_REQUEST);
        }

        for any in attr.values.iter() {
            let ereq: ExtensionReq = any.decode_into().or(Err(StatusCode::BAD_REQUEST))?;
            for ext in ereq.iter() {
                // If the issuer is self-signed, we are in debug mode.
                let iss = &issuer.tbs_certificate;
                let dbg = iss.issuer_unique_id == iss.subject_unique_id;
                let dbg = dbg && iss.issuer == iss.subject;

                // Validate the extension.
                let (copy, att) = match ext.extn_id {
                    Kvm::OID => (Kvm::default().verify(&cri, ext, dbg), Kvm::ATT),
                    Sgx::OID => (Sgx::default().verify(&cri, ext, dbg), Sgx::ATT),
                    Snp::OID => (Snp::default().verify(&cri, ext, dbg), Snp::ATT),
                    _ => return Err(StatusCode::BAD_REQUEST), // unsupported extension
                };

                // Save results.
                attested |= att;
                if copy.or(Err(StatusCode::BAD_REQUEST))? {
                    extensions.push(ext.to_vec().or(Err(StatusCode::INTERNAL_SERVER_ERROR))?);
                }
            }
        }
    }
    if !attested {
        return Err(StatusCode::UNAUTHORIZED);
    }

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
        subject_public_key_info: cri.public_key,
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
        use crate::*;

        use const_oid::db::rfc5912::{SECP_256_R_1, SECP_384_R_1};
        use const_oid::ObjectIdentifier;
        use der::{Any, Encodable};
        use x509::attr::Attribute;
        use x509::request::CertReqInfo;
        use x509::{ext::Extension, name::RdnSequence};

        use http::{header::CONTENT_TYPE, Request};
        use hyper::Body;
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

        fn cr(curve: ObjectIdentifier, exts: Vec<Extension<'_>>) -> Vec<u8> {
            let pki = PrivateKeyInfo::generate(curve).unwrap();
            let pki = PrivateKeyInfo::from_der(pki.as_ref()).unwrap();
            let spki = pki.public_key().unwrap();

            let req = ExtensionReq::from(exts).to_vec().unwrap();
            let any = Any::from_der(&req).unwrap();
            let att = Attribute {
                oid: ID_EXTENSION_REQ,
                values: vec![any].try_into().unwrap(),
            };

            // Create a certification request information structure.
            let cri = CertReqInfo {
                version: x509::request::Version::V1,
                attributes: vec![att].try_into().unwrap(),
                subject: RdnSequence::default(),
                public_key: spki,
            };

            // Sign the request.
            cri.sign(&pki).unwrap()
        }

        #[test]
        fn reencode() {
            let encoded = cr(SECP_256_R_1, vec![]);

            for byte in &encoded {
                eprint!("{:02X}", byte);
            }
            eprintln!();

            let decoded = CertReq::from_der(&encoded).unwrap();
            let reencoded = decoded.to_vec().unwrap();
            assert_eq!(encoded, reencoded);
        }

        #[tokio::test]
        async fn kvm() {
            let ext = Extension {
                extn_id: Kvm::OID,
                critical: false,
                extn_value: &[],
            };

            let request = Request::builder()
                .method("POST")
                .uri("/attest")
                .header(CONTENT_TYPE, PKCS10)
                .body(Body::from(cr(SECP_256_R_1, vec![ext])))
                .unwrap();

            let response = app(state()).oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);

            let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
            let sub = Certificate::from_der(&body).unwrap();
            let iss = Certificate::from_der(CRT).unwrap();
            iss.tbs_certificate.verify_crt(&sub).unwrap();
        }

        #[tokio::test]
        async fn sgx() {
            let evidence = ext::sgx::Evidence {
                pck: Certificate::from_der(include_bytes!("ext/sgx/sgx.pck")).unwrap(),
                quote: &[],
            }
            .to_vec()
            .unwrap();

            let ext = Extension {
                extn_id: Sgx::OID,
                critical: false,
                extn_value: &evidence,
            };

            let request = Request::builder()
                .method("POST")
                .uri("/attest")
                .header(CONTENT_TYPE, PKCS10)
                .body(Body::from(cr(SECP_256_R_1, vec![ext])))
                .unwrap();

            let response = app(state()).oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);

            let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
            let sub = Certificate::from_der(&body).unwrap();
            let iss = Certificate::from_der(CRT).unwrap();
            iss.tbs_certificate.verify_crt(&sub).unwrap();
        }

        #[tokio::test]
        async fn snp() {
            let evidence = ext::snp::Evidence {
                vcek: Certificate::from_der(include_bytes!("ext/snp/milan.vcek")).unwrap(),
                report: include_bytes!("ext/snp/milan.rprt"),
            }
            .to_vec()
            .unwrap();

            let ext = Extension {
                extn_id: Snp::OID,
                critical: false,
                extn_value: &evidence,
            };

            let request = Request::builder()
                .method("POST")
                .uri("/attest")
                .header(CONTENT_TYPE, PKCS10)
                .body(Body::from(cr(SECP_384_R_1, vec![ext])))
                .unwrap();

            let response = app(state()).oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);

            let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
            let sub = Certificate::from_der(&body).unwrap();
            let iss = Certificate::from_der(CRT).unwrap();
            iss.tbs_certificate.verify_crt(&sub).unwrap();
        }

        #[tokio::test]
        async fn err_no_attestation() {
            let request = Request::builder()
                .method("POST")
                .uri("/attest")
                .header(CONTENT_TYPE, PKCS10)
                .body(Body::from(cr(SECP_256_R_1, vec![])))
                .unwrap();

            let response = app(state()).oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }

        #[tokio::test]
        async fn err_no_content_type() {
            let request = Request::builder()
                .method("POST")
                .uri("/attest")
                .body(Body::from(cr(SECP_256_R_1, vec![])))
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
                .body(Body::from(cr(SECP_256_R_1, vec![])))
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
            let mut cr = cr(SECP_256_R_1, vec![]);
            *cr.last_mut().unwrap() += 1; // Modify the signature...

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
