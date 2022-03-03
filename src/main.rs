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

            let test_message = test_file[..0x2A0].to_vec();
            println!("Message to hash: {:02?}", test_message);

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
            println!("Der bytes: {:?}", der);

            println!("R={:?}", r);
            println!("S={:?}", s);
            //panic!("");

            assert_eq!(r.len(), s.len(), "R & S bytes are equal");
            assert_eq!(r.len(), 0x48, "R & S are 0x48 bytes");

            let data_hash_value = Sha384::digest(&test_file[..0x2A0]);
            println!("Message hash: {:02X?}", data_hash_value);
            assert_eq!(data_hash_value.len(), 48, "sha-384 is 48 bytes long");

            const MILAN_VCEK: &str = include_str!("../certs/amd/milan_vcek.pem");
            let veck = PkiPath::parse_pem(MILAN_VCEK).unwrap();
            let vcek_path = PkiPath::from_ders(&veck).unwrap();
            assert_eq!(vcek_path.len(), 1, "The SNP cert is just one cert");
            let the_cert = vcek_path.first().unwrap();

            match the_cert.tbs_certificate.verify_raw(
                data_hash_value.as_slice(),
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

        #[repr(C)]
        #[derive(Debug)]
        struct SnpReportData {
            pub version: u32,
            pub guest_svn: u32,
            pub policy: u64,
            pub family_id: [u8; 16],
            pub image_id: [u8; 16],
            pub vmpl: u32,
            pub sig_algo: u32,
            pub plat_version: u64,
            pub plat_info: u64,
            pub author_key_en: u32,
            rsvd1: u32,
            pub report_data: [u8; 64],
            pub measurement: [u8; 48],
            pub host_data: [u8; 32],
            pub id_key_digest: [u8; 48],
            pub author_key_digest: [u8; 48],
            pub report_id: [u8; 32],
            pub report_id_ma: [u8; 32],
            pub reported_tcb: u64,
            rsvd2: [u8; 24],
            pub chip_id: [u8; 64],
            rsvd3: [u8; 192],
            pub signature: [u8; 512],
        }

        unsafe fn any_as_u8_slice<T: Sized>(p: &T) -> &[u8] {
            ::std::slice::from_raw_parts((p as *const T) as *const u8, ::std::mem::size_of::<T>())
        }

        #[test]
        fn test_milan_validation_from_struct() {
            let report = SnpReportData {
                version: 2,
                guest_svn: 0,
                policy: 720896,
                family_id: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                image_id: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                vmpl: 0,
                sig_algo: 1,
                plat_version: 4828703225471303682,
                plat_info: 1,
                author_key_en: 0,
                rsvd1: 0,
                report_data: [
                    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
                    22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41,
                    42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61,
                    62, 63,
                ],
                measurement: [
                    126, 222, 97, 236, 74, 54, 95, 237, 207, 80, 62, 141, 224, 125, 38, 213, 200,
                    62, 180, 63, 78, 196, 186, 140, 190, 137, 51, 158, 158, 185, 146, 153, 147, 65,
                    210, 26, 102, 181, 134, 210, 150, 8, 239, 113, 17, 199, 86, 158,
                ],
                host_data: [
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0,
                ],
                id_key_digest: [
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                ],
                author_key_digest: [
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                ],
                report_id: [
                    37, 231, 167, 178, 243, 181, 192, 242, 224, 124, 91, 79, 44, 116, 130, 2, 148,
                    181, 105, 101, 216, 161, 66, 103, 38, 220, 151, 238, 172, 89, 189, 10,
                ],
                report_id_ma: [
                    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
                    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
                ],
                reported_tcb: 4828703225471303682,
                rsvd2: [
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                ],
                chip_id: [
                    41, 113, 216, 50, 137, 33, 105, 133, 59, 193, 107, 172, 170, 110, 141, 208,
                    121, 134, 243, 142, 232, 214, 81, 101, 228, 68, 245, 145, 210, 202, 111, 124,
                    97, 142, 226, 56, 109, 209, 75, 218, 7, 222, 153, 229, 6, 34, 102, 251, 20,
                    130, 203, 95, 248, 97, 224, 140, 175, 87, 147, 29, 152, 241, 188, 205,
                ],
                rsvd3: [
                    2, 0, 0, 0, 0, 0, 3, 67, 42, 42, 1, 0, 42, 42, 1, 0, 2, 0, 0, 0, 0, 0, 3, 67,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                ],
                signature: [
                    160, 111, 118, 79, 134, 89, 60, 82, 50, 213, 224, 161, 248, 127, 207, 22, 211,
                    214, 208, 17, 19, 51, 190, 29, 138, 122, 242, 94, 191, 11, 191, 121, 0, 87,
                    105, 73, 232, 81, 244, 59, 47, 16, 8, 8, 86, 135, 228, 207, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 109, 249, 167, 100, 48,
                    186, 142, 160, 54, 95, 171, 25, 218, 199, 152, 169, 74, 171, 27, 7, 186, 57,
                    163, 138, 31, 14, 246, 160, 15, 120, 222, 164, 180, 83, 18, 170, 161, 5, 227,
                    239, 253, 113, 23, 3, 254, 205, 3, 160, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                ],
            };

            #[derive(Clone, Debug, Sequence)]
            struct EcdsaSig<'a> {
                r: UIntBytes<'a>,
                s: UIntBytes<'a>,
            }

            use crate::crypto;
            use der::Document;
            use sha2::{Digest, Sha384};
            let test_file = unsafe { any_as_u8_slice(&report) };
            assert_eq!(test_file.len(), 0x4A0, "attestation blob size");

            let test_message = test_file[..0x2A0].to_vec();
            println!("Message to hash: {:02?}", test_message);

            let test_signature = &test_file[0x2A0..];
            assert_eq!(test_signature.len(), 0x0200, "attestation signature size");

            let mut r = report.signature[..0x48].to_vec();
            r.reverse();

            let mut s = report.signature[0x48..0x90].to_vec();
            s.reverse();

            assert_eq!(r.len(), s.len(), "R & S bytes are equal");
            assert_eq!(r.len(), 0x48, "R & S are 0x48 bytes");

            let ecdsa = EcdsaSig {
                r: UIntBytes::new(&r).unwrap(),
                s: UIntBytes::new(&s).unwrap(),
            };

            let der = ecdsa.to_vec().unwrap();
            println!("Der bytes: {:?}", der);

            println!("R={:?}", r);
            println!("S={:?}", s);
            //panic!("");

            let data_hash_value = Sha384::digest(&test_file[..0x2A0]);
            println!("Message hash: {:02X?}", data_hash_value);
            assert_eq!(data_hash_value.len(), 48, "sha-384 is 48 bytes long");

            const MILAN_VCEK: &str = include_str!("../certs/amd/milan_vcek2.pem");
            let veck = PkiPath::parse_pem(MILAN_VCEK).unwrap();
            let vcek_path = PkiPath::from_ders(&veck).unwrap();
            assert_eq!(vcek_path.len(), 1, "The SNP cert is just one cert");
            let the_cert = vcek_path.first().unwrap();

            match the_cert.tbs_certificate.verify_raw(
                data_hash_value.as_slice(),
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
