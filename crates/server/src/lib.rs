// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: Apache-2.0

#![warn(rust_2018_idioms, unused_lifetimes, unused_qualifications, clippy::all)]

mod kvm;

use attestation::crypto::{CertReqExt, PrivateKeyInfoExt, TbsCertificateExt};
use attestation::sgx::Sgx;
use attestation::snp::Snp;
use kvm::Kvm;

use std::io::BufRead;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use anyhow::{anyhow, Context};
use axum::body::Bytes;
use axum::extract::{Extension, TypedHeader};
use axum::headers::ContentType;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::Router;
use const_oid::db::rfc5280::{
    ID_CE_BASIC_CONSTRAINTS, ID_CE_EXT_KEY_USAGE, ID_CE_KEY_USAGE, ID_CE_SUBJECT_ALT_NAME,
    ID_KP_CLIENT_AUTH, ID_KP_SERVER_AUTH,
};
use const_oid::db::rfc5912::ID_EXTENSION_REQ;
use der::asn1::{GeneralizedTime, Ia5StringRef, UIntRef};
use der::{Decode, Encode, Sequence};
use hyper::StatusCode;
use sec1::pkcs8::PrivateKeyInfo;
use serde::Deserialize;
use tower_http::trace::{
    DefaultOnBodyChunk, DefaultOnEos, DefaultOnFailure, DefaultOnRequest, DefaultOnResponse,
    TraceLayer,
};
use tower_http::LatencyUnit;
use tracing::{debug, Level};
use x509::attr::Attribute;
use x509::ext::pkix::name::GeneralName;
use x509::ext::pkix::{BasicConstraints, ExtendedKeyUsage, KeyUsage, KeyUsages, SubjectAltName};
use x509::name::RdnSequence;
use x509::request::{CertReq, ExtensionReq};
use x509::time::{Time, Validity};
use x509::{Certificate, TbsCertificate};
use zeroize::Zeroizing;

pub const PKCS10: &str = "application/pkcs10";
pub const BUNDLE: &str = "application/vnd.steward.pkcs10-bundle.v1";

#[derive(Clone, Deserialize, Debug, Default, Eq, PartialEq)]
pub struct Config {
    pub sgx: Option<attestation::sgx::config::Config>,
    pub snp: Option<attestation::snp::config::Config>,
}

#[derive(Clone, Debug)]
pub struct State {
    key: Zeroizing<Vec<u8>>,
    pub crt: Vec<u8>,
    san: Option<String>,
    config: Config,
}

/// ASN.1
/// Output ::= SEQUENCE {
///     chain SEQUENCE OF Certificate,
///     issued SEQUENCE OF Certificate,
/// }
#[derive(Clone, Debug, Default, Sequence)]
pub struct Output<'a> {
    /// The signing certificate chain back to the root.
    pub chain: Vec<Certificate<'a>>,

    /// All issued certificates.
    pub issued: Vec<Certificate<'a>>,
}

impl State {
    pub fn load(
        san: Option<String>,
        key: impl AsRef<Path>,
        crt: impl AsRef<Path>,
        config: Option<String>,
    ) -> anyhow::Result<Self> {
        // Load the key file.
        let key = std::io::BufReader::new(std::fs::File::open(key)?);

        // Load the crt file.
        let crt = std::io::BufReader::new(std::fs::File::open(crt)?);

        Self::read(san, key, crt, config)
    }

    pub fn read(
        san: Option<String>,
        mut key: impl BufRead,
        mut crt: impl BufRead,
        config: Option<String>,
    ) -> anyhow::Result<Self> {
        let key = match rustls_pemfile::read_one(&mut key)? {
            Some(rustls_pemfile::Item::PKCS8Key(buf)) => Zeroizing::new(buf),
            _ => return Err(anyhow!("invalid key file")),
        };

        let crt = match rustls_pemfile::read_one(&mut crt)? {
            Some(rustls_pemfile::Item::X509Certificate(buf)) => buf,
            _ => return Err(anyhow!("invalid key file")),
        };

        // Validate the syntax of the files.
        PrivateKeyInfo::from_der(key.as_ref())?;
        Certificate::from_der(crt.as_ref())?;

        let config = if let Some(path) = config {
            let config = std::fs::read_to_string(path).context("failed to read config file")?;
            toml::from_str(&config).context("failed to parse config")?
        } else {
            Config::default()
        };

        Ok(State {
            crt,
            san,
            key,
            config,
        })
    }

    pub fn generate(san: Option<String>, hostname: &str) -> anyhow::Result<Self> {
        use const_oid::db::rfc5912::SECP_256_R_1 as P256;

        // Generate the private key.
        let key = PrivateKeyInfo::generate(P256)?;
        let pki = PrivateKeyInfo::from_der(key.as_ref())?;

        // Create a relative distinguished name.
        let rdns = RdnSequence::encode_from_string(&format!("CN={hostname}"))?;
        let rdns = RdnSequence::from_der(&rdns)?;

        // Create the extensions.
        let ku = KeyUsage(KeyUsages::KeyCertSign.into()).to_vec()?;
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
            serial_number: UIntRef::new(&[0u8])?,
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
            san,
            config: Default::default(),
        })
    }
}

#[derive(Debug, Clone, Default)]
struct SpanMaker;

impl<B> tower_http::trace::MakeSpan<B> for SpanMaker {
    fn make_span(&mut self, request: &axum::http::request::Request<B>) -> tracing::span::Span {
        let reqid = uuid::Uuid::new_v4();
        tracing::span!(
            Level::INFO,
            "request",
            method = %request.method(),
            uri = %request.uri(),
            version = ?request.version(),
            headers = ?request.headers(),
            request_id = %reqid,
        )
    }
}

pub fn app(state: State) -> Router {
    Router::new()
        .route("/", post(attest))
        .route("/", get(health))
        .layer(Extension(Arc::new(state)))
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(SpanMaker)
                .on_request(DefaultOnRequest::new().level(Level::INFO))
                .on_response(
                    DefaultOnResponse::new()
                        .level(Level::INFO)
                        .latency_unit(LatencyUnit::Micros),
                )
                .on_body_chunk(DefaultOnBodyChunk::new())
                .on_eos(
                    DefaultOnEos::new()
                        .level(Level::INFO)
                        .latency_unit(LatencyUnit::Micros),
                )
                .on_failure(
                    DefaultOnFailure::new()
                        .level(Level::INFO)
                        .latency_unit(LatencyUnit::Micros),
                ),
        )
}

async fn health() -> StatusCode {
    StatusCode::OK
}

fn attest_request(
    issuer: &Certificate<'_>,
    pki: &PrivateKeyInfo<'_>,
    sans: SubjectAltName<'_>,
    cr: CertReq<'_>,
    validity: &Validity,
    state: &State,
) -> Result<Vec<u8>, StatusCode> {
    let info = cr.verify().map_err(|e| {
        debug!("failed to verify certificate info: {e}");
        StatusCode::BAD_REQUEST
    })?;

    let mut extensions = Vec::new();
    let mut attested = false;
    for Attribute { oid, values } in info.attributes.iter() {
        if *oid != ID_EXTENSION_REQ {
            debug!("invalid extension {oid}");
            return Err(StatusCode::BAD_REQUEST);
        }
        for any in values.iter() {
            let ereq: ExtensionReq<'_> = any.decode_into().map_err(|e| {
                debug!("failed to decode extension request: {e}");
                StatusCode::BAD_REQUEST
            })?;
            for ext in Vec::from(ereq) {
                // If the issuer is self-signed, we are in debug mode.
                let iss = &issuer.tbs_certificate;
                let dbg = iss.issuer_unique_id == iss.subject_unique_id;
                let dbg = dbg && iss.issuer == iss.subject;

                // Validate the extension.
                let (copy, att) = match ext.extn_id {
                    Kvm::OID => (Kvm::default().verify(&info, &ext, dbg), Kvm::ATT),
                    Sgx::OID => (
                        Sgx::default().verify(&info, &ext, state.config.sgx.as_ref(), dbg),
                        Sgx::ATT,
                    ),
                    Snp::OID => (
                        Snp::default().verify(&info, &ext, state.config.snp.as_ref(), dbg),
                        Snp::ATT,
                    ),
                    oid => {
                        debug!("extension `{oid}` is unsupported");
                        return Err(StatusCode::BAD_REQUEST);
                    }
                };
                let copy = copy.map_err(|e| {
                    debug!("extension validation failed: {e}");
                    StatusCode::BAD_REQUEST
                })?;

                // Save results.
                attested |= att;
                if copy {
                    extensions.push(ext);
                }
            }
        }
    }
    if !attested {
        debug!("attestation failed");
        return Err(StatusCode::UNAUTHORIZED);
    }

    // Add Subject Alternative Name
    let sans: Vec<u8> = sans.to_vec().or(Err(StatusCode::INTERNAL_SERVER_ERROR))?;
    extensions.push(x509::ext::Extension {
        extn_id: ID_CE_SUBJECT_ALT_NAME,
        critical: false,
        extn_value: &sans,
    });

    // Add extended key usage.
    let eku = ExtendedKeyUsage(vec![ID_KP_SERVER_AUTH, ID_KP_CLIENT_AUTH])
        .to_vec()
        .or(Err(StatusCode::INTERNAL_SERVER_ERROR))?;
    extensions.push(x509::ext::Extension {
        extn_id: ID_CE_EXT_KEY_USAGE,
        critical: false,
        extn_value: &eku,
    });

    // Generate the instance id.
    let uuid = uuid::Uuid::new_v4();
    let serial_number = UIntRef::new(uuid.as_bytes()).or(Err(StatusCode::INTERNAL_SERVER_ERROR))?;

    let signature = pki
        .signs_with()
        .or(Err(StatusCode::INTERNAL_SERVER_ERROR))?;

    // Create and sign the new certificate.
    TbsCertificate {
        version: x509::Version::V3,
        serial_number,
        signature,
        issuer: issuer.tbs_certificate.subject.clone(),
        validity: *validity,
        subject: info.subject,
        subject_public_key_info: info.public_key,
        issuer_unique_id: issuer.tbs_certificate.subject_unique_id,
        subject_unique_id: None,
        extensions: Some(extensions),
    }
    .sign(pki)
    .or(Err(StatusCode::INTERNAL_SERVER_ERROR))
}

/// Receives:
/// ASN.1 SEQUENCE OF CertRequest.
/// Returns:
/// ASN.1 SEQUENCE OF Output.
pub async fn attest(
    TypedHeader(ct): TypedHeader<ContentType>,
    Extension(state): Extension<Arc<State>>,
    body: Bytes,
) -> Result<Vec<u8>, impl IntoResponse> {
    // Decode the signing certificate and key.
    let issuer = Certificate::from_der(&state.crt).or(Err(StatusCode::INTERNAL_SERVER_ERROR))?;
    let isskey = PrivateKeyInfo::from_der(&state.key).or(Err(StatusCode::INTERNAL_SERVER_ERROR))?;

    const TTL: Duration = Duration::from_secs(60 * 60 * 24 * 28);
    let now = SystemTime::now();
    let end = now + TTL;
    let validity = Validity {
        not_before: Time::try_from(now).or(Err(StatusCode::INTERNAL_SERVER_ERROR))?,
        not_after: Time::try_from(end).or(Err(StatusCode::INTERNAL_SERVER_ERROR))?,
    };

    // Check for correct mime type.
    let reqs = match ct.to_string().as_ref() {
        PKCS10 => vec![CertReq::from_der(body.as_ref()).or(Err(StatusCode::BAD_REQUEST))?],
        BUNDLE => Vec::from_der(body.as_ref()).or(Err(StatusCode::BAD_REQUEST))?,
        _ => return Err(StatusCode::BAD_REQUEST),
    };

    // Decode and verify the certification requests.
    reqs.into_iter()
        .map(|cr| {
            // Create the basic subject alt name.
            let name = Ia5StringRef::new("foo.bar.hub.profian.com")
                .or(Err(StatusCode::INTERNAL_SERVER_ERROR))?;
            let mut sans = vec![GeneralName::DnsName(name)];

            // Optionally, add the configured subject alt name.
            if let Some(name) = &state.san {
                let name = Ia5StringRef::new(name).or(Err(StatusCode::INTERNAL_SERVER_ERROR))?;
                sans.push(GeneralName::DnsName(name));
            }
            attest_request(
                &issuer,
                &isskey,
                SubjectAltName(sans),
                cr,
                &validity,
                &state,
            )
        })
        .collect::<Result<Vec<_>, _>>()
        .and_then(|issued| {
            let issued: Vec<Certificate<'_>> = issued
                .iter()
                .map(|c| Certificate::from_der(c).or(Err(StatusCode::INTERNAL_SERVER_ERROR)))
                .collect::<Result<_, _>>()?;

            match ct.to_string().as_ref() {
                PKCS10 => vec![issuer, issued[0].clone()].to_vec(),
                BUNDLE => Output {
                    chain: vec![issuer],
                    issued,
                }
                .to_vec(),
                _ => return Err(StatusCode::BAD_REQUEST),
            }
            .or(Err(StatusCode::INTERNAL_SERVER_ERROR))
        })
}

pub fn init_tracing() {
    if std::env::var("RUST_LOG_JSON").is_ok() {
        tracing_subscriber::fmt::fmt()
            .json()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .init();
    } else {
        tracing_subscriber::fmt::init();
    }
}

#[cfg(test)]
mod tests {
    use super::{init_tracing, Config};
    use rstest::rstest;
    use std::sync::Once;

    static TRACING: Once = Once::new();

    mod attest {
        use super::super::kvm::Kvm;
        use super::super::{app, Output, State, BUNDLE, PKCS10};
        use super::{init_tracing, rstest, TRACING};
        use axum::body::Body;

        use attestation::crypto::{CertReqInfoExt, PrivateKeyInfoExt, TbsCertificateExt};
        use const_oid::db::rfc5912::{ID_EXTENSION_REQ, SECP_256_R_1};
        use const_oid::ObjectIdentifier;
        use der::{AnyRef, Decode, Encode};
        use x509::attr::Attribute;
        use x509::request::{CertReq, CertReqInfo, ExtensionReq};
        use x509::{ext::Extension, name::RdnSequence};
        use x509::{Certificate, PkiPath};

        use axum::response::Response;
        use http::header::CONTENT_TYPE;
        use http::{Request, StatusCode};
        use sec1::pkcs8::PrivateKeyInfo;
        use tower::ServiceExt; // for `app.oneshot()`

        fn certificates_state() -> State {
            #[cfg(not(target_os = "wasi"))]
            return State::load(None, "../../testdata/ca.key", "../../testdata/ca.crt", None)
                .expect("failed to load state");
            #[cfg(target_os = "wasi")]
            {
                let crt =
                    std::io::BufReader::new(include_bytes!("../../../testdata/ca.crt").as_slice());
                let key =
                    std::io::BufReader::new(include_bytes!("../../../testdata/ca.key").as_slice());

                State::read(None, key, crt, None).expect("failed to load state")
            }
        }

        fn hostname_state() -> State {
            State::generate(None, "localhost").unwrap()
        }

        fn cr(curve: ObjectIdentifier, exts: Vec<Extension<'_>>, multi: bool) -> Vec<u8> {
            let pki = PrivateKeyInfo::generate(curve).unwrap();
            let pki = PrivateKeyInfo::from_der(pki.as_ref()).unwrap();
            let spki = pki.public_key().unwrap();

            let req = ExtensionReq::from(exts).to_vec().unwrap();
            let any = AnyRef::from_der(&req).unwrap();
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
            let signed = cri.sign(&pki).unwrap();
            if multi {
                vec![CertReq::from_der(&signed).unwrap()].to_vec().unwrap()
            } else {
                signed
            }
        }

        async fn attest_response(state: State, response: Response, multi: bool) {
            let body = hyper::body::to_bytes(response.into_body()).await.unwrap();

            let path = if multi {
                let response = Output::from_der(body.as_ref()).unwrap();
                let mut path = response.chain;
                path.push(response.issued[0].clone());
                path
            } else {
                PkiPath::from_der(&body).unwrap()
            };

            let issr = Certificate::from_der(&state.crt).unwrap();
            assert_eq!(2, path.len());
            assert_eq!(issr, path[0]);
            issr.tbs_certificate.verify_crt(&path[1]).unwrap();
        }

        #[test]
        fn reencode_multi() {
            let encoded = cr(SECP_256_R_1, vec![], true);
            let crs = Vec::<CertReq<'_>>::from_der(&encoded).unwrap();
            assert_eq!(crs.len(), 1);

            let encoded: Vec<u8> = crs[0].to_vec().unwrap();
            let decoded = CertReq::from_der(&encoded).unwrap();
            let reencoded: Vec<u8> = decoded.to_vec().unwrap();
            assert_eq!(encoded, reencoded);
        }

        #[test]
        fn reencode_single() {
            let encoded = cr(SECP_256_R_1, vec![], false);
            let decoded = CertReq::from_der(&encoded).unwrap();
            let reencoded = decoded.to_vec().unwrap();
            assert_eq!(encoded, reencoded);
        }

        #[rstest]
        #[case(PKCS10, false)]
        #[case(BUNDLE, true)]
        #[tokio::test]
        async fn kvm_certs(#[case] header: &str, #[case] multi: bool) {
            TRACING.call_once(init_tracing);
            let ext = Extension {
                extn_id: Kvm::OID,
                critical: false,
                extn_value: &[],
            };

            let request = Request::builder()
                .method("POST")
                .uri("/")
                .header(CONTENT_TYPE, header)
                .body(Body::from(cr(SECP_256_R_1, vec![ext], multi)))
                .unwrap();

            let response = app(certificates_state()).oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            attest_response(certificates_state(), response, multi).await;
        }

        #[rstest]
        #[case(PKCS10, false)]
        #[case(BUNDLE, true)]
        #[tokio::test]
        async fn kvm_hostname(#[case] header: &str, #[case] multi: bool) {
            TRACING.call_once(init_tracing);
            let ext = Extension {
                extn_id: Kvm::OID,
                critical: false,
                extn_value: &[],
            };

            let request = Request::builder()
                .method("POST")
                .uri("/")
                .header(CONTENT_TYPE, header)
                .body(Body::from(cr(SECP_256_R_1, vec![ext], multi)))
                .unwrap();

            let state = hostname_state();
            let response = app(state.clone()).oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            attest_response(state, response, multi).await;
        }

        // Though similar to the above test, this is the only test which
        // actually sends many CSRs, versus an array of just one CSR.
        #[tokio::test]
        async fn kvm_hostname_many_certs() {
            TRACING.call_once(init_tracing);
            let ext = Extension {
                extn_id: Kvm::OID,
                critical: false,
                extn_value: &[],
            };

            let one_cr_bytes = cr(SECP_256_R_1, vec![ext], true);
            let crs = Vec::<CertReq<'_>>::from_der(&one_cr_bytes).unwrap();
            assert_eq!(crs.len(), 1);

            let five_crs = vec![
                crs[0].clone(),
                crs[0].clone(),
                crs[0].clone(),
                crs[0].clone(),
                crs[0].clone(),
            ];

            let request = Request::builder()
                .method("POST")
                .uri("/")
                .header(CONTENT_TYPE, BUNDLE)
                .body(Body::from(five_crs.to_vec().unwrap()))
                .unwrap();

            let state = hostname_state();
            let response = app(state.clone()).oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);

            let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
            let output = Output::from_der(body.as_ref()).unwrap();

            assert_eq!(output.issued.len(), five_crs.len());
        }

        #[rstest]
        #[case(PKCS10, false)]
        #[case(BUNDLE, true)]
        #[tokio::test]
        async fn err_no_attestation_certs(#[case] header: &str, #[case] multi: bool) {
            TRACING.call_once(init_tracing);
            let request = Request::builder()
                .method("POST")
                .uri("/")
                .header(CONTENT_TYPE, header)
                .body(Body::from(cr(SECP_256_R_1, vec![], multi)))
                .unwrap();

            let response = app(certificates_state()).oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }

        #[tokio::test]
        async fn err_no_attestation_hostname() {
            TRACING.call_once(init_tracing);
            let request = Request::builder()
                .method("POST")
                .uri("/")
                .header(CONTENT_TYPE, BUNDLE)
                .body(Body::from(cr(SECP_256_R_1, vec![], true)))
                .unwrap();

            let response = app(hostname_state()).oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }

        #[rstest]
        #[case(false)]
        #[case(true)]
        #[tokio::test]
        async fn err_no_content_type(#[case] multi: bool) {
            TRACING.call_once(init_tracing);
            let request = Request::builder()
                .method("POST")
                .uri("/")
                .body(Body::from(cr(SECP_256_R_1, vec![], multi)))
                .unwrap();

            let response = app(certificates_state()).oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }

        #[tokio::test]
        async fn err_empty_body() {
            TRACING.call_once(init_tracing);
            let request = Request::builder()
                .method("POST")
                .uri("/")
                .body(Body::empty())
                .unwrap();

            let response = app(certificates_state()).oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }

        #[tokio::test]
        async fn err_bad_body() {
            TRACING.call_once(init_tracing);
            let request = Request::builder()
                .method("POST")
                .uri("/")
                .body(Body::from(vec![0x01, 0x02, 0x03, 0x04]))
                .unwrap();

            let response = app(certificates_state()).oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }

        #[tokio::test]
        async fn err_bad_csr_sig() {
            TRACING.call_once(init_tracing);
            let mut cr = cr(SECP_256_R_1, vec![], true);
            let last = cr.last_mut().unwrap();
            *last = last.wrapping_add(1); // Modify the signature...

            let request = Request::builder()
                .method("POST")
                .uri("/")
                .header(CONTENT_TYPE, BUNDLE)
                .body(Body::from(cr))
                .unwrap();

            let response = app(certificates_state()).oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }
    }

    // Unit tests for configuration
    mod config {
        use super::{init_tracing, rstest, Config, TRACING};
        use attestation::sgx::quote::traits::ParseBytes;
        use attestation::sgx::quote::Quote;
        use attestation::snp::{Evidence, PolicyFlags, Report, Snp};
        use attestation::{Digest, Measurements};

        use std::collections::HashSet;

        use der::Decode;
        use sgx::parameters::MiscSelect;
        use x509::attr::Attribute;
        use x509::request::{CertReq, ExtensionReq};
        use x509::Certificate;

        const DEFAULT_CONFIG: &str = include_str!("../../../testdata/steward.toml");
        const ICELAKE_XEON_CSR: &[u8] = include_bytes!(
            "../../../crates/attestation/src/sgx/icelake.signed.tcb.crl.multi.xeon.csr"
        );
        const ICELAKE_I5_CSR: &[u8] = include_bytes!(
            "../../../crates/attestation/src/sgx/icelake.signed.tcb.crl.single.i5.csr"
        );
        const MILAN_CSR: &[u8] =
            include_bytes!("../../../crates/attestation/src/snp/milan.signed.crl.csr");

        // Matches what's in `testdata/steward.toml`
        const SIGNER: &str = "7a49a07df0f8e90a6e1d9a63e3c696d9c844f0e3f8739b21daa640f99facc48a";

        fn assert_sgx_config(
            csr: &CertReq<'_>,
            conf: &attestation::sgx::config::Config,
        ) -> anyhow::Result<()> {
            let sgx = attestation::sgx::Sgx::default();

            #[allow(unused_variables)]
            for Attribute { oid, values } in csr.info.attributes.iter() {
                for any in values.iter() {
                    let ereq: ExtensionReq<'_> = any.decode_into()?;
                    for ext in Vec::from(ereq) {
                        let (quote, bytes): (Quote<'_>, _) = ext.extn_value.parse()?;
                        let chain = quote.chain()?;
                        let chain = chain
                            .iter()
                            .map(|c| Certificate::from_der(c))
                            .collect::<Result<Vec<_>, _>>()?;

                        // Validate the report.
                        let pck = sgx.trusted(&chain, &quote.crls)?;
                        let report = quote.verify(pck)?;
                        sgx.verify(&csr.info, &ext, Some(conf), false)?;
                    }
                }
            }
            Ok(())
        }

        fn assert_snp_config(
            csr: &CertReq<'_>,
            conf: &attestation::snp::config::Config,
        ) -> anyhow::Result<()> {
            let snp = Snp::default();
            #[allow(unused_variables)]
            for Attribute { oid, values } in csr.info.attributes.iter() {
                for any in values.iter() {
                    let ereq: ExtensionReq<'_> = any.decode_into()?;
                    for ext in Vec::from(ereq) {
                        let evidence = Evidence::from_der(ext.extn_value)?;
                        let array = evidence.report.try_into()?;
                        let report = Report::cast(array);
                        snp.verify(&csr.info, &ext, Some(conf), false)?;
                    }
                }
            }
            Ok(())
        }

        #[test]
        fn test_config_empty() {
            let config: Config = toml::from_str("").expect("Couldn't deserialize");

            assert!(config.sgx.is_none());
            assert!(config.snp.is_none());
        }

        #[test]
        fn test_config() {
            TRACING.call_once(init_tracing);
            let config: Config = toml::from_str(
                r#"
            [snp]
            policy_flags = ["SingleSocket", "Debug", "SMT"]
            signer = ["e368c18e60842db9325778532dd81594d732078bf01aa91686be40333da639e08733b910bd057bdda50d715968b075ce"]
            abi = ">1.0"

            [sgx]
            signer = ["2eba0f494f428e799c22d6f12778aebea4dc8d991f9e63fd3cddd57ac6eb5dd9"]
            "#,
            )
                .expect("Couldn't deserialize");

            let snp = attestation::snp::config::Config {
                measurements: Measurements {
                    signer: HashSet::from([Digest([
                        0xe3, 0x68, 0xc1, 0x8e, 0x60, 0x84, 0x2d, 0xb9, 0x32, 0x57, 0x78, 0x53,
                        0x2d, 0xd8, 0x15, 0x94, 0xd7, 0x32, 0x07, 0x8b, 0xf0, 0x1a, 0xa9, 0x16,
                        0x86, 0xbe, 0x40, 0x33, 0x3d, 0xa6, 0x39, 0xe0, 0x87, 0x33, 0xb9, 0x10,
                        0xbd, 0x05, 0x7b, 0xdd, 0xa5, 0x0d, 0x71, 0x59, 0x68, 0xb0, 0x75, 0xce,
                    ])]),
                    hash: Default::default(),
                    hash_blacklist: Default::default(),
                },
                id_key_digest: Default::default(),
                id_key_digest_blacklist: Default::default(),
                abi: ">1.0".parse().unwrap(),
                policy_flags: Some(
                    (PolicyFlags::Reserved
                        | PolicyFlags::SingleSocket
                        | PolicyFlags::Debug
                        | PolicyFlags::SMT)
                        .bits(),
                ),
                platform_info_flags: None,
            };

            let sgx = attestation::sgx::config::Config {
                measurements: Measurements {
                    signer: HashSet::from([Digest([
                        0x2e, 0xba, 0x0f, 0x49, 0x4f, 0x42, 0x8e, 0x79, 0x9c, 0x22, 0xd6, 0xf1,
                        0x27, 0x78, 0xae, 0xbe, 0xa4, 0xdc, 0x8d, 0x99, 0x1f, 0x9e, 0x63, 0xfd,
                        0x3c, 0xdd, 0xd5, 0x7a, 0xc6, 0xeb, 0x5d, 0xd9,
                    ])]),
                    hash: Default::default(),
                    hash_blacklist: Default::default(),
                },
                features: Default::default(),
                enclave_security_version: None,
                enclave_product_id: None,
                misc_select: MiscSelect::default(),
                allowed_advisories: Default::default(),
            };

            let steward = Config {
                sgx: Some(sgx),
                snp: Some(snp),
            };

            assert_eq!(config, steward);
        }

        #[rstest]
        #[case(ICELAKE_XEON_CSR)]
        #[case(ICELAKE_I5_CSR)]
        #[test]
        fn test_sgx_signed_canned_csr(#[case] csr: &[u8]) {
            TRACING.call_once(init_tracing);
            let csr = CertReq::from_der(csr).unwrap();
            let config: Config = toml::from_str(DEFAULT_CONFIG).expect("Couldn't deserialize");
            assert_sgx_config(&csr, &config.sgx.unwrap()).unwrap();
        }

        #[test]
        fn test_sgx_signed_csr_bad_config_signer() {
            TRACING.call_once(init_tracing);
            let csr = CertReq::from_der(ICELAKE_I5_CSR).unwrap();
            let config: Config = toml::from_str(
                r#"
            [sgx]
            signer = ["00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF"]
            "#,
            )
            .expect("Couldn't deserialize");
            let error = assert_sgx_config(&csr, &config.sgx.unwrap()).err().unwrap();
            assert_eq!(
                error.to_string(),
                format!("sgx untrusted enarx signer {SIGNER}")
            );
        }

        #[test]
        fn test_sgx_signed_csr_bad_config_enclave_version() {
            let csr = CertReq::from_der(ICELAKE_I5_CSR).unwrap();
            let config: Config = toml::from_str(&*format!(
                r#"
            [sgx]
            signer = ["{SIGNER}"]
            enclave_security_version = 9999
            "#,
            ))
            .expect("Couldn't deserialize");

            let error = assert_sgx_config(&csr, &config.sgx.unwrap()).err().unwrap();
            assert_eq!(error.to_string(), "sgx untrusted enclave security version");
        }

        #[test]
        fn test_sgx_signed_csr_extra_tcb_advisories() {
            let csr = CertReq::from_der(ICELAKE_I5_CSR).unwrap();
            let config: Config = toml::from_str(&*format!(
                r#"
            [sgx]
            signer = ["{SIGNER}"]
            allowed_advisories = ["bogus-1234"]
            "#,
            ))
            .expect("Couldn't deserialize");

            let error = assert_sgx_config(&csr, &config.sgx.unwrap()).err().unwrap();
            assert!(error
                .to_string()
                .starts_with("sgx TCB report has additional advisories"));
        }

        #[test]
        fn test_snp_signed_canned_csr() {
            TRACING.call_once(init_tracing);
            let csr = CertReq::from_der(MILAN_CSR).unwrap();
            let config: Config = toml::from_str(DEFAULT_CONFIG).expect("Couldn't deserialize");
            assert!(assert_snp_config(&csr, &config.snp.unwrap()).is_ok());
        }

        #[test]
        fn test_snp_signed_canned_csr_bad_author_key() {
            let csr = CertReq::from_der(MILAN_CSR).unwrap();

            let config: Config = toml::from_str(
                r#"
            [snp]
            policy_flags = ["SingleSocket", "Debug"]
            signer = ["e368c18e60842db9325778532dd81594d732078bf01aa91686be40333da639e08733b910bd057bdda50d715968b075ce"]
            "#,
            ).expect("Couldn't deserialize");

            assert!(assert_snp_config(&csr, &config.snp.unwrap()).is_err());
        }

        #[test]
        fn test_snp_signed_canned_csr_bad_abi_version() {
            let csr = CertReq::from_der(MILAN_CSR).unwrap();

            let config: Config = toml::from_str(
                r#"
            [snp]
            signer = ["5b2181f5e2294fa0709d22b3f85d9d88b287b897c6b7289004802b53bbf09bc50f5469f98a6d6718d5f9c918d3d3c16f"]
            abi = ">254.0"
            "#,
            ).expect("Couldn't deserialize");

            assert!(assert_snp_config(&csr, &config.snp.unwrap()).is_err());
        }

        #[test]
        fn test_snp_signed_canned_csr_blacklisted_id_key() {
            let csr = CertReq::from_der(MILAN_CSR).unwrap();

            let config: Config = toml::from_str(r#"
            [snp]
            signer = ["5b2181f5e2294fa0709d22b3f85d9d88b287b897c6b7289004802b53bbf09bc50f5469f98a6d6718d5f9c918d3d3c16f"]
            id_key_digest_blacklist = ["966a25a22ee44283aa51bfb3682c990fd9e0a7457c5f60f4ac4eb5c41715478c4b206b0e01dc11aae8628f5aa29e0560"]
            "#).expect("Couldn't deserialize");

            assert!(assert_snp_config(&csr, &config.snp.unwrap()).is_err());
        }
    }
}
