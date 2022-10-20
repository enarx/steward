// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: AGPL-3.0-only

#![warn(rust_2018_idioms, unused_lifetimes, unused_qualifications, clippy::all)]

#[macro_use]
extern crate anyhow;

mod crypto;
mod ext;

use crypto::*;

use std::io::BufRead;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use anyhow::Context;
use axum::body::Bytes;
use axum::extract::{Extension, TypedHeader};
use axum::headers::ContentType;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::Router;
use clap::Parser;
use confargs::{prefix_char_filter, Toml};
use const_oid::db::rfc5280::{
    ID_CE_BASIC_CONSTRAINTS, ID_CE_EXT_KEY_USAGE, ID_CE_KEY_USAGE, ID_CE_SUBJECT_ALT_NAME,
    ID_KP_CLIENT_AUTH, ID_KP_SERVER_AUTH,
};
use const_oid::db::rfc5912::ID_EXTENSION_REQ;
use der::asn1::{GeneralizedTime, Ia5StringRef, UIntRef};
use der::{Decode, Encode, Sequence};
use ext::kvm::Kvm;
use ext::sgx::Sgx;
use ext::snp::Snp;
use ext::ExtVerifier;
use hyper::StatusCode;
use rustls_pemfile::Item;
use sec1::pkcs8::PrivateKeyInfo;
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

const PKCS10: &str = "application/pkcs10";
const BUNDLE: &str = "application/vnd.steward.pkcs10-bundle.v1";

/// Attestation server for use with Enarx.
///
/// Any command-line options listed here may be specified by one or
/// more configuration files, which can be used by passing the
/// name of the file on the command-line with the syntax `@config.toml`.
/// The configuration file must contain valid TOML table mapping argument
/// names to their values.
#[derive(Clone, Debug, Parser)]
#[command(author, version, about)]
struct Args {
    #[arg(short, long, env = "STEWARD_KEY")]
    key: Option<PathBuf>,

    #[arg(short, long, env = "STEWARD_CRT")]
    crt: Option<PathBuf>,

    #[arg(short, long, env = "ROCKET_PORT", default_value = "3000")]
    port: u16,

    #[arg(short, long, env = "ROCKET_ADDRESS", default_value = "::")]
    addr: IpAddr,

    #[arg(long, env = "RENDER_EXTERNAL_HOSTNAME")]
    host: Option<String>,

    #[arg(long, env = "STEWARD_SAN")]
    san: Option<String>,
}

#[derive(Debug)]
#[cfg_attr(test, derive(Clone))]
struct State {
    key: Zeroizing<Vec<u8>>,
    crt: Vec<u8>,
    san: Option<String>,
}

/// ASN.1
/// Output ::= SEQUENCE {
///     chain SEQUENCE OF Certificate,
///     issued SEQUENCE OF Certificate,
/// }
#[derive(Clone, Debug, Default, Sequence)]
struct Output<'a> {
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
    ) -> anyhow::Result<Self> {
        // Load the key file.
        let key = std::io::BufReader::new(std::fs::File::open(key)?);

        // Load the crt file.
        let crt = std::io::BufReader::new(std::fs::File::open(crt)?);

        Self::read(san, key, crt)
    }

    pub fn read(
        san: Option<String>,
        mut key: impl BufRead,
        mut crt: impl BufRead,
    ) -> anyhow::Result<Self> {
        let key = match rustls_pemfile::read_one(&mut key)? {
            Some(Item::PKCS8Key(buf)) => Zeroizing::new(buf),
            _ => return Err(anyhow!("invalid key file")),
        };

        let crt = match rustls_pemfile::read_one(&mut crt)? {
            Some(Item::X509Certificate(buf)) => buf,
            _ => return Err(anyhow!("invalid key file")),
        };

        // Validate the syntax of the files.
        PrivateKeyInfo::from_der(key.as_ref())?;
        Certificate::from_der(crt.as_ref())?;

        Ok(State { crt, san, key })
    }

    pub fn generate(san: Option<String>, hostname: &str) -> anyhow::Result<Self> {
        use const_oid::db::rfc5912::SECP_256_R_1 as P256;

        // Generate the private key.
        let key = PrivateKeyInfo::generate(P256)?;
        let pki = PrivateKeyInfo::from_der(key.as_ref())?;

        // Create a relative distinguished name.
        let rdns = RdnSequence::encode_from_string(&format!("CN={}", hostname))?;
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
        Ok(Self { key, crt, san })
    }
}

#[cfg_attr(not(target_os = "wasi"), tokio::main)]
#[cfg_attr(target_os = "wasi", tokio::main(flavor = "current_thread"))]
async fn main() -> anyhow::Result<()> {
    if std::env::var("RUST_LOG_JSON").is_ok() {
        tracing_subscriber::fmt::fmt()
            .json()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .init();
    } else {
        tracing_subscriber::fmt::init();
    }

    let args = confargs::args::<Toml>(prefix_char_filter::<'@'>)
        .context("Failed to parse config")
        .map(Args::parse_from)?;
    let state = match (args.key, args.crt, args.host) {
        (None, None, Some(host)) => State::generate(args.san, &host)?,
        (Some(key), Some(crt), _) => State::load(args.san, key, crt)?,
        _ => {
            eprintln!("Either:\n* Specify the public key `--crt` and private key `--key`, or\n* Specify the host `--host`.\n\nRun with `--help` for more information.");
            return Err(anyhow!("invalid configuration"));
        }
    };

    #[cfg(not(target_os = "wasi"))]
    {
        use std::net::SocketAddr;
        let addr = SocketAddr::from((args.addr, args.port));
        tracing::debug!("listening on {}", addr);
        axum::Server::bind(&addr)
            .serve(app(state).into_make_service())
            .await?;
    }
    #[cfg(target_os = "wasi")]
    {
        use std::os::wasi::io::FromRawFd;
        tracing::debug!("listening");
        let std_listener = unsafe { std::net::TcpListener::from_raw_fd(3) };
        std_listener
            .set_nonblocking(true)
            .context("failed to set NONBLOCK")?;
        axum::Server::from_tcp(std_listener)
            .context("failed to construct server")?
            .serve(app(state).into_make_service())
            .await?;
    }

    Ok(())
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

fn app(state: State) -> Router {
    Router::new()
        .route("/", post(attest))
        .route("/", get(health))
        .layer(Extension(Arc::new(state)))
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(SpanMaker::default())
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
                    Sgx::OID => (Sgx::default().verify(&info, &ext, dbg), Sgx::ATT),
                    Snp::OID => (Snp::default().verify(&info, &ext, dbg), Snp::ATT),
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
        subject: RdnSequence(Vec::new()),
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
async fn attest(
    TypedHeader(ct): TypedHeader<ContentType>,
    body: Bytes,
    Extension(state): Extension<Arc<State>>,
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
            attest_request(&issuer, &isskey, SubjectAltName(sans), cr, &validity)
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

#[cfg(test)]
mod tests {
    mod attest {
        use crate::ext::{kvm::Kvm, sgx::Sgx, snp::Snp, ExtVerifier};
        use crate::*;
        use const_oid::db::rfc5912::{ID_EXTENSION_REQ, SECP_256_R_1, SECP_384_R_1};
        use const_oid::ObjectIdentifier;
        use der::{AnyRef, Encode};
        use x509::attr::Attribute;
        use x509::request::{CertReq, CertReqInfo, ExtensionReq};
        use x509::PkiPath;
        use x509::{ext::Extension, name::RdnSequence};

        use axum::response::Response;
        use http::header::CONTENT_TYPE;
        use http::Request;
        use hyper::Body;
        use rstest::rstest;
        use tower::ServiceExt; // for `app.oneshot()`

        fn certificates_state() -> State {
            #[cfg(not(target_os = "wasi"))]
            return State::load(None, "testdata/ca.key", "testdata/ca.crt")
                .expect("failed to load state");
            #[cfg(target_os = "wasi")]
            {
                let crt = std::io::BufReader::new(include_bytes!("../testdata/ca.crt").as_slice());
                let key = std::io::BufReader::new(include_bytes!("../testdata/ca.key").as_slice());

                State::read(None, key, crt).expect("failed to load state")
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
        async fn sgx_certs(#[case] header: &str, #[case] multi: bool) {
            for quote in [
                include_bytes!("ext/sgx/quote.unknown").as_slice(),
                include_bytes!("ext/sgx/quote.icelake").as_slice(),
            ] {
                let ext = Extension {
                    extn_id: Sgx::OID,
                    critical: false,
                    extn_value: quote,
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
        }

        #[rstest]
        #[case(PKCS10, false)]
        #[case(BUNDLE, true)]
        #[tokio::test]
        async fn sgx_hostname(#[case] header: &str, #[case] multi: bool) {
            for quote in [
                include_bytes!("ext/sgx/quote.unknown").as_slice(),
                include_bytes!("ext/sgx/quote.icelake").as_slice(),
            ] {
                let ext = Extension {
                    extn_id: Sgx::OID,
                    critical: false,
                    extn_value: quote,
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
        }

        #[rstest]
        #[case(PKCS10, false)]
        #[case(BUNDLE, true)]
        #[tokio::test]
        async fn snp_certs(#[case] header: &str, #[case] multi: bool) {
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
                .uri("/")
                .header(CONTENT_TYPE, header)
                .body(Body::from(cr(SECP_384_R_1, vec![ext], multi)))
                .unwrap();

            let response = app(certificates_state()).oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            attest_response(certificates_state(), response, multi).await;
        }

        #[rstest]
        #[case(PKCS10, false)]
        #[case(BUNDLE, true)]
        #[tokio::test]
        async fn snp_hostname(#[case] header: &str, #[case] multi: bool) {
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
                .uri("/")
                .header(CONTENT_TYPE, header)
                .body(Body::from(cr(SECP_384_R_1, vec![ext], multi)))
                .unwrap();

            let state = hostname_state();
            let response = app(state.clone()).oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            attest_response(state, response, multi).await;
        }

        #[rstest]
        #[case(PKCS10, false)]
        #[case(BUNDLE, true)]
        #[tokio::test]
        async fn err_no_attestation_certs(#[case] header: &str, #[case] multi: bool) {
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
}
