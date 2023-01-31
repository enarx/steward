// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: AGPL-3.0-only

//! Intel SGX Documentation is available at the following link.
//! Section references in further documentation refer to this document.
//! <https://www.intel.com/content/dam/www/public/emea/xe/en/documents/manuals/64-ia-32-architectures-software-developer-vol-3d-part-4-manual.pdf>
//!
//! The Quote structure is used to provide proof to an off-platform entity that an application
//! enclave is running with Intel SGX protections on a trusted Intel SGX enabled platform.
//! See Section A.4 in the following link for all types in this module:
//! <https://download.01.org/intel-sgx/dcap-1.0/docs/SGX_ECDSA_QuoteGenReference_DCAP_API_Linux_1.0.pdf>

pub mod body;
pub mod es256;
pub mod qe;
pub mod tcb;
pub mod traits;

use super::super::crypto::{CrlList, TbsCertificateExt};
use body::Body;
use std::str::FromStr;
use traits::{FromBytes, ParseBytes, Steal};

use anyhow::anyhow;
use der::{Decode, Encode, Sequence};
use p256::ecdsa::signature::Verifier;
use rustls_pemfile::ec_private_keys;
use sgx::ReportBody;
use sha2::{digest::DynDigest, Sha256};
use tcb::{TcbInfo, TcbRoot};
use x509::{Certificate, TbsCertificate};

#[derive(Sequence)]
struct TcbPackage<'a> {
    crts: Vec<Certificate<'a>>,
    #[asn1(type = "OCTET STRING")]
    report: &'a [u8],
}

#[derive(Sequence)]
struct SgxEvidence<'a> {
    #[asn1(type = "OCTET STRING")]
    quote: &'a [u8],
    crl: CrlList<'a>,
    tcb: TcbPackage<'a>,
}

pub struct Tcb<'a> {
    /// Parsed structure of the Intel TCB report to ensure updated firmware
    pub report: TcbInfo,
    /// Bytes of the Intel TCB report to validate the TCB report signature
    pub bytes: Vec<u8>,
    /// Bytes of the Intel TCB report signature for validation
    pub sign: Vec<u8>,
    /// Intel TCB signing certificates
    pub certs: Vec<Certificate<'a>>,
}

pub struct Quote<'a> {
    /// Body of the SGX attestation report
    body: &'a Body,
    /// Signature for the SGX attestation report
    sign: es256::SignatureData<'a>,
    /// Intel CRLs
    pub crls: CrlList<'a>,
    /// TCB report items
    pub tcb: Tcb<'a>,
}

impl<'a> FromBytes<'a> for Quote<'a> {
    type Error = anyhow::Error;

    fn from_bytes(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), Self::Error> {
        let evidence = SgxEvidence::from_der(bytes)?;

        // Get the string version of the TCB body before sorting to avoid breaking the signature
        let tcb_size = evidence.tcb.report.len();
        let tcb_bytes = Vec::from(&evidence.tcb.report[11..tcb_size - 144]);
        let tcb_bytes = String::from_utf8(tcb_bytes).unwrap();

        let tcb_root: TcbRoot = serde_json::from_slice(evidence.tcb.report)?;

        // Convert the signature to DER, as that's the expected format in spki.rs for validation.
        let tcb_signature = p256::ecdsa::Signature::from_str(&tcb_root.signature)?;
        let tcb_signature = tcb_signature.to_der().to_bytes().to_vec();
        let mut tcb_report = tcb_root.tcb_info;

        // So that we can start with the most recent TCB PCESVN when validating
        tcb_report
            .tcb_levels
            .sort_by(|l, r| l.tcb_date.cmp(&r.tcb_date).reverse());

        // Reverse the certs so Intel's root is first, then the TCB cert.
        let mut tcb_certificates = evidence.tcb.crts;
        tcb_certificates.reverse();

        let (body, bytes): (&Body, _) = evidence.quote.parse()?;

        if body.version() != 3 {
            return Err(anyhow!("unsupported quote version"));
        }

        if body.key_type() != body::Body::KEY_TYPE_ES256 {
            return Err(anyhow!("unsupported quote key type"));
        }

        if body.qe_vendor_id != body::Body::QE_VENDOR_ID_INTEL {
            return Err(anyhow!("unsupported quote qe vendor id"));
        }

        let (sign, bytes) = bytes.parse()?;
        let crls = evidence.crl;

        Ok((
            Quote {
                body,
                sign,
                crls,
                tcb: Tcb {
                    report: tcb_report,
                    bytes: tcb_bytes.into_bytes(),
                    sign: tcb_signature,
                    certs: tcb_certificates,
                },
            },
            bytes,
        ))
    }
}

impl<'a> Quote<'a> {
    pub fn chain(&self) -> anyhow::Result<&Vec<Vec<u8>>> {
        match &self.sign.iqe.cert {
            qe::cert::Data::PckCertChain(chain) => Ok(chain),
        }
    }

    pub fn verify(&self, pck: &TbsCertificate<'_>) -> anyhow::Result<&'a ReportBody> {
        // Validate the QE report.
        pck.verify_raw(
            self.sign.iqe.rprt.as_ref(),
            pck.signature,
            &self.sign.iqe.sign.to_vec()?,
        )?;

        // Validate the Attestation Key.
        let mut data = [0u8; 64];
        let mut hash = <Sha256 as sha2::Digest>::new();
        hash.update(self.sign.key.as_ref());
        hash.update(self.sign.iqe.auth.as_ref());
        hash.finalize_into(&mut data[..32])?;
        if data != self.sign.iqe.rprt.reportdata {
            return Err(anyhow!("untrusted ecdsa attestation key"));
        }

        // Verify the signature on the enclave report.
        let vkey = p256::ecdsa::VerifyingKey::from_sec1_bytes(self.sign.key.sec1())?;
        let sig = p256::ecdsa::Signature::from_der(&self.sign.sig.to_vec()?)?;
        vkey.verify(self.body.as_ref(), &sig)?;

        // Verify the PCE security version.
        if self.body.pce_svn() < Body::PCE_SVN {
            return Err(anyhow!("untrusted pce: {}", self.body.pce_svn()));
        }

        // Verify the QE security version.
        if self.body.qe_svn() < Body::QE_SVN {
            return Err(anyhow!("untrusted qe: {}", self.body.qe_svn()));
        }

        Ok(&self.body.report)
    }
}
