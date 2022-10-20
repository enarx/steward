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
pub mod traits;

use anyhow::anyhow;
use body::Body;
use cryptography::ext::TbsCertificateExt;
use traits::{FromBytes, ParseBytes, Steal};

use cryptography::p256::ecdsa::signature::Verifier;
use cryptography::sha2::{digest::DynDigest, Sha256};
use cryptography::x509::TbsCertificate;
use der::Encode;
use sgx::ReportBody;

pub struct Quote<'a> {
    body: &'a Body,
    sign: es256::SignatureData<'a>,
}

impl<'a> FromBytes<'a> for Quote<'a> {
    type Error = anyhow::Error;

    fn from_bytes(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), Self::Error> {
        let (body, bytes): (&Body, _) = bytes.parse()?;

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

        Ok((Quote { body, sign }, bytes))
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
        let mut hash = <Sha256 as cryptography::sha2::Digest>::new();
        hash.update(self.sign.key.as_ref());
        hash.update(self.sign.iqe.auth.as_ref());
        hash.finalize_into(&mut data[..32])?;
        if data != self.sign.iqe.rprt.reportdata {
            return Err(anyhow!("untrusted ecdsa attestation key"));
        }

        // Verify the signature on the enclave report.
        let vkey = cryptography::p256::ecdsa::VerifyingKey::from_sec1_bytes(self.sign.key.sec1())?;
        let sig = cryptography::p256::ecdsa::Signature::from_der(&self.sign.sig.to_vec()?)?;
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
