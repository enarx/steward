// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: AGPL-3.0-only

use anyhow::{anyhow, bail, Result};
use der::{asn1::BitStringRef, Encode};
use pkcs8::PrivateKeyInfo;
use x509::ext::Extension;
use x509::request::{CertReq, CertReqInfo, ExtensionReq};

use super::{PrivateKeyInfoExt, SubjectPublicKeyInfoExt};
use crate::ext::{kvm::Kvm, sgx::Sgx, snp::Snp, ExtVerifier};

use const_oid::db::rfc5912::ID_EXTENSION_REQ;
use x509::Certificate;

pub trait CertReqExt<'a> {
    /// Verifies that a certification request is sane.
    ///
    /// This verifies that the certification request is properly self signed
    /// and well formatted. The rest is up to you.
    fn verify(self) -> Result<CertReqInfo<'a>>;
}

impl<'a> CertReqExt<'a> for CertReq<'a> {
    fn verify(self) -> Result<CertReqInfo<'a>> {
        if self.info.version != x509::request::Version::V1 {
            return Err(anyhow!("invalid version"));
        }

        let sign = self
            .signature
            .as_bytes()
            .ok_or_else(|| anyhow!("invalid signature"))?;
        let body = self.info.to_vec()?;
        self.info.public_key.verify(&body, self.algorithm, sign)?;

        Ok(self.info)
    }
}

pub trait CertReqInfoExt<'a> {
    /// Signs the `CertReqInfo` with the specified `PrivateKeyInfo`
    fn sign(self, pki: &PrivateKeyInfo<'_>) -> Result<Vec<u8>>;

    /// Check that the `CertReqInfo`
    fn attest(&self, issuer: &Certificate<'_>) -> Result<Vec<Extension<'a>>>;
}

impl<'a> CertReqInfoExt<'a> for CertReqInfo<'a> {
    fn sign(self, pki: &PrivateKeyInfo<'_>) -> Result<Vec<u8>> {
        let algo = pki.signs_with()?;
        let body = self.to_vec()?;
        let sign = pki.sign(&body, algo)?;

        let rval = CertReq {
            info: self,
            algorithm: algo,
            signature: BitStringRef::from_bytes(&sign)?,
        };

        Ok(rval.to_vec()?)
    }

    fn attest(&self, issuer: &Certificate<'_>) -> Result<Vec<Extension<'a>>> {
        let mut extensions = Vec::new();
        let mut attested = false;
        for attr in self.attributes.iter() {
            if attr.oid != ID_EXTENSION_REQ {
                bail!("invalid extension");
            }

            for any in attr.values.iter() {
                let ereq: ExtensionReq<'_> = any.decode_into().or_else(|e| bail!(e))?;
                for ext in Vec::from(ereq) {
                    // If the issuer is self-signed, we are in debug mode.
                    let iss = &issuer.tbs_certificate;
                    let dbg = iss.issuer_unique_id == iss.subject_unique_id;
                    let dbg = dbg && iss.issuer == iss.subject;

                    // Validate the extension.
                    let (copy, att) = match ext.extn_id {
                        Kvm::OID => (Kvm::default().verify(self, &ext, dbg), Kvm::ATT),
                        Sgx::OID => (Sgx::default().verify(self, &ext, dbg), Sgx::ATT),
                        Snp::OID => (Snp::default().verify(self, &ext, dbg), Snp::ATT),
                        _ => bail!("unsupported extension"),
                    };

                    // Save results.
                    attested |= att;
                    if copy.or_else(|e| bail!(e))? {
                        extensions.push(ext);
                    }
                }
            }
        }
        if !attested {
            bail!("attestation failed");
        }
        Ok(extensions)
    }
}
