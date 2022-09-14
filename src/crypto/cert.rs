// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: AGPL-3.0-only

use super::*;

use std::time::SystemTime;

use anyhow::{anyhow, Result};
use const_oid::db::rfc5280::{ID_CE_BASIC_CONSTRAINTS, ID_CE_KEY_USAGE};
use der::asn1::BitStringRef;
use der::{Decode, Encode};
use pkcs8::{AlgorithmIdentifier, ObjectIdentifier, PrivateKeyInfo};
use x509::ext::pkix::{BasicConstraints, KeyUsage, KeyUsages};
use x509::ext::Extension;
use x509::{Certificate, TbsCertificate};

pub trait TbsCertificateExt<'a> {
    /// Decodes all extensions with the specified oid.
    fn extensions<T: Decode<'a>>(&self, oid: ObjectIdentifier) -> Result<Vec<(bool, T)>>;

    /// Signs the `TbsCertificate` with the specified `PrivateKeyInfo`
    fn sign(self, pki: &PrivateKeyInfo<'_>) -> Result<Vec<u8>>;

    /// Verifies a raw signature with extension handling.
    ///
    /// You probably don't want this function. The other functions in
    /// this trait provide default extension handling plus additional
    /// validations.
    fn verify_ext(
        &self,
        body: &[u8],
        algo: AlgorithmIdentifier<'_>,
        signature: &[u8],
        ext: impl FnMut(&Extension<'_>) -> Result<bool>,
    ) -> Result<()>;

    /// Verifies a raw signature
    ///
    /// NOTE: this function is not for validating a certificate!
    ///
    /// The signature on the specified body will be validated with the
    /// specified algorithm. Note that the signature is provided in the
    /// already encoded form as it would appear in an X.509 certificate
    /// or a PKCS#10 certification request. If you have a signature in
    /// another format, you will have to reformat it to the correct format.
    fn verify_raw(
        &self,
        body: &[u8],
        algo: AlgorithmIdentifier<'_>,
        signature: &[u8],
    ) -> Result<()>;

    /// Verifies a certificate
    ///
    /// The signature on the specified certificate will be validated as a
    /// child of the parent certificate. This includes additional field
    /// validation as well as default extension validation.
    fn verify_crt<'r, 'c>(&self, cert: &'r Certificate<'c>) -> Result<&'r TbsCertificate<'c>>;
}

impl<'a> TbsCertificateExt<'a> for TbsCertificate<'a> {
    fn extensions<T: Decode<'a>>(&self, oid: ObjectIdentifier) -> Result<Vec<(bool, T)>> {
        self.extensions
            .as_deref()
            .unwrap_or(&[])
            .iter()
            .filter(|e| e.extn_id == oid)
            .map(|e| Ok((e.critical, T::from_der(e.extn_value)?)))
            .collect()
    }

    fn sign(self, pki: &PrivateKeyInfo<'_>) -> Result<Vec<u8>> {
        let algo = self.signature;
        let body = self.to_vec()?;
        let sign = pki.sign(&body, algo)?;

        let rval = Certificate {
            tbs_certificate: self,
            signature_algorithm: algo,
            signature: BitStringRef::from_bytes(&sign)?,
        };

        Ok(rval.to_vec()?)
    }

    fn verify_ext(
        &self,
        body: &[u8],
        algo: AlgorithmIdentifier<'_>,
        signature: &[u8],
        mut ext: impl FnMut(&Extension<'_>) -> Result<bool>,
    ) -> Result<()> {
        // Validate the certificate time constraints.
        if self.validity.not_before.to_system_time() > SystemTime::now() {
            return Err(anyhow!("cert unborn"));
        }
        if self.validity.not_after.to_system_time() < SystemTime::now() {
            return Err(anyhow!("cert expired"));
        }

        // Validate certificate extensions.
        if let Some(extensions) = self.extensions.as_ref() {
            for extension in extensions {
                if !ext(extension)? && extension.critical {
                    return Err(anyhow!(
                        "unhandled critical extension: {}",
                        extension.extn_id
                    ));
                }
            }
        }

        self.subject_public_key_info.verify(body, algo, signature)
    }

    fn verify_raw(
        &self,
        body: &[u8],
        algo: AlgorithmIdentifier<'_>,
        signature: &[u8],
    ) -> Result<()> {
        self.verify_ext(body, algo, signature, |ext| {
            Ok(match ext.extn_id {
                // Since we aren't validating a cert, we only care that this is well-formed.
                ID_CE_BASIC_CONSTRAINTS => BasicConstraints::from_der(ext.extn_value).is_ok(),

                // Ensure we are allowed to sign with this certificate.
                ID_CE_KEY_USAGE => {
                    let ku = KeyUsage::from_der(ext.extn_value)?;
                    if !ku.0.contains(KeyUsages::DigitalSignature) {
                        return Err(anyhow!("not allowed to sign documents"));
                    }

                    true
                }

                _ => false,
            })
        })
    }

    fn verify_crt<'r, 'c>(&self, cert: &'r Certificate<'c>) -> Result<&'r TbsCertificate<'c>> {
        // Validate that the parent cert is the issuer.
        if cert.tbs_certificate.issuer != self.subject {
            return Err(anyhow!("subject mismatch"));
        }
        if cert.tbs_certificate.issuer_unique_id != self.subject_unique_id {
            return Err(anyhow!("id mismatch"));
        }

        // Encode the certificate body for validation.
        let body = cert.tbs_certificate.to_vec()?;
        let sign = cert
            .signature
            .as_bytes()
            .ok_or_else(|| anyhow!("invalid signature"))?;

        self.verify_ext(&body, cert.signature_algorithm, sign, |ext| {
            Ok(match ext.extn_id {
                // Validate that the parent is allowed to sign certificates.
                ID_CE_KEY_USAGE => {
                    let ku = KeyUsage::from_der(ext.extn_value)?;
                    if !ku.0.contains(KeyUsages::KeyCertSign) {
                        return Err(anyhow!("not allowed to sign certificates"));
                    }

                    true
                }

                // Validate the cert is a CA with a valid maximum depth.
                ID_CE_BASIC_CONSTRAINTS => {
                    let pbc = BasicConstraints::from_der(ext.extn_value)?;
                    if !pbc.ca {
                        return Err(anyhow!("not ca enabled"));
                    }

                    // When validating a self-signed cert, we shortcut the below test.
                    let selfsigned = self.subject_public_key_info
                        == cert.tbs_certificate.subject_public_key_info;

                    // If the parent has a depth limit, the child MUST have a shorter depth limit.
                    let child_bcs = cert
                        .tbs_certificate
                        .extensions::<BasicConstraints>(ID_CE_BASIC_CONSTRAINTS)?
                        .into_iter()
                        .filter(|e| !selfsigned && e.0 && e.1.ca)
                        .map(|e| e.1);
                    for cbc in child_bcs {
                        match (pbc.path_len_constraint, cbc.path_len_constraint) {
                            (Some(p), Some(c)) if c >= p => return Err(anyhow!("path constraint")),
                            (Some(..), None) => return Err(anyhow!("missing path constraint")),
                            _ => (),
                        }
                    }

                    true
                }

                _ => false,
            })
        })?;

        Ok(&cert.tbs_certificate)
    }
}
