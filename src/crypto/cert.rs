use std::time::SystemTime;

use anyhow::{anyhow, Result};
use der::{asn1::BitString, Encodable};
use pkcs8::{AlgorithmIdentifier, PrivateKeyInfo};
use x509::{Certificate, TbsCertificate};

use super::*;

pub trait TbsCertificateExt {
    /// Signs the `TbsCertificate` with the specified `PrivateKeyInfo`
    fn sign(self, pki: &PrivateKeyInfo) -> Result<Vec<u8>>;

    /// Verifies a signature
    ///
    /// The signature on the specified body will be validated with the
    /// specified algorithm. Note that the signature is provided in the
    /// already encoded form as it would appear in an X.509 certificate
    /// or a PKCS#10 certification request. If you have a signature in
    /// another format, you will have to reformat it to the correct format.
    fn verify_bytes(&self, body: &[u8], algo: AlgorithmIdentifier, signature: &[u8]) -> Result<()>;

    fn verify<'r, 'c>(&self, cert: &'r Certificate<'c>) -> Result<&'r TbsCertificate<'c>>;
}

impl<'a> TbsCertificateExt for TbsCertificate<'a> {
    fn sign(self, pki: &PrivateKeyInfo) -> Result<Vec<u8>> {
        let algo = self.signature;
        let body = self.to_vec()?;
        let sign = pki.sign(&body, algo)?;

        let rval = Certificate {
            tbs_certificate: self,
            signature_algorithm: algo,
            signature: BitString::from_bytes(&sign)?,
        };

        Ok(rval.to_vec()?)
    }

    fn verify_bytes(&self, body: &[u8], algo: AlgorithmIdentifier, signature: &[u8]) -> Result<()> {
        if self.validity.not_before.to_system_time() > SystemTime::now() {
            return Err(anyhow!("cert unborn"));
        }

        if self.validity.not_after.to_system_time() < SystemTime::now() {
            return Err(anyhow!("cert expired"));
        }

        /*
        if let Some(extensions) = self.extensions.as_ref() {
            for extension in extensions {
                if extension.critical {
                    return Err(anyhow!(
                        "unknown critical extension: {:?}",
                        extension.extn_id
                    ));
                }
            }
        }
        */

        self.subject_public_key_info.verify(body, algo, signature)
    }

    fn verify<'r, 'c>(&self, cert: &'r Certificate<'c>) -> Result<&'r TbsCertificate<'c>> {
        if cert.tbs_certificate.issuer != self.subject {
            return Err(anyhow!("subject mismatch"));
        }

        if cert.tbs_certificate.issuer_unique_id != self.subject_unique_id {
            return Err(anyhow!("id mismatch"));
        }

        let body = cert.tbs_certificate.to_vec()?;
        let sign = cert
            .signature
            .as_bytes()
            .ok_or(anyhow!("invalid signature"))?;

        self.verify_bytes(&body, cert.signature_algorithm, sign)?;
        Ok(&cert.tbs_certificate)
    }
}
