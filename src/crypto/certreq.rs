// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: AGPL-3.0-only

use anyhow::{anyhow, Result};
use const_oid::ObjectIdentifier;
use der::{asn1::BitStringRef, Encode};
use pkcs8::PrivateKeyInfo;
use spki::AlgorithmIdentifier;
use x509::request::{CertReq, CertReqInfo};

use super::{PrivateKeyInfoExt, SubjectPublicKeyInfoExt};

#[cfg(target_os = "wasi")]
use wasi_crypto_guest::signatures::SignatureKeyPair;

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

pub trait CertReqInfoExt {
    /// Signs the `CertReqInfo` with the specified `PrivateKeyInfo`
    fn sign(self, pki: &PrivateKeyInfo<'_>) -> Result<Vec<u8>>;

    #[cfg(target_os = "wasi")]
    /// Signs the `CertReqInfo` with the specified `wasi_crypto_guest::signatures::SignatureKeyPair`
    fn sign_kp(self, oid: &ObjectIdentifier, kp: &SignatureKeyPair) -> Result<Vec<u8>>;
}

impl<'a> CertReqInfoExt for CertReqInfo<'a> {
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

    #[cfg(target_os = "wasi")]
    fn sign_kp(self, oid: &ObjectIdentifier, kp: &SignatureKeyPair) -> Result<Vec<u8>> {
        let body = self.to_vec()?;
        let sign = match kp.sign(body) {
            Ok(x) => x,
            Err(e) => {
                return Err(anyhow!("{:?}", e).into());
            }
        };
        let sign = match sign.raw() {
            Ok(x) => x,
            Err(e) => {
                return Err(anyhow!("{:?}", e).into());
            }
        };

        let rval = CertReq {
            info: self,
            algorithm: AlgorithmIdentifier {
                oid: *oid,
                parameters: None, // Seems to always be none
            },
            signature: BitStringRef::from_bytes(&sign)?,
        };

        Ok(rval.to_vec()?)
    }
}
