// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: AGPL-3.0-only

use anyhow::{anyhow, Result};
use const_oid::ObjectIdentifier;
use der::{asn1::BitStringRef, Encode};
#[cfg(target_os = "wasi")]
use p256::ecdsa::signature::Signature as _;
#[cfg(target_os = "wasi")]
use p256::ecdsa::Signature as p256_signature;
#[cfg(target_os = "wasi")]
use p384::ecdsa::signature::Signature as _;
#[cfg(target_os = "wasi")]
use p384::ecdsa::Signature as p384_signature;
use pkcs8::PrivateKeyInfo;
use spki::AlgorithmIdentifier;
use x509::request::{CertReq, CertReqInfo};

use const_oid::db::rfc5912::{
    ECDSA_WITH_SHA_256, ECDSA_WITH_SHA_384, ID_EXTENSION_REQ, SECP_256_R_1, SECP_384_R_1,
};

use super::{PrivateKeyInfoExt, SubjectPublicKeyInfoExt};

#[cfg(target_os = "wasi")]
use wasi_crypto_guest::signatures::SignatureKeyPair;

pub trait CertReqExt<'a> {
    /// Verifies that a certification request is sane.
    ///
    /// This verifies that the certification request is properly self signed
    /// and well formatted. The rest is up to you.
    fn verify(self) -> Result<CertReqInfo<'a>>;
    #[cfg(target_os = "wasi")]
    fn verify_kp(self, kp: &SignatureKeyPair) -> Result<CertReqInfo<'a>>;
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

    fn verify_kp(self, kp: &SignatureKeyPair) -> Result<CertReqInfo<'a>> {
        if self.info.version != x509::request::Version::V1 {
            return Err(anyhow!("invalid version"));
        }

        let sign = self
            .signature
            .as_bytes()
            .ok_or_else(|| anyhow!("invalid signature"))?;

        eprintln!("CSR got signature as bytes, len = {}", sign.len());

        let algo_str = match self.algorithm.oid {
            ECDSA_WITH_SHA_256 => "ECDSA_P256_SHA256",
            ECDSA_WITH_SHA_384 => "ECDSA_P384_SHA384",
            oid => {
                return Err(anyhow!("Unexpected OID: {:?}", oid));
            }
        };

        let body = self.info.to_vec()?;

        eprintln!("CSR body as bytes, len = {}", body.len());

        let signature_obj = match wasi_crypto_guest::signatures::Signature::from_raw(algo_str, sign)
        {
            Ok(x) => x,
            Err(e) => {
                return Err(anyhow!(
                    "Failed to get wasi-crypto signature object from bytes {:?}",
                    e
                ));
            }
        };

        eprintln!("CSR got wasi-crypto sig object");

        let pubkey = kp.publickey().unwrap();

        eprintln!("CSR got wasi-crypto public key object");

        match pubkey.signature_verify(body, &signature_obj) {
            Ok(_) => {
                eprintln!("CSR validated!");
            }
            Err(e) => {
                eprintln!("CSR failed to validate signature {:?}", e);
                return Err(anyhow!("Failed to validate signature {:?}", e));
            }
        }

        eprintln!("CSR validly signed");

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
            signature: BitStringRef::from_bytes(&sign).unwrap(),
        };

        Ok(rval.to_vec()?)
    }
}
