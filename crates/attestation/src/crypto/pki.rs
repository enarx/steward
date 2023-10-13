// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: Apache-2.0

use anyhow::{anyhow, bail, Result};
use sec1::pkcs8::{EncodePrivateKey, ObjectIdentifier, PrivateKeyInfo, SubjectPublicKeyInfo};
use zeroize::Zeroizing;

use der::Decode;
use sec1::EcPrivateKey;
use spki::AlgorithmIdentifier;

use const_oid::db::rfc5912::{
    ECDSA_WITH_SHA_256, ECDSA_WITH_SHA_384, ID_EC_PUBLIC_KEY as ECPK, SECP_256_R_1 as P256,
    SECP_384_R_1 as P384,
};

const ES256: AlgorithmIdentifier<'static> = AlgorithmIdentifier {
    oid: ECDSA_WITH_SHA_256,
    parameters: None,
};

const ES384: AlgorithmIdentifier<'static> = AlgorithmIdentifier {
    oid: ECDSA_WITH_SHA_384,
    parameters: None,
};

pub trait PrivateKeyInfoExt {
    /// Generates a keypair
    ///
    /// Returns the DER encoding of the `PrivateKeyInfo` type.
    fn generate(oid: ObjectIdentifier) -> Result<Zeroizing<Vec<u8>>>;

    /// Get the public key
    ///
    /// This function creates a `SubjectPublicKeyInfo` which corresponds with
    /// this private key. Note that this function does not do any cryptographic
    /// calculations. It expects that the `PrivateKeyInfo` already contains the
    /// public key.
    fn public_key(&self) -> Result<SubjectPublicKeyInfo<'_>>;

    /// Get the default signing algorithm for this `SubjectPublicKeyInfo`
    fn signs_with(&self) -> Result<AlgorithmIdentifier<'_>>;

    /// Signs the body with the specified algorithm
    ///
    /// Note that the signature is returned in its encoded form as it will
    /// appear in an X.509 certificate or PKCS#10 certification request.
    fn sign(&self, body: &[u8], algo: AlgorithmIdentifier<'_>) -> Result<Vec<u8>>;
}

impl<'a> PrivateKeyInfoExt for PrivateKeyInfo<'a> {
    fn generate(oid: ObjectIdentifier) -> Result<Zeroizing<Vec<u8>>> {
        let rand = rand::thread_rng();

        let doc = match oid {
            P256 => p256::SecretKey::random(rand)
                .to_pkcs8_der()
                .map_err(|e| anyhow!("{:?}", e))?,

            P384 => p384::SecretKey::random(rand)
                .to_pkcs8_der()
                .map_err(|e| anyhow!("{:?}", e))?,

            _ => bail!("unsupported"),
        };

        Ok(doc.to_bytes())
    }

    fn public_key(&self) -> Result<SubjectPublicKeyInfo<'_>> {
        match self.algorithm.oids()? {
            (ECPK, ..) => {
                let ec = EcPrivateKey::from_der(self.private_key)?;
                let pk = ec.public_key.ok_or_else(|| anyhow!("missing public key"))?;
                Ok(SubjectPublicKeyInfo {
                    algorithm: self.algorithm,
                    subject_public_key: pk,
                })
            }
            _ => bail!("unsupported"),
        }
    }

    fn signs_with(&self) -> Result<AlgorithmIdentifier<'_>> {
        match self.algorithm.oids()? {
            (ECPK, Some(P256)) => Ok(ES256),
            (ECPK, Some(P384)) => Ok(ES384),
            _ => bail!("unsupported"),
        }
    }

    fn sign(&self, body: &[u8], algo: AlgorithmIdentifier<'_>) -> Result<Vec<u8>> {
        let ec = EcPrivateKey::from_der(self.private_key)?;
        match (self.algorithm.oids()?, algo) {
            ((ECPK, Some(P256)), ES256) => {
                use p256::ecdsa::signature::Signer;
                use p256::ecdsa::Signature;
                let sign_key = p256::ecdsa::SigningKey::from_bytes(ec.private_key)?;
                let signed: Signature = sign_key.sign(body);
                Ok(signed.to_der().as_bytes().to_vec())
            }

            ((ECPK, Some(P384)), ES384) => {
                use p384::ecdsa::signature::Signer;
                use p384::ecdsa::Signature;
                let sign_key = p384::ecdsa::SigningKey::from_bytes(ec.private_key)?;
                let signed: Signature = sign_key.sign(body);
                Ok(signed.to_der().as_bytes().to_vec())
            }

            _ => bail!("unsupported"),
        }
    }
}
