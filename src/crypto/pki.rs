use der::{Decodable, Encodable};
use sec1::EcPrivateKey;
use spki::AlgorithmIdentifier;

use anyhow::{anyhow, Result};
use pkcs8::{ObjectIdentifier, PrivateKeyInfo, SubjectPublicKeyInfo};
use zeroize::Zeroizing;

use super::oids::*;

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
    fn public_key(&self) -> Result<SubjectPublicKeyInfo>;

    /// Get the default signing algorithm for this `SubjectPublicKeyInfo`
    fn signs_with(&self) -> Result<AlgorithmIdentifier>;

    /// Signs the body with the specified algorithm
    ///
    /// Note that the signature is returned in its encoded form as it will
    /// appear in an X.509 certificate or PKCS#10 certification request.
    fn sign(&self, body: &[u8], algo: AlgorithmIdentifier) -> Result<Vec<u8>>;
}

impl<'a> PrivateKeyInfoExt for PrivateKeyInfo<'a> {
    fn generate(oid: ObjectIdentifier) -> Result<Zeroizing<Vec<u8>>> {
        let rand = ring::rand::SystemRandom::new();

        let doc = match oid {
            NISTP256 => {
                use ring::signature::{EcdsaKeyPair, ECDSA_P256_SHA256_ASN1_SIGNING as ALG};
                EcdsaKeyPair::generate_pkcs8(&ALG, &rand)?
            }

            NISTP384 => {
                use ring::signature::{EcdsaKeyPair, ECDSA_P384_SHA384_ASN1_SIGNING as ALG};
                EcdsaKeyPair::generate_pkcs8(&ALG, &rand)?
            }

            _ => return Err(anyhow!("unsupported")),
        };

        Ok(doc.as_ref().to_vec().into())
    }

    fn public_key(&self) -> Result<SubjectPublicKeyInfo> {
        match self.algorithm.oids()? {
            (ECPUBKEY, ..) => {
                let ec = EcPrivateKey::from_der(self.private_key)?;
                let pk = ec.public_key.ok_or_else(|| anyhow!("missing public key"))?;
                Ok(SubjectPublicKeyInfo {
                    algorithm: self.algorithm,
                    subject_public_key: pk,
                })
            }
            _ => return Err(anyhow!("unsupported")),
        }
    }

    fn signs_with(&self) -> Result<AlgorithmIdentifier> {
        match self.algorithm.oids()? {
            (ECPUBKEY, Some(NISTP256)) => Ok(AlgorithmIdentifier {
                oid: ECDSA_SHA256,
                parameters: None,
            }),

            (ECPUBKEY, Some(NISTP384)) => Ok(AlgorithmIdentifier {
                oid: ECDSA_SHA384,
                parameters: None,
            }),

            _ => return Err(anyhow!("unsupported")),
        }
    }

    fn sign(&self, body: &[u8], algo: AlgorithmIdentifier) -> Result<Vec<u8>> {
        let rng = ring::rand::SystemRandom::new();
        match (self.algorithm.oids()?, algo.oids()?) {
            ((ECPUBKEY, Some(NISTP256)), (ECDSA_SHA256, None)) => {
                use ring::signature::{EcdsaKeyPair, ECDSA_P256_SHA256_ASN1_SIGNING as ALG};
                let kp = EcdsaKeyPair::from_pkcs8(&ALG, &self.to_vec()?)?;
                Ok(kp.sign(&rng, body)?.as_ref().to_vec())
            }

            ((ECPUBKEY, Some(NISTP384)), (ECDSA_SHA384, None)) => {
                use ring::signature::{EcdsaKeyPair, ECDSA_P384_SHA384_ASN1_SIGNING as ALG};
                let kp = EcdsaKeyPair::from_pkcs8(&ALG, &self.to_vec()?)?;
                Ok(kp.sign(&rng, body)?.as_ref().to_vec())
            }

            _ => Err(anyhow!("unsupported")),
        }
    }
}
