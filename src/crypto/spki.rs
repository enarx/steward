use super::oids::*;

use der::{Decodable, Sequence};
use ring::signature::VerificationAlgorithm as VerAlg;
use ring::signature::*;
use spki::{AlgorithmIdentifier, SubjectPublicKeyInfo};

use anyhow::{anyhow, Result};

#[derive(Clone, Debug, PartialEq, Eq, Sequence)]
pub struct RsaSsaPssParams<'a> {
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT")]
    hash_algorithm: AlgorithmIdentifier<'a>,

    #[asn1(context_specific = "1", tag_mode = "EXPLICIT")]
    mask_algorithm: AlgorithmIdentifier<'a>,

    #[asn1(context_specific = "2", tag_mode = "EXPLICIT")]
    salt_length: u32,

    #[asn1(context_specific = "3", tag_mode = "EXPLICIT")]
    trailer_field: u32,
}

pub trait SubjectPublicKeyInfoExt {
    /// Verifies a signature
    ///
    /// The signature on the specified body will be validated with the
    /// specified algorithm. Note that the signature is provided in the
    /// already encoded form as it would appear in an X.509 certificate
    /// or a PKCS#10 certification request. If you have a signature in
    /// another format, you will have to reformat it to the correct format.
    fn verify(&self, body: &[u8], algo: AlgorithmIdentifier, signature: &[u8]) -> Result<()>;
}

impl<'a> SubjectPublicKeyInfoExt for SubjectPublicKeyInfo<'a> {
    fn verify(&self, body: &[u8], algo: AlgorithmIdentifier, sign: &[u8]) -> Result<()> {
        let alg: &'static dyn VerAlg = match (self.algorithm.oids()?, (algo.oid, algo.parameters)) {
            ((ECPUBKEY, Some(NISTP256)), (ECDSA_SHA256, None)) => &ECDSA_P256_SHA256_ASN1,
            ((ECPUBKEY, Some(NISTP384)), (ECDSA_SHA384, None)) => &ECDSA_P384_SHA384_ASN1,
            ((RSA_ES_PKCS1_V1_5, None), (RSA_SSA_PSS, Some(p))) => {
                // Decompose the RSA PSS parameters.
                let RsaSsaPssParams {
                    hash_algorithm: hash,
                    mask_algorithm: mask,
                    salt_length: salt,
                    trailer_field: tfld,
                } = p.decode_into()?;

                // Validate the sanity of the mask algorithm.
                let algo = match (mask.oid, mask.parameters) {
                    (RSA_MGF1, Some(p)) => {
                        let p = p.decode_into::<AlgorithmIdentifier>()?;
                        match (p.oids()?, salt, tfld) {
                            ((SHA256, None), 32, 1) => Ok(SHA256),
                            ((SHA384, None), 48, 1) => Ok(SHA384),
                            ((SHA512, None), 64, 1) => Ok(SHA512),
                            _ => Err(anyhow!("unsupported")),
                        }
                    }
                    _ => Err(anyhow!("unsupported")),
                }?;

                // Prepare for validation.
                match (hash.oids()?, algo) {
                    ((SHA256, None), SHA256) => &RSA_PSS_2048_8192_SHA256,
                    ((SHA384, None), SHA384) => &RSA_PSS_2048_8192_SHA384,
                    ((SHA512, None), SHA512) => &RSA_PSS_2048_8192_SHA512,
                    _ => return Err(anyhow!("unsupported")),
                }
            }
            _ => return Err(anyhow!("unsupported")),
        };

        let upk = UnparsedPublicKey::new(alg, self.subject_public_key);
        Ok(upk.verify(body, sign)?)
    }
}
