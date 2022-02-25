use spki::{AlgorithmIdentifier, SubjectPublicKeyInfo};

use anyhow::{anyhow, Result};

use super::oids::*;

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
        match (self.algorithm.oids()?, algo.oids()?) {
            ((ECPUBKEY, Some(NISTP256)), (ECDSA_SHA256, None)) => {
                use ring::signature::{UnparsedPublicKey, ECDSA_P256_SHA256_ASN1 as ALG};
                let upk = UnparsedPublicKey::new(&ALG, self.subject_public_key);
                upk.verify(body, sign)?;
                Ok(())
            }

            ((ECPUBKEY, Some(NISTP384)), (ECDSA_SHA384, None)) => {
                use ring::signature::{UnparsedPublicKey, ECDSA_P384_SHA384_ASN1 as ALG};
                let upk = UnparsedPublicKey::new(&ALG, self.subject_public_key);
                upk.verify(body, sign)?;
                Ok(())
            }

            _ => Err(anyhow!("unsupported")),
        }
    }
}
