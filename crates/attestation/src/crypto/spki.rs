// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: AGPL-3.0-only

use anyhow::{anyhow, Result};
use const_oid::ObjectIdentifier;
use der::{asn1::AnyRef, Sequence};

use rsa::pkcs1::DecodeRsaPublicKey;
#[cfg(all(target_os = "wasi", feature = "wasi-crypto"))]
use spki::EncodePublicKey;
use spki::{AlgorithmIdentifier, SubjectPublicKeyInfo};

use const_oid::db::rfc5912::{
    ECDSA_WITH_SHA_256, ECDSA_WITH_SHA_384, ID_EC_PUBLIC_KEY as ECPK, ID_MGF_1, ID_RSASSA_PSS,
    ID_SHA_256 as SHA256, ID_SHA_384 as SHA384, ID_SHA_512 as SHA512, RSA_ENCRYPTION as RSA,
    SECP_256_R_1 as P256, SECP_384_R_1 as P384,
};
#[cfg(all(target_os = "wasi", feature = "wasi-crypto"))]
use der::pem::LineEnding;

#[cfg(all(target_os = "wasi", feature = "wasi-crypto"))]
use wasi_crypto_guest::signatures::{Signature, SignaturePublicKey};

const ES256: (ObjectIdentifier, Option<AnyRef<'static>>) = (ECDSA_WITH_SHA_256, None);
const ES384: (ObjectIdentifier, Option<AnyRef<'static>>) = (ECDSA_WITH_SHA_384, None);

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
    fn verify(&self, body: &[u8], algo: AlgorithmIdentifier<'_>, signature: &[u8]) -> Result<()>;
}

impl<'a> SubjectPublicKeyInfoExt for SubjectPublicKeyInfo<'a> {
    #[cfg(all(target_os = "wasi", feature = "wasi-crypto"))]
    fn verify(&self, body: &[u8], algo: AlgorithmIdentifier<'_>, sign: &[u8]) -> Result<()> {
        let algo_name = match (self.algorithm.oids()?, (algo.oid, algo.parameters)) {
            ((ECPK, Some(P256)), ES256) => "ECDSA_P256_SHA256",
            ((ECPK, Some(P384)), ES384) => "ECDSA_P384_SHA384",
            ((RSA, None), (ID_RSASSA_PSS, Some(p))) => {
                // Decompose the RSA PSS parameters.
                let RsaSsaPssParams {
                    hash_algorithm: hash,
                    mask_algorithm: mask,
                    salt_length: salt,
                    trailer_field: tfld,
                } = p.decode_into().unwrap();

                // Validate the sanity of the mask algorithm.
                let algo = match (mask.oid, mask.parameters) {
                    (ID_MGF_1, Some(p)) => {
                        let p = p.decode_into::<AlgorithmIdentifier<'_>>()?;
                        match (p.oids()?, salt, tfld) {
                            ((SHA256, None), 32, 1) => Ok(SHA256),
                            ((SHA384, None), 48, 1) => Ok(SHA384),
                            ((SHA512, None), 64, 1) => Ok(SHA512),
                            ((x, y), s, t) => {
                                eprint!(
                                    "Unknown RSA hash and components: {:?}, {:?}, salt {}, tfld {}",
                                    x, y, s, t
                                );
                                Err(anyhow!("unsupported"))
                            }
                        }
                    }
                    (x, _) => {
                        eprintln!("Unknown RSA OID {:?}", x);
                        Err(anyhow!("unsupported"))
                    }
                }
                .map_err(|e| {
                    eprintln!("Some algo error {:?}", e);
                    anyhow!("{:?}", e)
                })
                .unwrap();

                match (hash.oids()?, algo) {
                    ((SHA256, None), SHA256) => "RSA_PSS_2048_SHA256",
                    ((SHA384, None), SHA384) => "RSA_PSS_3072_SHA384",
                    ((SHA512, None), SHA512) => "RSA_PSS_4096_SHA512",
                    _ => {
                        eprintln!("Error unknown hash.oids");
                        bail!("unsupported")
                    }
                }
            }
            _ => {
                eprintln!("Unknown algorithm, should not be here!");
                bail!("unsupported")
            }
        };

        let public_key = match algo_name {
            "RSA_PSS_2048_SHA256" | "RSA_PSS_3072_SHA384" | "RSA_PSS_4096_SHA512" => {
                let pkey = rsa::RsaPublicKey::from_pkcs1_der(self.subject_public_key)?;
                SignaturePublicKey::from_pem(
                    algo_name,
                    pkey.to_public_key_pem(LineEnding::LF).unwrap().as_bytes(),
                )
                .map_err(|e| anyhow!("{:?}", e))
                .unwrap()
            }
            _ => SignaturePublicKey::from_raw(algo_name, self.subject_public_key)
                .map_err(|e| anyhow!("{:?}", e))
                .unwrap(),
        };

        let signature = match algo_name {
            "ECDSA_P256_SHA256" => {
                let temp = p256::ecdsa::Signature::from_der(sign)?;
                temp.to_vec()
            }
            "ECDSA_P384_SHA384" => {
                let temp = p384::ecdsa::Signature::from_der(sign)?;
                temp.to_vec()
            }
            "RSA_PSS_2048_SHA256" | "RSA_PSS_3072_SHA384" | "RSA_PSS_4096_SHA512" => {
                use signature::Signature;
                let s = rsa::pss::Signature::from_bytes(sign)?;
                eprintln!("Made RSA signature");
                s.to_vec()
            }
            _ => sign.to_vec(),
        };

        let signature = Signature::from_raw(algo_name, &signature)
            .map_err(|e| anyhow!("{:?}", e))
            .unwrap();

        Ok(public_key
            .signature_verify(body, &signature)
            .map_err(|e| anyhow!("{:?}", e))
            .unwrap())
    }

    #[cfg(any(not(target_os = "wasi"), not(feature = "wasi-crypto")))]
    fn verify(&self, body: &[u8], algo: AlgorithmIdentifier<'_>, sign: &[u8]) -> Result<()> {
        match (self.algorithm.oids()?, (algo.oid, algo.parameters)) {
            ((ECPK, Some(P256)), ES256) => {
                use p256::ecdsa::signature::Verifier;
                let vkey = p256::ecdsa::VerifyingKey::from_sec1_bytes(self.subject_public_key)?;
                let sig = p256::ecdsa::Signature::from_der(sign)?;
                Ok(vkey.verify(body, &sig)?)
            }

            ((ECPK, Some(P384)), ES384) => {
                use p384::ecdsa::signature::Verifier;
                let vkey = p384::ecdsa::VerifyingKey::from_sec1_bytes(self.subject_public_key)?;
                let sig = p384::ecdsa::Signature::from_der(sign)?;
                Ok(vkey.verify(body, &sig)?)
            }

            ((RSA, None), (ID_RSASSA_PSS, Some(p))) => {
                use signature::{Signature, Verifier};
                // Decompose the RSA PSS parameters.
                let RsaSsaPssParams {
                    hash_algorithm: hash,
                    mask_algorithm: mask,
                    salt_length: salt,
                    trailer_field: tfld,
                } = p.decode_into()?;

                let pkey = rsa::RsaPublicKey::from_pkcs1_der(self.subject_public_key)?;
                let s = rsa::pss::Signature::from_bytes(sign)?;

                // Validate the sanity of the mask algorithm.
                let algo = match (mask.oid, mask.parameters) {
                    (ID_MGF_1, Some(p)) => {
                        let p = p.decode_into::<AlgorithmIdentifier<'_>>()?;
                        match (p.oids()?, salt, tfld) {
                            ((SHA256, None), 32, 1) => Ok(SHA256),
                            ((SHA384, None), 48, 1) => Ok(SHA384),
                            ((SHA512, None), 64, 1) => Ok(SHA512),
                            _ => Err(anyhow!("unsupported")),
                        }
                    }
                    _ => Err(anyhow!("unsupported")),
                }?;

                match (hash.oids()?, algo) {
                    ((SHA256, None), SHA256) => {
                        let vkey = rsa::pss::VerifyingKey::<sha2::Sha256>::new(pkey);
                        Ok(vkey.verify(body, &s)?)
                    }
                    ((SHA384, None), SHA384) => {
                        let vkey = rsa::pss::VerifyingKey::<sha2::Sha384>::new(pkey);
                        Ok(vkey.verify(body, &s)?)
                    }
                    ((SHA512, None), SHA512) => {
                        let vkey = rsa::pss::VerifyingKey::<sha2::Sha512>::new(pkey);
                        Ok(vkey.verify(body, &s)?)
                    }
                    _ => Err(anyhow!("unsupported")),
                }
            }

            _ => Err(anyhow!("unsupported")),
        }
    }
}
