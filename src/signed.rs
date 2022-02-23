use der::asn1::{BitString, ObjectIdentifier, SequenceRef};
use der::{Any, Decodable, DecodeValue, Decoder, Encodable, Header, Sequence};
use ecdsa::signature::Signer;
use pkcs8::PrivateKeyInfo;
use sec1::EcPrivateKey;
use spki::{AlgorithmIdentifier, SubjectPublicKeyInfo};

use displaydoc::Display;
use pkcs10::CertReqInfo;
use thiserror::Error;
use x509::TbsCertificate;

pub const ECPUBKEY: ObjectIdentifier = ObjectIdentifier::new("1.2.840.10045.2.1");
pub const NISTP256: ObjectIdentifier = ObjectIdentifier::new("1.2.840.10045.3.1.7");
//const ECDSA_SHA224: ObjectIdentifier = ObjectIdentifier::new("1.2.840.10045.4.3.1");
const ECDSA_SHA256: ObjectIdentifier = ObjectIdentifier::new("1.2.840.10045.4.3.2");
//const ECDSA_SHA384: ObjectIdentifier = ObjectIdentifier::new("1.2.840.10045.4.3.3");
//const ECDSA_SHA512: ObjectIdentifier = ObjectIdentifier::new("1.2.840.10045.4.3.4");

pub type Certificate<'a> = Signed<'a, TbsCertificate<'a>>;
pub type CertReq<'a> = Signed<'a, CertReqInfo<'a>>;

trait AlgorithmIdentifierExt {
    fn oids(&self) -> der::Result<(ObjectIdentifier, Option<ObjectIdentifier>)>;
}

impl<'a> AlgorithmIdentifierExt for AlgorithmIdentifier<'a> {
    fn oids(&self) -> der::Result<(ObjectIdentifier, Option<ObjectIdentifier>)> {
        Ok((
            self.oid,
            match self.parameters {
                None => None,
                Some(p) => match p {
                    Any::NULL => None,
                    _ => Some(p.oid()?),
                },
            },
        ))
    }
}

#[derive(Display, Debug, Error)]
pub enum Error {
    /// ec
    Ec(#[from] elliptic_curve::Error),

    /// ecdsa
    Ecdsa(#[from] ecdsa::Error),

    /// der
    Der(#[from] der::Error),

    /// unsupported
    Unsupported,

    /// invalid
    Invalid,
}

pub trait SignsWith<'a> {
    // Returns the default signature type for a signer
    fn signs_with(&self) -> Option<AlgorithmIdentifier<'a>>;
}

impl<'a> SignsWith<'a> for PrivateKeyInfo<'a> {
    fn signs_with(&self) -> Option<AlgorithmIdentifier<'a>> {
        match self.algorithm.oids().ok()? {
            (ECPUBKEY, Some(NISTP256)) => Some(AlgorithmIdentifier {
                oid: ECDSA_SHA256,
                parameters: None,
            }),

            _ => None,
        }
    }
}

pub trait Signable<'a>: Decodable<'a> + Encodable {
    /// Returns the signature type for this signable object
    fn algorithm(&self) -> Option<AlgorithmIdentifier<'a>> {
        None
    }
}

impl<'a> Signable<'a> for CertReqInfo<'a> {}
impl<'a> Signable<'a> for TbsCertificate<'a> {
    fn algorithm(&self) -> Option<AlgorithmIdentifier<'a>> {
        Some(self.signature)
    }
}

/// A signed data type
///
/// This type provides a generic approach to ASN.1 signed types like
/// `Certificate` and `CertificateRequest`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signed<'a, B: Signable<'a>> {
    body: B,
    algo: AlgorithmIdentifier<'a>,
    sign: BitString<'a>,
}

impl<'a, B: Signable<'a>> DecodeValue<'a> for Signed<'a, B> {
    fn decode_value(decoder: &mut Decoder<'a>, header: Header) -> der::Result<Self> {
        SequenceRef::decode_value(decoder, header)?.decode_body(|decoder| {
            let body = decoder.decode().unwrap();
            let algo = decoder.decode()?;
            let sign = decoder.decode()?;
            Ok(Self { body, algo, sign })
        })
    }
}

impl<'a, B: Signable<'a>> Sequence<'a> for Signed<'a, B> {
    fn fields<F, T>(&self, f: F) -> der::Result<T>
    where
        F: FnOnce(&[&dyn Encodable]) -> der::Result<T>,
    {
        f(&[&self.body, &self.algo, &self.sign])
    }
}

impl<'a, B: Signable<'a>> Signed<'a, B> {
    /// Signs the `body` with the specified `pki`
    ///
    /// The signature itself is written to `buf`, but this should be considered opaque.
    pub fn sign(body: B, pki: &PrivateKeyInfo<'a>, buf: &'a mut Vec<u8>) -> Result<Self, Error> {
        let algo = body
            .algorithm()
            .or(pki.signs_with())
            .ok_or(Error::Unsupported)?;

        buf.clear();
        match (pki.algorithm.oids()?, algo.oids()?) {
            ((ECPUBKEY, Some(NISTP256)), (ECDSA_SHA256, None)) => {
                use p256::ecdsa::SigningKey;

                let ecpk = EcPrivateKey::from_der(pki.private_key)?;
                if ecpk.parameters.is_some() {
                    return Err(Error::Unsupported);
                }

                let sk = SigningKey::from_bytes(ecpk.private_key)?;
                let sig = sk.sign(&body.to_vec()?).to_der();
                buf.extend_from_slice(sig.as_ref());
                let sign = BitString::from_bytes(buf)?;

                Ok(Signed { body, algo, sign })
            }

            _ => return Err(Error::Unsupported),
        }
    }

    /// Verify a signature with the given `spki`
    ///
    /// Returns the verified body on success.
    pub fn verify(&self, spki: &SubjectPublicKeyInfo<'a>) -> Result<&B, Error> {
        let sign = self.sign.as_bytes().ok_or(Error::Unsupported)?;
        let pkey = &spki.subject_public_key;
        let body = self.body.to_vec()?;

        if let Some(algo) = self.body.algorithm() {
            if algo != self.algo {
                return Err(Error::Invalid);
            }
        }

        match (spki.algorithm.oids()?, self.algo.oids()?) {
            ((ECPUBKEY, Some(NISTP256)), (ECDSA_SHA256, None)) => {
                use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
                let key = VerifyingKey::from_sec1_bytes(pkey)?;
                let sig = Signature::from_der(sign)?;
                key.verify(&body, &sig)?;
            }

            _ => return Err(Error::Unsupported),
        }

        Ok(&self.body)
    }

    pub fn body(&self) -> &B {
        &self.body
    }
}
