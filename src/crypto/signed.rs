use der::*;
use pkcs8::PrivateKeyInfo;
use spki::{AlgorithmIdentifier, SubjectPublicKeyInfo};
use x509::request::CertReqInfo;
use x509::TbsCertificate;

use anyhow::{anyhow, Result};

use super::pki::PrivateKeyInfoExt;
use super::spki::SubjectPublicKeyInfoExt;

pub type Certificate<'a> = Signed<'a, TbsCertificate<'a>>;
pub type CertReq<'a> = Signed<'a, CertReqInfo<'a>>;

pub trait Signable: Sized + Encodable {
    /// Returns the signature type for this signable object
    fn algorithm<'i>(&'i self, pki: &'i PrivateKeyInfo) -> Result<AlgorithmIdentifier<'i>> {
        pki.signs_with()
    }

    /// Signs the object with the specified `PrivateKeyInfo`
    fn sign(self, pki: &PrivateKeyInfo) -> Result<Vec<u8>> {
        let abuf = self.algorithm(pki)?.to_vec()?;
        let algo = AlgorithmIdentifier::from_der(&abuf)?;

        let body = self.to_vec()?;
        let sign = pki.sign(&body, algo)?;

        let rval = Signed {
            body: self,
            algo,
            sign: asn1::BitString::from_bytes(&sign)?,
        };

        Ok(rval.to_vec()?)
    }
}

impl<'a> Signable for CertReqInfo<'a> {}
impl<'a> Signable for TbsCertificate<'a> {
    fn algorithm<'i>(&'i self, _: &'i PrivateKeyInfo) -> Result<AlgorithmIdentifier<'i>> {
        Ok(self.signature)
    }
}

/// A signed data type
///
/// This type provides a generic approach to ASN.1 signed types like
/// `Certificate` and `CertificateRequest`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signed<'a, B> {
    body: B,
    algo: AlgorithmIdentifier<'a>,
    sign: asn1::BitString<'a>,
}

impl<'a, B> FixedTag for Signed<'a, B> {
    const TAG: Tag = Tag::Sequence;
}

impl<'a, B: Signable + Decodable<'a>> DecodeValue<'a> for Signed<'a, B> {
    fn decode_value(decoder: &mut Decoder<'a>, header: Header) -> der::Result<Self> {
        asn1::SequenceRef::decode_value(decoder, header)?.decode_body(|decoder| {
            let body = decoder.decode().unwrap();
            let algo = decoder.decode()?;
            let sign = decoder.decode()?;
            Ok(Self { body, algo, sign })
        })
    }
}

impl<'a, B: Signable + Encodable> EncodeValue for Signed<'a, B> {
    fn value_len(&self) -> der::Result<Length> {
        let body = self.body.encoded_len()?;
        let algo = self.algo.encoded_len()?;
        let sign = self.sign.encoded_len()?;
        (body + algo)? + sign
    }

    fn encode_value(&self, encoder: &mut Encoder<'_>) -> der::Result<()> {
        encoder.encode(&self.body)?;
        encoder.encode(&self.algo)?;
        encoder.encode(&self.sign)?;
        Ok(())
    }
}

impl<'a, B: Signable + Decodable<'a> + Encodable> Signed<'a, B> {
    /// Verify a signature with the given `spki`
    ///
    /// Returns the verified body on success.
    pub fn verify(&self, spki: &'a SubjectPublicKeyInfo<'a>) -> Result<&B> {
        let sign = self.sign.as_bytes().ok_or(anyhow!("invalid signature"))?;
        let body = self.body.to_vec()?;
        spki.verify(&body, self.algo, sign)?;
        Ok(&self.body)
    }

    pub fn body(&self) -> &B {
        &self.body
    }
}
