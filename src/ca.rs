use std::borrow::Borrow;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, SystemTime};

use der::asn1::{BitString, UIntBytes};
use der::{Decodable, Encodable};
use p256::ecdsa::{signature::Signer, SigningKey};
use pkcs10::CertReq;
use pkcs8::{AlgorithmIdentifier, PrivateKeyInfo};
use sec1::EcPrivateKey;
use x501::time::{Time, Validity};
use x509::{Certificate, TbsCertificate};

use displaydoc::Display;
use thiserror::Error;

#[derive(Display, Debug, Error)]
pub enum Error {
    /// der
    Der(#[from] der::Error),

    /// ec
    Ec(#[from] p256::elliptic_curve::Error),

    /// ecdsa
    Ecdsa(#[from] p256::ecdsa::Error),

    /// unsupported
    Unsupported,
}

pub struct CertificationAuthority<'a, C: Borrow<Certificate<'a>>, K: Borrow<PrivateKeyInfo<'a>>> {
    certificate: C,
    private_key: K,
    serial: &'a AtomicUsize,
}

impl<'a> CertificationAuthority<'a, Certificate<'a>, PrivateKeyInfo<'a>> {
    pub fn from_der(
        certificate: &'a [u8],
        private_key: &'a [u8],
        serial: &'a AtomicUsize,
    ) -> der::Result<Self> {
        Ok(Self::new(
            Certificate::from_der(certificate)?,
            PrivateKeyInfo::from_der(private_key)?,
            serial,
        ))
    }
}

impl<'a, C: Borrow<Certificate<'a>>, K: Borrow<PrivateKeyInfo<'a>>>
    CertificationAuthority<'a, C, K>
{
    fn parse_signing_key(&self) -> Result<SigningKey, Error> {
        let pki = self.private_key.borrow();

        match (pki.algorithm.oid, pki.algorithm.parameters.map(|p| p.oid())) {
            (super::ECPUBKEY, Some(Ok(super::NISTP256))) => (),
            _ => return Err(Error::Unsupported),
        }

        let pk = EcPrivateKey::from_der(pki.private_key)?;
        if pk.parameters.is_some() {
            return Err(Error::Unsupported);
        }

        Ok(SigningKey::from_bytes(pk.private_key)?)
    }

    pub fn new(certificate: C, private_key: K, serial: &'a AtomicUsize) -> Self {
        Self {
            certificate,
            private_key,
            serial,
        }
    }

    pub fn issue(&self, cr: &CertReq) -> Result<Vec<u8>, Error> {
        let algorithm = AlgorithmIdentifier {
            oid: super::ECDSA_SHA256,
            parameters: None,
        };

        // Get the current time and the expiration of the cert.
        let now = SystemTime::now();
        let end = now + Duration::from_secs(60 * 60 * 24);
        let validity = Validity {
            not_before: Time::try_from(now)?,
            not_after: Time::try_from(end)?,
        };

        // Get the next serial number.
        let serial = self.serial.fetch_add(1, Ordering::SeqCst).to_be_bytes();
        let serial = UIntBytes::new(&serial)?;

        // Create the new certificate.
        let issuer = self.certificate.borrow();
        let tbs = TbsCertificate {
            version: x509::Version::V3,
            serial_number: serial,
            signature: algorithm,
            issuer: issuer.tbs_certificate.subject.clone(),
            validity,
            subject: issuer.tbs_certificate.subject.clone(), // FIXME
            subject_public_key_info: cr.info.public_key.clone(),
            issuer_unique_id: issuer.tbs_certificate.subject_unique_id.clone(),
            subject_unique_id: None,
            extensions: None,
        };

        // Sign the certificate.
        let sig = self.parse_signing_key()?.sign(&tbs.to_vec()?).to_der();
        let cert = Certificate {
            tbs_certificate: tbs,
            signature_algorithm: algorithm,
            signature: BitString::from_bytes(sig.as_ref())?,
        };

        Ok(cert.to_vec()?)
    }
}
