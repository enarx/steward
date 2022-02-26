use std::ops::{Deref, DerefMut};

use anyhow::{anyhow, Result};
use der::{Decodable, DecodeValue, Decoder, Encodable, FixedTag, Header, Tag};
use x509::{Certificate, TbsCertificate};

use super::TbsCertificateExt;

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct PkiPath<'a>(Vec<Certificate<'a>>);

impl<'a> Deref for PkiPath<'a> {
    type Target = Vec<Certificate<'a>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<'a> DerefMut for PkiPath<'a> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<'a> FixedTag for PkiPath<'a> {
    const TAG: Tag = Vec::<Certificate<'a>>::TAG;
}

impl<'a> DecodeValue<'a> for PkiPath<'a> {
    fn decode_value(decoder: &mut Decoder<'a>, header: Header) -> der::Result<Self> {
        Ok(Self(Vec::decode_value(decoder, header)?))
    }
}

impl<'a> Encodable for PkiPath<'a> {
    fn encoded_len(&self) -> der::Result<der::Length> {
        self.0.encoded_len()
    }

    fn encode(&self, encoder: &mut der::Encoder<'_>) -> der::Result<()> {
        self.0.encode(encoder)
    }
}

impl<'a> PkiPath<'a> {
    #[allow(dead_code)]
    pub fn parse_pem(pem: &str) -> Result<Vec<Vec<u8>>> {
        let mut all = Vec::new();
        let mut cur = None;
        for line in pem.lines() {
            match (line, cur.take()) {
                ("-----BEGIN CERTIFICATE-----", None) => cur = Some(String::new()),
                ("-----END CERTIFICATE-----", Some(c)) => all.push(base64::decode(c)?),
                (l, Some(mut c)) => {
                    c.push_str(l);
                    cur = Some(c);
                }
                _ => return Err(anyhow!("invalid pem file")),
            }
        }

        all.reverse();
        Ok(all)
    }

    #[allow(dead_code)]
    pub fn from_ders<T: AsRef<[u8]>>(der: &'a [T]) -> Result<PkiPath<'a>> {
        let mut all = Vec::new();

        for enc in der {
            all.push(Certificate::from_der(enc.as_ref())?);
        }

        Ok(Self(all))
    }

    #[allow(dead_code)]
    pub fn verify<'b: 'a>(
        &'b self,
        mut issuer: &'b TbsCertificate<'b>,
    ) -> Result<&'b TbsCertificate<'a>> {
        for cert in &self.0 {
            issuer = issuer.verify_crt(cert)?;
        }

        Ok(issuer)
    }
}

#[cfg(test)]
mod verify {
    mod amd {
        use super::super::PkiPath;

        #[test]
        fn genoa() {
            const CHAIN: &str = include_str!("../../certs/amd/genoa.pem");

            // Verify that validation succeeds
            let all = PkiPath::parse_pem(CHAIN).unwrap();
            let path = PkiPath::from_ders(&all).unwrap();
            path.verify(&path[0].tbs_certificate).unwrap();

            // Verify that validation fails when modified
            for i in 0..all.len() {
                let mut modified = all.clone();
                *modified[i].last_mut().unwrap() = 0;

                let path = PkiPath::from_ders(&modified).unwrap();
                path.verify(&path[0].tbs_certificate).unwrap_err();
            }
        }

        #[test]
        fn milan() {
            const CHAIN: &str = include_str!("../../certs/amd/milan.pem");

            // Verify that validation succeeds
            let all = PkiPath::parse_pem(CHAIN).unwrap();
            let path = PkiPath::from_ders(&all).unwrap();
            path.verify(&path[0].tbs_certificate).unwrap();

            // Verify that validation fails when modified
            for i in 0..all.len() {
                let mut modified = all.clone();
                *modified[i].last_mut().unwrap() = 0;

                let path = PkiPath::from_ders(&modified).unwrap();
                path.verify(&path[0].tbs_certificate).unwrap_err();
            }
        }

        #[test]
        fn sgx() {
            const CHAIN: &str = include_str!("../../certs/intel/sgx.pem");

            // Verify that validation succeeds
            let all = PkiPath::parse_pem(CHAIN).unwrap();
            let path = PkiPath::from_ders(&all).unwrap();
            path.verify(&path[0].tbs_certificate).unwrap();

            // Verify that validation fails when modified
            for i in 0..all.len() {
                let mut modified = all.clone();
                *modified[i].last_mut().unwrap() = 0;

                let path = PkiPath::from_ders(&modified).unwrap();
                path.verify(&path[0].tbs_certificate).unwrap_err();
            }
        }
    }
}
