// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: AGPL-3.0-only

use crate::crypto::{SubjectPublicKeyInfoExt, TbsCertificateExt};
use std::collections::HashSet;

use anyhow::{bail, Context, Result};
use der::{Encode, Sequence};
use tracing::debug;
use x509::crl::CertificateList;
use x509::PkiPath;

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct CrlListEntry<'a> {
    pub url: String,
    pub crl: CertificateList<'a>,
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct CrlList<'a> {
    pub crls: Vec<CrlListEntry<'a>>,
}

impl<'a> CrlList<'a> {
    fn get_crl_by_url(&self, url: &str) -> Option<&CertificateList> {
        for pair in &self.crls {
            if pair.url == url {
                return Some(&pair.crl);
            }
        }
        None
    }
}

pub trait PkiPathCRLCheck<'a> {
    fn check_crl(&self, pairs: &CrlList<'a>) -> Result<()>;
}

impl<'a> PkiPathCRLCheck<'a> for PkiPath<'a> {
    fn check_crl(&self, pairs: &CrlList<'a>) -> Result<()> {
        // We want to ensure that a valid CRL was passed, so we make sure at least one of the CRLs
        // is valid for this `PkiPath`, otherwise, no valid CRLs were received, and that's not okay.
        let mut validated_crls = HashSet::new();
        let mut found = false;
        let mut iter = self.iter().peekable();
        loop {
            let cert = iter.next();
            let next = iter.peek();
            if cert.is_none() || next.is_none() {
                break;
            }
            let cert = cert.unwrap();
            let next = *next.unwrap();

            let (url, crl) = {
                let mut urls = next.tbs_certificate.get_crl_urls()?;
                // Some end certs use the parent cert CRL
                if urls.is_empty() {
                    urls = cert.tbs_certificate.get_crl_urls()?;
                }

                if let Some(crl) = pairs.get_crl_by_url(&urls[0]) {
                    (urls[0].clone(), crl)
                } else {
                    debug!("No CRLS");
                    continue;
                }
            };

            if let Some(next_update) = crl.tbs_cert_list.next_update {
                if next_update.to_system_time() <= std::time::SystemTime::now() {
                    // Don't error on CRL expiration in unit tests
                    #[cfg(not(debug_assertions))]
                    bail!("CRL expired");
                    #[cfg(debug_assertions)]
                    debug!("CRL {} expired.", crl.tbs_cert_list.issuer);
                }
            }

            if validated_crls.contains(&url) {
                // Using the parent cert CRL
                // Should only be for AMD.
                debug_assert!(!crl.tbs_cert_list.issuer.to_string().contains("AMD"));
                if let Some(revocations) = crl.tbs_cert_list.revoked_certificates.as_ref() {
                    for revoked in revocations {
                        if revoked.serial_number == next.tbs_certificate.serial_number {
                            bail!("revoked!");
                        }
                    }
                }
                found = true;
                continue;
            }

            let raw_bytes = crl.tbs_cert_list.to_vec().unwrap();
            match cert.tbs_certificate.subject_public_key_info.verify(
                &raw_bytes,
                cert.signature_algorithm,
                crl.signature.raw_bytes(),
            ) {
                Ok(_) => {
                    if let Some(revocations) = crl.tbs_cert_list.revoked_certificates.as_ref() {
                        for revoked in revocations {
                            if revoked.serial_number == next.tbs_certificate.serial_number {
                                bail!("revoked!");
                            }
                        }
                    }
                    found = true;
                    validated_crls.insert(url);
                }
                Err(e) => {
                    return Err(e).context("CRL validation error");
                }
            }
        }
        if found {
            return Ok(());
        }
        Err(anyhow::Error::msg("no valid CRL was provided"))
    }
}

#[cfg(test)]
mod tests {
    use super::super::{PkiPathCRLCheck, PrivateKeyInfoExt, TbsCertificateExt};
    use super::*;

    use const_oid::db::rfc5280::{ID_CE_BASIC_CONSTRAINTS, ID_CE_KEY_USAGE};
    use const_oid::db::rfc5912::SECP_256_R_1 as P256;
    use der::asn1::{BitStringRef, GeneralizedTime, Ia5StringRef, UIntRef};
    use der::Decode;
    use sec1::pkcs8::PrivateKeyInfo;
    use std::time::{Duration, SystemTime};
    use x509::crl::{RevokedCert, TbsCertList};
    use x509::ext::pkix::crl::dp::DistributionPoint;
    use x509::ext::pkix::crl::CrlDistributionPoints;
    use x509::ext::pkix::name::{DistributionPointName, GeneralName};
    use x509::ext::pkix::{BasicConstraints, KeyUsage, KeyUsages};
    use x509::name::RdnSequence;
    use x509::time::{Time, Validity};
    use x509::{Certificate, TbsCertificate};
    use zeroize::Zeroizing;

    const REVOKED_SERIAL: u32 = 99;
    const TEST_URL: &str = "https://pki.example.com/crl.der";
    const TEST_ISSUER: &str = "CN=localhost";

    fn create_ca() -> (Zeroizing<Vec<u8>>, Vec<u8>) {
        // Generate the private key.
        let key = PrivateKeyInfo::generate(P256).unwrap();
        let pki = PrivateKeyInfo::from_der(key.as_ref()).unwrap();

        // Create a relative distinguished name for the "Issuer" field.
        let rdns = RdnSequence::encode_from_string(TEST_ISSUER).unwrap();
        let rdns = RdnSequence::from_der(&rdns).unwrap();

        // Create the extensions.
        let ku = KeyUsage((KeyUsages::KeyCertSign | KeyUsages::CRLSign).into())
            .to_vec()
            .unwrap();
        let bc = BasicConstraints {
            ca: true,
            path_len_constraint: Some(0),
        }
        .to_vec()
        .unwrap();

        // Create the certificate duration.
        let now = SystemTime::now();
        let dur = Duration::from_secs(60 * 60);
        let validity = Validity {
            not_before: Time::GeneralTime(GeneralizedTime::from_system_time(now).unwrap()),
            not_after: Time::GeneralTime(GeneralizedTime::from_system_time(now + dur).unwrap()),
        };

        let crl_dist = CrlDistributionPoints(vec![DistributionPoint {
            distribution_point: Some(DistributionPointName::FullName(vec![
                GeneralName::UniformResourceIdentifier(Ia5StringRef::new(TEST_URL).unwrap()),
            ])),
            reasons: None,
            crl_issuer: None,
        }]);

        let crl_dist = crl_dist.to_vec().unwrap();

        // Create the certificate body.
        let tbs = TbsCertificate {
            version: x509::Version::V3,
            serial_number: UIntRef::new(&[0u8]).unwrap(),
            signature: pki.signs_with().unwrap(),
            issuer: rdns.clone(),
            validity,
            subject: rdns,
            subject_public_key_info: pki.public_key().unwrap(),
            issuer_unique_id: None,
            subject_unique_id: None,
            extensions: Some(vec![
                x509::ext::Extension {
                    extn_id: ID_CE_KEY_USAGE,
                    critical: true,
                    extn_value: &ku,
                },
                x509::ext::Extension {
                    extn_id: ID_CE_BASIC_CONSTRAINTS,
                    critical: true,
                    extn_value: &bc,
                },
                x509::ext::Extension {
                    extn_id: const_oid::db::rfc5912::ID_CE_CRL_DISTRIBUTION_POINTS,
                    critical: false,
                    extn_value: &crl_dist,
                },
            ]),
        };

        // Self-sign the certificate.
        let crt = tbs.sign(&pki).unwrap();

        (key, crt)
    }

    fn create_cert(
        ca_key: &Zeroizing<Vec<u8>>,
        cert_serial: &UIntRef,
    ) -> (Zeroizing<Vec<u8>>, Vec<u8>) {
        let ca_pki = PrivateKeyInfo::from_der(ca_key.as_ref()).unwrap();

        // Generate the private key.
        let key = PrivateKeyInfo::generate(P256).unwrap();
        let pki = PrivateKeyInfo::from_der(key.as_ref()).unwrap();

        // Create the extensions.
        let ku = KeyUsage(KeyUsages::EncipherOnly.into()).to_vec().unwrap();
        let bc = BasicConstraints {
            ca: false,
            path_len_constraint: None,
        }
        .to_vec()
        .unwrap();

        // Create a relative distinguished name for the "Issuer" field.
        let rdns_issuer = RdnSequence::encode_from_string(TEST_ISSUER).unwrap();
        let rdns_issuer = RdnSequence::from_der(&rdns_issuer).unwrap();

        let rdns_subject = RdnSequence::encode_from_string("CN=Test_Cert").unwrap();
        let rdns_subject = RdnSequence::from_der(&rdns_subject).unwrap();

        // Create the certificate duration.
        let now = SystemTime::now();
        let dur = Duration::from_secs(60 * 60);
        let validity = Validity {
            not_before: Time::GeneralTime(GeneralizedTime::from_system_time(now).unwrap()),
            not_after: Time::GeneralTime(GeneralizedTime::from_system_time(now + dur).unwrap()),
        };

        let crl_dist = CrlDistributionPoints(vec![DistributionPoint {
            distribution_point: Some(DistributionPointName::FullName(vec![
                GeneralName::UniformResourceIdentifier(Ia5StringRef::new(TEST_URL).unwrap()),
            ])),
            reasons: None,
            crl_issuer: None,
        }]);

        let crl_dist = crl_dist.to_vec().unwrap();

        // Create the certificate body.
        let tbs = TbsCertificate {
            version: x509::Version::V3,
            serial_number: cert_serial.clone(),
            signature: pki.signs_with().unwrap(),
            issuer: rdns_issuer,
            validity,
            subject: rdns_subject,
            subject_public_key_info: pki.public_key().unwrap(),
            issuer_unique_id: None,
            subject_unique_id: None,
            extensions: Some(vec![
                x509::ext::Extension {
                    extn_id: ID_CE_KEY_USAGE,
                    critical: true,
                    extn_value: &ku,
                },
                x509::ext::Extension {
                    extn_id: ID_CE_BASIC_CONSTRAINTS,
                    critical: true,
                    extn_value: &bc,
                },
                x509::ext::Extension {
                    extn_id: const_oid::db::rfc5912::ID_CE_CRL_DISTRIBUTION_POINTS,
                    critical: false,
                    extn_value: &crl_dist,
                },
            ]),
        };

        // Self-sign the certificate.
        let crt = tbs.sign(&ca_pki).unwrap();

        (key, crt)
    }

    fn create_crl(
        ca_key: &Zeroizing<Vec<u8>>,
        ca_cert: &Certificate,
        cert_serial: Option<UIntRef>,
    ) -> Vec<u8> {
        let ca_pki = PrivateKeyInfo::from_der(ca_key.as_ref()).unwrap();

        let now = SystemTime::now();
        let dur = Duration::from_secs(60 * 60 * 24);
        let yesterday = Time::GeneralTime(GeneralizedTime::from_system_time(now - dur).unwrap());

        // Create a relative distinguished name for the "Issuer" field.
        let rdns = RdnSequence::encode_from_string(TEST_ISSUER).unwrap();
        let rdns = RdnSequence::from_der(&rdns).unwrap();

        let revoked = if let Some(serial) = cert_serial {
            Some(vec![RevokedCert {
                serial_number: serial,
                revocation_date: yesterday,
                crl_entry_extensions: None,
            }])
        } else {
            None
        };

        let tbs_cert = TbsCertList {
            version: Default::default(),
            signature: ca_cert.signature_algorithm.clone(),
            issuer: rdns,
            this_update: yesterday,
            next_update: None,
            revoked_certificates: revoked,
            crl_extensions: None,
        };

        let signature = ca_pki
            .sign(
                &tbs_cert.to_vec().unwrap(),
                ca_cert.signature_algorithm.clone(),
            )
            .unwrap();

        let crl = CertificateList {
            tbs_cert_list: tbs_cert,
            signature_algorithm: ca_cert.signature_algorithm.clone(),
            signature: BitStringRef::from_bytes(&signature).unwrap(),
        };

        crl.to_vec().unwrap()
    }

    #[test]
    fn not_revoked() {
        let revoked_serial = REVOKED_SERIAL.to_be_bytes();
        let revoked_serial = UIntRef::new(&revoked_serial).unwrap();

        // Create a Certificate Authority
        let (ca_pki, ca_cert) = create_ca();
        let ca_cert = Certificate::from_der(&ca_cert).unwrap();

        // Create an end Certificate
        let (_end_pki, end_cert) = create_cert(&ca_pki, &revoked_serial);
        let end_cert = Certificate::from_der(&end_cert).unwrap();

        // Create a empty Certificate Revocation List
        let crl = create_crl(&ca_pki, &ca_cert, None);
        let crl = CertificateList::from_der(&crl).unwrap();

        // Check the PKI path (CA and end Certificates)
        let path = PkiPath::from([ca_cert, end_cert]);

        let crl_list = CrlList {
            crls: vec![CrlListEntry {
                url: TEST_URL.into(),
                crl,
            }],
        };

        // Should be okay
        assert!(path.check_crl(&crl_list).is_ok());
    }

    #[test]
    fn revoked() {
        let revoked_serial = REVOKED_SERIAL.to_be_bytes();
        let revoked_serial = UIntRef::new(&revoked_serial).unwrap();

        // Create a Certificate Authority
        let (ca_pki, ca_cert) = create_ca();
        let ca_cert = Certificate::from_der(&ca_cert).unwrap();

        // Create an end Certificate
        let (_end_pki, end_cert) = create_cert(&ca_pki, &revoked_serial);
        let end_cert = Certificate::from_der(&end_cert).unwrap();

        // Create a Certificate Revocation List
        let crl = create_crl(&ca_pki, &ca_cert, Some(revoked_serial));
        let crl = CertificateList::from_der(&crl).unwrap();

        // Check the PKI path (CA and end Certificates)
        let path = PkiPath::from([ca_cert, end_cert]);

        let crl_list = CrlList {
            crls: vec![CrlListEntry {
                url: TEST_URL.into(),
                crl,
            }],
        };

        // Should be revoked!
        let err = path.check_crl(&crl_list).err().unwrap();
        assert_eq!(err.to_string(), "revoked!");
    }

    #[test]
    fn wrong_crl() {
        let revoked_serial = REVOKED_SERIAL.to_be_bytes();
        let revoked_serial = UIntRef::new(&revoked_serial).unwrap();

        // Create a Certificate Authority
        let (ca_pki1, ca_cert1) = create_ca();
        let ca_cert1 = Certificate::from_der(&ca_cert1).unwrap();

        // Create a second Certificate Authority
        let (ca_pki2, ca_cert2) = create_ca();
        let ca_cert2 = Certificate::from_der(&ca_cert2).unwrap();

        // Create an end Certificate
        let (_end_pki, end_cert) = create_cert(&ca_pki1, &revoked_serial);
        let end_cert = Certificate::from_der(&end_cert).unwrap();

        // Create an empty Certificate Revocation List from second Certificate Authority
        let empty_crl = create_crl(&ca_pki2, &ca_cert2, None);
        let empty_crl = CertificateList::from_der(&empty_crl).unwrap();

        // Check the PKI path (CA and end Certificates)
        let path = PkiPath::from([ca_cert1, end_cert]);

        let crl_list = CrlList {
            crls: vec![CrlListEntry {
                url: TEST_URL.into(),
                crl: empty_crl,
            }],
        };

        // Should fail as the provided CRL isn't for this Certificate chain
        let err = path.check_crl(&crl_list).err().unwrap();
        assert_eq!(err.to_string(), "CRL validation error");
    }
}
