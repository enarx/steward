use crate::crypto::*;

use std::{fmt::Debug, mem::size_of};

use anyhow::{anyhow, Context, Result};

use const_oid::db::rfc5912::ECDSA_WITH_SHA_384;
use const_oid::ObjectIdentifier;
use der::asn1::UIntBytes;
use der::{Decodable, Encodable, Sequence};
use pkcs8::AlgorithmIdentifier;
use sha2::Digest;
use x509::ext::Extension;
use x509::{request::CertReqInfo, Certificate};
use x509::{PkiPath, TbsCertificate};

use super::ExtVerifier;

#[derive(Clone, Debug, PartialEq, Eq, Sequence)]
pub struct Evidence<'a> {
    pub vcek: Certificate<'a>,

    #[asn1(type = "OCTET STRING")]
    pub report: &'a [u8],
}

#[repr(C, packed)]
#[derive(Copy, Clone, Debug)]
struct Body {
    pub version: u32,
    pub guest_svn: u32,
    pub policy: u64,
    pub family_id: [u8; 16],
    pub image_id: [u8; 16],
    pub vmpl: u32,
    pub sig_algo: u32,
    pub plat_version: u64,
    pub plat_info: u64,
    pub author_key_en: u32,
    rsvd1: u32,
    pub report_data: [u8; 64],
    pub measurement: [u8; 48],
    pub host_data: [u8; 32],
    pub id_key_digest: [u8; 48],
    pub author_key_digest: [u8; 48],
    pub report_id: [u8; 32],
    pub report_id_ma: [u8; 32],
    /// Represents the bootloader, SNP firmware, and patch level of the CPU
    pub reported_tcb: u64,
    rsvd2: [u8; 24],
    pub chip_id: [u8; 64],
    rsvd3: [u8; 192],
}

impl AsRef<[u8; size_of::<Self>()]> for Body {
    fn as_ref(&self) -> &[u8; size_of::<Self>()] {
        unsafe { std::mem::transmute::<_, &[u8; size_of::<Self>()]>(self) }
    }
}

#[repr(C, packed)]
#[derive(Copy, Clone, Debug)]
struct Es384 {
    r: [u8; 0x48],
    s: [u8; 0x48],
}

impl Es384 {
    /// Converts the concatenated signature to a der signature.
    pub fn to_der(mut self) -> Result<Vec<u8>> {
        /// ECDSA-Sig-Value ::= SEQUENCE {
        ///    r INTEGER,
        ///    s INTEGER
        /// }
        #[derive(Clone, Debug, Sequence)]
        struct EcdsaSig<'a> {
            r: UIntBytes<'a>,
            s: UIntBytes<'a>,
        }

        self.r.reverse();
        self.s.reverse();

        let es = EcdsaSig {
            r: UIntBytes::new(&self.r)?,
            s: UIntBytes::new(&self.s)?,
        };

        Ok(es.to_vec()?)
    }
}

#[repr(C, packed)]
#[derive(Copy, Clone)]
union Signature {
    bytes: [u8; 512],
    es384: Es384,
}

/// The attestation report from the trusted environment on an AMD system
#[repr(C, packed)]
#[derive(Copy, Clone)]
struct Report {
    pub body: Body,
    pub signature: Signature,
}

impl Debug for Report {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Report").field("body", &self.body).finish()
    }
}

impl Report {
    /// Casts a byte buffer into a report.
    pub fn cast(raw: &[u8; size_of::<Self>()]) -> &Self {
        unsafe { std::mem::transmute(raw) }
    }
}

#[derive(Clone, Debug, Default)]
pub struct Snp(());

impl Snp {
    const ROOTS: &'static [&'static [u8]] = &[
        include_bytes!("milan.pkipath"),
        include_bytes!("genoa.pkipath"),
    ];

    // This ensures that the supplied vcek is rooted in one of our trusted chains.
    fn is_trusted<'c>(&self, vcek: &'c Certificate<'c>) -> Result<&'c TbsCertificate<'c>> {
        for root in Self::ROOTS {
            let path = PkiPath::from_der(root)?;

            let mut signer = Some(&path.0[0].tbs_certificate);
            for cert in path.0.iter().chain([vcek].into_iter()) {
                signer = signer.and_then(|s| s.verify_crt(cert).ok());
            }

            if let Some(signer) = signer {
                if signer == &vcek.tbs_certificate {
                    return Ok(&vcek.tbs_certificate);
                }
            }
        }

        Err(anyhow!("snp vcek is untrusted"))
    }
}

impl ExtVerifier for Snp {
    const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.58270.1.3");
    const ATT: bool = true;

    fn verify(&self, cri: &CertReqInfo<'_>, ext: &Extension<'_>, dbg: bool) -> Result<bool> {
        if ext.critical {
            return Err(anyhow!("snp extension cannot be critical"));
        }

        // Decode the evidence.
        let evidence = Evidence::from_der(ext.extn_value)?;

        // Validate the VCEK.
        let vcek = self.is_trusted(&evidence.vcek)?;

        // Force certs to have the same key type as the VCEK.
        //
        // A note about this check is in order. We don't want to build crypto
        // algorithm negotiation into this protocol. Not only is it complex
        // but it is also subject to downgrade attacks. For example, if the
        // weakest link in the certificate chain is a P384 key and the
        // attacker downgrades the negotiation to P256, it has just weakened
        // security for the whole chain.
        //
        // We solve this by using forcing the certification request to have
        // the same key type as the VCEK. This means we have no worse security
        // than whatever AMD chose for the VCEK.
        //
        // Additionally, we do this check early to be defensive.
        if cri.public_key.algorithm != vcek.subject_public_key_info.algorithm {
            return Err(anyhow!("snp vcek algorithm mismatch"));
        }

        // Extract the report and its signature.
        let array = evidence
            .report
            .try_into()
            .context("snp report is incorrect size")?;
        let report = Report::cast(array);
        let signature = unsafe { report.signature.es384 }.to_der()?;

        // Validate the report signature.
        vcek.verify_raw(
            report.body.as_ref(),
            AlgorithmIdentifier {
                oid: ECDSA_WITH_SHA_384,
                parameters: None,
            },
            &signature,
        )
        .context("snp report contains invalid signature")?;

        // TODO: additional field validations.

        if !dbg {
            // Validate that the certification request came from an SNP VM.
            let hash = sha2::Sha384::digest(&cri.public_key.to_vec()?);
            if hash.as_slice() != &report.body.report_data[..hash.as_slice().len()] {
                return Err(anyhow!("snp report.report_data is invalid"));
            }
        }

        Ok(true)
    }
}
