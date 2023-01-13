// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: AGPL-3.0-only

pub mod config;

use self::config::Config;
use super::crypto::{CrlList, PkiPathCRLCheck, TbsCertificateExt};

use std::{fmt::Debug, mem::size_of};

use anyhow::{bail, ensure, Context, Result};
use const_oid::db::rfc5912::ECDSA_WITH_SHA_384;
use const_oid::ObjectIdentifier;
use der::asn1::UIntRef;
use der::{Decode, Encode, Sequence};
use flagset::{flags, FlagSet};
use sec1::pkcs8::AlgorithmIdentifier;
use semver::Version;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha384};
use x509::ext::Extension;
use x509::{request::CertReqInfo, Certificate};
use x509::{PkiPath, TbsCertificate};

#[derive(Clone, Debug, PartialEq, Eq, Sequence)]
pub struct Certificates<'a> {
    pub vcek: Certificate<'a>,
    pub crl: CrlList<'a>,
}

#[derive(Clone, Debug, PartialEq, Eq, Sequence)]
pub struct Evidence<'a> {
    pub crts: Certificates<'a>,

    #[asn1(type = "OCTET STRING")]
    pub report: &'a [u8],
}

flags! {
    #[derive(Deserialize, Serialize)]
    pub enum PolicyFlags: u8 {
        /// Indicates if only one socket is permitted
        SingleSocket = 1 << 4,
        /// Indicates if debugging is permitted
        Debug = 1 << 3,
        /// Indicates is association with migration assistant is permitted
        MigrateMA = 1 << 2,
        /// Reserved, must be one
        Reserved = 1 << 1,
        /// Indicates if SMT is permitted
        SMT = 1 << 0,
    }

    /// Indication of memory mode, either SME or TSME.
    #[derive(Deserialize, Serialize, Default)]
    pub enum PlatformInfoFlags: u8 {
        /// Transparent Secure Memory Encryption
        TSME = 1 << 1,
        /// Secure Memory Encryption
        #[default]
        SME = 1 << 0,
    }
}

#[repr(C, packed)]
#[derive(Copy, Clone, Debug)]
pub struct Policy {
    /// Minimum ABI minor version required for the guest to run
    pub abi_minor: u8,
    /// Minimum ABI major version required for the guest to run
    pub abi_major: u8,
    /// Bit fields indicating enabled features
    pub flags: FlagSet<PolicyFlags>,
    /// Reserved, must be zero
    rsvd: [u8; 5],
}

impl From<Policy> for Version {
    fn from(value: Policy) -> Self {
        Version::new(value.abi_major as _, value.abi_minor as _, 0)
    }
}

#[repr(C, packed)]
#[derive(Copy, Clone, Debug)]
pub struct PlatformInfo {
    /// Bit fields indicating enabled features
    pub flag: PlatformInfoFlags,
    /// Reserved
    rsvd: [u8; 7],
}

#[repr(C, packed)]
#[derive(Copy, Clone, Debug)]
pub struct Body {
    /// The version of the attestation report, currently 2
    pub version: u32,
    /// Guest Security Version Number (SVN)
    pub guest_svn: u32,
    /// The guest policy
    /// This indicates the required version of the firmware, and if debugging is enabled.
    pub policy: Policy,
    /// The family ID provided at launch
    pub family_id: [u8; 16],
    /// The image ID provided at launch
    pub image_id: [u8; 16],
    /// The guest Virtual Machine Privilege Level (VMPL) for the attestation report
    pub vmpl: u32,
    /// The signature algorithm used to sign this report
    pub sig_algo: u32,
    /// Current TCB
    pub plat_version: u64,
    /// Platform information
    pub plat_info: PlatformInfo,
    /// Indicates (zero or one) that the digest of the author key is in `author_key_digest`
    /// The other bits are reserved and must be zero.
    pub author_key_en: u32,
    /// Reserved, must be zero
    rsvd1: u32,
    /// Guest-provided data
    pub report_data: [u8; 64],
    /// The measurement calculated at launch
    pub measurement: [u8; 48],
    /// Data provided by the hypervisor at launch
    pub host_data: [u8; 32],
    /// SHA-384 of the public key
    pub id_key_digest: [u8; 48],
    /// SHA-384 of the author key that certified the ID key, or zeros is `author_key_en` is 1
    pub author_key_digest: [u8; 48],
    /// The report ID of this guest
    pub report_id: [u8; 32],
    /// The report ID of this guest's migration agent
    pub report_id_ma: [u8; 32],
    /// Represents the bootloader, SNP firmware, and patch level of the CPU
    pub reported_tcb: u64,
    /// Reserved, must be zero
    rsvd2: [u8; 24],
    /// The identifier unique to the chip, optionally masked and set to zero
    pub chip_id: [u8; 64],
    /// Committed TCB
    pub committed_tcb: u64,
    /// The build number of the Current Version
    pub current_build: u8,
    /// The minor number of the Current Version
    pub current_minor: u8,
    /// The major number of the Current Version
    pub current_major: u8,
    /// Reserved, must be zero
    rsvd3: u8,
    /// The build number of the Committed Version
    pub committed_build: u8,
    /// The minor number of the Committed Version
    pub committed_minor: u8,
    /// The major number of the Committed Version
    pub committed_major: u8,
    /// Reserved, must be zero
    rsvd4: u8,
    /// The Current TCB at the time the guest was launched or imported
    pub launch_tcb: u64,
    /// Reserved, must be zero
    rsvd5: [u8; 168],
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
            r: UIntRef<'a>,
            s: UIntRef<'a>,
        }

        self.r.reverse();
        self.s.reverse();

        let es = EcdsaSig {
            r: UIntRef::new(&self.r)?,
            s: UIntRef::new(&self.s)?,
        };

        Ok(es.to_vec()?)
    }
}

#[repr(C, packed)]
#[derive(Copy, Clone)]
pub union Signature {
    bytes: [u8; 512],
    es384: Es384,
}

/// The attestation report from the trusted environment on an AMD system
#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct Report {
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

    pub const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.58270.1.3");
    pub const ATT: bool = true;

    // This ensures that the supplied vcek is rooted in one of our trusted chains.
    fn is_trusted<'c>(&self, certs: &'c Certificates<'c>) -> Result<&'c TbsCertificate<'c>> {
        for root in Self::ROOTS {
            let path = PkiPath::from_der(root)?;
            let vcek = &certs.vcek;

            let mut signer = Some(&path[0].tbs_certificate);
            for cert in path.iter().chain([vcek].into_iter()) {
                signer = signer.and_then(|s| s.verify_crt(cert).ok());
            }

            if let Some(signer) = signer {
                if signer == &vcek.tbs_certificate {
                    let mut path = path;
                    path.push(vcek.clone());
                    path.check_crl(&certs.crl)?;
                    return Ok(&vcek.tbs_certificate);
                }
            }
        }

        bail!("snp vcek is untrusted")
    }

    pub fn verify(
        &self,
        cri: &CertReqInfo<'_>,
        ext: &Extension<'_>,
        config: Option<&Config>,
        dbg: bool,
    ) -> Result<bool> {
        ensure!(!ext.critical, "snp extension cannot be critical");

        // Decode the evidence.
        let evidence = Evidence::from_der(ext.extn_value)?;

        // Validate the VCEK.
        let vcek = self.is_trusted(&evidence.crts)?;

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
        ensure!(
            cri.public_key.algorithm == vcek.subject_public_key_info.algorithm,
            "snp vcek algorithm mismatch"
        );

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

        // Should only be version 2
        ensure!(
            report.body.version == 2,
            "snp report has an unknown version"
        );

        // Check policy
        ensure!(
            report.body.policy.flags.contains(PolicyFlags::Reserved),
            "snp guest policy mandatory reserved flag not set"
        );

        // Enarx doesn't support migration to another machine
        ensure!(
            !report.body.policy.flags.contains(PolicyFlags::MigrateMA),
            "snp guest policy migration flag was set"
        );

        // Only check major.minor, as there isn't a revision or patch version in the attestation.
        if report.body.policy.abi_major > report.body.current_major {
            bail!("snp policy has higher abi major than firmware");
        } else if report.body.policy.abi_minor > report.body.current_minor {
            bail!("snp policy has higher abi minor than firmware");
        }

        // Check reserved fields
        ensure!(
            report.body.rsvd1 == 0,
            "snp report reserved field 1 was set"
        );

        ensure!(
            report.body.rsvd2 == [0; 24],
            "snp report reserved field 2 was set"
        );

        ensure!(
            report.body.rsvd3 == 0,
            "snp report reserved field 3 was set"
        );

        ensure!(
            report.body.rsvd4 == 0,
            "snp report reserved field 4 was set"
        );

        ensure!(
            report.body.rsvd5 == [0; 168],
            "snp report reserved field 5 was set"
        );

        ensure!(
            report.body.policy.rsvd == [0; 5],
            "snp report policy reserved fields were set"
        );

        ensure!(
            report.body.plat_info.rsvd == [0; 7],
            "snp report platform_info reserved fields were set"
        );

        // Check fields not set by Enarx
        ensure!(report.body.sig_algo == 1, "snp signature algorithm not 1");

        // Check fields set by Enarx
        ensure!(report.body.family_id == [0; 16], "snp family id was set");

        ensure!(report.body.image_id == [0; 16], "snp image id was set");

        ensure!(
            report.body.host_data == [0; 32],
            "snp report host_data field should not be set by Enarx"
        );

        ensure!(report.body.vmpl == 0, "snp report vmpl field invalid value");

        if !dbg {
            // Validate that the certification request came from an SNP VM.
            let hash = Sha384::digest(cri.public_key.to_vec()?);
            ensure!(
                hash.as_slice() == &report.body.report_data[..hash.as_slice().len()],
                "snp report.report_data is invalid"
            );

            ensure!(
                !report.body.policy.flags.contains(PolicyFlags::Debug),
                "snp guest policy permits debugging"
            );
        }

        if let Some(config) = config {
            ensure!(
                config.abi.matches(&report.body.policy.into()),
                "snp minimum abi not met"
            );

            if !config.measurements.signer.is_empty() {
                ensure!(report.body.author_key_en == 1, "snp author key unset");

                let approved = config
                    .measurements
                    .signer
                    .contains(&report.body.author_key_digest);
                ensure!(approved, "snp untrusted enarx author_key_digest");
            }

            if !config.id_key_digest.is_empty() {
                let approved = config.id_key_digest.contains(&report.body.id_key_digest);
                ensure!(
                    approved,
                    "snp untrusted enarx id_key_digest not in list of allowed key digests"
                );
            }

            if !config.id_key_digest_blacklist.is_empty() {
                let denied = config
                    .id_key_digest_blacklist
                    .contains(&report.body.id_key_digest);
                ensure!(!denied, "snp untrusted enarx id_key_digest in blacklist");
            }

            if !config.measurements.hash.is_empty() {
                let allowed = config.measurements.hash.contains(&report.body.measurement);
                ensure!(allowed, "snp untrusted enarx measurement");
            }

            if !config.measurements.hash_blacklist.is_empty() {
                let denied = config
                    .measurements
                    .hash_blacklist
                    .contains(&report.body.measurement);
                ensure!(!denied, "snp untrusted enarx hash");
            }

            if let Some(flags) = config.platform_info_flags {
                ensure!(
                    flags == report.body.plat_info.flag,
                    "snp unexpected platform info flags"
                );
            }
        }

        Ok(false)
    }
}
