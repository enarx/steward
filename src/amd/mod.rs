use crate::crypto::{PkiPath, TbsCertificateExt};
use der::asn1::UIntBytes;
use der::{Decodable, Encodable, Sequence, asn1::ObjectIdentifier};
use pkcs8;
use const_oid::db::rfc5912::ECDSA_WITH_SHA_384;
use x509::Certificate;

// ECDSA-Sig-Value ::= SEQUENCE {
//    r INTEGER,
//    s INTEGER
// }
#[derive(Clone, Debug, Sequence)]
struct EcdsaSig<'a> {
    r: UIntBytes<'a>,
    s: UIntBytes<'a>,
}

/// The attestation report from the trusted environment on an AMD system
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
struct SnpReportData {
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
    pub signature: [u8; 512],
}

const SNP_SIGNATURE_OFFSET:usize = 0x2A0;
const SNP_BIGNUM_SIZE:usize = 0x48;

impl SnpReportData {
    fn get_message(&self) -> Vec<u8> {
        let bytes = unsafe { std::mem::transmute::<&SnpReportData, &[u8;0x4A0]>(self) };
        println!("SnpReportSize: {}", bytes.len());
        bytes[..SNP_SIGNATURE_OFFSET].to_vec()
    }

    fn get_signature(&self) -> Vec<u8> {
        let bytes = unsafe { std::mem::transmute::<&SnpReportData, &[u8;0x4A0]>(self) };
        let mut r = bytes[SNP_SIGNATURE_OFFSET..SNP_SIGNATURE_OFFSET+SNP_BIGNUM_SIZE].to_vec();
        let mut s = bytes[SNP_SIGNATURE_OFFSET+SNP_BIGNUM_SIZE..SNP_SIGNATURE_OFFSET+2*SNP_BIGNUM_SIZE].to_vec();
        r.reverse();
        s.reverse();

        let ecdsa = EcdsaSig {
            r: UIntBytes::new(&r).unwrap(),
            s: UIntBytes::new(&s).unwrap(),
        };

        ecdsa.to_vec().unwrap()
    }
}

fn validate_snp_report(the_report: &SnpReportData, the_certificate: &Certificate) -> anyhow::Result<()> {
    the_certificate.tbs_certificate.verify_raw(
        the_report.get_message().as_slice(),
        pkcs8::AlgorithmIdentifier {
            oid: ECDSA_WITH_SHA_384,
            parameters: None,
        },
        the_report.get_signature().as_slice(),
    )
}

mod test {
    mod amd {
        use std::fs;
        use crate::amd::{SnpReportData, validate_snp_report};
        use crate::crypto::PkiPath;

        #[test]
        fn test_milan_validation_struct() {
            let test_file = fs::read("tests/snp_sample_attestation.bin").unwrap();
            let mut fixed_sized_bytes = [0u8; 0x4A0];
            for (i, v) in test_file.iter().enumerate() { fixed_sized_bytes[i] = *v; }
            let the_report:SnpReportData = unsafe { std::mem::transmute::<[u8;0x4A0],SnpReportData>(fixed_sized_bytes) };
            assert_eq!(test_file.len(), 0x4A0, "attestation blob size");

            const MILAN_VCEK: &str = include_str!("../../tests/milan_vcek.pem");
            let vcek = PkiPath::parse_pem(MILAN_VCEK).unwrap();
            let the_cert = PkiPath::from_ders(&vcek).unwrap();
            let the_cert = the_cert.first().unwrap();

            match validate_snp_report(&the_report, the_cert) {
                Ok(_) => {
                    println!("Success!")
                }
                Err(e) => {
                    eprintln!("Validation failed: {}", e)
                }
            }
        }
    }
}