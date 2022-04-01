mod quote;

use super::ExtVerifier;
use crate::crypto::*;
use quote::traits::ParseBytes;

use std::fmt::Debug;

use anyhow::{anyhow, Result};
use const_oid::ObjectIdentifier;
use der::{Decodable, Encodable};
use sgx::parameters::{Attributes, MiscSelect};
use sha2::{Digest, Sha256};
use x509::{ext::Extension, request::CertReqInfo, Certificate, TbsCertificate};

#[derive(Clone, Debug)]
pub struct Sgx([Certificate<'static>; 1]);

impl Default for Sgx {
    fn default() -> Self {
        Self([Certificate::from_der(Self::ROOT).unwrap()])
    }
}

impl Sgx {
    const ROOT: &'static [u8] = include_bytes!("root.der");

    fn trusted<'c>(&'c self, chain: &'c [Certificate<'c>]) -> Result<&'c TbsCertificate<'c>> {
        let mut signer = &self.0[0].tbs_certificate;
        for cert in self.0.iter().chain(chain.iter()) {
            signer = signer.verify_crt(cert)?;
        }

        Ok(signer)
    }
}

impl ExtVerifier for Sgx {
    const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.58270.1.2");
    const ATT: bool = true;

    fn verify(&self, cri: &CertReqInfo<'_>, ext: &Extension<'_>, dbg: bool) -> Result<bool> {
        if ext.critical {
            return Err(anyhow!("sgx extension cannot be critical"));
        }

        // Decode the quote.
        let (quote, bytes): (quote::Quote<'_>, _) = ext.extn_value.parse()?;
        if !bytes.is_empty() {
            return Err(anyhow!("unknown trailing bytes in sgx quote"));
        }

        // Parse the certificate chain.
        let chain = quote.chain()?;
        let chain = chain
            .iter()
            .map(|c| Certificate::from_der(c))
            .collect::<Result<Vec<_>, _>>()?;

        // Validate the report.
        let pck = self.trusted(&chain)?;
        let rpt = quote.verify(pck)?;

        // Force certs to have the same key type as the PCK.
        //
        // A note about this check is in order. We don't want to build crypto
        // algorithm negotiation into this protocol. Not only is it complex
        // but it is also subject to downgrade attacks. For example, if the
        // weakest link in the certificate chain is a P384 key and the
        // attacker downgrades the negotiation to P256, it has just weakened
        // security for the whole chain.
        //
        // We solve this by using forcing the certification request to have
        // the same key type as the PCK. This means we have no worse security
        // than whatever Intel chose for the PCK.
        //
        // Additionally, we do this check early to be defensive.
        if cri.public_key.algorithm != pck.subject_public_key_info.algorithm {
            return Err(anyhow!("sgx pck algorithm mismatch"));
        }

        if !dbg {
            // TODO: Validate that the certification request came from an SGX enclave.
            let hash = Sha256::digest(&cri.public_key.to_vec()?);
            if hash.as_slice() != &rpt.reportdata[..hash.as_slice().len()] {
                return Err(anyhow!("sgx report data is invalid"));
            }

            if rpt.mrenclave != [0u8; 32] {
                return Err(anyhow!("untrusted enarx runtime"));
            }

            if rpt.mrsigner != [0u8; 32] {
                return Err(anyhow!("untrusted enarx signer"));
            }

            if rpt.cpusvn != [0u8; 16] {
                return Err(anyhow!("untrusted cpu"));
            }

            if rpt.attributes() != Attributes::default() {
                return Err(anyhow!("untrusted attributes"));
            }

            if rpt.misc_select() != MiscSelect::default() {
                return Err(anyhow!("untrusted misc select"));
            }

            if rpt.enclave_product_id() != u16::MAX {
                return Err(anyhow!("untrusted enclave product id"));
            }

            if rpt.enclave_security_version() < u16::MAX {
                return Err(anyhow!("untrusted enclave"));
            }
        }

        Ok(true)
    }
}
