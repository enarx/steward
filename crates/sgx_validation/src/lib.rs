// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: AGPL-3.0-only

pub mod config;
pub mod quote;

use cryptography::ext::*;
use quote::traits::ParseBytes;

use std::fmt::Debug;

use crate::config::Config;
use anyhow::{bail, ensure, Result};
use cryptography::const_oid::ObjectIdentifier;
use cryptography::sha2::{Digest, Sha256};
use cryptography::x509::{ext::Extension, request::CertReqInfo, Certificate, TbsCertificate};
use der::{Decode, Encode};
use sgx::parameters::{Features, MiscSelect};

#[derive(Clone, Debug)]
pub struct Sgx([Certificate<'static>; 1]);

impl Default for Sgx {
    fn default() -> Self {
        Self([Certificate::from_der(Self::ROOT).unwrap()])
    }
}

impl Sgx {
    const ROOT: &'static [u8] = include_bytes!("root.der");
    pub const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.58270.1.2");
    pub const ATT: bool = true;

    pub fn trusted<'c>(&'c self, chain: &'c [Certificate<'c>]) -> Result<&'c TbsCertificate<'c>> {
        let mut signer = &self.0[0].tbs_certificate;
        for cert in self.0.iter().chain(chain.iter()) {
            signer = signer.verify_crt(cert)?;
        }

        Ok(signer)
    }

    pub fn verify(
        &self,
        cri: &CertReqInfo<'_>,
        ext: &Extension<'_>,
        config: Option<&Config>,
        dbg: bool,
    ) -> Result<bool> {
        if ext.critical {
            bail!("sgx extension cannot be critical");
        }

        // Decode the quote.
        let (quote, bytes): (quote::Quote<'_>, _) = ext.extn_value.parse()?;
        if !bytes.is_empty() {
            bail!("unknown trailing bytes in sgx quote");
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
            bail!("sgx pck algorithm mismatch");
        }

        if !dbg {
            // TODO: Validate that the certification request came from an SGX enclave.
            let hash = Sha256::digest(cri.public_key.to_vec()?);
            ensure!(
                hash.as_slice() == &rpt.reportdata[..hash.as_slice().len()],
                "sgx report data is invalid"
            );

            if let Some(config) = config {
                if !config.enarx_signer.is_empty() {
                    let mut signed = false;
                    for signer in &config.enarx_signer {
                        if rpt.mrsigner == signer.as_ref() {
                            signed = true;
                            break;
                        }
                    }
                    ensure!(signed, "sgx untrusted enarx signer");
                }

                if !config.enarx_signer_blacklist.is_empty() {
                    for signer in &config.enarx_signer_blacklist {
                        ensure!(
                            rpt.mrsigner != signer.as_ref(),
                            "sgx untrusted enarx signer"
                        );
                    }
                }

                if !config.enarx_hash.is_empty() {
                    let mut signed = false;
                    for hash in &config.enarx_hash {
                        if rpt.mrenclave == hash.as_ref() {
                            signed = true;
                            break;
                        }
                    }
                    ensure!(signed, "sgx untrusted enarx hash");
                }

                if !config.enarx_hash_blacklist.is_empty() {
                    for hash in &config.enarx_hash_blacklist {
                        ensure!(rpt.mrenclave != hash.as_ref(), "sgx untrusted enarx hash");
                    }
                }

                if let Some(product_id) = config.enclave_product_id {
                    ensure!(
                        rpt.enclave_product_id() >= product_id,
                        "sgx untrusted enclave product id"
                    );
                }

                if let Some(version) = config.enclave_security_version {
                    ensure!(
                        rpt.enclave_security_version() >= version,
                        "sgx untrusted enclave security version"
                    );
                }

                if config.features > 0
                    && !rpt
                        .attributes()
                        .features()
                        .difference(Features::from_bits_truncate(config.features))
                        .is_empty()
                {
                    bail!("sgx untrusted features");
                }
            }

            if rpt.misc_select() != MiscSelect::default() {
                bail!("sgx untrusted misc select");
            }
        }

        Ok(false)
    }
}
