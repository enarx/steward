// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: AGPL-3.0-only

#![allow(unused_variables, unused_imports)] // temporary until CRL validation enabled

pub mod config;
pub mod quote;

use crate::crypto::*;
use crate::sgx::config::Config;
use quote::traits::ParseBytes;
use std::collections::HashSet;

use anyhow::{anyhow, bail, ensure, Result};
use chrono::Local;
use const_oid::ObjectIdentifier;
use der::{Decode, Encode};
use sgx::pck::SgxExtension;
use sha2::{Digest, Sha256};
use tracing::debug;
use x509::{ext::Extension, request::CertReqInfo, Certificate, PkiPath, TbsCertificate};

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

    pub fn trusted<'c>(
        &'c self,
        chain: &'c [Certificate<'c>],
        crls: &'c CrlList<'c>,
    ) -> Result<&'c TbsCertificate<'c>> {
        let mut signer = &self.0[0].tbs_certificate;
        for cert in self.0.iter().chain(chain.iter()) {
            signer = signer.verify_crt(cert)?;
        }

        //PkiPath::from(chain).check_crl(crls)?;

        Ok(signer)
    }

    pub fn verify(
        &self,
        cri: &CertReqInfo<'_>,
        ext: &Extension<'_>,
        config: Option<&Config>,
        dbg: bool,
    ) -> Result<bool> {
        ensure!(!ext.critical, "sgx extension cannot be critical");

        // Decode the quote.
        let (quote, bytes): (quote::Quote<'_>, _) = ext.extn_value.parse()?;
        ensure!(bytes.is_empty(), "sgx unknown trailing bytes in sgx quote");

        ensure!(
            quote.tcb.report.issue_date < Local::now(),
            "sgx TCB report is from the future"
        );
        #[cfg(not(debug_assertions))]
        ensure!(
            quote.tcb.report.next_update > Local::now(),
            "TCB report is outdated"
        );
        #[cfg(debug_assertions)]
        if quote.tcb.report.next_update > Local::now() {
            debug!("SGX TCB report is outdated");
        }

        // Parse the certificate chain.
        let chain = quote.chain()?;
        let chain = chain
            .iter()
            .map(|c| Certificate::from_der(c))
            .collect::<Result<Vec<_>, _>>()?;

        // Validate the report.
        let pck = self.trusted(&chain, &quote.crls)?;
        let rpt = quote.verify(pck)?;

        ensure!(pck.extensions.is_some(), "sgx CPU cert missing extensions");
        let extensions = &pck.extensions.as_ref().unwrap();

        let sgx_extensions =
            SgxExtension::from_x509_extensions(extensions).map_err(|e| anyhow!("{e}"))?;

        // Parse the TCB certificate chain
        let tcb_chain = &quote.tcb.certs;
        ensure!(chain[0] == tcb_chain[0], "sgx TCB root not SGX root");
        let tcb_signer = self.trusted(tcb_chain, &quote.crls)?;

        // Validate TCB report
        tcb_chain[1]
            .tbs_certificate
            .subject_public_key_info
            .verify(
                &quote.tcb.bytes,
                tcb_chain[1].tbs_certificate.signature,
                &quote.tcb.sign,
            )?;
        let fmspc = hex::encode_upper(sgx_extensions.fmspc);
        ensure!(
            fmspc == quote.tcb.report.fmspc,
            "sgx FMSPC mismatch between TCB report {} and PCK {}",
            quote.tcb.report.fmspc,
            fmspc
        );

        // Check each `quote.tcb.report.tcb_levels`
        // Find where the PCESVN from the PCK is greater than or equal to the TCB level
        // Use that level's values for the `svn` values and `tcbStatus`, safe reference to it for later validation
        // Else not trusted!
        let tcb = {
            let mut tcb = None;
            let tcbsvns = sgx_extensions.tcb_components;
            for tcb_level in quote.tcb.report.tcb_levels.iter() {
                let mut does_match = true;
                for (index, tcbsvn) in tcbsvns.iter().enumerate().take(tcbsvns.len()) {
                    if tcbsvn < &tcb_level.tcb.sgxtcbcomponents[index].svn {
                        does_match = false;
                        break;
                    }
                }
                if !does_match {
                    continue;
                }
                if sgx_extensions.pcesvn >= tcb_level.tcb.pcesvn {
                    tcb = Some(tcb_level);
                    break;
                }
            }
            tcb
        };

        ensure!(tcb.is_some(), "sgx no TCB level supported");
        let tcb = tcb.unwrap();

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
        ensure!(
            cri.public_key.algorithm == pck.subject_public_key_info.algorithm,
            "sgx pck algorithm mismatch"
        );

        if !dbg {
            // Validate that the certification request came from an SGX enclave.
            let hash = Sha256::digest(cri.public_key.to_vec()?);
            ensure!(
                hash.as_slice() == &rpt.reportdata[..hash.as_slice().len()],
                "sgx report data is invalid"
            );
        }

        if let Some(config) = config {
            if !config.measurements.signer.is_empty() {
                let signed = config.measurements.signer.contains(&rpt.mrsigner);
                ensure!(
                    signed,
                    "sgx untrusted enarx signer {}",
                    hex::encode(rpt.mrsigner)
                );
            }

            if !config.measurements.hash.is_empty() {
                let approved = config.measurements.hash.contains(&rpt.mrenclave);
                ensure!(
                    approved,
                    "sgx untrusted enarx hash {}",
                    hex::encode(rpt.mrenclave)
                );
            }

            if !config.measurements.hash_blacklist.is_empty() {
                let denied = config.measurements.hash_blacklist.contains(&rpt.mrenclave);
                ensure!(!denied, "sgx untrusted enarx hash");
            }

            if let Some(product_id) = config.enclave_product_id {
                ensure!(
                    rpt.enclave_product_id() == product_id,
                    "sgx untrusted enclave product id {}",
                    rpt.enclave_product_id(),
                );
            }

            if let Some(version) = config.enclave_security_version {
                ensure!(
                    rpt.enclave_security_version() >= version,
                    "sgx untrusted enclave security version"
                );
            }

            if !config.features.is_empty()
                && !rpt
                    .attributes()
                    .features()
                    .difference(config.features)
                    .is_empty()
            {
                bail!("sgx untrusted features");
            }

            if !config.misc_select.is_empty() {
                ensure!(
                    rpt.misc_select().difference(config.misc_select).is_empty(),
                    "sgx untrusted misc select"
                );
            }

            if !config.allowed_advisories.is_empty() {
                if let Some(advisories) = &tcb.advisory_ids {
                    let tcb_advisories = HashSet::from_iter(advisories.iter().cloned());
                    ensure!(
                        tcb_advisories.is_subset(&config.allowed_advisories),
                        "sgx TCB report has additional advisories: {:?}",
                        tcb_advisories.difference(&config.allowed_advisories)
                    );
                }
            } else {
                // No permitted advisories in attestation configuration, so ensure TCB is up-to-date.
                ensure!(
                    tcb.tcb_status == "UpToDate",
                    "sgx TCB report shows firmware not `UpToDate`"
                );
            }
        } else {
            // No attestation configuration, so ensure TCB is up-to-date.
            ensure!(
                tcb.tcb_status == "UpToDate",
                "sgx TCB report shows firmware not `UpToDate`"
            );
        }

        Ok(false)
    }
}
