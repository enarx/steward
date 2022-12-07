// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: AGPL-3.0-only

use anyhow::{anyhow, Result};
use cryptography::const_oid::ObjectIdentifier;
use cryptography::x509::{ext::Extension, request::CertReqInfo};

/// An extension validator for KVM evidence.
///
/// KVM can't actually attest since it has no attestation flow. Therefore, the
/// extension is empty. We accept this if the steward is running in debug mode,
/// indicated by the issuer being a self-signed certificate.
#[derive(Clone, Debug, Default)]
pub struct Kvm(());

impl Kvm {
    pub(crate) const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.58270.1.1");
    pub(crate) const ATT: bool = true;

    pub(crate) fn verify(&self, _cri: &CertReqInfo<'_>, ext: &Extension<'_>) -> Result<bool> {
        if ext.critical {
            return Err(anyhow!("kvm extension cannot be critical"));
        }

        if !ext.extn_value.is_empty() {
            return Err(anyhow!("invalid kvm extension"));
        }

        #[cfg(not(feature = "insecure"))]
        return Err(anyhow!("steward not in debug mode"));

        #[cfg(feature = "insecure")]
        Ok(true)
    }
}
