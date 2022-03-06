use anyhow::{anyhow, Result};
use const_oid::ObjectIdentifier;
use x509::{ext::Extension, request::CertReqInfo};

use super::ExtVerifier;

/// An extension validator for KVM evidence.
///
/// KVM can't actually attest since it has no attestation flow. Therefore, the
/// extension is empty. We accept this if the steward is running in debug mode,
/// indicated by the issuer being a self-signed certificate.
#[derive(Clone, Debug, Default)]
pub struct Kvm(());

impl ExtVerifier for Kvm {
    const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.58270.1.1");
    const ATT: bool = true;

    fn verify(&self, _cri: &CertReqInfo<'_>, ext: &Extension<'_>, dbg: bool) -> Result<bool> {
        if ext.critical {
            return Err(anyhow!("kvm extension cannot be critical"));
        }

        if !ext.extn_value.is_empty() {
            return Err(anyhow!("invalid kvm extension"));
        }

        if !dbg {
            return Err(anyhow!("steward not in debug mode"));
        }

        Ok(true)
    }
}
