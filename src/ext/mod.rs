// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: AGPL-3.0-only

use anyhow::Result;
use const_oid::ObjectIdentifier;
use x509::{ext::Extension, request::CertReqInfo};

pub mod kvm;
pub mod sgx;
pub mod snp;

/// Validates an extension for inclusion in a certificate.
///
/// The certification request can contain requests to add an extension to a
/// certificate. Instances of this trait can be used to verify these
/// extensions for inclusion.
pub trait ExtVerifier {
    /// The OID of the extensions this verifier can verify.
    const OID: ObjectIdentifier;

    /// Whether or not this verifier is an attestation.
    const ATT: bool = false;

    /// Verifies a certification request extension request.
    ///
    /// Returning an error will cancel the entire certification request.
    /// Returning `Ok(true)` will cause the extension to be included in the
    /// certificate. Returning `Ok(false)` will allow the certification request
    /// to continue, but this particular extension will not be included
    /// in the resulting certificate.
    fn verify(&self, cri: &CertReqInfo<'_>, ext: &Extension<'_>, dbg: bool) -> Result<bool>;
}
