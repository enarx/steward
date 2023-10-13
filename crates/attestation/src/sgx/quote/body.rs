// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: Apache-2.0

use super::{FromBytes, ParseBytes};

use std::intrinsics::transmute;
use std::mem::size_of;
use std::slice::from_raw_parts;

use sgx::ReportBody;

#[repr(C)]
pub struct Body {
    version: [u8; 2],
    key_type: [u8; 2],
    reserved: [u8; 4],
    qe_svn: [u8; 2],
    pce_svn: [u8; 2],
    pub qe_vendor_id: [u8; 16],
    pub user_data: [u8; 20],
    pub report: ReportBody,
}

impl Body {
    pub const KEY_TYPE_ES256: u16 = 2;
    pub const QE_VENDOR_ID_INTEL: [u8; 16] =
        *b"\x93\x9A\x72\x33\xF7\x9C\x4C\xA9\x94\x0A\x0D\xB3\x95\x7F\x06\x07";

    pub const PCE_SVN: u16 = 12;
    pub const QE_SVN: u16 = 7;

    /// Version of the `Quote` structure
    pub fn version(&self) -> u16 {
        u16::from_le_bytes(self.version)
    }

    /// Type of attestation key used
    pub fn key_type(&self) -> u16 {
        u16::from_le_bytes(self.key_type)
    }

    /// Security version of the QE
    #[allow(unused)]
    pub fn qe_svn(&self) -> u16 {
        u16::from_le_bytes(self.qe_svn)
    }

    /// Security version of the Provisioning Certification Enclave
    #[allow(unused)]
    pub fn pce_svn(&self) -> u16 {
        u16::from_le_bytes(self.pce_svn)
    }
}

impl AsRef<[u8]> for Body {
    fn as_ref(&self) -> &[u8] {
        unsafe { from_raw_parts(self as *const Self as *const u8, size_of::<Self>()) }
    }
}

impl<'a> FromBytes<'a> for &'a Body {
    type Error = anyhow::Error;

    fn from_bytes(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), Self::Error> {
        let (body, bytes): (&[u8; size_of::<Body>()], _) = bytes.parse()?;
        let body = unsafe { transmute(body) };
        Ok((body, bytes))
    }
}

#[cfg(test)]
mod test {
    use super::Body;
    use testaso::testaso;

    testaso! {
        struct Body: 1, 432 => {
            version: 0,
            key_type: 2,
            reserved: 4,
            qe_svn: 8,
            pce_svn: 10,
            qe_vendor_id: 12,
            user_data: 28,
            report: 48
        }
    }
}
