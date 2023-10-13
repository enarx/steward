// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: Apache-2.0

pub mod auth;
pub mod cert;

use super::{FromBytes, ParseBytes};

use std::array::TryFromSliceError;
use std::mem::{size_of, transmute};

use anyhow::Error;
use sgx::ReportBody;

impl<'a> FromBytes<'a> for &'a ReportBody {
    type Error = TryFromSliceError;

    fn from_bytes(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), Self::Error> {
        let (report, bytes): (&[u8; size_of::<ReportBody>()], _) = bytes.parse()?;
        Ok((unsafe { transmute(report) }, bytes))
    }
}

#[derive(Clone, Debug)]
pub struct QuotingEnclave<'a, S: core::fmt::Debug> {
    pub rprt: &'a ReportBody,
    pub sign: S,
    pub auth: auth::Data<'a>,
    pub cert: cert::Data,
}

impl<'a, S: core::fmt::Debug + FromBytes<'a, Error = Error>> FromBytes<'a>
    for QuotingEnclave<'a, S>
{
    type Error = Error;

    fn from_bytes(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), Self::Error> {
        let (rprt, bytes) = bytes.parse()?;
        let (sign, bytes) = bytes.parse()?;
        let (auth, bytes) = bytes.parse()?;
        let (cert, bytes) = bytes.parse()?;
        let qe = Self {
            rprt,
            sign,
            auth,
            cert,
        };

        Ok((qe, bytes))
    }
}
