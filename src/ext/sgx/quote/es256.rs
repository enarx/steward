// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: AGPL-3.0-only

use super::{qe::QuotingEnclave, FromBytes, ParseBytes};

use std::array::TryFromSliceError;

use der::{asn1::UIntBytes, Sequence};

#[derive(Clone, Debug)]
#[repr(C)]
pub struct PublicKey([u8; 65]);

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0[1..]
    }
}

impl<'a> FromBytes<'a> for PublicKey {
    type Error = TryFromSliceError;

    fn from_bytes(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), Self::Error> {
        let (key, bytes): (&[u8; 64], _) = bytes.parse()?;

        // Encode the key as SEC1.
        let mut sec1 = [0u8; 65];
        sec1[0] = 4;
        sec1[1..].copy_from_slice(key);

        Ok((Self(sec1), bytes))
    }
}

impl PublicKey {
    pub fn sec1(&self) -> &[u8] {
        &self.0
    }
}

/// ECDSA-Sig-Value ::= SEQUENCE {
///    r INTEGER,
///    s INTEGER
/// }
#[derive(Clone, Debug, Sequence)]
pub struct Signature<'a> {
    r: UIntBytes<'a>,
    s: UIntBytes<'a>,
}

impl<'a> FromBytes<'a> for Signature<'a> {
    type Error = anyhow::Error;

    fn from_bytes(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), Self::Error> {
        let (r, bytes): (&[u8; 32], _) = bytes.parse()?;
        let (s, bytes): (&[u8; 32], _) = bytes.parse()?;
        let sv = Self {
            r: UIntBytes::new(r).unwrap(),
            s: UIntBytes::new(s).unwrap(),
        };

        Ok((sv, bytes))
    }
}

/// A.4, Table 4
#[derive(Clone, Debug)]
#[repr(C)]
pub struct SignatureData<'a> {
    pub sig: Signature<'a>,
    pub key: PublicKey,
    pub iqe: QuotingEnclave<'a, Signature<'a>>,
}

impl<'a> FromBytes<'a> for SignatureData<'a> {
    type Error = anyhow::Error;

    fn from_bytes(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), Self::Error> {
        let (len, bytes) = bytes.parse()?;
        let len = u32::from_le_bytes(len).try_into().unwrap();
        if len > bytes.len() {
            return Err(anyhow!("invalid signature data length"));
        }
        let bytes = &bytes[..len];

        let (sig, bytes) = bytes.parse()?;
        let (key, bytes) = bytes.parse()?;
        let (iqe, bytes) = bytes.parse()?;
        Ok((SignatureData { sig, key, iqe }, bytes))
    }
}
