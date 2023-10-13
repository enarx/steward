// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: Apache-2.0

use super::super::{FromBytes, ParseBytes, Steal};

use anyhow::anyhow;

#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum Data {
    PckCertChain(Vec<Vec<u8>>),
}

impl<'a> FromBytes<'a> for Data {
    type Error = anyhow::Error;

    fn from_bytes(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), Self::Error> {
        let (typ, bytes) = bytes.parse()?;
        let (len, bytes) = bytes.parse()?;
        let (buf, bytes) = bytes.steal(u32::from_le_bytes(len).try_into().unwrap())?;

        match u16::from_le_bytes(typ) {
            5 => {
                let chain = std::str::from_utf8(buf)
                    .map_err(|e| anyhow!("invalid certification data: {}", e))?
                    .replace("-----END CERTIFICATE-----", "-----END CERTIFICATE-----\n");

                let mut certs = rustls_pemfile::certs(&mut chain.as_bytes())
                    .map_err(|e| anyhow!("invalid certification data: {}", e))?;

                certs.reverse();
                Ok((Self::PckCertChain(certs), bytes))
            }

            _ => Err(anyhow!("unsupported certification data")),
        }
    }
}
