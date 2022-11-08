// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: AGPL-3.0-only

use serde::{Deserialize, Deserializer};
use std::borrow::Borrow;
use std::collections::HashSet;
use std::fmt::{Display, Formatter};
use std::ops::Deref;

/// Digest generic in hash size `N`
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct Digest<const N: usize>(pub [u8; N]);

impl<'de, const N: usize> Deserialize<'de> for Digest<N> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error;

        let dig: String = Deserialize::deserialize(deserializer)?;
        let dig = hex::decode(dig).map_err(|e| Error::custom(format!("invalid hex: {e}")))?;
        let dig = dig.try_into().map_err(|v: Vec<_>| {
            Error::custom(format!(
                "expected digest to have length of {N}, got {}",
                v.len()
            ))
        })?;
        Ok(Digest(dig))
    }
}

impl<const N: usize> AsRef<[u8; N]> for Digest<N> {
    fn as_ref(&self) -> &[u8; N] {
        &self.0
    }
}

impl<const N: usize> Borrow<[u8; N]> for Digest<N> {
    fn borrow(&self) -> &[u8; N] {
        &self.0
    }
}

impl<const N: usize> Deref for Digest<N> {
    type Target = [u8; N];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<const N: usize> Display for Digest<N> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
struct UnvalidatedMeasurements<const N: usize> {
    #[serde(default)]
    signer: HashSet<Digest<N>>,

    #[serde(default)]
    hash: HashSet<Digest<N>>,

    #[serde(default)]
    hash_blacklist: HashSet<Digest<N>>,
}

impl<const N: usize> TryFrom<UnvalidatedMeasurements<N>> for Measurements<N> {
    type Error = String;

    fn try_from(
        UnvalidatedMeasurements {
            signer,
            hash,
            hash_blacklist,
        }: UnvalidatedMeasurements<N>,
    ) -> Result<Self, Self::Error> {
        if signer.is_empty() && hash.is_empty() && hash_blacklist.is_empty() {
            Err("one of `signer`, `hash`, or `hash_blacklist` must be specified".to_string())
        } else if let Some(offending) = hash.intersection(&hash_blacklist).next() {
            Err(format!(
                "same hash `{offending}` in both `hash` and `hash_blacklist`"
            ))
        } else {
            Ok(Self {
                signer,
                hash,
                hash_blacklist,
            })
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, try_from = "UnvalidatedMeasurements<N>")]
pub struct Measurements<const N: usize> {
    /// Allowed signing key digests
    pub signer: HashSet<Digest<N>>,

    /// Allowed Enarx binary digests.
    /// This is the hash of the Enclave environment after the Enarx binary is loaded
    /// but before any workload is loaded, so this is a hash of the Enarx binary
    /// in memory.
    pub hash: HashSet<Digest<N>>,

    /// Denied Enarx binary digests.
    pub hash_blacklist: HashSet<Digest<N>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serde() {
        let signer: HashSet<_> = HashSet::from([
            Digest([0x12, 0x34, 0x56, 0x78]),
            Digest([0x00, 0x11, 0x22, 0x33]),
        ]);

        let hash: HashSet<_> = HashSet::from([
            Digest([0x00, 0x11, 0x22, 0x33]),
            Digest([0x42, 0xff, 0xff, 0xff]),
        ]);

        const SIGNER: &str = r#"signer = ["12345678", "00112233"]"#;
        const HASH: &str = r#"hash = ["00112233", "42ffffff"]"#;
        const BLACKLIST: &str = r#"hash = ["00112233"]"#;

        assert!(toml::from_str::<Measurements<3>>(SIGNER).is_err());

        assert!(toml::from_str::<Measurements<4>>(&format!(
            r#"
{HASH}
{BLACKLIST}
"#
        ))
        .is_err());

        assert!(toml::from_str::<Measurements<3>>(&format!(
            r#"
{HASH} 
"#
        ))
        .is_err());

        assert!(toml::from_str::<Measurements<5>>(&format!(
            r#"
{SIGNER} 
"#
        ))
        .is_err());

        assert!(toml::from_str::<Measurements<5>>(&format!(
            r#"
{HASH} 
"#
        ))
        .is_err());

        assert_eq!(
            toml::from_str::<Measurements<4>>(&format!(
                r#"
{SIGNER}
"#
            ))
            .expect("failed to parse config"),
            Measurements {
                signer: signer.clone(),
                hash: Default::default(),
                hash_blacklist: Default::default(),
            },
        );

        assert_eq!(
            toml::from_str::<Measurements<4>>(&format!(
                r#"
{HASH}
"#
            ))
            .expect("failed to parse config"),
            Measurements {
                signer: Default::default(),
                hash: hash.clone(),
                hash_blacklist: Default::default(),
            },
        );

        assert_eq!(
            toml::from_str::<Measurements<4>>(&format!(
                r#"
{SIGNER}
{HASH}
"#
            ))
            .expect("failed to parse config"),
            Measurements {
                hash,
                signer,
                hash_blacklist: Default::default(),
            },
        );
    }
}
