// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: AGPL-3.0-only

use serde::de::Error;
use serde::{Deserialize, Deserializer, Serialize};

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct Digest(Vec<u8>);

impl<'de> Deserialize<'de> for Digest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s: String = Deserialize::deserialize(deserializer)?;

        Ok(Self(
            hex::decode(s).map_err(|_| Error::custom("invalid hex"))?,
        ))
    }
}

impl AsRef<[u8]> for Digest {
    fn as_ref(&self) -> &[u8] {
        self.0.as_slice()
    }
}

#[cfg(test)]
mod tests {
    use crate::digest::Digest;
    use serde::Deserialize;

    #[test]
    fn deserialize_hash_to_vec() {
        #[derive(Clone, Debug, Default, Deserialize)]
        struct TestConfig {
            some_hash: Digest,
        }

        let config_raw = r#"
        some_hash = "0102030405060708090a0b0c0d"
        "#;

        let config_obj: TestConfig = toml::from_str(config_raw).expect("Couldn't deserialize");
        assert_eq!(
            config_obj.some_hash.0,
            [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]
        );
    }
}
