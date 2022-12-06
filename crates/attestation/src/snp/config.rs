// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: AGPL-3.0-only

use super::super::{Digest, Measurements};
use super::{PlatformInfoFlags, PolicyFlags};

use flagset::FlagSet;
use semver::VersionReq;
use serde::{Deserialize, Deserializer};
use std::collections::HashSet;

#[derive(Clone, Deserialize, Debug, Default, Eq, PartialEq)]
pub enum SnpPolicyFlags {
    Debug,
    SingleSocket,
    #[default]
    SMT,
}

#[derive(Clone, Deserialize, Debug, Default, Eq, PartialEq)]
pub struct Config {
    /// Values for `author_key_digest` in the report body, as `Measurements::signer()`
    /// This is the list of public keys which have signed the signing key of the Enarx binary.
    /// Values for `measurement` in the report body, as `Measurements::hash()`
    /// This is the hash of the Enclave environment after the Enarx binary is loaded
    /// but before any workload is loaded, so this is a hash of the Enarx binary
    /// in memory.
    #[serde(flatten, default)]
    pub measurements: Measurements<48>,

    /// Values for `id_key_digest` in the report body.
    /// This is the list of public keys which have signed the Enarx binary.
    #[serde(default)]
    pub id_key_digest: HashSet<Digest<48>>,

    /// Prohibited values for `id_key_digest` in the report body.
    /// This is the list of public keys which have signed the Enarx binary.
    #[serde(default)]
    pub id_key_digest_blacklist: HashSet<Digest<48>>,

    /// Minimum value for `policy.abi_major`.`policy.abi_minor`
    #[serde(default)]
    pub abi: VersionReq,

    #[serde(default)]
    #[serde(deserialize_with = "from_policy_string")]
    pub policy_flags: Option<u8>,

    #[serde(default)]
    pub platform_info_flags: Option<PlatformInfoFlags>,
}

fn from_policy_string<'de, D>(deserializer: D) -> Result<Option<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    let s: Vec<SnpPolicyFlags> = Deserialize::deserialize(deserializer)?;

    let mut flags = FlagSet::<PolicyFlags>::from(PolicyFlags::Reserved);

    for flag in s {
        match flag {
            SnpPolicyFlags::Debug => {
                flags |= PolicyFlags::Debug;
            }
            SnpPolicyFlags::SingleSocket => {
                flags |= PolicyFlags::SingleSocket;
            }
            SnpPolicyFlags::SMT => {
                flags |= PolicyFlags::SMT;
            }
        }
    }

    Ok(Some(flags.bits()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Digest;
    use std::collections::HashSet;

    const SIGNER: &str = r#"signer = ["6d193a53817dfc0c7834e6c84687414c08de0b2839aa6593272bd628d1e23c3470f22e80ddec3262f0079ae4747d36aa"]"#;
    const DIGEST: Digest<48> = Digest([
        0x6d, 0x19, 0x3a, 0x53, 0x81, 0x7d, 0xfc, 0x0c, 0x78, 0x34, 0xe6, 0xc8, 0x46, 0x87, 0x41,
        0x4c, 0x08, 0xde, 0x0b, 0x28, 0x39, 0xaa, 0x65, 0x93, 0x27, 0x2b, 0xd6, 0x28, 0xd1, 0xe2,
        0x3c, 0x34, 0x70, 0xf2, 0x2e, 0x80, 0xdd, 0xec, 0x32, 0x62, 0xf0, 0x07, 0x9a, 0xe4, 0x74,
        0x7d, 0x36, 0xaa,
    ]);

    #[test]
    fn empty_config() {
        assert!(toml::from_str::<Config>("").is_err());
    }

    #[test]
    fn flags() {
        let config: Config = toml::from_str(&format!(
            r#"
        {SIGNER}
        policy_flags = ["SingleSocket", "Debug"]
        platform_info_flags = "SME"
        "#,
        ))
        .expect("Couldn't deserialize");

        assert_eq!(config.platform_info_flags.unwrap(), PlatformInfoFlags::SME);

        assert_eq!(
            FlagSet::<PolicyFlags>::new(config.policy_flags.unwrap()).unwrap(),
            PolicyFlags::SingleSocket | PolicyFlags::Debug | PolicyFlags::Reserved
        );

        assert_eq!(config.measurements.signer.len(), 1);
        assert!(config.measurements.signer.contains(&DIGEST));
    }

    #[test]
    fn semver() {
        let config: Config = toml::from_str(&format!(
            r#"
        {SIGNER}
        abi = "1.0"
        "#,
        ))
        .expect("Couldn't deserialize");
        assert_eq!(config.abi.to_string(), "^1.0");
        assert_eq!(
            config.measurements.signer,
            HashSet::from_iter(vec![DIGEST].into_iter())
        );
    }

    #[test]
    fn too_short() {
        let config: Result<Config, toml::de::Error> = toml::from_str(
            r#"
        signer = ["7e95e98b98abd5bf71ff3f8c7cd0678a2ea46b3438c6684f49469f5c5a442cb0fb6ad33fa000e04d4ae4635051dd68"]
        "#,
        );
        assert!(config.is_err());
    }
}
