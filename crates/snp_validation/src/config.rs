// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: AGPL-3.0-only

use crate::{PlatformInfoFlags, PolicyFlags};
use cryptography::digest::Digest;
use flagset::FlagSet;
use semver::VersionReq;
use serde::de::Error;
use serde::{Deserialize, Deserializer, Serialize};

#[derive(Clone, Deserialize, Debug, Default, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Values for `author_key_digest` in the report body.
    /// This is the list of public keys which have signed the signing key of the Enarx binary.
    #[serde(default)]
    pub enarx_signer: Vec<Digest>,

    /// Prohibited values for `author_key_digest` in the report body.
    /// This is the list of disallowed public keys which have signed the signing key of the
    /// Enarx binary.
    #[serde(default)]
    pub enarx_signer_blacklist: Vec<Digest>,

    /// Values for `measurement` in the report body.
    /// This is the hash of the Enclave environment after the Enarx binary is loaded
    /// but before any workload is loaded, so this is a hash of the Enarx binary
    /// in memory.
    #[serde(default)]
    pub enarx_hash: Vec<Digest>,

    /// Prohibited values for `measurement` in the report body.
    /// This is the hash of the Enclave environment after the Enarx binary is loaded
    /// but before any workload is loaded, so this is a hash of the Enarx binary
    /// in memory.
    #[serde(default)]
    pub enarx_hash_blacklist: Vec<Digest>,

    /// Values for `id_key_digest` in the report body.
    /// This is the list of public keys which have signed the Enarx binary.
    #[serde(default)]
    pub id_key_digest: Vec<Digest>,

    /// Prohibited values for `id_key_digest` in the report body.
    /// This is the list of public keys which have signed the Enarx binary.
    #[serde(default)]
    pub id_key_digest_blacklist: Vec<Digest>,

    /// Minimum value for `policy.abi_major`.`policy.abi_minor`
    #[serde(default)]
    pub minimum_abi: VersionReq,

    #[serde(default)]
    #[serde(deserialize_with = "from_policy_string")]
    pub policy_flags: Option<u8>,

    #[serde(default)]
    #[serde(deserialize_with = "from_platform_string")]
    pub platform_info_flags: Option<PlatformInfoFlags>,
}

fn from_policy_string<'de, D>(deserializer: D) -> Result<Option<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    let s: &str = Deserialize::deserialize(deserializer)?;

    let mut flags = FlagSet::<PolicyFlags>::from(PolicyFlags::Reserved);

    for flag in s.to_string().split('|') {
        match flag.trim() {
            "Debug" => {
                flags |= PolicyFlags::Debug;
            }
            "MigrateMA" => {
                return Err(D::Error::custom("SNP migration not supported"));
            }
            "SingleSocket" => {
                flags |= PolicyFlags::SingleSocket;
            }
            "SMT" => {
                flags |= PolicyFlags::SMT;
            }
            _ => return Err(D::Error::custom(format!("unknown policy flag '{}'", flag))),
        }
    }

    Ok(Some(flags.bits()))
}

fn from_platform_string<'de, D>(deserializer: D) -> Result<Option<PlatformInfoFlags>, D::Error>
where
    D: Deserializer<'de>,
{
    let s: &str = Deserialize::deserialize(deserializer)?;

    let flag = match s.trim() {
        "SME" => PlatformInfoFlags::SME,
        "TSME" => PlatformInfoFlags::TSME,
        _ => {
            return Err(D::Error::custom(format!(
                "unknown platform info flag '{}'",
                s
            )))
        }
    };

    Ok(Some(flag))
}

#[cfg(test)]
mod tests {
    use crate::config::Config;
    use crate::PolicyFlags;
    use flagset::FlagSet;

    #[test]
    fn test_empty_config() {
        let config_raw = r#"
        "#;

        let config_obj: Config = toml::from_str(config_raw).expect("Couldn't deserialize");
        assert!(config_obj.policy_flags.is_none());
        assert!(config_obj.platform_info_flags.is_none());
    }

    #[test]
    fn test_flags() {
        let config_raw = r#"
        policy_flags = "SingleSocket | Debug"
        platform_info_flags = "SME"
        "#;

        let config_obj: Config = toml::from_str(config_raw).expect("Couldn't deserialize");
        assert!(config_obj.policy_flags.is_some());
        assert!(config_obj.platform_info_flags.is_some());

        let flags = FlagSet::<PolicyFlags>::new(config_obj.policy_flags.unwrap()).unwrap();
        assert_eq!(
            flags,
            PolicyFlags::SingleSocket | PolicyFlags::Debug | PolicyFlags::Reserved
        );
    }

    #[test]
    fn test_semver() {
        let config_raw = r#"
        minimum_abi = "1.0"
        "#;

        let config_obj: Config = toml::from_str(config_raw).expect("Couldn't deserialize");
        assert_eq!(config_obj.minimum_abi.to_string(), "^1.0");
    }
}
