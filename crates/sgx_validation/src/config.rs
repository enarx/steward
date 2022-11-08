// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: AGPL-3.0-only

use cryptography::digest::Digest;
use serde::{Deserialize, Deserializer, Serialize};
use sgx::parameters::Features;

#[derive(Clone, Deserialize, Debug, Serialize)]
pub enum SgxFeatures {
    CET,
    Debug,
    EIntKey,
    KSS,
    ProvisioningKey,
}

#[derive(Clone, Deserialize, Debug, Default, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Values for `mrsigner` in the report body.
    /// This is the list of public keys which have signed the Enarx binary.
    #[serde(default)]
    pub enarx_signer: Vec<Digest>,

    /// Prohibited values for `mrsigner` in the report body.
    /// This is the list of public keys which have signed the Enarx binary which are disallowed.
    #[serde(default)]
    pub enarx_signer_blacklist: Vec<Digest>,

    /// Values for `mrenclave` in the report body.
    /// This is the hash of the Enclave environment after the Enarx binary is loaded
    /// but before any workload is loaded, so this is a hash of the Enarx binary
    /// in memory.
    #[serde(default)]
    pub enarx_hash: Vec<Digest>,

    /// Prohibited values for `mrenclave` in the report body.
    /// This is the hash of the Enclave environment after the Enarx binary is loaded
    /// but before any workload is loaded, so this is a hash of the Enarx binary
    /// in memory.
    #[serde(default)]
    pub enarx_hash_blacklist: Vec<Digest>,

    /// Values for `features`.
    #[serde(default)]
    #[serde(deserialize_with = "from_features")]
    pub features: u64,

    /// Minimum value for `isv_svn`.
    pub enclave_security_version: Option<u16>,

    /// Value for `isv_prodid`, do not allow versions below this.
    pub enclave_product_id: Option<u16>,
}

fn from_features<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    let s: Vec<SgxFeatures> = Deserialize::deserialize(deserializer)?;

    let mut flags = Features::empty();

    flags |= Features::INIT; // Must be set
    flags |= Features::MODE64BIT; // Required by Enarx

    for flag in s {
        match flag {
            SgxFeatures::CET => {
                flags |= Features::CET;
            }
            SgxFeatures::Debug => {
                flags |= Features::DEBUG;
            }
            SgxFeatures::EIntKey => {
                flags |= Features::EINIT_KEY;
            }
            SgxFeatures::KSS => {
                flags |= Features::KSS;
            }
            SgxFeatures::ProvisioningKey => {
                flags |= Features::PROVISIONING_KEY;
            }
        }
    }

    Ok(flags.bits())
}

#[cfg(test)]
mod tests {
    use crate::config::Config;

    #[test]
    fn test_empty_config() {
        let config_obj: Config = toml::from_str("").expect("Couldn't deserialize");
        assert!(config_obj.enarx_signer.is_empty());
        assert!(config_obj.enclave_security_version.is_none());
    }

    #[test]
    fn test_list_of_hashes() {
        let config_raw = r#"
        enarx_signer = ["1234567890", "00112233445566778899"]
        "#;

        let config_obj: Config = toml::from_str(config_raw).expect("Couldn't deserialize");
        assert_eq!(config_obj.enarx_signer.len(), 2);
        assert_eq!(
            config_obj.enarx_signer.get(0).unwrap().as_ref(),
            &hex::decode("1234567890").unwrap()
        );
        assert_eq!(
            config_obj.enarx_signer.get(1).unwrap().as_ref(),
            &hex::decode("00112233445566778899").unwrap()
        );
    }
}
