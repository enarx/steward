// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: AGPL-3.0-only

use super::super::Measurements;
use std::collections::HashSet;

use serde::{Deserialize, Deserializer};
use sgx::parameters::{Features, MiscSelect};

#[derive(Clone, Deserialize, Debug, Eq, PartialEq)]
pub enum SgxFeatures {
    CET,
    Debug,
    EInitKey,
    KSS,
    ProvisioningKey,
}

#[derive(Clone, Deserialize, Debug, Eq, PartialEq)]
pub enum SgxMiscSelect {
    EXINFO,
}

#[derive(Clone, Deserialize, Debug, Default, Eq, PartialEq)]
pub struct Config {
    /// Values for `mrsigner` in the report body, as `Measurements::signer()`
    /// This is the list of public keys which have signed the Enarx binary.
    /// Values for `mrenclave` in the report body, as `Measurements::hash()`
    /// This is the hash of the Enclave environment after the Enarx binary is loaded but
    /// before any workload is loaded, so this is a hash of the Enarx binary in memory.
    #[serde(default, flatten)]
    pub measurements: Measurements<32>,

    /// Values for `features`.
    /// Checked against `sgx::parameters::attributes::Attributes::features()`
    /// These are CPU features reported by the CPU firmware, and most features are not
    /// relevant to security concerns, but are used for code execution. Only the features
    /// relevant for security are parsed here.
    #[serde(default)]
    #[serde(deserialize_with = "from_features")]
    pub features: Features,

    /// Minimum value for `isv_svn`.
    /// Checked against `sgx::report::ReportBody::enclave_security_version()`
    /// This is the security version of the enclave.
    pub enclave_security_version: Option<u16>,

    /// Value for `isv_prodid`, do not allow other ids.
    /// Checked against `sgx::report::ReportBody::enclave_product_id()`
    pub enclave_product_id: Option<u16>,

    /// Extra enclave creation parameters
    /// Checked against `sgx::report::ReportBody::misc_select()`
    #[serde(default)]
    #[serde(deserialize_with = "from_misc_select")]
    pub misc_select: MiscSelect,

    /// Allowed Intel advisories when validating the Intel TCB report
    #[serde(default)]
    pub allowed_advisories: HashSet<String>,
}

fn from_features<'de, D>(deserializer: D) -> Result<Features, D::Error>
where
    D: Deserializer<'de>,
{
    let s: Vec<SgxFeatures> = Deserialize::deserialize(deserializer)?;

    let mut flags = Features::empty();

    // Must be set according to Intel SGX documentation, this indicates permission
    // to create SGX enclaves.
    flags |= Features::INIT;

    // Required by Enarx, as Wasmtime requires 64-bit, and modern systems are all 64-bit anyway
    flags |= Features::MODE64BIT;

    for flag in s {
        match flag {
            SgxFeatures::CET => {
                flags |= Features::CET;
            }
            SgxFeatures::Debug => {
                flags |= Features::DEBUG;
            }
            SgxFeatures::EInitKey => {
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

    Ok(flags)
}

fn from_misc_select<'de, D>(deserializer: D) -> Result<MiscSelect, D::Error>
where
    D: Deserializer<'de>,
{
    let s: Vec<SgxMiscSelect> = Deserialize::deserialize(deserializer)?;

    let mut flags = MiscSelect::default();

    for flag in s {
        match flag {
            SgxMiscSelect::EXINFO => {
                flags |= MiscSelect::EXINFO;
            }
        }
    }

    Ok(flags)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Digest;
    use std::collections::HashSet;

    #[test]
    fn empty_config() {
        assert!(toml::from_str::<Config>("").is_err());
    }

    #[test]
    fn serde() {
        const SIGNER: &str =
            r#"signer = ["2eba0f494f428e799c22d6f12778aebea4dc8d991f9e63fd3cddd57ac6eb5dd9"]"#;

        let signer: HashSet<_> = HashSet::from([Digest([
            0x2e, 0xba, 0x0f, 0x49, 0x4f, 0x42, 0x8e, 0x79, 0x9c, 0x22, 0xd6, 0xf1, 0x27, 0x78,
            0xae, 0xbe, 0xa4, 0xdc, 0x8d, 0x99, 0x1f, 0x9e, 0x63, 0xfd, 0x3c, 0xdd, 0xd5, 0x7a,
            0xc6, 0xeb, 0x5d, 0xd9,
        ])]);

        let config: Config = toml::from_str(&format!(
            r#"
{SIGNER}
features = ["Debug"]
misc_select = ["EXINFO"]
"#,
        ))
        .expect("Couldn't deserialize");

        assert_eq!(config.measurements.signer, signer);
        assert_eq!(
            config.features.bits(),
            (Features::DEBUG | Features::INIT | Features::MODE64BIT).bits()
        );
        assert!(config.misc_select.contains(MiscSelect::EXINFO));
    }

    #[test]
    fn too_short() {
        let config: Result<Config, toml::de::Error> = toml::from_str(
            r#"
        signer = ["41c179d5c0d5bc4915752ccf9bbd2baa574716832235ef5bb998fadcda1e46"]
        "#,
        );
        assert!(config.is_err());
    }
}
