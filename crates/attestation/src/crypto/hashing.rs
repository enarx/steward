// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: AGPL-3.0-only

use anyhow::Result;

#[cfg(all(target_os = "wasi", feature = "wasi-crypto"))]
use anyhow::anyhow;
#[cfg(all(target_os = "wasi", feature = "wasi-crypto"))]
use wasi_crypto_guest::prelude::Hash;

#[cfg(any(not(target_os = "wasi"), not(feature = "wasi-crypto")))]
use sha2::{Digest, Sha256, Sha384};

#[inline]
pub fn sha256(data: impl AsRef<[u8]>) -> Result<Vec<u8>> {
    #[cfg(all(target_os = "wasi", feature = "wasi-crypto"))]
    return Ok(Hash::hash("SHA-256", data, 32, None).or_else(|_| Err(anyhow!("hash error")))?);

    #[cfg(any(not(target_os = "wasi"), not(feature = "wasi-crypto")))]
    Ok(Sha256::digest(data).as_slice().to_vec())
}

#[inline]
pub fn sha384(data: impl AsRef<[u8]>) -> Result<Vec<u8>> {
    #[cfg(all(target_os = "wasi", feature = "wasi-crypto"))]
    return Ok(Hash::hash("SHA-384", data, 48, None).or_else(|_| Err(anyhow!("hash error")))?);

    #[cfg(any(not(target_os = "wasi"), not(feature = "wasi-crypto")))]
    Ok(Sha384::digest(data).as_slice().to_vec())
}

#[cfg(all(target_os = "wasi", feature = "wasi-crypto"))]
#[cfg(test)]
mod wasi_crypto {
    use crate::{sha256, sha384};
    use sha2::Digest;

    const DATA: &[u8] = b"SOME_TEST_DATA";

    #[test]
    fn test_sha256() {
        let hash = sha256(DATA).unwrap();
        assert_eq!(hash, sha2::Sha256::digest(DATA).as_slice());
    }

    #[test]
    fn test_sha384() {
        let hash = sha384(DATA).unwrap();
        assert_eq!(hash, sha2::Sha384::digest(DATA).as_slice());
    }
}
