// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: AGPL-3.0-only

use crate::sha2::{Digest, Sha256};
#[cfg(target_family = "wasm")]
use anyhow::bail;
use anyhow::{ensure, Context, Result};
#[cfg(not(target_family = "wasm"))]
use hyper::Client;
#[cfg(not(target_family = "wasm"))]
use hyper_tls::HttpsConnector;
#[cfg(not(target_family = "wasm"))]
use std::fs::OpenOptions;
#[cfg(not(target_family = "wasm"))]
use std::io::Write;
use std::path::Path;

pub fn fetch_crl(url: &str) -> Result<Vec<u8>> {
    ensure!(
        url.starts_with("https://"),
        "refusing to use an unencrypted CRL url"
    );

    let file_name_hash = Sha256::digest(url);
    let file_name_hash = format!("{:}.crl", hex::encode(file_name_hash));

    if Path::new(&file_name_hash).exists() {
        return std::fs::read(file_name_hash).context("failed to read crl");
    }

    #[cfg(target_family = "wasm")]
    bail!("cannot make an outgoing connection");

    #[cfg(not(target_family = "wasm"))]
    {
        let url: http::Uri = url.parse()?;
        let mut https = HttpsConnector::new();
        https.https_only(true);
        let client = Client::builder().build::<_, hyper::Body>(https);

        let body = futures::executor::block_on(async move {
            let res = client.get(url).await.expect("unable to connect to server");
            hyper::body::to_bytes(res.into_body())
                .await
                .expect("unable to parse response from server")
        });

        Ok(body.to_vec())
    }
}

#[cfg(not(target_family = "wasm"))]
pub fn fetch_cache_crl(url: &str) -> Result<Vec<u8>> {
    let crl = fetch_crl(url)?;

    let file_name_hash = Sha256::digest(url);
    let file_name_hash = format!("{:}.crl", hex::encode(file_name_hash));

    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .open(file_name_hash)
        .unwrap();

    file.write_all(&crl)?;
    file.flush()?;

    Ok(crl)
}
