// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: AGPL-3.0-only

use crate::ext::TbsCertificateExt;
use crate::sha2::{Digest, Sha256};
use anyhow::bail;
use anyhow::{ensure, Context, Result};
#[cfg(not(target_family = "wasm"))]
use hyper::Client;
#[cfg(not(target_family = "wasm"))]
use hyper_tls::HttpsConnector;
use std::fmt::{Debug, Display, Formatter};
#[cfg(not(target_family = "wasm"))]
use std::fs::OpenOptions;
#[cfg(not(target_family = "wasm"))]
use std::io::Write;
use std::path::Path;
use x509::PkiPath;

#[derive(Debug, Eq, PartialEq)]
enum CrlError {
    NoCrlAvailable,
    Revoked,
}

impl Display for CrlError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            CrlError::NoCrlAvailable => write!(f, "No CRL available"),
            CrlError::Revoked => write!(f, "Certificate(s) revoked"),
        }
    }
}

impl std::error::Error for CrlError {}

trait PkiPathCRLCheck<'a> {
    /// Checks that:
    /// 1) There is/are CRL(s) available, and downloads as needed
    /// 2) The first certificate signed the CRL
    /// 3) None of the certificates in the Path are revoked.
    fn check_crl(&self, extra_crl_urls: Option<Vec<String>>) -> Result<()>;
}

impl<'a> PkiPathCRLCheck<'a> for PkiPath<'a> {
    fn check_crl(&self, extra_crl_urls: Option<Vec<String>>) -> Result<()> {
        let certs = self.iter();
        let mut crl_urls: Vec<String> = Vec::new();
        if let Some(extra_urls) = extra_crl_urls {
            crl_urls.append(&mut extra_urls.clone());
        }

        for cert in certs {
            crl_urls.append(&mut cert.tbs_certificate.get_crl_urls()?.clone());
            if crl_urls.is_empty() {
                continue;
            }
        }

        Ok(())
    }
}

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
