// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: AGPL-3.0-only

//!
//! # Overview
//!
//! Steward is a critical element of the Confidential Computing infrastructure.
//! The promise of Confidential Computing is fully utilized when the workload
//! runtime (Enarx WebAssembly) deployed into a Trusted Execution Environment
//! (TEE) is assessed and verified for correctness before an actual workload
//! is released into a TEE from the registry (Drawbridge). An external
//! **attestation service** must perform evidence verification and assessment
//! of the hardware's trustworthiness.
//!
//! **Steward implements such attestation service in a modular, pluggable
//! and scalable way.**
//!
//! **Modular:** The architecture of the Trusted Execution Environments
//! significantly differs between hardware vendors. As a result, the content
//! and structure of the evidence information are vendor-specific. The Steward
//! employs modular design to process specific types of evidence in different
//! backends.
//!
//! **Pluggable:** Steward employs a pluggable and extensible architecture
//! to allow the addition of new evidence information to the evidence payload
//! as well as the support of new hardware architectures.
//!
//! **Scalable:** Steward service is stateless. It receives a request with
//! all the information from the client and makes an assessment. As a result,
//! it is very lightweight and can be scaled up and down in response to
//! the request load.
//!
//! Attesting the hardware and workload runtime is only one part of
//! the Steward's responsibility. The other is the translation of the vendor
//! and use-case-specific attestation evidence into a format that standard
//! services and interfaces on the Internet can trust. Such a standard is PKI,
//! so Steward acts as a Certificate Authority that assesses the attestation
//! evidence and issues a certificate based on this evidence. The certificate
//! is returned to the workload and used by it to participate in
//! the authenticated data exchanges with other services over the encrypted
//! connections.
//!
//! # Design Materials
//!
//! [Attestation Concept](https://hackmd.io/@enarx/r1Yg2kb_s)
//! [Attestation Flow](https://hackmd.io/@enarx/SySK2_tHo)
//! [Full Provisioning Flow with Attestation](https://hackmd.io/@enarx/rJ55urrvo)
//!
//! # Licensing and Copyright
//!
//! Contributions to this project require copyright assignment to Profian.

#![warn(rust_2018_idioms, unused_lifetimes, unused_qualifications, clippy::all)]

use steward_server::{app, init_tracing, State};

use std::net::IpAddr;
use std::path::PathBuf;

use anyhow::{anyhow, Context};
use clap::Parser;
use confargs::{prefix_char_filter, Toml};

/// Attestation server for use with Enarx.
///
/// Any command-line options listed here may be specified by one or
/// more configuration files, which can be used by passing the
/// name of the file on the command-line with the syntax `@config.toml`.
/// The configuration file must contain valid TOML table mapping argument
/// names to their values.
#[derive(Clone, Debug, Parser)]
#[command(author, version, about)]
struct Args {
    #[arg(short, long, env = "STEWARD_KEY")]
    key: Option<PathBuf>,

    #[arg(short, long, env = "STEWARD_CRT")]
    crt: Option<PathBuf>,

    #[arg(short, long, env = "ROCKET_PORT", default_value = "3000")]
    port: u16,

    #[arg(short, long, env = "ROCKET_ADDRESS", default_value = "::")]
    addr: IpAddr,

    #[arg(long, env = "RENDER_EXTERNAL_HOSTNAME")]
    host: Option<String>,

    #[arg(long, env = "STEWARD_SAN")]
    san: Option<String>,

    #[arg(long)]
    config: Option<String>,
}

#[cfg_attr(not(target_os = "wasi"), tokio::main)]
#[cfg_attr(target_os = "wasi", tokio::main(flavor = "current_thread"))]
async fn main() -> anyhow::Result<()> {
    init_tracing();

    let args = confargs::args::<Toml>(prefix_char_filter::<'@'>)
        .context("Failed to parse config")
        .map(Args::parse_from)?;
    let state = match (args.key, args.crt, args.host) {
        (None, None, Some(host)) => State::generate(args.san, &host)?,
        (Some(key), Some(crt), _) => State::load(args.san, key, crt, args.config)?,
        _ => {
            eprintln!("Either:\n* Specify the public key `--crt` and private key `--key`, or\n* Specify the host `--host`.\n\nRun with `--help` for more information.");
            return Err(anyhow!("invalid configuration"));
        }
    };

    #[cfg(not(target_os = "wasi"))]
    {
        use std::net::SocketAddr;
        let addr = SocketAddr::from((args.addr, args.port));
        tracing::debug!("listening on {}", addr);
        axum::Server::bind(&addr)
            .serve(app(state).into_make_service())
            .await?;
    }
    #[cfg(target_os = "wasi")]
    {
        use std::os::wasi::io::FromRawFd;
        tracing::debug!("listening");
        let std_listener = unsafe { std::net::TcpListener::from_raw_fd(3) };
        std_listener
            .set_nonblocking(true)
            .context("failed to set NONBLOCK")?;
        axum::Server::from_tcp(std_listener)
            .context("failed to construct server")?
            .serve(app(state).into_make_service())
            .await?;
    }

    Ok(())
}
