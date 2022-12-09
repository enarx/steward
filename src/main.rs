// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: AGPL-3.0-only

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
