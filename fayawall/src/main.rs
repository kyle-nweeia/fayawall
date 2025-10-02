use std::{
    fs::read_to_string,
    io::{Write, stdin, stdout},
};

use aya::Ebpf;
use serde::Deserialize;
use toml::from_str;
use tracing::{info, warn};

use crate::{ebpf::Init, log::Log};

pub mod ebpf;
pub mod ipv4;
pub mod log;
pub mod maps;

const TARGET: &str = "fayawall::main";

#[derive(Deserialize)]
pub struct BlacklistPolicy {
    ipv4: Option<Vec<String>>,
}

#[derive(Deserialize)]
pub struct RateLimitPolicy {
    packet_limit: Option<String>,
    window_size: Option<String>,
}

#[derive(Deserialize)]
struct Policy {
    blacklist: Option<BlacklistPolicy>,
    #[serde(rename = "rate-limit")]
    rate_limit: Option<RateLimitPolicy>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _guard = Log::init()?;
    let mut cmd = String::new();
    let mut ebpf = Ebpf::init()?;
    let policy = read_to_string("policy.toml").unwrap_or_else(|e| {
        warn!(target: TARGET, "`policy.toml` not found: {e}");
        String::new()
    });
    let Policy {
        blacklist: blacklist_policy,
        rate_limit: rate_limit_policy,
    } = from_str(&policy)?;

    ebpf.blacklist()?.apply(blacklist_policy);
    ebpf.rate_limit_settings()?.apply(rate_limit_policy);

    loop {
        cmd.clear();
        print!("fayawall> ");
        stdout().flush()?;
        stdin().read_line(&mut cmd)?;

        let args = cmd.split_whitespace().collect::<Vec<_>>();

        if let Some((head, tail)) = args.split_at_checked(2) {
            match head {
                ["blacklist", "add"] => ebpf.blacklist()?.add(tail),

                ["blacklist", "del"] => ebpf.blacklist()?.del(tail),

                ["blacklist", "get"] => println!("{}", ebpf.blacklist()?),

                ["packet_limit", "get"] => {
                    println!("{}", ebpf.rate_limit_settings()?.get_packet_limit()?)
                }

                ["packet_limit", "set"] => {
                    let arg = tail.get(0).unwrap_or(&"").parse::<u64>();

                    match arg {
                        Ok(limit) => ebpf.rate_limit_settings()?.set_packet_limit(limit)?,
                        Err(e) => warn!(target: TARGET, "Invalid packet limit: {e}"),
                    }
                }

                ["window_size", "get"] => {
                    println!("{}", ebpf.rate_limit_settings()?.get_window_size()?)
                }

                ["window_size", "set"] => {
                    let arg = tail.get(0).unwrap_or(&"").parse::<u64>();

                    match arg {
                        Ok(size) => ebpf.rate_limit_settings()?.set_window_size(size)?,
                        Err(e) => warn!(target: TARGET, "Invalid window size: {e}"),
                    }
                }

                invalid_cmd => warn!(target: TARGET, "Invalid command: {invalid_cmd:?}"),
            }
        } else {
            match args.as_slice() {
                ["exit"] => break,
                invalid_cmd => warn!(target: TARGET, "Invalid command: {invalid_cmd:?}"),
            }
        }
    }

    info!(target: TARGET, "Exiting");

    Ok(())
}
