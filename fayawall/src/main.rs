use std::{
    fs::read_to_string,
    io::{Write, stdin, stdout},
};

use aya::Ebpf;
use toml::from_str;
use tracing::{error, info, warn};

use crate::{ebpf::Init, log::Log, policy::Policy};

pub mod ebpf;
pub mod ipv4;
pub mod log;
pub mod maps;
pub mod policy;

const TARGET: &str = "fayawall::main";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _guard = Log::init()?;

    info!(target: TARGET, "Starting");

    let mut cmd = String::new();
    let mut ebpf = Ebpf::init()?;

    match read_to_string("policy.toml") {
        Ok(policy) => match from_str(&policy) {
            Ok(Policy {
                blacklist,
                rate_limit,
            }) if blacklist.is_some() || rate_limit.is_some() => {
                info!(target: TARGET, "Applying policy");

                ebpf.blacklist()?.apply(blacklist);
                ebpf.rate_limit_settings()?.apply(rate_limit);

                info!(target: TARGET, "Policy applied");
            }

            Err(e) => error!(target: TARGET, "`policy.toml` not parsed: {e}"),

            _ => warn!(target: TARGET, "No policy found in `policy.toml`"),
        },

        Err(e) => warn!(target: TARGET, "`policy.toml` not found: {e}"),
    };

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
                    if let Ok(packet_limit) = ebpf.rate_limit_settings()?.get_packet_limit() {
                        println!("{packet_limit}");
                    } else {
                        info!(target: TARGET, "`packet_limit` not set");
                    }
                }

                ["packet_limit", "set"] => {
                    let arg = tail.get(0).unwrap_or(&"").parse::<u64>();

                    match arg {
                        Ok(limit) => ebpf.rate_limit_settings()?.set_packet_limit(limit)?,
                        Err(e) => warn!(target: TARGET, "Invalid packet limit: {e}"),
                    }
                }

                ["window_size", "get"] => {
                    if let Ok(window_size) = ebpf.rate_limit_settings()?.get_window_size() {
                        println!("{window_size}");
                    } else {
                        info!(target: TARGET, "`window_size` not set");
                    }
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
