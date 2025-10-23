use std::io::{Write, stdin, stdout};

use aya::Ebpf;
use tracing::{info, warn};

use crate::{ebpf::Init, log::Log, policy::Policy};

mod arg;
mod ebpf;
mod ipv4;
mod license;
mod log;
mod maps;
mod policy;

const TARGET: &str = "fayawall::main";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _guard = Log::init()?;

    info!(target: TARGET, "Starting");

    let mut cmd = String::new();
    let mut ebpf = Ebpf::init()?;

    #[cfg(all(feature = "license", not(test)))]
    license::License::verify().await?;

    Policy::apply(&mut ebpf)?;

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
                    let arg = tail.first().unwrap_or(&"").parse::<u64>();

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
                    let arg = tail.first().unwrap_or(&"").parse::<u64>();

                    match arg {
                        Ok(size) => ebpf.rate_limit_settings()?.set_window_size(size)?,
                        Err(e) => warn!(target: TARGET, "Invalid window size: {e}"),
                    }
                }

                invalid_cmd => warn!(target: TARGET, "Invalid command: {invalid_cmd:?}"),
            }
        } else {
            match args.as_slice() {
                [] => continue,
                ["exit"] => break,
                invalid_cmd => warn!(target: TARGET, "Invalid command: {invalid_cmd:?}"),
            }
        }
    }

    info!(target: TARGET, "Exiting");

    Ok(())
}
