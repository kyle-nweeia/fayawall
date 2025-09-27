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
        warn!(target: "fayawall::main", "`policy.toml` not found: {e}");
        String::new()
    });
    let Policy {
        blacklist: blacklist_policy,
        rate_limit: rate_limit_policy,
    } = from_str(&policy)?;

    {
        ebpf.rate_limit_settings()?.apply(rate_limit_policy);
    }

    let mut blacklist = ebpf.blacklist()?;

    blacklist.apply(blacklist_policy);

    loop {
        cmd.clear();
        print!("fayawall> ");
        stdout().flush()?;
        stdin().read_line(&mut cmd)?;

        if let Some((&arg, args)) = cmd.split_whitespace().collect::<Vec<&str>>().split_first() {
            match arg {
                "add" => blacklist.add(args),
                "del" => blacklist.del(args),
                "exit" => break,
                "list" => println!("Blacklisted IP addresses:\n{blacklist}"),
                _ => println!("Invalid command"),
            }
        }
    }

    info!(target: "fayawall::main", "Exiting");

    Ok(())
}
