use std::{
    fs::read_to_string,
    io::{Write, stdin, stdout},
};

use aya::Ebpf;
use toml::Table;
use tracing::info;

use crate::{ebpf::Init, log::Log};

pub mod ebpf;
pub mod ipv4;
pub mod log;
pub mod map;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _guard = Log::init()?;
    let mut cmd = String::new();
    let config = read_to_string("config.toml")
        .unwrap_or_default()
        .parse::<Table>()?;
    let mut ebpf = Ebpf::init()?;
    let mut blacklist = ebpf.blacklist()?;

    blacklist.apply(config);

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
