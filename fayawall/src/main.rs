use std::{
    fs::read_to_string,
    io::{Write, stdin, stdout},
};

use aya::Ebpf;
use fayawall::ebpf::Init;
use toml::Table;
use tracing::info;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _guard = fayawall::log::init()?;
    let mut cmd = String::new();
    let config = read_to_string("config.toml")
        .unwrap_or_default()
        .parse::<Table>()?;
    let mut ebpf = Ebpf::new()?;
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
                "list" => blacklist.list(),
                _ => println!("Invalid command"),
            }
        }
    }

    info!(target: "fayawall::main", "Exiting");

    Ok(())
}
