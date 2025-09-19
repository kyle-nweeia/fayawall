use aya::Ebpf;
use fayawall::{ebpf::Init, ipv4::Addr};
use std::io::{Write, stdin, stdout};
use tracing::info;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _guard = fayawall::log::init()?;
    let mut cmd = String::new();
    let mut ebpf = Ebpf::new()?;
    let mut blacklist = ebpf.blacklist()?;

    loop {
        cmd.clear();
        print!("fayawall> ");
        stdout().flush()?;
        stdin().read_line(&mut cmd)?;

        if let Some((&arg, args)) = cmd.split_whitespace().collect::<Vec<&str>>().split_first() {
            match arg {
                "add" => blacklist.add(Addr::parse(args)),
                "del" => blacklist.del(Addr::parse(args)),
                "exit" => break,
                "list" => blacklist.list(),
                _ => println!("Invalid command"),
            }
        }
    }

    info!(target: "fayawall::main", "Exiting");

    Ok(())
}
