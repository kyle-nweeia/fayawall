use aya::Ebpf;
use firewall::{ebpf::Init, ipv4::Addr};
use std::io::{Write, stdin, stdout};
use tracing::info;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _guard = firewall::log::init()?;
    let mut cmd = String::new();
    let mut ebpf = Ebpf::new()?;
    let mut blacklist = ebpf.blacklist()?;

    loop {
        cmd.clear();
        print!("firewall> ");
        stdout().flush()?;
        stdin().read_line(&mut cmd)?;

        if let Some((&arg, args)) = cmd.split_whitespace().collect::<Vec<&str>>().split_first() {
            match arg {
                "add" => Addr::parse(args).apply(
                    |addr| blacklist.insert(addr, 0, 0),
                    |addr| format!("{addr} added to blacklist"),
                    |addr| format!("{addr} could not be added to blacklist"),
                ),
                "del" => Addr::parse(args).apply(
                    |addr| blacklist.remove(&addr),
                    |addr| format!("{addr} removed from blacklist"),
                    |addr| format!("{addr} could not be removed from blacklist"),
                ),
                "exit" => break,
                "list" => {
                    println!("Blacklisted IP addresses:");
                    for res in blacklist.keys() {
                        if let Ok(key) = res {
                            println!(
                                "{}",
                                key.to_be_bytes()
                                    .iter()
                                    .map(|b| b.to_string())
                                    .collect::<Vec<String>>()
                                    .join(".")
                            );
                        }
                    }
                }
                _ => println!("Invalid command"),
            }
        }
    }

    info!("Exiting");

    Ok(())
}
