use aya::Ebpf;
use firewall::{ebpf::Init, ipv4::Addr};
use log::info;
use std::io::{Write, stdin, stdout};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    firewall::log::init()?;

    let mut args = String::new();
    let mut ebpf = Ebpf::new()?;
    let mut blacklist = ebpf.blacklist()?;

    loop {
        args.clear();
        print!("firewall> ");
        stdout().flush()?;
        stdin().read_line(&mut args)?;

        match *args.split_whitespace().collect::<Vec<&str>>().as_slice() {
            ["add", arg] => Addr::parse(arg).apply(
                |addr| blacklist.insert(addr, 0, 0),
                format!("{arg} added to blacklist"),
                format!("{arg} could not be added to blacklist"),
            ),
            ["del", arg] => Addr::parse(arg).apply(
                |addr| blacklist.remove(&addr),
                format!("{arg} removed from blacklist"),
                format!("{arg} could not be removed from blacklist"),
            ),
            ["exit"] => break,
            ["list"] => {
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
            [_, ..] => println!("Invalid command"),
            [] => continue,
        }
    }

    info!("Exiting");

    Ok(())
}
