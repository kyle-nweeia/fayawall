use clap::Parser;

#[derive(Debug, Parser)]
pub struct Arg {
    #[arg(short, long, default_value = "eth0")]
    pub iface: String,
}
