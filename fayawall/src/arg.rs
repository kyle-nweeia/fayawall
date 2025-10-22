use clap::Parser;

#[derive(Debug, Parser)]
pub struct Arg {
    #[arg(short, long, default_value = "eth0")]
    pub iface: String,

    #[arg(short, long, default_value = "license.toml")]
    pub license: String,

    #[arg(short, long, default_value = "policy.toml")]
    pub policy: String,
}
