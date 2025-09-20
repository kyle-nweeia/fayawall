use std::net::Ipv4Addr;

use tracing::warn;

pub struct Addr(pub Vec<Ipv4Addr>);

impl Addr {
    pub fn parse(args: &[&str]) -> Self {
        Self(
            args.iter()
                .filter_map(|arg| match arg.parse::<Ipv4Addr>() {
                    Ok(addr) => Some(addr),
                    Err(e) => {
                        warn!(r#""{arg}" could not be parsed into Ipv4Addr: {e}"#);
                        None
                    }
                })
                .collect(),
        )
    }
}
