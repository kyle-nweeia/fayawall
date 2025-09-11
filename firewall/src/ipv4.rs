use aya::maps::MapError;
use log::{error, info};
use std::net::Ipv4Addr;

pub struct Addr(Vec<Ipv4Addr>);

impl Addr {
    pub fn parse(args: &[&str]) -> Self {
        Self(
            args.iter()
                .filter_map(|arg| match arg.parse::<Ipv4Addr>() {
                    Ok(addr) => Some(addr),
                    Err(e) => {
                        println!(r#""{arg}" could not be parsed: {e}"#);
                        None
                    }
                })
                .collect(),
        )
    }

    pub fn apply<
        T: FnMut(u32) -> Result<(), MapError>,
        U: Fn(Ipv4Addr) -> String,
        V: Fn(Ipv4Addr) -> String,
    >(
        &mut self,
        mut f: T,
        ok_msg: U,
        err_msg: V,
    ) {
        for &addr in self.0.as_slice().iter() {
            if let Err(e) = f(addr.into()) {
                error!("{}: {}", err_msg(addr), e);
            } else {
                info!("{}", ok_msg(addr));
            }
        }
    }
}
