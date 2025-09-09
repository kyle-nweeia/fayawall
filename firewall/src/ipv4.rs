use aya::maps::MapError;
use log::{error, info};
use std::{net::Ipv4Addr, num::ParseIntError};

pub struct Addr(Vec<u32>);

impl Addr {
    pub fn parse(args: &[&str]) -> Self {
        Self(
            args.iter()
                .filter_map(|arg| {
                    if let Ok(octets) = arg
                        .split('.')
                        .map(|s| s.parse())
                        .collect::<Result<Vec<u8>, ParseIntError>>()
                    {
                        if let Ok([a, b, c, d]) = TryInto::<[u8; 4]>::try_into(octets) {
                            Some(Ipv4Addr::new(a, b, c, d).into())
                        } else {
                            println!("{arg} could not be parsed into four octets");
                            None
                        }
                    } else {
                        println!("{arg} could not be parsed into octets");
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
            if let Err(e) = f(addr) {
                error!("{}: {}", err_msg(addr.into()), e);
            } else {
                info!("{}", ok_msg(addr.into()));
            }
        }
    }
}
