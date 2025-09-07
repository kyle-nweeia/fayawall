use aya::maps::MapError;
use log::{error, info};
use std::{net::Ipv4Addr, num::ParseIntError};

pub struct Addr(Option<u32>);

impl Addr {
    pub fn parse(arg: &str) -> Self {
        Self(
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
            },
        )
    }

    pub fn apply<T: FnOnce(u32) -> Result<(), MapError>>(
        &self,
        f: T,
        ok_msg: String,
        err_msg: String,
    ) {
        if let Some(addr) = self.0 {
            if let Err(e) = f(addr) {
                error!("{err_msg}: {e}");
            } else {
                info!("{ok_msg}");
            }
        }
    }
}
