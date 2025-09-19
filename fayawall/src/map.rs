use aya::maps::{HashMap, MapData};
use tracing::{error, info};

use crate::ipv4::Addr;

pub struct Blacklist<'a>(pub HashMap<&'a mut MapData, u32, u32>);

impl<'a> Blacklist<'a> {
    pub fn add(&mut self, addrs: Addr) {
        for &addr in addrs.0.as_slice().iter() {
            if let Err(e) = self.0.insert(addr, 0, 0) {
                error!("{} could not be added to blacklist: {}", addr, e);
            } else {
                info!("{} added to blacklist", addr);
            }
        }
    }

    pub fn del(&mut self, addrs: Addr) {
        for &addr in addrs.0.as_slice().iter() {
            if let Err(e) = self.0.remove(&addr) {
                error!("{} could not be removed from blacklist: {}", addr, e);
            } else {
                info!("{} removed from blacklist", addr);
            }
        }
    }

    pub fn list(&self) {
        println!("Blacklisted IP addresses:");
        for res in self.0.keys() {
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
}
