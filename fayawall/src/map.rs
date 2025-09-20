use aya::maps::{HashMap, MapData};
use tracing::{error, info};

use crate::ipv4::Addr;

pub struct Blacklist<'a>(pub HashMap<&'a mut MapData, u32, u32>);

impl<'a> Blacklist<'a> {
    pub fn add(&mut self, args: &[&str]) {
        for &addr in Addr::parse(args).0.as_slice().iter() {
            if let Err(e) = self.0.insert(addr, 0, 0) {
                error!("{addr} could not be added to blacklist: {e}");
            } else {
                info!("{addr} added to blacklist");
            }
        }
    }

    pub fn del(&mut self, args: &[&str]) {
        for &addr in Addr::parse(args).0.as_slice().iter() {
            if let Err(e) = self.0.remove(&addr) {
                error!("{addr} could not be removed from blacklist: {e}");
            } else {
                info!("{addr} removed from blacklist");
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
