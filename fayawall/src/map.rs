use aya::maps::{HashMap, MapData};
use toml::{Table, Value};
use tracing::{error, info, warn};

use crate::ipv4::Addr;

pub struct Blacklist<'a>(pub HashMap<&'a mut MapData, u32, u32>);

impl<'a> Blacklist<'a> {
    pub fn add(&mut self, args: &[&str]) {
        for &addr in Addr::parse(args).0.as_slice().iter() {
            if let Err(e) = self.0.insert(addr.to_bits(), 0, 0) {
                error!("{addr} could not be added to blacklist: {e}");
            } else {
                info!("{addr} added to blacklist");
            }
        }
    }

    pub fn apply(&mut self, config: Table) {
        if config.is_empty() {
            warn!("`config.toml` is empty or missing");
            return;
        }

        if let Some(Value::Table(blacklist_tbl)) = config.get("blacklist") {
            if let Some(Value::Array(ipv4_arr)) = blacklist_tbl.get("ipv4") {
                let ipv4_strs = ipv4_arr
                    .iter()
                    .filter_map(|val| {
                        val.as_str().or_else(|| {
                            warn!("`{val}` could not be extracted from `ipv4` array as string");
                            None
                        })
                    })
                    .collect::<Vec<&str>>();
                let args = ipv4_strs.as_slice();

                self.add(args);
            } else {
                warn!("`ipv4` array could not be extracted from `blacklist` table");
            }
        } else {
            warn!("`blacklist` table could not be extracted from `config.toml`");
        }
    }

    pub fn del(&mut self, args: &[&str]) {
        for &addr in Addr::parse(args).0.as_slice().iter() {
            if let Err(e) = self.0.remove(&addr.to_bits()) {
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

    #[cfg(test)]
    fn keys(&self) -> Vec<u32> {
        self.0.keys().flatten().collect()
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use aya::Ebpf;
    use serial_test::serial;
    use toml::Table;

    use crate::ebpf::Init;

    #[serial]
    #[tokio::test]
    async fn add_addr_to_blacklist() {
        let mut ebpf = Ebpf::new().unwrap();
        let mut blacklist = ebpf.blacklist().unwrap();

        blacklist.add(&["127.0.0.1"]);
        assert_eq!(blacklist.keys(), vec![Ipv4Addr::new(127, 0, 0, 1).into()]);
    }

    #[serial]
    #[tokio::test]
    async fn add_invalid_addr_to_blacklist() {
        let mut ebpf = Ebpf::new().unwrap();
        let mut blacklist = ebpf.blacklist().unwrap();

        blacklist.add(&["invalid"]);
        assert_eq!(blacklist.keys(), vec![]);
    }

    #[serial]
    #[tokio::test]
    async fn apply_config_to_blacklist() {
        let mut ebpf = Ebpf::new().unwrap();
        let mut blacklist = ebpf.blacklist().unwrap();
        let config = "[blacklist]\nipv4 = [\"127.0.0.1\"]";

        blacklist.apply(config.parse::<Table>().unwrap());
        assert_eq!(blacklist.keys(), vec![Ipv4Addr::new(127, 0, 0, 1).into()]);
    }

    #[serial]
    #[tokio::test]
    async fn apply_empty_config_to_blacklist() {
        let mut ebpf = Ebpf::new().unwrap();
        let mut blacklist = ebpf.blacklist().unwrap();

        blacklist.apply("".parse::<Table>().unwrap());
        assert_eq!(blacklist.keys(), vec![]);
    }

    #[serial]
    #[tokio::test]
    async fn delete_addr_from_blacklist() {
        let mut ebpf = Ebpf::new().unwrap();
        let mut blacklist = ebpf.blacklist().unwrap();

        blacklist.add(&["127.0.0.1"]);
        blacklist.del(&["127.0.0.1"]);
        assert_eq!(blacklist.keys(), vec![]);
    }

    #[serial]
    #[tokio::test]
    async fn delete_invalid_addr_from_blacklist() {
        let mut ebpf = Ebpf::new().unwrap();
        let mut blacklist = ebpf.blacklist().unwrap();

        blacklist.add(&["127.0.0.1"]);
        blacklist.del(&["invalid"]);
        assert_eq!(blacklist.keys(), vec![Ipv4Addr::new(127, 0, 0, 1).into()]);
    }
}
