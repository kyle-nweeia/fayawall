use std::{
    fmt::{self, Display, Formatter},
    net::Ipv4Addr,
};

use aya::maps::{HashMap, MapData};
use tracing::{error, info, warn};

use crate::{ipv4::Addr, policy::BlacklistPolicy};

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

    pub fn apply(&mut self, blacklist_policy: Option<BlacklistPolicy>) {
        if let Some(BlacklistPolicy { ipv4 }) = blacklist_policy {
            if let Some(string_vec) = ipv4 {
                let arg_vec = string_vec.iter().map(String::as_str).collect::<Vec<_>>();
                let args = arg_vec.as_slice();

                self.add(args);
            } else {
                warn!("`ipv4` array not found in blacklist policy");
            }
        } else {
            warn!("`blacklist` table not found in policy");
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

    fn keys(&self) -> Vec<u32> {
        self.0.keys().flatten().collect()
    }
}

impl<'a> Display for Blacklist<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let blacklist = self
            .keys()
            .iter()
            .map(|&key| Ipv4Addr::from_bits(key).to_string())
            .collect::<Vec<_>>()
            .join("\n");

        write!(f, "{blacklist}")
    }
}

#[cfg(test)]
mod tests {
    use aya::Ebpf;
    use serial_test::serial;
    use toml::from_str;

    use crate::{Policy, ebpf::Init};

    use super::*;

    #[serial]
    #[tokio::test]
    async fn add_addr_to_blacklist() {
        let mut ebpf = Ebpf::init().unwrap();
        let mut blacklist = ebpf.blacklist().unwrap();

        blacklist.add(&["127.0.0.1"]);
        assert_eq!(blacklist.keys(), vec![Ipv4Addr::new(127, 0, 0, 1).into()]);
    }

    #[serial]
    #[tokio::test]
    async fn add_invalid_addr_to_blacklist() {
        let mut ebpf = Ebpf::init().unwrap();
        let mut blacklist = ebpf.blacklist().unwrap();

        blacklist.add(&["invalid"]);
        assert_eq!(blacklist.keys(), vec![]);
    }

    #[serial]
    #[tokio::test]
    async fn apply_policy_to_blacklist() {
        let mut ebpf = Ebpf::init().unwrap();
        let mut blacklist = ebpf.blacklist().unwrap();
        let policy = "[blacklist]\nipv4 = [\"127.0.0.1\"]";
        let blacklist_policy = from_str::<Policy>(policy).unwrap().blacklist;

        blacklist.apply(blacklist_policy);
        assert_eq!(blacklist.keys(), vec![Ipv4Addr::new(127, 0, 0, 1).into()]);
    }

    #[serial]
    #[tokio::test]
    async fn apply_empty_policy_to_blacklist() {
        let mut ebpf = Ebpf::init().unwrap();
        let mut blacklist = ebpf.blacklist().unwrap();
        let policy = "";
        let blacklist_policy = from_str::<Policy>(policy).unwrap().blacklist;

        blacklist.apply(blacklist_policy);
        assert_eq!(blacklist.keys(), vec![]);
    }

    #[serial]
    #[tokio::test]
    async fn delete_addr_from_blacklist() {
        let mut ebpf = Ebpf::init().unwrap();
        let mut blacklist = ebpf.blacklist().unwrap();

        blacklist.add(&["127.0.0.1"]);
        blacklist.del(&["127.0.0.1"]);
        assert_eq!(blacklist.keys(), vec![]);
    }

    #[serial]
    #[tokio::test]
    async fn delete_invalid_addr_from_blacklist() {
        let mut ebpf = Ebpf::init().unwrap();
        let mut blacklist = ebpf.blacklist().unwrap();

        blacklist.add(&["127.0.0.1"]);
        blacklist.del(&["invalid"]);
        assert_eq!(blacklist.keys(), vec![Ipv4Addr::new(127, 0, 0, 1).into()]);
    }

    #[serial]
    #[tokio::test]
    async fn format_blacklist() {
        let mut ebpf = Ebpf::init().unwrap();
        let mut blacklist = ebpf.blacklist().unwrap();

        blacklist.add(&["0.0.0.0", "1.1.1.1"]);
        assert!(["0.0.0.0\n1.1.1.1", "1.1.1.1\n0.0.0.0"].contains(&blacklist.to_string().as_str()));
    }
}
