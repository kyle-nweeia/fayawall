use std::{
    fmt::{self, Display, Formatter},
    net::Ipv4Addr,
};

use aya::maps::{HashMap, MapData};
use tracing::{error, info, warn};

use crate::{ipv4::Addr, policy::Ipv4ListPolicy};

pub struct Ipv4List<'a> {
    inner: HashMap<&'a mut MapData, u32, u32>,
    label: String,
}

impl<'a> Ipv4List<'a> {
    pub fn add(&mut self, args: &[&str]) {
        for &addr in Addr::parse(args).0.as_slice().iter() {
            if let Err(e) = self.inner.insert(addr.to_bits(), 0, 0) {
                error!("{addr} could not be added to {}: {e}", self.label);
            } else {
                info!("{addr} added to {}", self.label);
            }
        }
    }

    pub fn apply(&mut self, policy: Option<Ipv4ListPolicy>) {
        if let Some(Ipv4ListPolicy { ipv4 }) = policy {
            if let Some(string_vec) = ipv4 {
                let arg_vec = string_vec.iter().map(String::as_str).collect::<Vec<_>>();
                let args = arg_vec.as_slice();

                self.add(args);
            } else {
                warn!("`ipv4` array not found in {} policy", self.label);
            }
        } else {
            warn!("`{}` table not found in policy", self.label);
        }
    }

    pub fn del(&mut self, args: &[&str]) {
        for &addr in Addr::parse(args).0.as_slice().iter() {
            if let Err(e) = self.inner.remove(&addr.to_bits()) {
                error!("{addr} could not be removed from {}: {e}", self.label);
            } else {
                info!("{addr} removed from {}", self.label);
            }
        }
    }

    fn keys(&self) -> Vec<u32> {
        self.inner.keys().flatten().collect()
    }

    pub fn new<T: Into<String>>(label: T, map: HashMap<&'a mut MapData, u32, u32>) -> Self {
        Self {
            label: label.into(),
            inner: map,
        }
    }
}

impl<'a> Display for Ipv4List<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let ipv4_list = self
            .keys()
            .iter()
            .map(|&key| Ipv4Addr::from_bits(key).to_string())
            .collect::<Vec<_>>()
            .join("\n");

        write!(f, "{ipv4_list}")
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use aya::Ebpf;
    use serial_test::serial;
    use toml::from_str;

    use crate::{Policy, ebpf::Init};

    #[serial]
    #[tokio::test]
    async fn add_addr_to_blacklist() {
        let mut ebpf = Ebpf::init().unwrap();
        let mut blacklist = ebpf.blacklist().unwrap();
        let expected = vec![u32::from(Ipv4Addr::new(127, 0, 0, 1))];

        blacklist.add(&["127.0.0.1"]);
        assert_eq!(blacklist.keys(), expected);
    }

    #[serial]
    #[tokio::test]
    async fn add_addr_to_whitelist() {
        let mut ebpf = Ebpf::init().unwrap();
        let mut whitelist = ebpf.whitelist().unwrap();
        let expected = vec![u32::from(Ipv4Addr::new(127, 0, 0, 1))];

        whitelist.add(&["127.0.0.1"]);
        assert_eq!(whitelist.keys(), expected);
    }

    #[serial]
    #[tokio::test]
    async fn add_invalid_addr_to_blacklist() {
        let mut ebpf = Ebpf::init().unwrap();
        let mut blacklist = ebpf.blacklist().unwrap();

        blacklist.add(&["invalid"]);
        assert_eq!(blacklist.keys(), Vec::<u32>::new());
    }

    #[serial]
    #[tokio::test]
    async fn add_invalid_addr_to_whitelist() {
        let mut ebpf = Ebpf::init().unwrap();
        let mut whitelist = ebpf.whitelist().unwrap();

        whitelist.add(&["invalid"]);
        assert_eq!(whitelist.keys(), Vec::<u32>::new());
    }

    #[serial]
    #[tokio::test]
    async fn apply_policy_to_blacklist() {
        let mut ebpf = Ebpf::init().unwrap();
        let mut blacklist = ebpf.blacklist().unwrap();
        let expected = vec![u32::from(Ipv4Addr::new(127, 0, 0, 1))];
        let policy = "[blacklist]\nipv4 = [\"127.0.0.1\"]";
        let blacklist_policy = from_str::<Policy>(policy).unwrap().blacklist;

        blacklist.apply(blacklist_policy);
        assert_eq!(blacklist.keys(), expected);
    }

    #[serial]
    #[tokio::test]
    async fn apply_policy_to_whitelist() {
        let mut ebpf = Ebpf::init().unwrap();
        let mut whitelist = ebpf.whitelist().unwrap();
        let expected = vec![u32::from(Ipv4Addr::new(127, 0, 0, 1))];
        let policy = "[whitelist]\nipv4 = [\"127.0.0.1\"]";
        let whitelist_policy = from_str::<Policy>(policy).unwrap().whitelist;

        whitelist.apply(whitelist_policy);
        assert_eq!(whitelist.keys(), expected);
    }

    #[serial]
    #[tokio::test]
    async fn apply_empty_policy_to_blacklist() {
        let mut ebpf = Ebpf::init().unwrap();
        let mut blacklist = ebpf.blacklist().unwrap();
        let policy = "";
        let blacklist_policy = from_str::<Policy>(policy).unwrap().blacklist;

        blacklist.apply(blacklist_policy);
        assert_eq!(blacklist.keys(), Vec::<u32>::new());
    }

    #[serial]
    #[tokio::test]
    async fn apply_empty_policy_to_whitelist() {
        let mut ebpf = Ebpf::init().unwrap();
        let mut whitelist = ebpf.whitelist().unwrap();
        let policy = "";
        let whitelist_policy = from_str::<Policy>(policy).unwrap().blacklist;

        whitelist.apply(whitelist_policy);
        assert_eq!(whitelist.keys(), Vec::<u32>::new());
    }

    #[serial]
    #[tokio::test]
    async fn delete_addr_from_blacklist() {
        let mut ebpf = Ebpf::init().unwrap();
        let mut blacklist = ebpf.blacklist().unwrap();

        blacklist.add(&["127.0.0.1"]);
        blacklist.del(&["127.0.0.1"]);
        assert_eq!(blacklist.keys(), Vec::<u32>::new());
    }

    #[serial]
    #[tokio::test]
    async fn delete_addr_from_whitelist() {
        let mut ebpf = Ebpf::init().unwrap();
        let mut whitelist = ebpf.whitelist().unwrap();

        whitelist.add(&["127.0.0.1"]);
        whitelist.del(&["127.0.0.1"]);
        assert_eq!(whitelist.keys(), Vec::<u32>::new());
    }

    #[serial]
    #[tokio::test]
    async fn delete_invalid_addr_from_blacklist() {
        let mut ebpf = Ebpf::init().unwrap();
        let mut blacklist = ebpf.blacklist().unwrap();
        let expected = vec![u32::from(Ipv4Addr::new(127, 0, 0, 1))];

        blacklist.add(&["127.0.0.1"]);
        blacklist.del(&["invalid"]);
        assert_eq!(blacklist.keys(), expected);
    }

    #[serial]
    #[tokio::test]
    async fn delete_invalid_addr_from_whitelist() {
        let mut ebpf = Ebpf::init().unwrap();
        let mut whitelist = ebpf.whitelist().unwrap();
        let expected = vec![u32::from(Ipv4Addr::new(127, 0, 0, 1))];

        whitelist.add(&["127.0.0.1"]);
        whitelist.del(&["invalid"]);
        assert_eq!(whitelist.keys(), expected);
    }

    #[serial]
    #[tokio::test]
    async fn format_blacklist() {
        let mut ebpf = Ebpf::init().unwrap();
        let mut blacklist = ebpf.blacklist().unwrap();

        blacklist.add(&["0.0.0.0", "1.1.1.1"]);
        assert!(["0.0.0.0\n1.1.1.1", "1.1.1.1\n0.0.0.0"].contains(&blacklist.to_string().as_str()));
    }

    #[serial]
    #[tokio::test]
    async fn format_whitelist() {
        let mut ebpf = Ebpf::init().unwrap();
        let mut whitelist = ebpf.whitelist().unwrap();

        whitelist.add(&["0.0.0.0", "1.1.1.1"]);
        assert!(["0.0.0.0\n1.1.1.1", "1.1.1.1\n0.0.0.0"].contains(&whitelist.to_string().as_str()));
    }
}
