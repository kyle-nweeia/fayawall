use aya::{
    Ebpf, EbpfError,
    maps::HashMap,
    programs::{Xdp, XdpFlags},
};
use aya_log::EbpfLogger;
use clap::Parser;
use tracing::warn;

use crate::{
    arg::Arg,
    maps::{ipv4_list::Ipv4List, rate_limit_settings::RateLimitSettings},
};

pub trait Init {
    fn blacklist(&'_ mut self) -> Result<Ipv4List<'_>, EbpfError>;
    fn init() -> Result<Ebpf, EbpfError>;
    fn rate_limit_settings(&'_ mut self) -> Result<RateLimitSettings<'_>, EbpfError>;
    fn whitelist(&'_ mut self) -> Result<Ipv4List<'_>, EbpfError>;
}

impl Init for Ebpf {
    fn blacklist(&'_ mut self) -> Result<Ipv4List<'_>, EbpfError> {
        let map = self
            .map_mut("BLACKLIST")
            .expect("BPF map BLACKLIST not found");
        let hash_map = HashMap::try_from(map)?;

        Ok(Ipv4List::new("blacklist", hash_map))
    }

    fn init() -> Result<Ebpf, EbpfError> {
        let mut ebpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/fayawall"
        )))?;

        if let Err(e) = EbpfLogger::init(&mut ebpf) {
            warn!("eBPF logger failed to initialize: {e}");
        }

        let prog: &mut Xdp = ebpf
            .program_mut("xdp_firewall")
            .expect("BPF program xdp_firewall not found")
            .try_into()?;

        prog.load()?;
        prog.attach(&Arg::parse().iface, XdpFlags::SKB_MODE)?;

        Ok(ebpf)
    }

    fn rate_limit_settings(&'_ mut self) -> Result<RateLimitSettings<'_>, EbpfError> {
        let map = self
            .map_mut("RATE_LIMIT_SETTINGS")
            .expect("BPF map RATE_LIMIT_SETTINGS not found");
        let hash_map = HashMap::try_from(map)?;

        Ok(RateLimitSettings(hash_map))
    }

    fn whitelist(&'_ mut self) -> Result<Ipv4List<'_>, EbpfError> {
        let map = self
            .map_mut("WHITELIST")
            .expect("BPF map WHITELIST not found");
        let hash_map = HashMap::try_from(map)?;

        Ok(Ipv4List::new("whitelist", hash_map))
    }
}
