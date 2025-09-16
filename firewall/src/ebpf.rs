use aya::{
    Ebpf, EbpfError,
    maps::{HashMap, MapData},
    programs::{Xdp, XdpFlags},
};
use aya_log::EbpfLogger;
use clap::Parser;
use tracing::warn;

pub trait Init {
    fn new() -> Result<Ebpf, EbpfError>;
    fn blacklist(&mut self) -> Result<HashMap<&mut MapData, u32, u32>, EbpfError>;
}

#[derive(Debug, Parser)]
struct Arg {
    #[arg(short, long, default_value = "eth0")]
    pub iface: String,
}

impl Init for Ebpf {
    fn new() -> Result<Ebpf, EbpfError> {
        let mut ebpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/firewall"
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

    fn blacklist(&mut self) -> Result<HashMap<&mut MapData, u32, u32>, EbpfError> {
        let map = self
            .map_mut("BLACKLIST")
            .expect("BPF map BLACKLIST not found");

        Ok(HashMap::try_from(map)?)
    }
}
