#![no_main]
#![no_std]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::HashMap,
    programs::XdpContext,
};
use aya_log_ebpf::info;
use core::mem;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::Ipv4Hdr,
};

#[map]
static BLACKLIST: HashMap<u32, u32> = HashMap::<u32, u32>::with_max_entries(1024, 0);

#[xdp]
pub fn xdp_firewall(ctx: XdpContext) -> u32 {
    match try_xdp_firewall(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn block_addr(addr: u32) -> bool {
    unsafe { BLACKLIST.get(&addr).is_some() }
}

#[inline(always)]
unsafe fn data_ptr<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let data_end = ctx.data_end();
    let data_start = ctx.data();
    let header_size = mem::size_of::<T>();

    if data_start + offset + header_size > data_end {
        return Err(());
    }

    let ptr = (data_start + offset) as *const T;

    Ok(unsafe { &*ptr })
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}

fn try_xdp_firewall(ctx: XdpContext) -> Result<u32, ()> {
    let eth_hdr: *const EthHdr = unsafe { data_ptr(&ctx, 0)? };

    if unsafe { (*eth_hdr).ether_type } != EtherType::Ipv4.into() {
        return Ok(xdp_action::XDP_PASS);
    }

    let ipv4_hdr: *const Ipv4Hdr = unsafe { data_ptr(&ctx, EthHdr::LEN)? };
    let source = u32::from_be_bytes(unsafe { (*ipv4_hdr).src_addr });
    let action = match block_addr(source) {
        true => xdp_action::XDP_DROP,
        false => xdp_action::XDP_PASS,
    };

    info!(
        &ctx,
        "SOURCE: {:i}\tACTION: {}",
        source,
        match action {
            1 => "XDP_DROP",
            _ => "XDP_PASS",
        }
    );

    Ok(action)
}
