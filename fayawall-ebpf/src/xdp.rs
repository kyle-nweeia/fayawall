use core::mem;

use aya_ebpf::{
    bindings::xdp_action::{XDP_DROP, XDP_PASS},
    helpers::r#gen::bpf_ktime_get_ns,
    macros::map,
    maps::HashMap,
    programs::XdpContext,
};
use aya_log_ebpf::{info, warn};
use common::RateLimitSetting;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::Ipv4Hdr,
};

pub struct Error;

struct RateLimitWindow {
    window_start: u64,
    packet_count: u64,
}

#[map]
static BLACKLIST: HashMap<u32, u32> = HashMap::<u32, u32>::with_max_entries(1024, 0);

#[map]
static RATE_LIMIT_SETTINGS: HashMap<u8, u64> = HashMap::with_max_entries(2, 0);

#[map]
static RATE_LIMIT_WINDOWS: HashMap<u32, RateLimitWindow> = HashMap::with_max_entries(1024, 0);

#[map]
static WHITELIST: HashMap<u32, u32> = HashMap::<u32, u32>::with_max_entries(1024, 0);

fn block_addr(addr: u32) -> bool {
    unsafe { BLACKLIST.get(&addr).is_some() }
}

#[inline(always)]
unsafe fn data_ptr<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, Error> {
    let data_end = ctx.data_end();
    let data_start = ctx.data();
    let header_size = mem::size_of::<T>();

    if data_start + offset + header_size > data_end {
        return Err(Error);
    }

    let ptr = (data_start + offset) as *const T;

    Ok(unsafe { &*ptr })
}

fn rate_limit(addr: u32, ctx: &XdpContext) -> bool {
    let now = unsafe { bpf_ktime_get_ns() };

    match RATE_LIMIT_WINDOWS.get_ptr_mut(&addr) {
        Some(window) => unsafe {
            let packet_limit = *RATE_LIMIT_SETTINGS
                .get(&(RateLimitSetting::PacketLimit as u8))
                .unwrap_or(&u64::MAX);
            let window_size = *RATE_LIMIT_SETTINGS
                .get(&(RateLimitSetting::WindowSize as u8))
                .unwrap_or(&u64::MAX);

            if now - (*window).window_start > window_size {
                (*window).window_start = now;
                (*window).packet_count = 1;
            } else {
                (*window).packet_count += 1;
            }

            let packet_count = (*window).packet_count;

            if packet_count > packet_limit {
                warn!(
                    ctx,
                    "{} packets received in {} ms from `{:i}` exceed packet_limit: {}, window_size: {} ms",
                    packet_count,
                    now - (*window).window_start,
                    addr,
                    packet_limit,
                    window_size
                );

                true
            } else {
                false
            }
        },
        None => {
            RATE_LIMIT_WINDOWS
                .insert(
                    &addr,
                    &RateLimitWindow {
                        window_start: now,
                        packet_count: 1,
                    },
                    0,
                )
                .ok();

            false
        }
    }
}

fn whitelist(addr: u32) -> bool {
    unsafe { WHITELIST.get(&addr).is_some() }
}

pub fn try_xdp_firewall(ctx: XdpContext) -> Result<u32, Error> {
    let eth_hdr: *const EthHdr = unsafe { data_ptr(&ctx, 0)? };

    if unsafe { (*eth_hdr).ether_type } != EtherType::Ipv4.into() {
        return Ok(XDP_PASS);
    }

    let ipv4_hdr: *const Ipv4Hdr = unsafe { data_ptr(&ctx, EthHdr::LEN)? };
    let source = u32::from_be_bytes(unsafe { (*ipv4_hdr).src_addr });
    let action = if !whitelist(source) && (block_addr(source) || rate_limit(source, &ctx)) {
        XDP_DROP
    } else {
        XDP_PASS
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
