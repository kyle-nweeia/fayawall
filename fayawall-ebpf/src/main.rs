#![no_main]
#![no_std]

use aya_ebpf::{bindings::xdp_action::XDP_ABORTED, macros::xdp, programs::XdpContext};
use fayawall_ebpf::xdp::try_xdp_firewall;
use panic_halt as _;

#[xdp]
pub fn xdp_firewall(ctx: XdpContext) -> u32 {
    try_xdp_firewall(ctx).unwrap_or(XDP_ABORTED)
}
