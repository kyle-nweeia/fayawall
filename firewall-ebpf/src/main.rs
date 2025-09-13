#![no_main]
#![no_std]

use aya_ebpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};
use firewall_ebpf::xdp::try_xdp_firewall;

#[xdp]
pub fn xdp_firewall(ctx: XdpContext) -> u32 {
    match try_xdp_firewall(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
