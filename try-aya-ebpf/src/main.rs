#![no_std]
#![no_main]

use aya_bpf::{
    macros::tracepoint,
    programs::TracePointContext, BpfContext,
};
use aya_log_ebpf::{info, error};

#[tracepoint]
pub fn on_open(ctx: TracePointContext) -> u32 {
    match on_open_internal(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn on_open_internal(ctx: TracePointContext) -> Result<u32, u32> {
    match ctx.command() {
        Ok(command) => info!(&ctx, "tracepoint sys_enter_open called {}", core::str::from_utf8(&command).unwrap()),
        Err(_) => error!(&ctx, "error"),
    }
    
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
