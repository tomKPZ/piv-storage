//! Cooperative cancellation. SIGINT and SIGTERM set a flag without SA_RESTART,
//! so the kernel's interruptible SETUP returns EINTR; the frontend then unwinds
//! and removes only the mappings this attempt created (docs/cancellation.md).

use std::sync::atomic::{AtomicBool, Ordering};

use crate::error::{Error, Result};

static CANCELLED: AtomicBool = AtomicBool::new(false);

extern "C" fn on_signal(_: libc::c_int) {
    CANCELLED.store(true, Ordering::SeqCst);
}

pub fn install() {
    for signal in [libc::SIGINT, libc::SIGTERM] {
        // SAFETY: sigaction with a zeroed struct, an async-signal-safe handler
        // (one atomic store) and no SA_RESTART.
        unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = on_signal as extern "C" fn(libc::c_int) as usize;
            libc::sigemptyset(&mut action.sa_mask);
            action.sa_flags = 0;
            libc::sigaction(signal, &action, std::ptr::null_mut());
        }
    }
}

pub fn cancelled() -> bool {
    CANCELLED.load(Ordering::SeqCst)
}

pub fn check() -> Result<()> {
    if cancelled() { Err(Error::interrupted()) } else { Ok(()) }
}
