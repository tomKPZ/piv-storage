//! Explicit test-only hooks, replacing the Python guest tests' monkeypatching
//! of pivstore.blocks.native_setup. Inactive unless PIVSETUP_TEST_GATE is set;
//! setup itself is already restricted to the pinned disposable guest.
//!
//! With PIVSETUP_TEST_GATE=PREFIX:
//! - before the native SETUP ioctl, write PREFIX-ready.json (control path,
//!   generation, hex context) and wait until PREFIX-gate exists;
//! - after it returns, write PREFIX-setup.json (ioctl seconds, errno,
//!   interrupted, kernel status) and, if PIVSETUP_TEST_HOLD=1, wait until
//!   PREFIX-continue exists. Tests snapshot kprobe counters around the ioctl.
//!
//! PIVSETUP_TEST_FAIL=POINT injects an EIO failure (to exercise cleanup) at
//! one of: after-cryptsetup-open, before-setup, after-setup, first-view,
//! second-view.

use std::path::PathBuf;
use std::time::Duration;

use crate::error::{Error, Result};
use crate::ioctl::{FillCounts, KernelDevice};
use crate::signals;

pub fn fail(point: &str) -> Result<()> {
    if std::env::var("PIVSETUP_TEST_FAIL").as_deref() == Ok(point) {
        return Err(Error::os(libc::EIO, format!("Injected test failure: {point}")));
    }
    Ok(())
}

fn prefix() -> Option<String> {
    std::env::var("PIVSETUP_TEST_GATE").ok().filter(|p| !p.is_empty())
}

fn write_json(path: &str, text: &str) -> Result<()> {
    let temporary = format!("{path}.partial");
    std::fs::write(&temporary, text)?;
    std::fs::rename(&temporary, path)?;
    Ok(())
}

fn wait_for(path: &str) -> Result<()> {
    let path = PathBuf::from(path);
    while !path.exists() {
        signals::check()?;
        std::thread::sleep(Duration::from_millis(5));
    }
    Ok(())
}

fn json_string(value: &str) -> String {
    let mut out = String::from("\"");
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

pub fn before_setup(device: &KernelDevice, identity: &[u8]) -> Result<()> {
    let Some(prefix) = prefix() else { return Ok(()) };
    let context: String = identity.iter().map(|b| format!("{b:02x}")).collect();
    write_json(&format!("{prefix}-ready.json"), &format!(
        "{{\"control\": {}, \"generation\": {}, \"context\": \"{context}\", \"pid\": {}}}\n",
        json_string(&device.control_path.to_string_lossy()), device.generation, std::process::id()))?;
    wait_for(&format!("{prefix}-gate"))
}

pub fn after_setup(device: &KernelDevice, elapsed: Duration, result: &Result<FillCounts>, interrupted: bool) {
    let Some(prefix) = prefix() else { return };
    let errno = match result {
        Ok(_) => "null".to_string(),
        Err(error) => error.errno.map_or("null".to_string(), |e| e.to_string()),
    };
    let status = match device.status() {
        Ok(s) => format!(
            "{{\"active\": {}, \"views\": {}, \"failed\": {}, \"hidden_bytes\": {}, \"encryptions\": {}}}",
            s.active, s.views, s.failed, s.hidden_bytes, s.encryptions),
        Err(_) => "null".to_string(),
    };
    let _ = write_json(&format!("{prefix}-setup.json"), &format!(
        "{{\"seconds\": {:.6}, \"errno\": {errno}, \"interrupted\": {interrupted}, \"status\": {status}}}\n",
        elapsed.as_secs_f64()));
    if std::env::var("PIVSETUP_TEST_HOLD").as_deref() == Ok("1") {
        // Cancellation during the hold must not skip cleanup; ignore it here.
        let path = PathBuf::from(format!("{prefix}-continue"));
        while !path.exists() {
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}
