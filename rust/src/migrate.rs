//! Offline migration into a freshly formatted, initialized target volume.
//!
//! This one workflow provides primary rekey (a new LUKS volume key), resize
//! and sector-size change: both views of a format v4 source on any supported profile
//! are copied into the matching views of a new format v4 target, then
//! re-read from both devices with O_DIRECT and compared byte for byte. The
//! target hidden volume is destructively initialized first. Source contents
//! are only read (activation still writes ordinary journal metadata); the
//! caller retires the source. Migration is not atomic and not resumable:
//! after a failure, reformat the target and start again.

use std::alloc::{alloc_zeroed, dealloc, Layout};
use std::fs::{File, OpenOptions as FileOptions};
use std::os::unix::fs::{FileExt, OpenOptionsExt};
use std::path::Path;

use zeroize::Zeroize;

use crate::bail;
use crate::blocks::{close_blocks, open_blocks, HiddenSecret, OpenOptions, Views};
use crate::error::{Error, Result};
use crate::owner::{path_str, Allow};
use crate::signals;

const CHUNK: usize = 1 << 20;
const ALIGN: usize = 4096;
pub const SOURCE_NAME: &str = "piv-src";
pub const TARGET_NAME: &str = "piv-dst";

/// O_DIRECT-aligned copy buffer holding (possibly hidden) plaintext:
/// mlock()ed best-effort and wiped on drop.
struct Buffer {
    ptr: *mut u8,
    layout: Layout,
    locked: bool,
}

impl Buffer {
    fn new() -> Result<Self> {
        let layout = Layout::from_size_align(CHUNK, ALIGN).map_err(|_| Error::new("Invalid buffer layout"))?;
        // SAFETY: layout has a non-zero size.
        let ptr = unsafe { alloc_zeroed(layout) };
        if ptr.is_null() {
            bail!("Out of memory");
        }
        // SAFETY: ptr is a live allocation of CHUNK bytes.
        let locked = unsafe { libc::mlock(ptr.cast(), CHUNK) } == 0;
        Ok(Buffer { ptr, layout, locked })
    }

    fn slice(&mut self, len: usize) -> &mut [u8] {
        assert!(len <= CHUNK);
        // SAFETY: ptr is a live, exclusively borrowed allocation of CHUNK bytes.
        unsafe { std::slice::from_raw_parts_mut(self.ptr, len) }
    }
}

impl Drop for Buffer {
    fn drop(&mut self) {
        self.slice(CHUNK).zeroize();
        // SAFETY: unlocking and freeing the allocation made in new().
        unsafe {
            if self.locked {
                libc::munlock(self.ptr.cast(), CHUNK);
            }
            dealloc(self.ptr, self.layout);
        }
    }
}

fn open_direct(path: &str, write: bool) -> Result<File> {
    Ok(FileOptions::new().read(true).write(write).custom_flags(libc::O_DIRECT).open(path)?)
}

fn read_full(file: &File, buf: &mut [u8], offset: u64) -> Result<()> {
    let mut done = 0;
    while done < buf.len() {
        match file.read_at(&mut buf[done..], offset + done as u64) {
            Ok(0) => bail!("Short read during migration"),
            Ok(n) => done += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

fn write_full(file: &File, buf: &[u8], offset: u64) -> Result<()> {
    let mut done = 0;
    while done < buf.len() {
        match file.write_at(&buf[done..], offset + done as u64) {
            Ok(0) => bail!("Short write during migration"),
            Ok(n) => done += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

/// Copy `length` bytes from one view to another, flush, then re-read both
/// with O_DIRECT (bypassing the page cache) and compare byte for byte.
fn copy_view(source: &str, target: &str, length: u64) -> Result<()> {
    if length % 512 != 0 {
        bail!("View size is not a multiple of 512 bytes");
    }
    let (mut a, mut b) = (Buffer::new()?, Buffer::new()?);
    let src = open_direct(source, false)?;
    let dst = open_direct(target, true)?;
    let mut offset = 0u64;
    while offset < length {
        signals::check()?;
        let len = (length - offset).min(CHUNK as u64) as usize;
        let data = a.slice(len);
        read_full(&src, data, offset)?;
        write_full(&dst, data, offset)?;
        offset += len as u64;
    }
    dst.sync_all()?;
    drop(dst);
    let dst = open_direct(target, false)?;
    offset = 0;
    while offset < length {
        signals::check()?;
        let len = (length - offset).min(CHUNK as u64) as usize;
        read_full(&src, a.slice(len), offset)?;
        read_full(&dst, b.slice(len), offset)?;
        if a.slice(len) != b.slice(len) {
            bail!("Verification failed after migration");
        }
        offset += len as u64;
    }
    Ok(())
}

pub struct Report {
    pub decoy_bytes: u64,
    pub decoy_target_bytes: u64,
    pub hidden_bytes: u64,
    pub hidden_target_bytes: u64,
}

fn copy_both(src: &Views, dst: &Views) -> Result<Report> {
    if dst.decoy_bytes < src.decoy_bytes {
        bail!("Target decoy view is smaller than the source");
    }
    if dst.hidden_bytes < src.hidden_bytes {
        bail!("Target hidden view is smaller than the source");
    }
    for (role, from, to, length) in [("decoy", &src.decoy, &dst.decoy, src.decoy_bytes),
                                     ("hidden", &src.hidden, &dst.hidden, src.hidden_bytes)] {
        copy_view(from, to, length).map_err(|mut error| {
            error.note(format!("while migrating the {role} view"));
            error
        })?;
    }
    Ok(Report {
        decoy_bytes: src.decoy_bytes,
        decoy_target_bytes: dst.decoy_bytes,
        hidden_bytes: src.hidden_bytes,
        hidden_target_bytes: dst.hidden_bytes,
    })
}

#[allow(clippy::too_many_arguments)]
pub fn migrate(source: &Path, source_key_file: &Path, source_secret: HiddenSecret,
               target: &Path, target_key_file: &Path, target_secret: HiddenSecret,
               ab: bool, allow: Allow) -> Result<Report> {
    let canonical = |p: &Path| std::fs::canonicalize(p).map_err(Error::from);
    if canonical(source)? == canonical(target)? || path_str(source)? == path_str(target)? {
        bail!("Source and target must be different devices");
    }
    let src = open_blocks(source, source_key_file, source_secret,
                          &OpenOptions { name: SOURCE_NAME, initialize: false, ab: false, verify: false, allow })?;
    let result = (|| {
        let dst = open_blocks(target, target_key_file, target_secret,
                              &OpenOptions { name: TARGET_NAME, initialize: true, ab, verify: false, allow })?;
        let copied = copy_both(&src, &dst);
        let closed = close_blocks(target, target_key_file, TARGET_NAME, allow);
        match (copied, closed) {
            (Ok(report), Ok(())) => Ok(report),
            (Ok(_), Err(error)) => Err(error),
            (Err(mut error), Err(cleanup)) => {
                error.note(format!("Target close failed: {cleanup}"));
                Err(error)
            }
            (Err(error), Ok(())) => Err(error),
        }
    })();
    let closed = close_blocks(source, source_key_file, SOURCE_NAME, allow);
    match (result, closed) {
        (Ok(report), Ok(())) => Ok(report),
        (Ok(_), Err(error)) => Err(error),
        (Err(mut error), Err(cleanup)) => {
            error.note(format!("Source close failed: {cleanup}"));
            Err(error)
        }
        (Err(error), Ok(())) => Err(error),
    }
}
