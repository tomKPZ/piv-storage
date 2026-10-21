//! Key buffers: page-locked where possible and zeroized on drop.

use std::fs::File;
use std::io::Read;
use std::ops::{Deref, DerefMut};
use std::path::Path;

use zeroize::Zeroize;

use crate::error::{Error, Result};

/// Heap buffer with a fixed capacity (never reallocated, so no stale copies),
/// mlock()ed best-effort and wiped on drop.
pub struct Secret {
    data: Box<[u8]>,
    len: usize,
    locked: bool,
}

impl Secret {
    pub fn with_capacity(capacity: usize) -> Self {
        let data = vec![0u8; capacity.max(1)].into_boxed_slice();
        // SAFETY: data is a live allocation of the given length.
        let locked = unsafe { libc::mlock(data.as_ptr().cast(), data.len()) } == 0;
        Secret { data, len: 0, locked }
    }

    /// Read at most `limit` bytes (like Python's `read(limit)`), straight into
    /// locked memory. A caller checks the length, e.g. 33 to detect >32 bytes.
    pub fn read_file(path: &Path, limit: usize) -> Result<Self> {
        let mut file = File::open(path).map_err(|e| Error::from(e))?;
        let mut secret = Secret::with_capacity(limit);
        while secret.len < limit {
            match file.read(&mut secret.data[secret.len..limit]) {
                Ok(0) => break,
                Ok(n) => secret.len += n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e.into()),
            }
        }
        Ok(secret)
    }

    pub fn truncate(&mut self, len: usize) {
        if len < self.len {
            self.data[len..self.len].zeroize();
            self.len = len;
        }
    }

    pub fn push(&mut self, bytes: &[u8]) -> Result<()> {
        let end = self.len.checked_add(bytes.len()).filter(|&e| e <= self.data.len());
        let end = end.ok_or_else(|| Error::new("Secret buffer capacity exceeded"))?;
        self.data[self.len..end].copy_from_slice(bytes);
        self.len = end;
        Ok(())
    }
}

impl Deref for Secret {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.data[..self.len]
    }
}

impl DerefMut for Secret {
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.data[..self.len]
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        self.data.zeroize();
        if self.locked {
            // SAFETY: unlocking the same live allocation locked in with_capacity.
            unsafe { libc::munlock(self.data.as_ptr().cast(), self.data.len()) };
        }
    }
}

/// Keep keys out of core dumps and ptrace by non-root peers.
pub fn harden_process() {
    // SAFETY: plain prctl/setrlimit calls without pointers to Rust memory.
    unsafe {
        libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
        let none = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        libc::setrlimit(libc::RLIMIT_CORE, &none);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_read_and_truncate() {
        let dir = std::env::temp_dir().join(format!("pivsetup-secret-{}", std::process::id()));
        std::fs::write(&dir, [7u8; 40]).unwrap();
        let mut secret = Secret::read_file(&dir, 33).unwrap();
        std::fs::remove_file(&dir).unwrap();
        assert_eq!(secret.len(), 33);
        secret.truncate(32);
        assert_eq!(&secret[..], &[7u8; 32][..]);
        assert!(secret.push(&[1]).is_ok());
        assert!(secret.push(&[3]).is_err());
    }
}
