//! dm-piv control ABI (kernel/piv-control.h), packed exactly like the Python
//! struct formats with native (x86-64 little-endian) layout and no padding.

use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Path, PathBuf};

use zeroize::Zeroize;

use crate::bail;
use crate::cmd;
use crate::error::{Error, Result};

const DIR_WRITE: u64 = 1;
const DIR_READ: u64 = 2;

/// `piv-` followed by 1..=max characters of [A-Za-z0-9_-].
pub fn valid_piv_name(name: &str, max: usize) -> bool {
    let Some(rest) = name.strip_prefix("piv-") else { return false };
    !rest.is_empty() && rest.len() <= max && rest.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

pub fn command(number: u64, size: u64, direction: u64) -> u64 {
    direction << 30 | size << 16 | (b'P' as u64) << 8 | number
}

pub const QUERY_SIZE: usize = 48; // '=IIQQIIIIII'
pub const READ_SIZE: usize = 48; // '=IIQQ16sII'
pub const SETUP_SIZE: usize = 216; // '=IIQII32s128sIIQQQ'
pub const STATUS_SIZE: usize = 40; // '=QQQIIII' (STATUS version 4)
pub const KEYSLOT_SIZE: usize = 96; // '=IIQII32s32s2I' (KEYSLOT version 2)

/// SETUP ABI 6 (format v5 only): destructive initialization.
pub const SETUP_INITIALIZE: u32 = 1;
/// With SETUP_INITIALIZE: A/B record slots.
pub const SETUP_AB: u32 = 8;
/// Full audit: authenticate every primary sector at setup (else keyslot area only).
pub const SETUP_VERIFY: u32 = 16;
/// With SETUP_INITIALIZE: keyslot 0 and the directory only, no records.
pub const SETUP_QUICK: u32 = 32;
/// Without SETUP_INITIALIZE: zero records into every block whose record does
/// not authenticate (destructive for damaged blocks).
pub const SETUP_FILL: u32 = 64;
pub const KEYSLOT_ADD: u32 = 1;
pub const KEYSLOT_REMOVE: u32 = 2;

fn u32_at(b: &[u8], at: usize) -> u32 { u32::from_le_bytes(b[at..at + 4].try_into().unwrap()) }
fn u64_at(b: &[u8], at: usize) -> u64 { u64::from_le_bytes(b[at..at + 8].try_into().unwrap()) }

fn ioctl(fd: libc::c_int, request: u64, data: &mut [u8]) -> Result<()> {
    // SAFETY: data is a live, writable buffer of exactly the size encoded in
    // the request; the kernel copies at most that many bytes either way.
    let r = unsafe { libc::ioctl(fd, request as libc::c_ulong, data.as_mut_ptr()) };
    if r < 0 {
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(libc::EIO);
        return Err(Error::os(errno, std::io::Error::from_raw_os_error(errno).to_string()));
    }
    Ok(())
}

/// SETUP_FILL output: blocks already authenticated (skipped), given a zero
/// record, and left as they were (carrier unreadable or failing authentication).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FillCounts {
    pub valid: u64,
    pub written: u64,
    pub failed: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Status {
    pub generation: u64,
    pub hidden_bytes: u64,
    pub encryptions: u64,
    pub active: bool,
    pub views: u32,
    pub failed: bool,
}

pub struct KernelDevice {
    fd: libc::c_int,
    pub control_path: PathBuf,
    pub owner: PathBuf,
    pub name: String,
    pub generation: u64,
    pub sectors: u64,
    pub sector_size: u64,
    pub iv_size: u64,
    pub tuple_size: u64,
    pub flags: u32,
    pub lower_device: libc::dev_t,
}

impl KernelDevice {
    pub fn open(control: &Path, owner: &Path) -> Result<Self> {
        let name = owner.file_name().and_then(|n| n.to_str()).unwrap_or("").to_string();
        if !valid_piv_name(&name, usize::MAX) {
            bail!("Experimental owner must have a piv- name");
        }
        let path = CString::new(control.as_os_str().as_bytes()).map_err(|_| Error::new("Invalid control path"))?;
        // SAFETY: NUL-terminated path; flags only.
        let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDWR | libc::O_NOFOLLOW | libc::O_CLOEXEC) };
        if fd < 0 {
            return Err(Error::last_os(&format!("open {}", control.display())));
        }
        let mut device = KernelDevice {
            fd, control_path: control.to_path_buf(), owner: owner.to_path_buf(), name, generation: 0,
            sectors: 0, sector_size: 0, iv_size: 0, tuple_size: 0, flags: 0, lower_device: 0,
        };
        device.bind()?;
        Ok(device)
    }

    fn bind(&mut self) -> Result<()> {
        // SAFETY: fstat into a zeroed struct for our own descriptor.
        let mut info: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(self.fd, &mut info) } != 0 || info.st_mode & libc::S_IFMT != libc::S_IFCHR {
            bail!("Control must be a character device");
        }
        let q = self.query()?;
        let (version, size) = (u32_at(&q, 0), u32_at(&q, 4));
        let (sector, iv, tag, tuple, flags, reserved) =
            (u32_at(&q, 24), u32_at(&q, 28), u32_at(&q, 32), u32_at(&q, 36), u32_at(&q, 40), u32_at(&q, 44));
        if (version, size, reserved) != (2, 48, 0) || !matches!(tag, 16 | 20 | 32 | 64) || iv != 16
            || tuple != tag + iv
            || !(sector == 512 || sector == 4096) || flags != 0 {
            bail!("Unsupported kernel control/profile");
        }
        let mut devices = [0u8; 16];
        ioctl(self.fd, command(7, 16, DIR_READ), &mut devices)?;
        let (major, minor) = (u32_at(&devices, 0), u32_at(&devices, 4));
        let (low_major, low_minor) = (u32_at(&devices, 8), u32_at(&devices, 12));
        let meta = std::fs::metadata(&self.owner)?;
        if !meta.file_type().is_block_device() || meta.rdev() != libc::makedev(major, minor) {
            bail!("Control is bound to a different owner");
        }
        self.generation = u64_at(&q, 8);
        self.sectors = u64_at(&q, 16);
        self.sector_size = sector as u64;
        self.iv_size = iv as u64;
        self.tuple_size = tuple as u64;
        self.flags = flags;
        self.lower_device = libc::makedev(low_major, low_minor);
        Ok(())
    }

    fn query(&self) -> Result<[u8; QUERY_SIZE]> {
        let mut q = [0u8; QUERY_SIZE];
        ioctl(self.fd, command(0, QUERY_SIZE as u64, DIR_READ), &mut q)?;
        Ok(q)
    }

    pub fn check(&self) -> Result<()> {
        let q = self.query()?;
        if u64_at(&q, 8) != self.generation || u64_at(&q, 16) != self.sectors || u32_at(&q, 40) != self.flags {
            return Err(Error::os(libc::ESTALE, "Kernel owner changed"));
        }
        Ok(())
    }

    /// The 48-byte generation-bound request header used by lifecycle commands.
    pub fn request(&self) -> [u8; READ_SIZE] {
        let mut data = [0u8; READ_SIZE];
        data[0..4].copy_from_slice(&2u32.to_le_bytes());
        data[4..8].copy_from_slice(&(READ_SIZE as u32).to_le_bytes());
        data[8..16].copy_from_slice(&self.generation.to_le_bytes());
        data
    }

    pub fn begin(&self) -> Result<()> {
        ioctl(self.fd, command(5, READ_SIZE as u64, DIR_WRITE), &mut self.request())
    }

    pub fn detach(&self) -> Result<()> {
        ioctl(self.fd, command(13, READ_SIZE as u64, DIR_WRITE), &mut self.request())
    }

    pub fn status(&self) -> Result<Status> {
        let mut data = [0u8; STATUS_SIZE];
        ioctl(self.fd, command(14, STATUS_SIZE as u64, DIR_READ), &mut data)?;
        let status = Status {
            generation: u64_at(&data, 0), hidden_bytes: u64_at(&data, 8), encryptions: u64_at(&data, 16),
            active: u32_at(&data, 24) != 0, views: u32_at(&data, 28), failed: u32_at(&data, 32) != 0,
        };
        if status.generation != self.generation || u32_at(&data, 36) != 4 {
            bail!("Unsupported native status ABI");
        }
        Ok(status)
    }

    /// ABI 6 SETUP (@parity: RS parity fragments per lane, initialization
    /// only). The request (with the key) is wiped whatever happens. Returns
    /// the fill counts the kernel copies back (zero without SETUP_FILL).
    pub fn setup(&self, hidden_key: &[u8], identity: &[u8], flags: u32, parity: u32) -> Result<FillCounts> {
        if hidden_key.len() != 32 || identity.len() != crate::profile::BASE_CONTEXT_LENGTH {
            bail!("Invalid native key/context size");
        }
        let mut data = [0u8; SETUP_SIZE];
        data[0..4].copy_from_slice(&6u32.to_le_bytes());
        data[4..8].copy_from_slice(&(SETUP_SIZE as u32).to_le_bytes());
        data[8..16].copy_from_slice(&self.generation.to_le_bytes());
        data[16..20].copy_from_slice(&flags.to_le_bytes());
        data[20..24].copy_from_slice(&(identity.len() as u32).to_le_bytes());
        data[24..56].copy_from_slice(hidden_key);
        data[56..56 + identity.len()].copy_from_slice(identity);
        data[184..188].copy_from_slice(&parity.to_le_bytes());
        // SAFETY: lock the stack copy of the key for the ioctl's duration.
        let locked = unsafe { libc::mlock(data.as_ptr().cast(), data.len()) } == 0;
        let result = ioctl(self.fd, command(12, SETUP_SIZE as u64, DIR_READ | DIR_WRITE), &mut data)
            .map(|()| FillCounts { valid: u64_at(&data, 192), written: u64_at(&data, 200), failed: u64_at(&data, 208) });
        data.zeroize();
        if locked {
            unsafe { libc::munlock(data.as_ptr().cast(), data.len()) };
        }
        result
    }

    /// Add (kek given) or remove keyslot @slot on an active v5 owner,
    /// authorized by @auth, the current KEK of a listed keyslot (KEYSLOT
    /// version 2). The request (with both keys) is wiped whatever happens.
    pub fn keyslot(&self, slot: u32, kek: Option<&[u8]>, auth: &[u8]) -> Result<()> {
        if slot >= 4 || kek.is_some_and(|k| k.len() != 32) || auth.len() != 32 {
            bail!("Invalid keyslot request");
        }
        let mut data = [0u8; KEYSLOT_SIZE];
        data[0..4].copy_from_slice(&2u32.to_le_bytes());
        data[4..8].copy_from_slice(&(KEYSLOT_SIZE as u32).to_le_bytes());
        data[8..16].copy_from_slice(&self.generation.to_le_bytes());
        data[16..20].copy_from_slice(&slot.to_le_bytes());
        data[20..24].copy_from_slice(&(if kek.is_some() { KEYSLOT_ADD } else { KEYSLOT_REMOVE }).to_le_bytes());
        if let Some(kek) = kek {
            data[24..56].copy_from_slice(kek);
        }
        data[56..88].copy_from_slice(auth);
        // SAFETY: lock the stack copy of the keys for the ioctl's duration.
        let locked = unsafe { libc::mlock(data.as_ptr().cast(), data.len()) } == 0;
        let result = ioctl(self.fd, command(15, KEYSLOT_SIZE as u64, DIR_WRITE), &mut data);
        data.zeroize();
        if locked {
            unsafe { libc::munlock(data.as_ptr().cast(), data.len()) };
        }
        result
    }

    pub fn suspend(&self) -> Result<()> {
        cmd::dm(&["suspend", &self.name], None, true).map(|_| ())
    }

    pub fn resume(&self) -> Result<()> {
        cmd::dm(&["resume", &self.name], None, true).map(|_| ())
    }

    pub fn close(&mut self) {
        if self.fd >= 0 {
            // SAFETY: closing our own descriptor exactly once.
            unsafe { libc::close(self.fd) };
            self.fd = -1;
        }
    }
}

impl Drop for KernelDevice {
    fn drop(&mut self) {
        self.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_numbers_match_python() {
        // pivstore.kernel_api.command(number, size, direction)
        assert_eq!(command(12, 216, 3), 0xc0d8_500c);
        assert_eq!(command(14, 48, 2), 0x8030_500e);
        assert_eq!(command(0, 48, 2), 0x8030_5000);
        assert_eq!(command(15, 96, 1), 0x4060_500f);
    }

    #[test]
    fn names() {
        assert!(valid_piv_name("piv-native", 40));
        assert!(!valid_piv_name("piv-", 40));
        assert!(!valid_piv_name("native", 40));
        assert!(!valid_piv_name("piv-a/b", 40));
        assert!(!valid_piv_name(&format!("piv-{}", "a".repeat(41)), 40));
    }
}
