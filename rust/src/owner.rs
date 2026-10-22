//! Private owner lifecycle (pivstore/kernel_owner.py GuestOwner): guest guard,
//! LUKS/integrity validation, exclusive /run lock, ordinary cryptsetup open,
//! reload as piv-crypt with piv_control, control binding and identity checks.

use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};

use crate::bail;
use crate::cmd::{self, crypt, dm, dm_ok};
use crate::error::{Error, Result};
use crate::ioctl::{valid_piv_name, KernelDevice};
use crate::json;
use crate::profile::{self, Layout};

pub const PINNED_KERNEL: &str = "6.12.113+deb13-amd64";
/// Sanitizer build of the same source; accepted only on a guest image that
/// scripts/build_debug_kernel.py explicitly marked with /etc/piv-debug-kernel.
pub const DEBUG_KERNEL: &str = "6.12.113+deb13-amd64-pivdbg";
/// Newer-kernel port target (Debian trixie-backports); accepted only on a guest
/// image that scripts/build_port_image.py explicitly marked with /etc/piv-port-kernel.
pub const PORT_KERNEL: &str = "7.2.9+deb13-amd64";
const MIB: u64 = 1024 * 1024;

fn pinned_release(release: &str) -> bool {
    release == PINNED_KERNEL
        || (release == DEBUG_KERNEL && Path::new("/etc/piv-debug-kernel").exists())
        || (release == PORT_KERNEL && Path::new("/etc/piv-port-kernel").exists())
}

/// (major, minor, DM UUID) of a mapping, without reading any key-containing table.
pub type Identity = (String, String, String);

pub fn mapping_identity(name: &str) -> Result<Option<Identity>> {
    let output = dm(&["info", "-c", "--noheadings", "--separator", ",", "-o", "major,minor,uuid", name], None, false)?;
    if output.status != 0 {
        return Ok(None);
    }
    let fields: Vec<String> = output.stdout.trim().split(',').map(|f| f.trim().to_string()).collect();
    let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    if fields.len() != 3 || !digits(&fields[0]) || !digits(&fields[1]) {
        bail!("Invalid mapping identity");
    }
    Ok(Some((fields[0].clone(), fields[1].clone(), fields[2].clone())))
}

pub fn remove_mapping(name: &str, identity: &Identity, discard: bool) -> Result<()> {
    let Some(current) = mapping_identity(name)? else { return Ok(()) };
    if &current != identity {
        bail!("Refusing to remove changed mapping {name}");
    }
    if discard {
        // Failed private setup only: drain queued probes without exposing data.
        // The captured identity was checked above; normal close never uses this.
        dm_ok(&["wipe_table", "--noflush", name])?;
    }
    dm_ok(&["remove", "--retry", name]).map(|_| ())
}

fn uname_release() -> String {
    // SAFETY: uname into a zeroed struct.
    let mut info: libc::utsname = unsafe { std::mem::zeroed() };
    if unsafe { libc::uname(&mut info) } != 0 {
        return String::new();
    }
    let bytes: Vec<u8> = info.release.iter().take_while(|&&c| c != 0).map(|&c| c as u8).collect();
    String::from_utf8_lossy(&bytes).into_owned()
}

/// Explicit test-guest device opt-ins beyond the default /dev/vdb.
#[derive(Debug, Clone, Copy, Default)]
pub struct Allow {
    /// The dm-delay/dm-flakey test stack over /dev/vdb.
    pub test_stack: bool,
    /// The pinned guest's second disposable disk (/dev/vdc), for migration tests.
    pub second_disk: bool,
}

/// Restrict privileged setup to the pinned disposable QEMU guest and its
/// explicitly supported 128/512 MiB /dev/vdb (or the opted-in test devices).
pub fn guest_guard(source: &Path, allow: Allow) -> Result<u64> {
    // SAFETY: geteuid has no preconditions.
    let euid = unsafe { libc::geteuid() };
    let vendor = fs::read_to_string("/sys/class/dmi/id/sys_vendor").unwrap_or_default();
    if euid != 0 || !pinned_release(&uname_release()) || vendor.trim() != "QEMU" {
        bail!("Kernel setup is restricted to the pinned disposable QEMU guest");
    }
    let mut allowed = vec!["/dev/vdb"];
    if allow.test_stack {
        allowed.extend(["/dev/mapper/piv-test-delay", "/dev/mapper/piv-test-fault"]);
    }
    if allow.second_disk {
        allowed.push("/dev/vdc");
    }
    let is_block = fs::metadata(source).map(|m| m.file_type().is_block_device()).unwrap_or(false);
    if !allowed.iter().any(|a| source.as_os_str().as_bytes() == a.as_bytes()) || !is_block {
        bail!("Unsupported disposable test device");
    }
    let size: u64 = cmd::run("blockdev", &["--getsize64", path_str(source)?])?.trim().parse()
        .map_err(|_| Error::new("Invalid device size"))?;
    if size != 128 * MIB && size != 512 * MIB {
        bail!("Expected an explicitly supported 128 or 512 MiB disposable guest disk");
    }
    Ok(size)
}

pub fn path_str(path: &Path) -> Result<&str> {
    path.to_str().ok_or_else(|| Error::new("Non-UTF-8 path"))
}

fn holders(major: u32, minor: u32) -> Result<Vec<String>> {
    let mut names = Vec::new();
    for entry in fs::read_dir(format!("/sys/dev/block/{major}:{minor}/holders"))? {
        names.push(entry?.file_name().to_string_lossy().into_owned());
    }
    Ok(names)
}

pub struct GuestOwner {
    lock: Option<fs::File>,
    pub device: Option<KernelDevice>,
    pub created: bool,
    mappings: Vec<(String, Identity)>,
    pub name: String,
    lower_name: String,
    pub source: PathBuf,
    pub uuid: String,
    pub layout: Layout,
    offset: u64,
    /// Integrity tag bytes of the LUKS profile (16 AEGIS, 32 HMAC-SHA256).
    profile_tag: u64,
    mapping_cipher: &'static str,
    raw_major: u32,
    raw_minor: u32,
    lower_table: String,
}

impl GuestOwner {
    pub fn open(source: &Path, passphrase_file: &Path, name: &str, allow: Allow) -> Result<Self> {
        if !valid_piv_name(name, 40) {
            bail!("Invalid experimental mapping name");
        }
        let raw_bytes = guest_guard(source, allow)?;
        let source_text = path_str(source)?;
        let metadata = json::parse(&crypt(&["luksDump", "--dump-json-metadata", source_text])?)
            .map_err(|e| Error::new(format!("Invalid LUKS2 metadata: {e}")))?;
        let offset = profile::validate_segment(&metadata)?;
        profile::check_activation_flags(&metadata)?;
        let segment = metadata.get("segments").and_then(|s| s.get("0")).expect("validated segment");
        let encryption = segment.get("encryption").and_then(json::Value::as_str).expect("validated").to_string();
        let luks_sector = segment.get("sector_size").and_then(json::Value::as_u64).expect("validated");
        let integrity = segment.get("integrity").and_then(|i| i.get("type")).and_then(json::Value::as_str)
            .expect("validated").to_string();
        let (mapping_cipher, profile_tag) = profile::profile(&encryption, &integrity).expect("validated profile");
        let uuid = canonical_uuid(crypt(&["luksUUID", source_text])?.trim())?;
        let rdev = fs::metadata(source)?.rdev();
        let mut owner = GuestOwner {
            lock: None, device: None, created: false, mappings: Vec::new(), name: name.to_string(),
            lower_name: format!("{name}_dif"), source: source.to_path_buf(), uuid,
            layout: Layout { integrity_offset: 0, primary_bytes: 0, journal_sections: 0, journal_section_sectors: 0,
                             initial_sectors: 0, metadata_run_sectors: 0, interleave_sectors: 0, sector_size: 512,
                             tag_bytes: 16, iv_bytes: 12 },
            offset, mapping_cipher, profile_tag, raw_major: libc::major(rdev), raw_minor: libc::minor(rdev),
            lower_table: String::new(),
        };
        match owner.establish(&encryption, luks_sector, raw_bytes, passphrase_file) {
            Ok(()) => Ok(owner),
            Err(mut error) => {
                if owner.created {
                    if let Err(cleanup) = owner.remove(true) {
                        error.note(format!("Private mapping cleanup incomplete: {cleanup}"));
                    }
                }
                owner.close();
                Err(error)
            }
        }
    }

    fn establish(&mut self, encryption: &str, luks_sector: u64, raw_bytes: u64, passphrase_file: &Path) -> Result<()> {
        let directory = Path::new("/run/pivstore");
        if let Err(e) = fs::DirBuilder::new().mode(0o700).create(directory) {
            if e.kind() != std::io::ErrorKind::AlreadyExists {
                return Err(e.into());
            }
        }
        let info = fs::symlink_metadata(directory)?;
        if !info.file_type().is_dir() || info.permissions().mode() & 0o077 != 0 {
            bail!("Invalid global owner-lock directory");
        }
        let lock = fs::OpenOptions::new().read(true).write(true).create(true).mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(directory.join(format!("{}.lock", self.uuid)))?;
        let info = lock.metadata()?;
        if !info.file_type().is_file() || info.nlink() != 1 {
            bail!("Invalid global owner lock");
        }
        // SAFETY: flock on our own open descriptor.
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(Error::last_os("Owner lock"));
        }
        self.lock = Some(lock);
        // Only static format fields: live journal recovery belongs to Linux.
        let raw = fs::File::open(&self.source)?;
        let mut header = vec![0u8; 4096];
        read_exact_at(&raw, &mut header, self.offset)?;
        drop(raw);
        self.layout = profile::parse_superblock(&header, self.offset, raw_bytes)?;
        if self.layout.iv_bytes != 16 || self.layout.tag_bytes != self.profile_tag {
            bail!("LUKS profile ({encryption}) and integrity tuple size disagree");
        }
        if self.layout.sector_size != luks_sector {
            bail!("LUKS and integrity sector sizes disagree");
        }
        let name = self.name.clone();
        let existing = dm(&["info", &name], None, false)?.status == 0;
        if !existing {
            if mapping_identity(&self.lower_name)?.is_some() {
                return Err(Error::os(libc::EEXIST, "Lower mapping name is already in use"));
            }
            if !holders(self.raw_major, self.raw_minor)?.is_empty() {
                bail!("Disposable device already has an independent mapping");
            }
            self.created = true;
            let opened = crypt(&["open", "--disable-keyring", "--key-file", path_str(passphrase_file)?,
                                 path_str(&self.source)?, &name]);
            // A command can fail after the kernel created a mapping.
            let captured = self.capture_created();
            opened?;
            captured?;
            crate::hooks::fail("after-cryptsetup-open")?;
            if self.mappings.len() != 2 {
                bail!("Created mapping identity is missing");
            }
            let owner_size: u64 = cmd::run("blockdev", &["--getsize64", &format!("/dev/mapper/{name}")])?
                .trim().parse().map_err(|_| Error::new("Invalid owner size"))?;
            let table = dm_ok(&["table", &self.lower_name])?;
            self.check_integrity_table(&table, owner_size / self.layout.sector_size)?;
            self.reload_as_owner()?;
        }
        let expected_uuid = format!("CRYPT-LUKS2-{}-{}", self.uuid.replace('-', ""), name);
        if dm_ok(&["info", "-c", "--noheadings", "-o", "uuid", &name])?.trim() != expected_uuid {
            bail!("Mapping does not belong to this disposable LUKS volume");
        }
        if self.mappings.is_empty() {
            for mapping in [name.clone(), self.lower_name.clone()] {
                let identity = mapping_identity(&mapping)?.ok_or_else(|| Error::new("Mapping disappeared"))?;
                self.mappings.push((mapping, identity));
            }
        }
        dm_ok(&["mknodes", &name])?;
        let owner_path = PathBuf::from(format!("/dev/mapper/{name}"));
        let mut matches = Vec::new();
        for entry in fs::read_dir("/dev")? {
            let entry = entry?;
            if entry.file_name().as_bytes().starts_with(b"pivctl-") {
                // Controls bound to other owners are skipped (ValueError in Python).
                if let Ok(device) = KernelDevice::open(&entry.path(), &owner_path) {
                    matches.push(device);
                }
            }
        }
        if matches.len() != 1 {
            bail!("Expected exactly one native control for owner");
        }
        self.device = matches.pop();
        self.lower_table = dm_ok(&["table", &self.lower_name])?;
        self.validate()
    }

    /// Key-containing table is kept in locked memory and sent only via stdin.
    fn reload_as_owner(&self) -> Result<()> {
        let table = cmd::dm_table_with_keys(&self.name)?;
        let text = std::str::from_utf8(&table).map_err(|_| Error::new("Invalid primary table"))?;
        let fields: Vec<&str> = text.split_whitespace().collect();
        if fields.len() < 9 || fields[2..4] != ["crypt", self.mapping_cipher] {
            bail!("Unexpected primary mapping cipher");
        }
        let count: u64 = fields[8].parse().map_err(|_| Error::new("Unexpected primary mapping options"))?;
        let mut replacement = crate::secret::Secret::with_capacity(table.len() + 64);
        for (i, field) in fields.iter().enumerate() {
            if i > 0 {
                replacement.push(b" ")?;
            }
            match i {
                2 => replacement.push(b"piv-crypt")?,
                8 => replacement.push((count + 1).to_string().as_bytes())?,
                _ => replacement.push(field.as_bytes())?,
            }
        }
        replacement.push(b" piv_control\n")?;
        dm_ok(&["suspend", &self.name])?;
        dm(&["reload", &self.name], Some(&replacement), true)?;
        dm_ok(&["resume", &self.name])?;
        Ok(())
    }

    fn capture_created(&mut self) -> Result<()> {
        let expected = format!("CRYPT-LUKS2-{}-{}", self.uuid.replace('-', ""), self.name);
        for mapping in [self.name.clone(), self.lower_name.clone()] {
            let Some(identity) = mapping_identity(&mapping)? else { continue };
            if mapping == self.name {
                if identity.2 != expected {
                    continue;
                }
            } else {
                let table = dm_ok(&["table", &mapping])?;
                let words: Vec<&str> = table.split_whitespace().collect();
                let device = format!("{}:{}", self.raw_major, self.raw_minor);
                let start = (self.offset / 512).to_string();
                if !identity.2.starts_with("CRYPT-INTEGRITY-") || !identity.2.ends_with(&format!("-{}", self.lower_name))
                    || words.len() < 7 || words[2..5] != ["integrity", device.as_str(), start.as_str()] {
                    continue;
                }
            }
            self.mappings.retain(|(name, _)| name != &mapping);
            self.mappings.push((mapping, identity));
        }
        Ok(())
    }

    fn check_integrity_table(&self, table: &str, sectors: u64) -> Result<()> {
        profile::validate_integrity_table(table, sectors, self.raw_major, self.raw_minor, self.offset,
                                          self.layout.sector_size,
                                          self.layout.journal_sections * self.layout.journal_section_sectors,
                                          self.layout.tuple_bytes())
    }

    pub fn device(&self) -> &KernelDevice {
        self.device.as_ref().expect("bound control")
    }

    pub fn validate(&self) -> Result<()> {
        let device = self.device();
        device.check()?;
        let table = dm_ok(&["table", &self.name])?;
        if table.split_whitespace().skip(2).take(2).ne(["piv-crypt", self.mapping_cipher]) {
            bail!("Primary mapping cipher differs from LUKS metadata");
        }
        if (device.sectors, device.sector_size, device.iv_size, device.tuple_size)
            != (self.layout.sectors(), self.layout.sector_size, self.layout.iv_bytes, self.layout.tuple_bytes()) {
            bail!("Native geometry differs from supported superblock");
        }
        let lower = dm_ok(&["table", &self.lower_name])?;
        if lower != self.lower_table {
            bail!("Lower integrity mapping changed outside owner");
        }
        self.check_integrity_table(&lower, device.sectors)?;
        let lower_dev = fs::metadata(format!("/dev/mapper/{}", self.lower_name))?.rdev();
        if lower_dev != device.lower_device {
            bail!("Native control bound to unexpected lower device");
        }
        let lower_sys = fs::canonicalize(format!("/sys/dev/block/{}:{}", libc::major(lower_dev), libc::minor(lower_dev)))?;
        let lower_name = lower_sys.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        if holders(self.raw_major, self.raw_minor)? != [lower_name] {
            bail!("Unexpected independent holder of backing storage");
        }
        Ok(())
    }

    pub fn remove(&mut self, abort: bool) -> Result<()> {
        if abort && !self.created {
            bail!("Cannot discard an owner created by another attempt");
        }
        if let Some(device) = self.device.as_mut() {
            device.close();
        }
        for name in [self.name.clone(), self.lower_name.clone()] {
            if let Some((_, identity)) = self.mappings.iter().find(|(n, _)| n == &name).cloned() {
                remove_mapping(&name, &identity, abort && name == self.name)?;
            }
        }
        Ok(())
    }

    pub fn close(&mut self) {
        if let Some(device) = self.device.as_mut() {
            device.close();
        }
        self.lock = None;
    }
}

impl Drop for GuestOwner {
    fn drop(&mut self) {
        self.close();
    }
}

fn read_exact_at(file: &fs::File, buf: &mut [u8], offset: u64) -> Result<()> {
    use std::os::unix::fs::FileExt;
    file.read_exact_at(buf, offset).map_err(Error::from)
}

/// Python's str(uuid.UUID(text)): lower-case canonical 8-4-4-4-12 form.
pub fn canonical_uuid(text: &str) -> Result<String> {
    let hex: String = text.trim_start_matches("urn:").trim_start_matches("uuid:")
        .trim_matches(['{', '}']).chars().filter(|&c| c != '-').collect();
    if hex.len() != 32 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("Invalid LUKS UUID");
    }
    let h = hex.to_ascii_lowercase();
    Ok(format!("{}-{}-{}-{}-{}", &h[0..8], &h[8..12], &h[12..16], &h[16..20], &h[20..32]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uuid_canonical_form() {
        assert_eq!(canonical_uuid("0F1E2D3C-4B5A-4978-8695-A4B3C2D1E0F0").unwrap(),
                   "0f1e2d3c-4b5a-4978-8695-a4b3c2d1e0f0");
        assert!(canonical_uuid("not-a-uuid").is_err());
    }
}
