//! Paired native views (pivstore/blocks.py): open, close and v4 keyslots.

use std::path::Path;

use crate::bail;
use crate::cmd::{dm, dm_ok};
use crate::error::{Error, Result};
use crate::ioctl::{KernelDevice, SETUP_AB, SETUP_INITIALIZE, SETUP_VERIFY};
use crate::owner::{mapping_identity, remove_mapping, Allow, GuestOwner};
use crate::profile::context_v4;
use crate::secret::Secret;
use crate::{hooks, signals};

/// Argon2id parameters (RFC 9106 second recommendation, user decision
/// 2026-10-21): 64 MiB, 3 passes, 4 lanes. Nothing is stored in clear, so
/// they must be identical on every open (pivstore.blocks.ARGON2ID).
const ARGON2_M_KIB: u32 = 64 * 1024;
const ARGON2_T: u32 = 3;
const ARGON2_P: u32 = 4;

pub struct OpenOptions<'a> {
    pub name: &'a str,
    pub initialize: bool,
    pub ab: bool,
    pub verify: bool,
    pub allow: Allow,
}

pub struct Views {
    pub decoy: String,
    pub hidden: String,
    pub decoy_bytes: u64,
    pub hidden_bytes: u64,
}

pub enum HiddenSecret {
    Key(Secret),
    Passphrase(Secret),
}

pub fn base_identity(owner: &GuestOwner) -> Vec<u8> {
    let device = owner.device();
    let primary_bytes = device.sectors * device.sector_size;
    context_v4(&owner.uuid, primary_bytes, device.sector_size)
}

/// KEK for a v4 keyslot from a passphrase: Argon2id with salt v4 base
/// context || "/kek/argon2id" (the only passphrase KDF since scrypt was
/// removed by user decision 2026-10-22).
pub fn passphrase_kek(passphrase: &[u8], base_context: &[u8]) -> Result<Secret> {
    if passphrase.is_empty() {
        bail!("Empty passphrase");
    }
    let mut salt = base_context.to_vec();
    salt.extend_from_slice(b"/kek/argon2id");
    let mut kek = Secret::with_capacity(32);
    kek.push(&[0u8; 32])?;
    let params = argon2::Params::new(ARGON2_M_KIB, ARGON2_T, ARGON2_P, Some(32))
        .map_err(|e| Error::new(e.to_string()))?;
    argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
        .hash_password_into(passphrase, &salt, &mut kek)
        .map_err(|e| Error::new(e.to_string()))?;
    Ok(kek)
}

fn setup_flags(initialize: bool, ab: bool, verify: bool) -> Result<u32> {
    if ab && !initialize {
        bail!("--ab applies only with --initialize (the layout is read from the keyslot afterwards)");
    }
    Ok((if initialize { SETUP_INITIALIZE } else { 0 }) | (if ab { SETUP_AB } else { 0 })
        | (if verify { SETUP_VERIFY } else { 0 }))
}

fn native_setup(device: &KernelDevice, key: &[u8], identity: &[u8], flags: u32) -> Result<()> {
    hooks::fail("before-setup")?;
    hooks::before_setup(device, identity)?;
    let started = std::time::Instant::now();
    let result = device.setup(key, identity, flags);
    let interrupted = matches!(&result, Err(e) if e.errno == Some(libc::EINTR)) && signals::cancelled();
    hooks::after_setup(device, started.elapsed(), &result, interrupted);
    match result {
        Err(error) if interrupted => Err(Error { interrupted: true, ..error }),
        Err(error) => Err(error),
        Ok(()) => hooks::fail("after-setup"),
    }
}

pub fn open_blocks(source: &Path, key_file: &Path, secret: HiddenSecret, options: &OpenOptions) -> Result<Views> {
    if let HiddenSecret::Key(key) = &secret {
        if key.len() != 32 {
            bail!("Hidden key must contain exactly 32 bytes");
        }
    }
    let mut owner = GuestOwner::open(source, key_file, options.name, options.allow)?;
    let mut created: Vec<(String, String)> = Vec::new();
    let result = open_inner(&mut owner, secret, options, &mut created);
    match result {
        Ok(views) => {
            owner.close();
            Ok(views)
        }
        Err(mut error) => {
            if let Err(cleanup) = unwind(&mut owner, &created) {
                error.note(format!("Private mapping cleanup incomplete: {cleanup}"));
            }
            owner.close();
            Err(error)
        }
    }
}

fn unwind(owner: &mut GuestOwner, created: &[(String, String)]) -> Result<()> {
    for (mapping, token) in created.iter().rev() {
        if let Some(identity) = mapping_identity(mapping)? {
            if &identity.2 == token {
                remove_mapping(mapping, &identity, false)?;
            }
        }
    }
    if owner.created {
        // Removing the exclusive attempt's owner frees its native state; do not
        // issue an extra native checkpoint on failure.
        owner.remove(true)?;
    }
    Ok(())
}

fn open_inner(owner: &mut GuestOwner, secret: HiddenSecret, options: &OpenOptions,
              created: &mut Vec<(String, String)>) -> Result<Views> {
    let name = options.name;
    if owner.device().status()?.active {
        return Err(Error::os(libc::EEXIST, "Native block views are already active"));
    }
    if !owner.created {
        return Err(Error::os(libc::EEXIST, "Close the existing idle private owner before opening"));
    }
    for role in ["decoy", "hidden"] {
        if mapping_identity(&format!("{name}-{role}"))?.is_some() {
            return Err(Error::os(libc::EEXIST, "Public view name is already in use"));
        }
    }
    let flags = setup_flags(options.initialize, options.ab, options.verify)?;
    let identity = base_identity(owner);
    let key = match secret {
        HiddenSecret::Key(key) => key,
        HiddenSecret::Passphrase(passphrase) => passphrase_kek(&passphrase, &identity)?,
    };
    owner.validate()?;
    signals::check()?;
    let device = owner.device();
    device.suspend()?;
    device.begin()?;
    if let Err(mut error) = native_setup(device, &key, &identity, flags) {
        if error.errno == Some(libc::EKEYREJECTED) {
            error.note("No keyslot authenticated: wrong hidden key or passphrase, or a carrier never \
                        initialized (use --initialize)");
        }
        return Err(error);
    }
    drop(key);
    device.resume()?;
    let status = device.status()?;
    let decoy_sectors = device.sectors * (device.sector_size / 512);
    let generation = device.generation;
    for (role, sectors) in [("decoy", decoy_sectors), ("hidden", status.hidden_bytes / 512)] {
        let mapping = format!("{name}-{role}");
        let token = format!("PIVVIEW-{}", random_hex(16)?);
        created.push((mapping.clone(), token.clone()));
        let table = format!("0 {sectors} piv-view /dev/mapper/{name} {generation} {role}\n");
        dm(&["create", &mapping, "--uuid", &token], Some(table.as_bytes()), true)?;
        hooks::fail(if role == "decoy" { "first-view" } else { "second-view" })?;
    }
    Ok(Views {
        decoy: format!("/dev/mapper/{name}-decoy"),
        hidden: format!("/dev/mapper/{name}-hidden"),
        decoy_bytes: decoy_sectors * 512,
        hidden_bytes: status.hidden_bytes,
    })
}

pub fn close_blocks(source: &Path, key_file: &Path, name: &str, allow: Allow) -> Result<()> {
    if dm(&["info", name], None, false)?.status != 0 {
        return Err(Error::os(libc::ENOENT, "Native owner is not active"));
    }
    let mut owner = GuestOwner::open(source, key_file, name, allow)?;
    let result = close_inner(&mut owner, name);
    owner.close();
    result
}

fn close_inner(owner: &mut GuestOwner, name: &str) -> Result<()> {
    let device = owner.device();
    let status = device.status()?;
    let rdev = std::os::unix::fs::MetadataExt::rdev(&std::fs::metadata(&device.owner)?);
    let owner_names = [device.owner.to_string_lossy().into_owned(),
                       format!("{}:{}", libc::major(rdev), libc::minor(rdev))];
    let generation = device.generation.to_string();
    let mut views = Vec::new();
    for role in ["hidden", "decoy"] {
        let mapping = format!("{name}-{role}");
        let Some(identity) = mapping_identity(&mapping)? else { continue };
        let table = dm_ok(&["table", &mapping])?;
        let words: Vec<&str> = table.split_whitespace().collect();
        let sectors = if role == "hidden" { status.hidden_bytes / 512 } else { device.sectors * (device.sector_size / 512) };
        if !status.active || words.len() != 6 || words[..3] != ["0", sectors.to_string().as_str(), "piv-view"]
            || !owner_names.iter().any(|n| n == words[3]) || words[4..] != [generation.as_str(), role] {
            bail!("Refusing to remove unrelated view {mapping}");
        }
        views.push((mapping, identity));
    }
    // Validate BOTH names before removing either one.
    for (mapping, identity) in &views {
        remove_mapping(mapping, identity, false)?;
    }
    if status.active {
        owner.device().detach()?;
    }
    owner.remove(false)
}

pub fn keyslot(source: &Path, key_file: &Path, slot: u32, kek: Option<&[u8]>, name: &str, allow: Allow) -> Result<()> {
    let mut owner = GuestOwner::open(source, key_file, name, allow)?;
    let result = (|| {
        if owner.created || !owner.device().status()?.active {
            return Err(Error::os(libc::ENOENT, "Native views must be active to manage keyslots"));
        }
        owner.device().keyslot(slot, kek)
    })();
    let cleanup = if owner.created { owner.remove(true) } else { Ok(()) };
    owner.close();
    result.and(cleanup)
}

fn random_hex(bytes: usize) -> Result<String> {
    let mut buf = vec![0u8; bytes];
    let mut filled = 0;
    while filled < bytes {
        // SAFETY: getrandom into the unfilled tail of a live buffer.
        let n = unsafe { libc::getrandom(buf[filled..].as_mut_ptr().cast(), bytes - filled, 0) };
        if n < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error.into());
        }
        filled += n as usize;
    }
    Ok(buf.iter().map(|b| format!("{b:02x}")).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn setup_flags_match_kernel_abi() {
        // kernel/piv-control.h: INITIALIZE = 1, AB = 8, VERIFY = 16 (SETUP ABI 4).
        assert_eq!(setup_flags(false, false, false).unwrap(), 0);
        assert_eq!(setup_flags(true, false, false).unwrap(), 1);
        assert_eq!(setup_flags(true, true, false).unwrap(), 9);
        assert_eq!(setup_flags(false, false, true).unwrap(), 16);
        assert!(setup_flags(false, true, false).is_err());
    }

    #[test]
    fn passphrase_kek_matches_python_reference() {
        let hex = |s: &Secret| s.iter().map(|b| format!("{b:02x}")).collect::<String>();
        // cryptography Argon2id(salt=b'ctx/kek/argon2id', length=32, iterations=3,
        // lanes=4, memory_cost=65536).derive(b'pw')
        let kek = passphrase_kek(b"pw", b"ctx").unwrap();
        assert_eq!(hex(&kek), include_str!("../tests/argon2id-pw-ctx.hex").trim());
        assert!(passphrase_kek(b"", b"ctx").is_err());
    }
}
