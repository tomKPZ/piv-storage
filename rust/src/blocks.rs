//! Paired native views (pivstore/blocks.py): open, close and v5 keyslots.

use std::path::Path;

use crate::bail;
use crate::cmd::{dm, dm_ok};
use crate::error::{Error, Result};
use crate::ioctl::{KernelDevice, SETUP_AB, SETUP_INITIALIZE, SETUP_VERIFY};
use crate::owner::{mapping_identity, remove_mapping, Allow, GuestOwner};
use crate::profile::base_context;
use crate::secret::Secret;
use crate::{hooks, signals};

/// Argon2id cost tiers (`--kdf-cost`, docs/format-v5.md): (memory KiB,
/// passes), 4 lanes. Nothing is stored in clear, so the tier must be given on
/// every open (pivstore.blocks.ARGON2ID_TIERS).
const ARGON2_TIERS: [(u32, u32); 4] = [(64 * 1024, 3), (256 * 1024, 3), (1024 * 1024, 3), (2048 * 1024, 6)];
const ARGON2_P: u32 = 4;
/// Default tier: cryptsetup's LUKS2 Argon2id memory and lanes (user decision 2026-10-22).
pub const DEFAULT_KDF_COST: u8 = 3;
/// RS parity choices per lane (`--parity`, only with --initialize).
pub const PARITIES: [u32; 3] = [4, 8, 16];

pub struct OpenOptions<'a> {
    pub name: &'a str,
    pub initialize: bool,
    pub ab: bool,
    pub verify: bool,
    /// Reed–Solomon parity fragments per lane (0 = off); only with initialize.
    pub parity: u32,
    /// Argon2id cost tier for passphrases (1-4).
    pub kdf_cost: u8,
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
    base_context(&owner.uuid, primary_bytes, device.sector_size)
}

/// Parse `--kdf-cost` (1-4, default 3).
pub fn kdf_cost(value: Option<&str>) -> Result<u8> {
    match value {
        None => Ok(DEFAULT_KDF_COST),
        Some(text) => text.parse::<u8>().ok().filter(|t| (1..=4).contains(t))
            .ok_or_else(|| Error::new("--kdf-cost must be 1, 2, 3 or 4")),
    }
}

/// Parse `--parity` (4, 8 or 16; absent = 0).
pub fn parity(value: Option<&str>) -> Result<u32> {
    match value {
        None => Ok(0),
        Some(text) => text.parse::<u32>().ok().filter(|p| PARITIES.contains(p))
            .ok_or_else(|| Error::new("--parity must be 4, 8 or 16")),
    }
}

/// KEK for a v5 keyslot from a passphrase: Argon2id at cost @tier with salt
/// base context || "/kek/argon2id/" || ASCII tier digit (the only passphrase
/// KDF since scrypt was removed by user decision 2026-10-22).
pub fn passphrase_kek(passphrase: &[u8], base_context: &[u8], tier: u8) -> Result<Secret> {
    if passphrase.is_empty() {
        bail!("Empty passphrase");
    }
    if !(1..=4).contains(&tier) {
        bail!("Unsupported KDF cost tier");
    }
    let (memory, passes) = ARGON2_TIERS[usize::from(tier - 1)];
    let mut salt = base_context.to_vec();
    salt.extend_from_slice(b"/kek/argon2id/");
    salt.push(b'0' + tier);
    let mut kek = Secret::with_capacity(32);
    kek.push(&[0u8; 32])?;
    let params = argon2::Params::new(memory, passes, ARGON2_P, Some(32))
        .map_err(|e| Error::new(e.to_string()))?;
    argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
        .hash_password_into(passphrase, &salt, &mut kek)
        .map_err(|e| Error::new(e.to_string()))?;
    Ok(kek)
}

fn setup_flags(initialize: bool, ab: bool, verify: bool, parity: u32) -> Result<u32> {
    if ab && !initialize {
        bail!("--ab applies only with --initialize (the layout is read from the keyslot afterwards)");
    }
    if parity != 0 && (!initialize || !PARITIES.contains(&parity)) {
        bail!("--parity 4, 8 or 16 applies only with --initialize (it is read from the keyslot afterwards)");
    }
    Ok((if initialize { SETUP_INITIALIZE } else { 0 }) | (if ab { SETUP_AB } else { 0 })
        | (if verify { SETUP_VERIFY } else { 0 }))
}

fn native_setup(device: &KernelDevice, key: &[u8], identity: &[u8], flags: u32, parity: u32) -> Result<()> {
    hooks::fail("before-setup")?;
    hooks::before_setup(device, identity)?;
    let started = std::time::Instant::now();
    let result = device.setup(key, identity, flags, parity);
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
    let flags = setup_flags(options.initialize, options.ab, options.verify, options.parity)?;
    let identity = base_identity(owner);
    let passphrase = matches!(secret, HiddenSecret::Passphrase(_));
    let key = match secret {
        HiddenSecret::Key(key) => key,
        HiddenSecret::Passphrase(passphrase) => passphrase_kek(&passphrase, &identity, options.kdf_cost)?,
    };
    owner.validate()?;
    signals::check()?;
    let device = owner.device();
    device.suspend()?;
    device.begin()?;
    if let Err(mut error) = native_setup(device, &key, &identity, flags, options.parity) {
        if error.errno == Some(libc::EKEYREJECTED) {
            error.note("No keyslot authenticated: wrong hidden key or passphrase, or a carrier never \
                        initialized (use --initialize)");
            if passphrase {
                error.note(format!("Passphrases also need the --kdf-cost tier used when the keyslot was \
                                    written (this attempt: {}); a wrong tier looks like a wrong passphrase",
                                   options.kdf_cost));
            }
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
        // kernel/piv-control.h: INITIALIZE = 1, AB = 8, VERIFY = 16 (SETUP ABI 5).
        assert_eq!(setup_flags(false, false, false, 0).unwrap(), 0);
        assert_eq!(setup_flags(true, false, false, 0).unwrap(), 1);
        assert_eq!(setup_flags(true, true, false, 8).unwrap(), 9);
        assert_eq!(setup_flags(false, false, true, 0).unwrap(), 16);
        assert!(setup_flags(false, true, false, 0).is_err());
        assert!(setup_flags(false, false, false, 4).is_err());
        assert!(setup_flags(true, false, false, 5).is_err());
    }

    #[test]
    fn option_parsing() {
        assert_eq!(kdf_cost(None).unwrap(), 3);
        assert_eq!(kdf_cost(Some("1")).unwrap(), 1);
        assert!(kdf_cost(Some("0")).is_err() && kdf_cost(Some("5")).is_err() && kdf_cost(Some("x")).is_err());
        assert_eq!(parity(None).unwrap(), 0);
        assert_eq!(parity(Some("16")).unwrap(), 16);
        assert!(parity(Some("0")).is_err() && parity(Some("2")).is_err());
    }

    #[test]
    fn passphrase_kek_matches_python_reference() {
        let hex = |s: &Secret| s.iter().map(|b| format!("{b:02x}")).collect::<String>();
        // pivstore.blocks.passphrase_kek(b'pw', b'ctx', tier): cryptography
        // Argon2id(salt=b'ctx/kek/argon2id/<tier>', length=32, lanes=4, ...).
        let kek = passphrase_kek(b"pw", b"ctx", 1).unwrap();
        assert_eq!(hex(&kek), include_str!("../tests/argon2id-pw-ctx-tier1.hex").trim());
        let kek = passphrase_kek(b"pw", b"ctx", 3).unwrap();
        assert_eq!(hex(&kek), include_str!("../tests/argon2id-pw-ctx-tier3.hex").trim());
        assert!(passphrase_kek(b"", b"ctx", 1).is_err());
        assert!(passphrase_kek(b"pw", b"ctx", 0).is_err() && passphrase_kek(b"pw", b"ctx", 5).is_err());
    }

    /// Timing of every tier (release build): cargo test --release -- --ignored tier_timing --nocapture
    #[test]
    #[ignore]
    fn tier_timing() {
        for tier in 1..=4 {
            let started = std::time::Instant::now();
            passphrase_kek(b"pw", b"ctx", tier).unwrap();
            println!("tier {tier}: {:.3} s", started.elapsed().as_secs_f64());
        }
    }
}
