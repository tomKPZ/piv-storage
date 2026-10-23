//! `pivsetup status` and `pivsetup scrub`: read-only health reporting for an
//! active owner. Neither needs a key: both bind the owner's control device
//! (STATUS only) and the scrub reads the public views with O_DIRECT, so it
//! publishes nothing the views do not already expose and writes nothing.

use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};

use crate::bail;
use crate::cmd::{crypt, dm_ok};
use crate::error::{Error, Result};
use crate::ioctl::{valid_piv_name, KernelDevice, Status};
use crate::owner::{canonical_uuid, check_device, mapping_identity, path_str};
use crate::signals;

/// Format v5 layout (docs/format-v5.md): keyslot sectors, directory groups,
/// data fragments per record and the hidden block size.
const KEYSLOT_AREA: u64 = 112;
const DIRECTORY_GROUPS: u64 = 2;
const DATA_FRAGMENTS: u64 = 687;
const BLOCK: usize = 4096;
/// Hidden writes are shaped to these edges (kernel pn_shape).
const SHAPE_BYTES: u64 = 4096;
/// Decoy probe chunk (falls back to single sectors on EIO).
const PROBE_BYTES: usize = 65536;

/// Exit codes shared by status and scrub (1 stays "error", 130 "interrupted").
pub const EXIT_FAILED: i32 = 2;
pub const EXIT_INACTIVE: i32 = 3;
pub const EXIT_RECOVERED: i32 = 4;
pub const EXIT_UNAVAILABLE: i32 = 5;

fn json_string(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}

/// The owner mapping @name, if present, with its bound control device. The
/// owner must be a piv-crypt mapping created for a LUKS2 volume under this
/// name (DM UUID CRYPT-LUKS2-<uuid>-<name>); with @device, of that volume.
fn attach(name: &str, device: Option<&Path>) -> Result<Option<KernelDevice>> {
    if !valid_piv_name(name, 40) {
        bail!("Invalid experimental mapping name");
    }
    let expected_uuid = match device {
        Some(device) => {
            let (_, node) = check_device(device)?;
            let uuid = canonical_uuid(crypt(&["luksUUID", path_str(&node)?])?.trim())?;
            Some(format!("CRYPT-LUKS2-{}-{name}", uuid.replace('-', "")))
        }
        None => None,
    };
    let Some(identity) = mapping_identity(name)? else { return Ok(None) };
    let valid = match &expected_uuid {
        Some(expected) => &identity.2 == expected,
        None => identity.2.strip_prefix("CRYPT-LUKS2-").and_then(|rest| rest.strip_suffix(&format!("-{name}")))
            .is_some_and(|hex| hex.len() == 32 && hex.bytes().all(|b| b.is_ascii_hexdigit())),
    };
    if !valid {
        bail!("Mapping {name} does not belong to {}", device.map_or("a LUKS2 volume".into(), |d| d.display().to_string()));
    }
    let table = dm_ok(&["table", name])?;
    if table.split_whitespace().nth(2) != Some("piv-crypt") {
        bail!("Mapping {name} is not a dm-piv owner");
    }
    let owner = PathBuf::from(format!("/dev/mapper/{name}"));
    let mut matches = Vec::new();
    for entry in std::fs::read_dir("/dev")? {
        let entry = entry?;
        if entry.file_name().to_string_lossy().starts_with("pivctl-") {
            if let Ok(device) = KernelDevice::open(&entry.path(), &owner) {
                matches.push(device);
            }
        }
    }
    if matches.len() != 1 {
        bail!("Expected exactly one native control for owner {name}");
    }
    let device = matches.pop().expect("one control");
    let rdev = std::fs::metadata(&owner)?.rdev();
    if (libc::major(rdev).to_string(), libc::minor(rdev).to_string()) != (identity.0, identity.1) {
        bail!("Owner {name} changed while binding its control");
    }
    Ok(Some(device))
}

/// Hidden blocks of an active owner.
fn hidden_blocks(status: &Status) -> u64 {
    status.hidden_bytes / BLOCK as u64
}

fn state(status: Option<&Status>) -> (&'static str, i32) {
    match status {
        None => ("absent", EXIT_INACTIVE),
        Some(s) if s.failed => ("failed", EXIT_FAILED),
        Some(s) if !s.active => ("idle", EXIT_INACTIVE),
        Some(_) => ("active", 0),
    }
}

fn status_json(name: &str, status: Option<&Status>) -> String {
    let (state, _) = state(status);
    let owner = if status.is_some() { json_string(&format!("/dev/mapper/{name}")) } else { "null".into() };
    let mut text = format!("{{\n  \"name\": {},\n  \"owner\": {owner},\n  \"state\": \"{state}\"", json_string(name));
    if let Some(s) = status {
        text += &format!(",\n  \"active\": {},\n  \"failed\": {},\n  \"views\": {},\n  \"hidden_bytes\": {},\n  \
                          \"hidden_blocks\": {},\n  \"parity\": {},\n  \"ab\": {},\n  \"encryptions\": {},\n  \
                          \"rs_corrected_reads\": {}",
                         s.active, s.failed, s.views, s.hidden_bytes, hidden_blocks(s), s.parity, s.ab, s.encryptions,
                         s.corrected);
    }
    text + "\n}"
}

/// `pivsetup status`: prints the owner state as JSON; exit 0 active and
/// healthy, 2 fail-stopped, 3 absent or idle (no native state).
pub fn status(name: &str, device: Option<&Path>) -> Result<i32> {
    let status = match attach(name, device)? {
        Some(control) => Some(control.status()?),
        None => None,
    };
    println!("{}", status_json(name, status.as_ref()));
    Ok(state(status.as_ref()).1)
}

/// Record groups (first primary sector, sectors) carrying hidden block @index.
fn carrier_groups(index: u64, parity: u32, ab: bool) -> Vec<(u64, u64)> {
    let group = DATA_FRAGMENTS + 3 * u64::from(parity);
    let slots: &[u64] = if ab { &[0, 1] } else { &[0] };
    slots.iter().map(|slot| {
        let number = DIRECTORY_GROUPS + if ab { 2 * index + slot } else { index };
        (KEYSLOT_AREA + number * group, group)
    }).collect()
}

/// Primary sectors [lo, hi) a rewrite of [first, first + count) touches:
/// extended to 4 KiB edges, clamped to the device (pivstore.records.shaped_extent).
fn shaped_extent(first: u64, count: u64, sector_size: u64, sectors: u64) -> (u64, u64) {
    let unit = (SHAPE_BYTES / sector_size).max(1);
    (first - first % unit, (first + count).div_ceil(unit).saturating_mul(unit).min(sectors))
}

/// Hidden blocks whose shaped carrier intersects primary sectors [lo, hi).
fn blocks_touching(lo: u64, hi: u64, blocks: u64, parity: u32, ab: bool, sector_size: u64, sectors: u64) -> Vec<u64> {
    let group = DATA_FRAGMENTS + 3 * u64::from(parity);
    let first_record = KEYSLOT_AREA + DIRECTORY_GROUPS * group;
    if hi <= first_record.saturating_sub(SHAPE_BYTES / sector_size) || blocks == 0 {
        return Vec::new();
    }
    let per_block = if ab { 2 * group } else { group };
    let low = lo.saturating_sub(first_record) / per_block;
    let high = (hi.saturating_sub(first_record) / per_block + 1).min(blocks - 1);
    (low.saturating_sub(1)..=high).filter(|&index| {
        carrier_groups(index, parity, ab).iter().any(|&(first, count)| {
            let (a, b) = shaped_extent(first, count, sector_size, sectors);
            a < hi && lo < b
        })
    }).collect()
}

/// Merge sorted sectors into (first, count) runs.
fn runs(sectors: &[u64]) -> Vec<(u64, u64)> {
    let mut out: Vec<(u64, u64)> = Vec::new();
    for &sector in sectors {
        match out.last_mut() {
            Some((first, count)) if *first + *count == sector => *count += 1,
            _ => out.push((sector, 1)),
        }
    }
    out
}

/// Page-aligned buffer for O_DIRECT.
struct Aligned {
    ptr: *mut u8,
    layout: std::alloc::Layout,
}

impl Aligned {
    fn new(size: usize) -> Result<Self> {
        let layout = std::alloc::Layout::from_size_align(size, 4096).map_err(|_| Error::new("Invalid buffer"))?;
        // SAFETY: nonzero size, valid alignment; freed in Drop with the same layout.
        let ptr = unsafe { std::alloc::alloc_zeroed(layout) };
        if ptr.is_null() {
            return Err(Error::os(libc::ENOMEM, "Out of memory"));
        }
        Ok(Aligned { ptr, layout })
    }
}

impl Drop for Aligned {
    fn drop(&mut self) {
        // SAFETY: allocated in new() with this layout.
        unsafe { std::alloc::dealloc(self.ptr, self.layout) };
        self.ptr = std::ptr::null_mut();
    }
}

/// One O_DIRECT read of @length bytes at @offset: Ok(true) read, Ok(false)
/// EIO (unauthenticated or unreadable), other errors returned. A signal
/// that interrupts it is retried unless the scrub was cancelled.
fn read_at(file: &std::fs::File, buffer: &Aligned, length: usize, offset: u64) -> Result<bool> {
    loop {
        // SAFETY: @buffer holds at least @length writable bytes.
        let n = unsafe { libc::pread(file.as_raw_fd(), buffer.ptr.cast(), length, offset as libc::off_t) };
        if n == length as isize {
            return Ok(true);
        }
        if n >= 0 {
            return Err(Error::os(libc::EIO, format!("Short read at byte {offset}")));
        }
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(libc::EIO);
        match errno {
            libc::EIO => return Ok(false),
            libc::EINTR if !signals::cancelled() => continue,
            libc::EINTR => return Err(Error::interrupted()),
            _ => return Err(Error::os(errno, format!("Read at byte {offset}: {}", std::io::Error::from_raw_os_error(errno)))),
        }
    }
}

/// Primary sectors in [lo, hi) whose decoy reads return EIO.
fn probe_decoy(file: &std::fs::File, buffer: &Aligned, sector_size: u64, lo: u64, hi: u64) -> Result<Vec<u64>> {
    let per_chunk = PROBE_BYTES as u64 / sector_size;
    let mut bad = Vec::new();
    let mut at = lo;
    while at < hi {
        signals::check()?;
        let count = per_chunk.min(hi - at);
        if !read_at(file, buffer, (count * sector_size) as usize, at * sector_size)? {
            for sector in at..at + count {
                if !read_at(file, buffer, sector_size as usize, sector * sector_size)? {
                    bad.push(sector);
                }
            }
        }
        at += count;
    }
    Ok(bad)
}

/// A public view of owner @name (role decoy or hidden) with the expected
/// table, opened read-only with O_DIRECT; the opened device must be the
/// checked mapping.
fn open_view(name: &str, control: &KernelDevice, role: &str, sectors512: u64) -> Result<std::fs::File> {
    let mapping = format!("{name}-{role}");
    let identity = mapping_identity(&mapping)?.ok_or_else(|| Error::os(libc::ENOENT, format!("{mapping} is not active")))?;
    let rdev = std::fs::metadata(&control.owner)?.rdev();
    let owner_names = [control.owner.to_string_lossy().into_owned(), format!("{}:{}", libc::major(rdev), libc::minor(rdev))];
    let table = dm_ok(&["table", &mapping])?;
    let words: Vec<&str> = table.split_whitespace().collect();
    let generation = control.generation.to_string();
    if words.len() != 6 || words[..3] != ["0", sectors512.to_string().as_str(), "piv-view"]
        || !owner_names.iter().any(|n| n == words[3]) || words[4..] != [generation.as_str(), role] {
        bail!("Refusing to read unrelated view {mapping}");
    }
    let path = format!("/dev/mapper/{mapping}");
    let file = std::fs::OpenOptions::new().read(true).custom_flags(libc::O_DIRECT | libc::O_CLOEXEC).open(&path)?;
    let info = file.metadata()?;
    if !info.file_type().is_block_device()
        || (libc::major(info.rdev()).to_string(), libc::minor(info.rdev()).to_string()) != (identity.0, identity.1) {
        bail!("{path} changed while opening it");
    }
    Ok(file)
}

pub struct ScrubOptions {
    /// Maximum blocks listed per category (counts are always complete).
    pub limit: usize,
    /// Also read the whole decoy view and report every EIO sector run.
    pub decoy: bool,
}

#[derive(Default)]
struct Report {
    blocks: u64,
    scanned: u64,
    valid: u64,
    recovered: u64,
    unavailable: u64,
    recovered_blocks: Vec<u64>,
    /// (block, EIO decoy sector runs within its shaped carrier)
    unavailable_blocks: Vec<(u64, Vec<(u64, u64)>)>,
    /// (first, count, hidden blocks whose shaped carrier it intersects)
    decoy_runs: Option<Vec<(u64, u64, Vec<u64>)>>,
    decoy_runs_total: u64,
    encryptions: u64,
    seconds: f64,
    complete: bool,
    owner_failed: bool,
}

fn pairs(runs: &[(u64, u64)]) -> String {
    runs.iter().map(|(f, c)| format!("[{f}, {c}]")).collect::<Vec<_>>().join(", ")
}

fn list(values: &[u64]) -> String {
    values.iter().map(u64::to_string).collect::<Vec<_>>().join(", ")
}

fn scrub_json(name: &str, status: &Status, sector_size: u64, limit: usize, r: &Report) -> String {
    let unavailable = r.unavailable_blocks.iter()
        .map(|(block, eio)| format!("\n    {{\"block\": {block}, \"decoy_eio\": [{}]}}", pairs(eio)))
        .collect::<Vec<_>>().join(",");
    let mut text = format!(
        "{{\n  \"hidden\": {},\n  \"complete\": {},\n  \"owner_failed\": {},\n  \"blocks\": {},\n  \"scanned\": {},\n  \
         \"valid\": {},\n  \"recovered\": {},\n  \"unavailable\": {},\n  \"parity\": {},\n  \"ab\": {},\n  \
         \"sector_size\": {sector_size},\n  \"encryptions_during_scrub\": {},\n  \"seconds\": {:.3},\n  \
         \"list_limit\": {limit},\n  \
         \"recovered_blocks\": [{}],\n  \"unavailable_blocks\": [{}{}]",
        json_string(&format!("/dev/mapper/{name}-hidden")), r.complete, r.owner_failed, r.blocks, r.scanned, r.valid,
        r.recovered, r.unavailable, status.parity, status.ab, r.encryptions, r.seconds, list(&r.recovered_blocks), unavailable,
        if unavailable.is_empty() { "" } else { "\n  " });
    if let Some(runs) = &r.decoy_runs {
        let items = runs.iter()
            .map(|(first, count, blocks)| format!("\n    {{\"first\": {first}, \"count\": {count}, \"blocks\": [{}]}}", list(blocks)))
            .collect::<Vec<_>>().join(",");
        text += &format!(",\n  \"decoy_eio_runs\": {},\n  \"decoy_eio\": [{items}{}]", r.decoy_runs_total,
                         if items.is_empty() { "" } else { "\n  " });
    }
    text + "\n}"
}

fn scrub_exit(r: &Report) -> i32 {
    if r.owner_failed {
        EXIT_FAILED
    } else if !r.complete {
        130
    } else if r.unavailable > 0 || r.decoy_runs_total > 0 {
        EXIT_UNAVAILABLE
    } else if r.recovered > 0 {
        EXIT_RECOVERED
    } else {
        0
    }
}

/// `pivsetup scrub`: read every hidden block once through the hidden view
/// (O_DIRECT, so the kernel authenticates each record) and classify it as
/// valid, recovered (its record authenticated only after RS correction,
/// attributed by the STATUS counter around each read) or unavailable (EIO).
/// For listed unavailable blocks, the decoy sectors of their shaped carriers
/// that read EIO are reported (restore those before rewriting the block).
/// Read-only: nothing is written. Exit 0 all valid, 4 some recovered, 5 some
/// unavailable (or decoy EIO with --decoy), 2 owner failed, 3 not active,
/// 130 cancelled (partial report printed).
pub fn scrub(name: &str, device: Option<&Path>, options: &ScrubOptions) -> Result<i32> {
    let Some(control) = attach(name, device)? else {
        return Err(Error::os(libc::ENOENT, format!("Native owner {name} is not active")));
    };
    let started = std::time::Instant::now();
    let start = control.status()?;
    if start.failed {
        println!("{}", status_json(name, Some(&start)));
        return Ok(EXIT_FAILED);
    }
    if !start.active {
        return Err(Error::os(libc::ENOENT, format!("Native views of {name} are not active")));
    }
    let sector_size = control.sector_size;
    let sectors = control.sectors;
    let hidden = open_view(name, &control, "hidden", start.hidden_bytes / 512)?;
    let decoy = open_view(name, &control, "decoy", sectors * (sector_size / 512))?;
    let buffer = Aligned::new(PROBE_BYTES)?;
    let mut report = Report { blocks: hidden_blocks(&start), ..Report::default() };
    let mut previous = start.corrected;
    let mut result = Ok(());
    for index in 0..report.blocks {
        if signals::cancelled() {
            break;
        }
        let ok = match read_at(&hidden, &buffer, BLOCK, index * BLOCK as u64) {
            Ok(ok) => ok,
            Err(error) => { result = Err(error); break; }
        };
        let now = control.status()?;
        if now.failed {
            report.owner_failed = true;
            break;
        }
        report.scanned += 1;
        if !ok {
            report.unavailable += 1;
            if report.unavailable_blocks.len() < options.limit {
                report.unavailable_blocks.push((index, Vec::new()));
            }
        } else if now.corrected > previous {
            report.recovered += 1;
            if report.recovered_blocks.len() < options.limit {
                report.recovered_blocks.push(index);
            }
        } else {
            report.valid += 1;
        }
        previous = now.corrected;
    }
    // Carrier probes of the listed unavailable blocks, then the optional
    // whole-decoy pass.
    if result.is_ok() && !report.owner_failed && !signals::cancelled() {
        result = (|| {
            for (index, eio) in report.unavailable_blocks.iter_mut() {
                let mut bad = Vec::new();
                for (first, count) in carrier_groups(*index, start.parity, start.ab) {
                    let (lo, hi) = shaped_extent(first, count, sector_size, sectors);
                    bad.extend(probe_decoy(&decoy, &buffer, sector_size, lo, hi)?);
                }
                bad.sort_unstable();
                bad.dedup();
                *eio = runs(&bad);
            }
            if options.decoy {
                let all = runs(&probe_decoy(&decoy, &buffer, sector_size, 0, sectors)?);
                report.decoy_runs_total = all.len() as u64;
                report.decoy_runs = Some(all.into_iter().take(options.limit).map(|(first, count)| {
                    let mut touched = blocks_touching(first, first + count, report.blocks, start.parity, start.ab,
                                                      sector_size, sectors);
                    touched.truncate(options.limit);
                    (first, count, touched)
                }).collect());
            }
            Ok(())
        })();
    }
    let end = control.status()?;
    report.owner_failed |= end.failed;
    report.encryptions = end.encryptions.saturating_sub(start.encryptions);
    report.seconds = started.elapsed().as_secs_f64();
    match result {
        Ok(()) => {}
        Err(error) if error.interrupted => {}
        Err(error) => return Err(error),
    }
    report.complete = report.scanned == report.blocks && !report.owner_failed && !signals::cancelled()
        && (!options.decoy || report.decoy_runs.is_some());
    println!("{}", scrub_json(name, &start, sector_size, options.limit, &report));
    let code = scrub_exit(&report);
    if code == EXIT_UNAVAILABLE || code == EXIT_RECOVERED {
        eprintln!("pivsetup: {} hidden block(s) unavailable, {} recovered by parity; see docs/native-faults.md \
                   (repair after damage)", report.unavailable, report.recovered);
    }
    Ok(code)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn carrier_layout_matches_format_v5() {
        // Block i at 112 + G * (2 + i); A/B slots at groups 2 + 2i and 3 + 2i.
        assert_eq!(carrier_groups(0, 0, false), vec![(112 + 2 * 687, 687)]);
        assert_eq!(carrier_groups(3, 8, false), vec![(112 + 5 * 711, 711)]);
        assert_eq!(carrier_groups(1, 0, true), vec![(112 + 4 * 687, 687), (112 + 5 * 687, 687)]);
    }

    #[test]
    fn shaped_extent_matches_python() {
        // pivstore.records.shaped_extent (tests/test_shape_trace.py values).
        assert_eq!(shaped_extent(14, 14, 512, 1 << 18), (8, 32));
        assert_eq!(shaped_extent(98, 14, 512, 1 << 18), (96, 112));
        assert_eq!(shaped_extent(1486, 687, 4096, 1 << 15), (1486, 2173));
        assert_eq!(shaped_extent(1486, 687, 512, 1490), (1480, 1490));
    }

    #[test]
    fn blocks_touching_uses_shaped_carriers() {
        let (unit, sectors) = (512, 1 << 20);
        let first = 112 + 2 * 687; // 1486: block 0, shaped from 1480
        assert!(blocks_touching(0, 112, 100, 0, false, unit, sectors).is_empty());
        assert_eq!(blocks_touching(1480, 1481, 100, 0, false, unit, sectors), vec![0]);
        // The last sectors of block 0's 4 KiB unit also belong to block 1's
        // shaped extent (block 1 starts at 2173, shaped from 2168).
        assert_eq!(blocks_touching(2170, 2171, 100, 0, false, unit, sectors), vec![0, 1]);
        assert_eq!(blocks_touching(first + 687 + 100, first + 687 + 101, 100, 0, false, unit, sectors), vec![1]);
        // 4096-byte sectors: no shaping overlap.
        assert_eq!(blocks_touching(2172, 2174, 100, 0, false, 4096, sectors), vec![0, 1]);
        assert_eq!(blocks_touching(2173, 2174, 100, 0, false, 4096, sectors), vec![1]);
        // A/B: block 0 owns groups 2 and 3; the last block is clamped.
        assert_eq!(blocks_touching(first + 687 + 5, first + 687 + 6, 10, 0, true, 4096, sectors), vec![0]);
        assert_eq!(blocks_touching(sectors - 10, sectors, 10, 0, false, 4096, sectors), Vec::<u64>::new());
    }

    #[test]
    fn sector_runs() {
        assert_eq!(runs(&[]), vec![]);
        assert_eq!(runs(&[3, 4, 5, 9, 11, 12]), vec![(3, 3), (9, 1), (11, 2)]);
    }

    fn sample(failed: bool, active: bool) -> Status {
        Status { generation: 7, hidden_bytes: 8192, encryptions: 5, active, views: 3, failed, corrected: 1, parity: 8,
                 ab: true }
    }

    #[test]
    fn status_states_and_exit_codes() {
        assert_eq!(state(None), ("absent", EXIT_INACTIVE));
        assert_eq!(state(Some(&sample(false, true))), ("active", 0));
        assert_eq!(state(Some(&sample(true, true))), ("failed", EXIT_FAILED));
        assert_eq!(state(Some(&sample(true, false))), ("failed", EXIT_FAILED));
        assert_eq!(state(Some(&sample(false, false))), ("idle", EXIT_INACTIVE));
        let text = status_json("piv-native", Some(&sample(false, true)));
        for field in ["\"state\": \"active\"", "\"hidden_blocks\": 2", "\"parity\": 8", "\"ab\": true",
                      "\"rs_corrected_reads\": 1", "\"owner\": \"/dev/mapper/piv-native\""] {
            assert!(text.contains(field), "{field} in {text}");
        }
        assert!(status_json("piv-x", None).contains("\"owner\": null"));
    }

    #[test]
    fn scrub_exit_codes_and_json() {
        let mut r = Report { blocks: 4, scanned: 4, valid: 4, complete: true, ..Report::default() };
        assert_eq!(scrub_exit(&r), 0);
        r.recovered = 1;
        assert_eq!(scrub_exit(&r), EXIT_RECOVERED);
        r.unavailable = 1;
        r.unavailable_blocks = vec![(2, vec![(5000, 3)])];
        assert_eq!(scrub_exit(&r), EXIT_UNAVAILABLE);
        let text = scrub_json("piv-native", &sample(false, true), 512, 64, &r);
        assert!(text.contains("{\"block\": 2, \"decoy_eio\": [[5000, 3]]}"), "{text}");
        assert!(!text.contains("decoy_eio_runs"));
        r.complete = false;
        assert_eq!(scrub_exit(&r), 130);
        r.owner_failed = true;
        assert_eq!(scrub_exit(&r), EXIT_FAILED);
        let clean = Report { decoy_runs: Some(vec![(9, 2, vec![0])]), decoy_runs_total: 1, complete: true,
                             ..Report::default() };
        assert_eq!(scrub_exit(&clean), EXIT_UNAVAILABLE);
        assert!(scrub_json("piv-native", &sample(false, true), 512, 64, &clean)
            .contains("{\"first\": 9, \"count\": 2, \"blocks\": [0]}"));
    }
}
