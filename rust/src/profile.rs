//! LUKS2 segment / dm-integrity superblock validation and public volume
//! contexts. Mirrors pivstore/profile.py, format.py and kernel_api.py exactly;
//! the Python versions remain the independent diagnostic cross-check.

use crate::bail;
use crate::error::Result;
use crate::json::Value;

/// LUKS encryption name -> (LUKS integrity type, exact dm-crypt cipher spec).
/// AEGIS-128 only: format v4 needs 16-byte IVs (AES-GCM and ChaCha20-Poly1305
/// with 12-byte IVs were removed with format v3 on 2026-10-21).
pub const PRIMARY_PROFILES: [(&str, &str, &str); 1] = [
    ("aegis128-random", "aead", "capi:aegis128-random"),
];

pub fn profile(encryption: &str) -> Option<(&'static str, &'static str)> {
    PRIMARY_PROFILES.iter().find(|p| p.0 == encryption).map(|p| (p.1, p.2))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Layout {
    pub integrity_offset: u64,
    pub primary_bytes: u64,
    pub journal_sections: u64,
    pub journal_section_sectors: u64,
    pub initial_sectors: u64,
    pub metadata_run_sectors: u64,
    pub interleave_sectors: u64,
    pub sector_size: u64,
    pub tag_bytes: u64,
    pub iv_bytes: u64,
}

impl Layout {
    pub fn sectors(&self) -> u64 {
        self.primary_bytes / self.sector_size
    }

    pub fn tuple_bytes(&self) -> u64 {
        self.tag_bytes + self.iv_bytes
    }

    /// (data byte offset, tuple byte offset) of a primary sector.
    pub fn offsets(&self, index: u64) -> Option<(u64, u64)> {
        if index >= self.sectors() {
            return None;
        }
        let factor = self.sector_size / 512;
        let sector512 = index.checked_mul(factor)?;
        let (area, offset) = (sector512 / self.interleave_sectors, sector512 % self.interleave_sectors);
        let run = self.interleave_sectors.checked_add(self.metadata_run_sectors)?;
        let base = self.integrity_offset.checked_add(
            self.initial_sectors.checked_add(area.checked_mul(run)?)?.checked_mul(512)?)?;
        Some((base.checked_add((self.metadata_run_sectors + offset).checked_mul(512)?)?,
              base.checked_add((offset / factor).checked_mul(self.tuple_bytes())?)?))
    }
}

fn le_u16(b: &[u8], at: usize) -> u64 { u16::from_le_bytes(b[at..at + 2].try_into().unwrap()) as u64 }
fn le_u32(b: &[u8], at: usize) -> u64 { u32::from_le_bytes(b[at..at + 4].try_into().unwrap()) as u64 }
fn le_u64(b: &[u8], at: usize) -> u64 { u64::from_le_bytes(b[at..at + 8].try_into().unwrap()) }

/// Static dm-integrity v4 superblock fields (struct '<8sBBHIQIB').
pub fn parse_superblock(header: &[u8], offset: u64, file_size: u64) -> Result<Layout> {
    if header.len() != 4096 {
        bail!("Incomplete integrity superblock");
    }
    let (magic, version, interleave) = (&header[0..8], header[8], header[9]);
    let tuple_size = le_u16(header, 10);
    let sections = le_u32(header, 12);
    let provided = le_u64(header, 16);
    let flags = le_u32(header, 24);
    let block = header[28];
    if magic != b"integrt\0" || version != 4 || interleave != 15 || flags != 8
        || tuple_size != 32 || !(block == 0 || block == 3) {
        bail!("Unsupported integrity superblock profile");
    }
    if offset < 32768 || offset % 4096 != 0 || offset.checked_add(4096).map_or(true, |e| e > file_size) {
        bail!("Invalid integrity offset");
    }
    let factor = 1u64 << block;
    if !(1..=4096).contains(&sections) || provided == 0 || provided % factor != 0 {
        bail!("Invalid integrity dimensions");
    }
    // Pinned Linux: header address8 + saved data-sector tails8*factor + tuple[28|32].
    let entry_bytes = (8 + 8 * factor + tuple_size).div_ceil(8) * 8;
    let section_sectors = (504 / entry_bytes) * 8 * factor + 8;
    let initial = 8 + section_sectors * sections;
    let metadata_run = (tuple_size * (32768 / factor)).div_ceil(4096) * 8;
    let Some(primary_bytes) = provided.checked_mul(512) else { bail!("Invalid integrity dimensions") };
    let layout = Layout {
        integrity_offset: offset, primary_bytes, journal_sections: sections,
        journal_section_sectors: section_sectors, initial_sectors: initial,
        metadata_run_sectors: metadata_run, interleave_sectors: 32768,
        sector_size: 512 * factor, tag_bytes: 16, iv_bytes: tuple_size - 16,
    };
    if layout.sectors() == 0 {
        bail!("Invalid integrity dimensions");
    }
    let Some((data, tag)) = layout.offsets(layout.sectors() - 1) else { bail!("Primary extents exceed image size") };
    if data.checked_add(layout.sector_size).map_or(true, |e| e > file_size)
        || tag.checked_add(tuple_size).map_or(true, |e| e > file_size) {
        bail!("Primary extents exceed image size");
    }
    Ok(layout)
}

/// Exactly one ordinary pinned-profile segment; returns its byte offset.
pub fn validate_segment(metadata: &Value) -> Result<u64> {
    let Some(config) = metadata.get("config").filter(|c| c.as_object().is_some()) else {
        bail!("Invalid LUKS2 metadata")
    };
    if config.get("requirements").is_some_and(Value::is_truthy) {
        bail!("Unsupported LUKS2 requirements");
    }
    let segments = metadata.get("segments").and_then(Value::as_object);
    let Some(segments) = segments.filter(|s| s.len() == 1 && s.contains_key("0")) else {
        bail!("Exactly one ordinary segment is supported")
    };
    let segment = &segments["0"];
    let expected = ["encryption", "integrity", "iv_tweak", "offset", "sector_size", "size", "type"];
    let Some(fields) = segment.as_object().filter(|f| f.keys().map(String::as_str).eq(expected)) else {
        bail!("Unsupported segment fields")
    };
    let encryption = fields["encryption"].as_str();
    let Some((integrity, _)) = encryption.and_then(profile) else { bail!("Unsupported primary encryption profile") };
    if fields["type"].as_str() != Some("crypt") || fields["size"].as_str() != Some("dynamic")
        || fields["iv_tweak"].as_str() != Some("0")
        || !matches!(fields["sector_size"].as_u64(), Some(512 | 4096)) {
        bail!("Unsupported primary encryption profile");
    }
    let integrity_ok = fields["integrity"].as_object().is_some_and(|i| {
        i.len() == 3 && i.get("type").and_then(Value::as_str) == Some(integrity)
            && i.get("journal_encryption").and_then(Value::as_str) == Some("none")
            && i.get("journal_integrity").and_then(Value::as_str) == Some("none")
    });
    if !integrity_ok {
        bail!("Unsupported integrity/journal algorithms");
    }
    let offset = fields["offset"].as_str().filter(|o| !o.is_empty() && o.bytes().all(|b| b.is_ascii_digit()));
    match offset.and_then(|o| o.parse().ok()) {
        Some(value) => Ok(value),
        None => bail!("Invalid segment offset"),
    }
}

/// LUKS2 persistent activation flags: none, or exactly "no-journal" (stock
/// `cryptsetup open --integrity-no-journal --persistent`). Any other flag
/// would change the stock tables and is refused.
pub fn no_journal(metadata: &Value) -> Result<bool> {
    match metadata.get("config").and_then(|c| c.get("flags")) {
        None => Ok(false),
        Some(Value::Array(flags)) if flags.is_empty() => Ok(false),
        Some(Value::Array(flags)) if flags.len() == 1 && flags[0].as_str() == Some("no-journal") => Ok(true),
        Some(_) => bail!("Unsupported LUKS2 activation flags"),
    }
}

/// The stock lower dm-integrity table produced by pinned cryptsetup: journaled
/// ("J") by default, or direct ("D") when the volume persists "no-journal".
#[allow(clippy::too_many_arguments)]
pub fn validate_integrity_table(table: &str, sectors: u64, raw_major: u32, raw_minor: u32, offset: u64,
                                sector_size: u64, journal_sectors: u64, tuple_size: u64,
                                no_journal: bool) -> Result<()> {
    if tuple_size != 32 {
        bail!("Unsupported lower tuple size");
    }
    let words: Vec<&str> = table.split_whitespace().collect();
    let length = sectors.checked_mul(sector_size / 512).map(|v| v.to_string()).unwrap_or_default();
    let device = format!("{raw_major}:{raw_minor}");
    let (start_sector, tuple) = ((offset / 512).to_string(), tuple_size.to_string());
    if words.len() < 8 || words[..3] != ["0", length.as_str(), "integrity"]
        || words[3..7] != [device.as_str(), start_sector.as_str(), tuple.as_str(), if no_journal { "D" } else { "J" }]
        || words[7].parse::<usize>().ok() != Some(words.len() - 8) {
        bail!("Unsupported lower integrity mapping");
    }
    let options = &words[8..];
    let buffer = "buffer_sectors:128";
    let mut required = vec!["interleave_sectors:32768", buffer, "fix_padding"];
    if !no_journal {
        required.extend(["journal_watermark:50", "commit_time:10000"]);
    }
    match sector_size {
        4096 => required.push("block_size:4096"),
        512 => {}
        _ => bail!("Unsupported lower sector size"),
    }
    let mut unique: Vec<&str> = options.to_vec();
    unique.sort_unstable();
    unique.dedup();
    if options.len() != required.len() + 1 || unique.len() != options.len()
        || !required.iter().all(|r| options.contains(r)) {
        bail!("Unsupported lower integrity options");
    }
    let extra: Vec<&&str> = options.iter().filter(|o| !required.contains(o)).collect();
    let journal = match extra.as_slice() {
        [one] if one.starts_with("journal_sectors:") => one["journal_sectors:".len()..].parse::<u64>().ok(),
        _ => bail!("Unsupported lower integrity journal"),
    };
    if journal != Some(journal_sectors) {
        bail!("Unsupported lower integrity journal size");
    }
    Ok(())
}

/// Format v4 base context (docs/format-v4.md):
/// "pivstore/volume/v4\0" UUID NUL LE64 primary bytes LE64 sector size.
/// The kernel appends "/ab" itself for the A/B layout.
pub fn context_v4(uuid: &str, primary_bytes: u64, sector_size: u64) -> Vec<u8> {
    let mut value = b"pivstore/volume/v4\0".to_vec();
    value.extend_from_slice(uuid.as_bytes());
    value.push(0);
    value.extend_from_slice(&primary_bytes.to_le_bytes());
    value.extend_from_slice(&sector_size.to_le_bytes());
    value
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json::parse;

    fn superblock(tuple: u16, sections: u32, provided: u64, block: u8) -> Vec<u8> {
        let mut h = vec![0u8; 4096];
        h[..8].copy_from_slice(b"integrt\0");
        h[8] = 4;
        h[9] = 15;
        h[10..12].copy_from_slice(&tuple.to_le_bytes());
        h[12..16].copy_from_slice(&sections.to_le_bytes());
        h[16..24].copy_from_slice(&provided.to_le_bytes());
        h[24..28].copy_from_slice(&8u32.to_le_bytes());
        h[28] = block;
        h
    }

    #[test]
    fn superblock_geometry_matches_python_reference() {
        // AEGIS-128 4096-byte fixture shape (32-byte tuples, as tests/test_profile.py).
        let layout = parse_superblock(&superblock(32, 7, 231_456, 3), 16_777_216, 1 << 30).unwrap();
        assert_eq!((layout.sector_size, layout.iv_bytes, layout.sectors()), (4096, 16, 28_932));
        assert_eq!(layout.journal_section_sectors, (504 / 104) * 64 + 8);
        assert_eq!(layout.initial_sectors, 8 + layout.journal_section_sectors * 7);
        assert_eq!(layout.metadata_run_sectors, (32 * 4096u64).div_ceil(4096) * 8);
        let layout = parse_superblock(&superblock(32, 7, 2048, 0), 16_777_216, 1 << 30).unwrap();
        assert_eq!((layout.sector_size, layout.iv_bytes), (512, 16));
        for bad in [superblock(28, 7, 2048, 0), superblock(30, 7, 2048, 0), superblock(32, 0, 2048, 0),
                    superblock(32, 7, 2049, 3)] {
            assert!(parse_superblock(&bad, 16_777_216, 1 << 30).is_err());
        }
        assert!(parse_superblock(&superblock(32, 7, 2048, 0), 1000, 1 << 30).is_err());
        assert!(parse_superblock(&superblock(32, 7, 1 << 40, 0), 16_777_216, 1 << 30).is_err());
    }

    fn metadata(encryption: &str, integrity: &str, extra: &str) -> Value {
        parse(&format!(r#"{{"config":{{"requirements":{{}}}},"segments":{{"0":{{"type":"crypt","offset":"16777216",
            "size":"dynamic","iv_tweak":"0","encryption":"{encryption}","sector_size":4096,
            "integrity":{{"type":"{integrity}","journal_encryption":"none","journal_integrity":"none"}}{extra}}}}}}}"#))
            .unwrap()
    }

    #[test]
    fn segment_validation() {
        assert_eq!(validate_segment(&metadata("aegis128-random", "aead", "")).unwrap(), 16_777_216);
        assert!(validate_segment(&metadata("chacha20-random", "poly1305", "")).is_err());
        assert!(validate_segment(&metadata("aes-gcm-random", "aead", "")).is_err());
        assert!(validate_segment(&metadata("aegis128-random", "poly1305", "")).is_err());
        assert!(validate_segment(&metadata("aes-xts-plain64", "aead", "")).is_err());
        assert!(validate_segment(&metadata("aegis128-random", "aead", r#","flags":[]"#)).is_err());
        let required = parse(r#"{"config":{"requirements":{"mandatory":["online-reencrypt"]}},"segments":{}}"#).unwrap();
        assert!(validate_segment(&required).is_err());
    }

    #[test]
    fn integrity_table_validation() {
        let table = "0 231456 integrity 254:16 32768 32 J 7 journal_sectors:1848 interleave_sectors:32768 \
                     buffer_sectors:128 journal_watermark:50 commit_time:10000 fix_padding block_size:4096";
        validate_integrity_table(table, 28_932, 254, 16, 16_777_216, 4096, 1848, 32, false).unwrap();
        assert!(validate_integrity_table(table, 28_932, 254, 16, 16_777_216, 4096, 1849, 32, false).is_err());
        assert!(validate_integrity_table(table, 28_932, 254, 16, 16_777_216, 4096, 1848, 28, false).is_err());
        assert!(validate_integrity_table(&table.replace(" J ", " D "), 28_932, 254, 16, 16_777_216, 4096, 1848, 32, false).is_err());
        // Direct mode (persistent no-journal): exactly the observed stock options.
        let direct = "0 231456 integrity 254:16 32768 32 D 5 block_size:4096 journal_sectors:1848 \
                      interleave_sectors:32768 buffer_sectors:128 fix_padding";
        validate_integrity_table(direct, 28_932, 254, 16, 16_777_216, 4096, 1848, 32, true).unwrap();
        assert!(validate_integrity_table(direct, 28_932, 254, 16, 16_777_216, 4096, 1848, 32, false).is_err());
        assert!(validate_integrity_table(table, 28_932, 254, 16, 16_777_216, 4096, 1848, 32, true).is_err());
        let flags = |text: &str| parse(&format!(r#"{{"config":{{"flags":{text}}}}}"#)).unwrap();
        assert!(!no_journal(&flags("[]")).unwrap());
        assert!(no_journal(&flags(r#"["no-journal"]"#)).unwrap());
        assert!(no_journal(&flags(r#"["allow-discards"]"#)).is_err());
        assert!(no_journal(&flags(r#"["no-journal","allow-discards"]"#)).is_err());
        assert!(validate_integrity_table(&table.replace("fix_padding", "fix_hmac"), 28_932, 254, 16, 16_777_216, 4096, 1848, 32, false).is_err());
    }

    #[test]
    fn contexts() {
        let uuid = "00000000-0000-4000-8000-000000000000";
        let v4 = context_v4(uuid, 128 << 20, 4096);
        assert!(v4.starts_with(b"pivstore/volume/v4\0") && v4.len() == 19 + 36 + 1 + 16);
        assert_eq!(&v4[56..64], &(128u64 << 20).to_le_bytes());
        assert_eq!(&v4[64..72], &4096u64.to_le_bytes());
    }
}
