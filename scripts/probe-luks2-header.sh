#!/usr/bin/env bash
# Probe stock LUKS2 header keyslot-area behaviour, AF-stripe embedding, payload
# sizes, and stock-initramfs unlock primitives inside the disposable guest.
source /mnt/piv-work/guest-common.sh

guest_packages python3-cryptography \
    linux-headers-6.12.113+deb13-amd64=6.12.113-1 gcc-14 make
dpkg-query -W -f='${Package}\t${Version}\n' > /mnt/piv-work/packages.tsv

guest_build_module

python3 - <<'PY'
import hashlib
import json
import math
import os
import shutil
import struct
import subprocess
import tempfile
from pathlib import Path
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

DEV = "/dev/vdb"
HDR_TOTAL = 16 * 1024 * 1024  # default 16 MiB LUKS2 header + keyslots area
PAGE = 4096


def run(cmd, check=True, input_bytes=None):
    return subprocess.run(cmd, check=check, input=input_bytes,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts if c)


def chi_square_uniform(data: bytes) -> float:
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    expected = len(data) / 256.0
    return sum(((c - expected) ** 2) / expected for c in counts)


def zero_pages(data: bytes) -> int:
    return sum(
        1 for off in range(0, len(data), PAGE)
        if data[off:off + PAGE] == b"\x00" * PAGE
    )


def page_digests(data: bytes) -> list[bytes]:
    return [
        hashlib.sha256(data[off:off + PAGE]).digest()
        for off in range(0, len(data), PAGE)
    ]


def diff_ranges(before: list[bytes], after: list[bytes]) -> list[list[int]]:
    changed = [i for i, (a, b) in enumerate(zip(before, after)) if a != b]
    if not changed:
        return []
    ranges = []
    start = prev = changed[0]
    for idx in changed[1:]:
        if idx == prev + 1:
            prev = idx
        else:
            ranges.append([start * PAGE, (prev + 1) * PAGE])
            start = prev = idx
    ranges.append([start * PAGE, (prev + 1) * PAGE])
    return ranges


def read_hdr(size: int = HDR_TOTAL) -> bytes:
    with open(DEV, "rb") as f:
        return f.read(size)


def write_at(offset: int, data: bytes) -> None:
    with open(DEV, "r+b") as f:
        f.seek(offset)
        f.write(data)
        f.flush()
        os.fsync(f.fileno())


def luks_json() -> dict:
    out = run(["cryptsetup", "luksDump", "--dump-json-metadata", DEV]).stdout
    return json.loads(out.decode("utf-8"))


work = Path(tempfile.mkdtemp(prefix="hdr-probe-"))
k0 = work / "k0.key"
k1 = work / "k1.key"
k2 = work / "k2.key"
k0.write_bytes(b"0" * 64)
k1.write_bytes(b"1" * 64)
k2.write_bytes(b"2" * 64)

results = {"profiles": {}, "operations": {}, "af_stripe_proof": {}, "sizes": {}, "initramfs": {}}

# 1. Measure fresh luksFormat layout and unallocated keyslot-area entropy across profiles.
profiles = [
    ("aes-xts-512-hmac-sha256", [
        "--cipher", "aes-xts-random", "--key-size", "512",
        "--integrity", "hmac-sha256", "--sector-size", "512",
    ]),
    ("aes-xts-256-hmac-sha256", [
        "--cipher", "aes-xts-random", "--key-size", "256",
        "--integrity", "hmac-sha256", "--sector-size", "512",
    ]),
    ("aegis128-random", [
        "--cipher", "aegis128-random", "--key-size", "128",
        "--integrity", "aead", "--sector-size", "512",
    ]),
]

for name, extra_args in profiles:
    # Pre-fill first 20 MiB with a known non-zero, non-random pattern (0xA5)
    # to distinguish zero-wiped regions, random-wiped regions, and untouched regions.
    write_at(0, b"\xa5" * (20 * 1024 * 1024))
    run([
        "cryptsetup", "luksFormat", "--batch-mode", "--type", "luks2",
        "--pbkdf", "argon2id", "--pbkdf-force-iterations", "4",
        "--pbkdf-memory", "32768", "--pbkdf-parallel", "1",
        *extra_args, DEV, str(k0),
    ])
    meta = luks_json()
    slot0 = meta["keyslots"]["0"]
    seg0 = meta["segments"]["0"]
    cfg = meta["config"]
    slot_off = int(slot0["area"]["offset"])
    slot_size = int(slot0["area"]["size"])
    vk_size = int(slot0["key_size"])
    stripes = int(slot0["af"]["stripes"])
    af_bytes = vk_size * stripes
    af_sector_bytes = ((af_bytes + 511) // 512) * 512
    data_off = int(seg0["offset"])
    json_size = int(cfg["json_size"])
    keyslots_size = int(cfg["keyslots_size"])
    hdr_bin_and_json = (json_size + 4096) * 2

    raw = read_hdr(data_off)
    unused_start = slot_off + slot_size
    unused_end = hdr_bin_and_json + keyslots_size
    unused = raw[unused_start:unused_end]
    slot_tail = raw[slot_off + af_sector_bytes:slot_off + slot_size]

    results["profiles"][name] = {
        "vk_bytes": vk_size,
        "af_stripes": stripes,
        "af_raw_bytes": af_bytes,
        "af_sector_rounded_bytes": af_sector_bytes,
        "chosen_stripes_3999_bytes": vk_size * (stripes - 1),
        "slot0_area_offset": slot_off,
        "slot0_area_size": slot_size,
        "slot0_4k_padding_tail_bytes": len(slot_tail),
        "slot0_4k_padding_tail_entropy": round(shannon_entropy(slot_tail), 6) if slot_tail else None,
        "json_size": json_size,
        "metadata_copy_bytes": json_size + 4096,
        "two_metadata_copies_bytes": hdr_bin_and_json,
        "keyslots_size": keyslots_size,
        "data_offset_bytes": data_off,
        "unused_keyslots_offset": unused_start,
        "unused_keyslots_bytes": len(unused),
        "unused_keyslots_zero_4k_pages": zero_pages(unused),
        "unused_keyslots_shannon_entropy": round(shannon_entropy(unused), 6),
        "unused_keyslots_chi_square": round(chi_square_uniform(unused), 2),
        "max_slots_by_space": keyslots_size // slot_size,
    }

# 2. Format with the recommended profile (aes-xts-512-hmac-sha256) and trace operations.
write_at(0, b"\xa5" * (20 * 1024 * 1024))
run([
    "cryptsetup", "luksFormat", "--batch-mode", "--type", "luks2",
    "--cipher", "aes-xts-random", "--key-size", "512",
    "--integrity", "hmac-sha256", "--sector-size", "512",
    "--pbkdf", "argon2id", "--pbkdf-force-iterations", "4",
    "--pbkdf-memory", "32768", "--pbkdf-parallel", "1",
    DEV, str(k0),
])

# Plant a 64 KiB pseudorandom marker in the upper tail of the keyslots area
# at [14 MiB, 14 MiB + 64 KiB) to verify whether operations preserve it.
TAIL_OFFSET = 14 * 1024 * 1024
marker = hashlib.shake_256(b"piv-header-stash-probe-marker").digest(65536)
write_at(TAIL_OFFSET, marker)


def record_op(op_name, fn):
    before_raw = read_hdr()
    before_dig = page_digests(before_raw)
    fn()
    after_raw = read_hdr()
    after_dig = page_digests(after_raw)
    meta = luks_json()
    slots_summary = {
        k: {"offset": int(v["area"]["offset"]), "size": int(v["area"]["size"])}
        for k, v in meta.get("keyslots", {}).items()
    }
    results["operations"][op_name] = {
        "changed_4k_ranges": diff_ranges(before_dig, after_dig),
        "keyslots_after": slots_summary,
        "tail_marker_intact": after_raw[TAIL_OFFSET:TAIL_OFFSET + len(marker)] == marker,
    }


record_op("open_close_default", lambda: (
    run(["cryptsetup", "open", DEV, "probe-tmp", "--key-file", str(k0)]),
    run(["cryptsetup", "close", "probe-tmp"]),
))

record_op("open_close_persistent_no_journal", lambda: (
    run(["cryptsetup", "open", "--integrity-no-journal", "--persistent",
         DEV, "probe-tmp", "--key-file", str(k0)]),
    run(["cryptsetup", "close", "probe-tmp"]),
))

record_op("config_label", lambda: (
    run(["cryptsetup", "config", "--label", "data-vol", DEV]),
))

record_op("token_add_remove", lambda: (
    run(["cryptsetup", "token", "import", "--token-id", "0", DEV],
        input_bytes=b'{"type":"user","keyslots":["0"]}'),
    run(["cryptsetup", "token", "remove", "--token-id", "0", DEV]),
))

record_op("repair_healthy", lambda: (
    run(["cryptsetup", "repair", DEV]),
))

def corrupt_and_repair():
    write_at(16384, b"\x00" * 4096)
    run(["cryptsetup", "repair", DEV])

record_op("repair_corrupted_secondary_header", corrupt_and_repair)

record_op("luksAddKey_slot1", lambda: (
    run(["cryptsetup", "luksAddKey", "--batch-mode",
         "--pbkdf", "argon2id", "--pbkdf-force-iterations", "4",
         "--pbkdf-memory", "32768", "--pbkdf-parallel", "1",
         DEV, str(k1), "--key-file", str(k0)]),
))

record_op("luksKillSlot_slot1", lambda: (
    run(["cryptsetup", "luksKillSlot", "--batch-mode", DEV, "1", "--key-file", str(k0)]),
))

record_op("luksChangeKey_slot0_first", lambda: (
    run(["cryptsetup", "luksChangeKey", "--batch-mode",
         "--pbkdf", "argon2id", "--pbkdf-force-iterations", "4",
         "--pbkdf-memory", "32768", "--pbkdf-parallel", "1",
         DEV, str(k1), "--key-file", str(k0)]),
))

record_op("luksChangeKey_slot0_second", lambda: (
    run(["cryptsetup", "luksChangeKey", "--batch-mode",
         "--pbkdf", "argon2id", "--pbkdf-force-iterations", "4",
         "--pbkdf-memory", "32768", "--pbkdf-parallel", "1",
         DEV, str(k0), "--key-file", str(k1)]),
))

record_op("luksConvertKey_slot0", lambda: (
    run(["cryptsetup", "luksConvertKey", "--batch-mode",
         "--pbkdf", "argon2id", "--pbkdf-force-iterations", "4",
         "--pbkdf-memory", "65536", "--pbkdf-parallel", "1",
         DEV, "--key-file", str(k0)]),
))

# Normalize slot 0 back to offset 32768 by running luksConvertKey once more.
record_op("luksConvertKey_slot0_back_to_32768", lambda: (
    run(["cryptsetup", "luksConvertKey", "--batch-mode",
         "--pbkdf", "argon2id", "--pbkdf-force-iterations", "4",
         "--pbkdf-memory", "32768", "--pbkdf-parallel", "1",
         DEV, "--key-file", str(k0)]),
))

bkp = work / "hdr.backup"
run(["cryptsetup", "luksHeaderBackup", DEV, "--header-backup-file", str(bkp)])
bkp_bytes = bkp.read_bytes()

# Overwrite tail marker on disk, then restore from backup and verify marker returns.
write_at(TAIL_OFFSET, b"\x00" * len(marker))
record_op("luksHeaderRestore", lambda: (
    run(["cryptsetup", "luksHeaderRestore", "--batch-mode", DEV, "--header-backup-file", str(bkp)]),
))
results["operations"]["luksHeaderBackup_info"] = {
    "backup_file_bytes": len(bkp_bytes),
    "backup_preserves_tail_marker": bkp_bytes[TAIL_OFFSET:TAIL_OFFSET + len(marker)] == marker,
}

# Confirm reencrypt is refused on integrity volumes.
reenc = run(["cryptsetup", "reencrypt", "--batch-mode", DEV, "--key-file", str(k0)], check=False)
results["operations"]["reencrypt_refused"] = {
    "returncode": reenc.returncode,
    "stderr": reenc.stderr.decode("utf-8", errors="replace").strip(),
}

# 3. Live verification of the chosen AF-stripe construction in active keyslot 0.
# Convert slot 0 to PBKDF2-SHA256 for simple KDF derivation in Python (the AF and XTS
# storage steps are identical for Argon2id and PBKDF2 keyslots).
run([
    "cryptsetup", "luksConvertKey", "--batch-mode",
    "--pbkdf", "pbkdf2", "--hash", "sha256", "--pbkdf-force-iterations", "1000",
    DEV, "--key-file", str(k0),
])
# Convert once more so slot 0 sits at offset 32768.
run([
    "cryptsetup", "luksConvertKey", "--batch-mode",
    "--pbkdf", "pbkdf2", "--hash", "sha256", "--pbkdf-force-iterations", "1000",
    DEV, "--key-file", str(k0),
])

# Write a known pattern to the unlocked primary volume first to verify it after AF embedding.
run(["cryptsetup", "open", DEV, "af-test", "--key-file", str(k0)])
with open("/dev/mapper/af-test", "wb") as f:
    f.write(hashlib.sha256(b"primary-test-sector").digest() * 128)
    f.flush()
    os.fsync(f.fileno())
run(["cryptsetup", "close", "af-test"])

import base64

meta = luks_json()
slot0 = meta["keyslots"]["0"]
slot_off = int(slot0["area"]["offset"])
slot_size = int(slot0["area"]["size"])
vk_len = int(slot0["key_size"])  # 96
stripes = int(slot0["af"]["stripes"])  # 4000
af_bytes = vk_len * stripes  # 384000
salt = base64.b64decode(slot0["kdf"]["salt"])
iters = int(slot0["kdf"]["iterations"])
area_key_len = int(slot0["area"]["key_size"])  # 64

derived_key = hashlib.pbkdf2_hmac("sha256", k0.read_bytes(), salt, iters, dklen=area_key_len)


def xts_crypt(buf: bytes, key: bytes, encrypt: bool) -> bytes:
    out = bytearray(len(buf))
    for sec in range(len(buf) // 512):
        tweak = struct.pack("<Q", sec) + b"\x00" * 8
        cipher = Cipher(algorithms.AES(key), modes.XTS(tweak))
        ctx = cipher.encryptor() if encrypt else cipher.decryptor()
        chunk = buf[sec * 512:(sec + 1) * 512]
        out[sec * 512:(sec + 1) * 512] = ctx.update(chunk) + ctx.finalize()
    return bytes(out)


def af_diffuse_sha256(block: bytes) -> bytes:
    out = bytearray()
    full_blocks = len(block) // 32
    rem = len(block) % 32
    for i in range(full_blocks):
        h = hashlib.sha256()
        h.update(struct.pack(">I", i))
        h.update(block[i * 32:(i + 1) * 32])
        out.extend(h.digest())
    if rem:
        h = hashlib.sha256()
        h.update(struct.pack(">I", full_blocks))
        h.update(block[full_blocks * 32:])
        out.extend(h.digest()[:rem])
    return bytes(out)


def af_merge_prefix(af_buf: bytes, blocksize: int, count: int) -> bytes:
    buf = b"\x00" * blocksize
    for i in range(count):
        stripe = af_buf[i * blocksize:(i + 1) * blocksize]
        xored = bytes(a ^ b for a, b in zip(stripe, buf))
        buf = af_diffuse_sha256(xored)
    return buf


# Recover actual VK from existing slot 0 to verify Python decrypt + AF_merge matches cryptsetup.
orig_cipher = read_hdr()[slot_off:slot_off + af_bytes]
orig_af = xts_crypt(orig_cipher, derived_key, encrypt=False)
b_3999_orig = af_merge_prefix(orig_af, vk_len, stripes - 1)
last_orig = orig_af[(stripes - 1) * vk_len:stripes * vk_len]
vk = bytes(a ^ b for a, b in zip(last_orig, b_3999_orig))

# Verify against cryptsetup --dump-volume-key.
vk_dump = work / "vk.bin"
run(["cryptsetup", "luksDump", "--batch-mode", "--dump-volume-key",
     "--volume-key-file", str(vk_dump), "--key-file", str(k0), DEV])
assert vk == vk_dump.read_bytes(), "Recovered VK mismatch"

# Construct a chosen 383,904-byte ciphertext payload for stripes 0..3998.
chosen_len = (stripes - 1) * vk_len  # 383,904 bytes
chosen_blob = hashlib.shake_256(b"chosen-af-stripes-hidden-stash-payload").digest(chosen_len)

# Decrypt the chosen on-disk ciphertext (padded with 96 dummy bytes) under derived_key
# to obtain the corresponding AF plaintext stripes 0..3998.
padded_cipher = chosen_blob + b"\x00" * vk_len
decrypted_prefix = xts_crypt(padded_cipher, derived_key, encrypt=False)[:chosen_len]

# Compute b_3999 over decrypted stripes 0..3998 and solve stripe 3999 = VK ^ b_3999.
b_3999_new = af_merge_prefix(decrypted_prefix, vk_len, stripes - 1)
d_3999_new = bytes(a ^ b for a, b in zip(vk, b_3999_new))
new_af_plain = decrypted_prefix + d_3999_new
new_slot_cipher = xts_crypt(new_af_plain, derived_key, encrypt=True)

# Write new_slot_cipher into slot 0 on disk.
write_at(slot_off, new_slot_cipher)
disk_slot_cipher = read_hdr()[slot_off:slot_off + af_bytes]

# Verify stock cryptsetup opens the modified keyslot and authenticates the primary data!
run(["cryptsetup", "open", DEV, "af-test", "--key-file", str(k0)])
with open("/dev/mapper/af-test", "rb") as f:
    primary_check = f.read(4096)
run(["cryptsetup", "close", "af-test"])

results["af_stripe_proof"] = {
    "slot_offset": slot_off,
    "vk_bytes": vk_len,
    "af_total_bytes": af_bytes,
    "chosen_payload_bytes": chosen_len,
    "solved_final_stripe_bytes": vk_len,
    "on_disk_prefix_exact_match": disk_slot_cipher[:chosen_len] == chosen_blob,
    "stock_cryptsetup_open_succeeded": True,
    "primary_plaintext_verified": primary_check == hashlib.sha256(b"primary-test-sector").digest() * 128,
    "on_disk_shannon_entropy": round(shannon_entropy(disk_slot_cipher), 6),
    "decrypted_af_shannon_entropy": round(shannon_entropy(new_af_plain), 6),
}

# 4. Measure binary and module sizes (raw, stripped, xz -9e, gzip -9).
ko_raw = Path("/mnt/piv-work/experimental-dm-piv.ko")
ko_debug_stripped = work / "dm-piv.strip-debug.ko"
ko_unneeded_stripped = work / "dm-piv.strip-unneeded.ko"
shutil.copyfile(ko_raw, ko_debug_stripped)
shutil.copyfile(ko_raw, ko_unneeded_stripped)
run(["strip", "--strip-debug", str(ko_debug_stripped)])
run(["strip", "--strip-unneeded", str(ko_unneeded_stripped)])

# Verify insmod works with --strip-unneeded module!
run(["modprobe", "dm-mod"])
run(["modprobe", "dm-crypt"])
run(["modprobe", "dm-integrity"])
run(["insmod", str(ko_unneeded_stripped)])
run(["rmmod", "dm_piv"])


def compressed_sizes(p: Path) -> dict:
    raw_b = p.read_bytes()
    xz_b = run(["xz", "-9e", "-c", str(p)]).stdout
    gz_b = run(["gzip", "-9", "-c", str(p)]).stdout
    return {
        "raw_bytes": len(raw_b),
        "xz_9e_bytes": len(xz_b),
        "gzip_9_bytes": len(gz_b),
    }


piv_raw = Path("/mnt/piv-work/pivsetup")
piv_stripped = work / "pivsetup.stripped"
shutil.copyfile(piv_raw, piv_stripped)
run(["strip", "--strip-all", str(piv_stripped)])

# Bundle stripped pivsetup + strip-unneeded dm-piv.ko + 1 KiB unlock script + two 64B keys into a .tar.xz
bundle_dir = work / "bundle"
bundle_dir.mkdir()
shutil.copyfile(piv_stripped, bundle_dir / "pivsetup")
os.chmod(bundle_dir / "pivsetup", 0o755)
shutil.copyfile(ko_unneeded_stripped, bundle_dir / "dm-piv.ko")
(bundle_dir / "luks.key").write_bytes(os.urandom(64))
(bundle_dir / "hidden.key").write_bytes(os.urandom(64))
(bundle_dir / "unlock.sh").write_text(
    "#!/bin/sh\nset -eu\ninsmod /run/piv-stash/dm-piv.ko\n"
    "/run/piv-stash/pivsetup open-blocks --device \"$1\" "
    "--key-file /run/piv-stash/luks.key --hidden-key-file /run/piv-stash/hidden.key\n"
)
bundle_tar = work / "bundle.tar"
run(["tar", "-cf", str(bundle_tar), "-C", str(bundle_dir), "."])
bundle_tar_xz = run(["xz", "-9e", "-c", str(bundle_tar)]).stdout
# Pad to 512-byte sector boundary for dm-crypt plain mode
padded_len = ((len(bundle_tar_xz) + 511) // 512) * 512

results["sizes"] = {
    "dm_piv_ko_raw": compressed_sizes(ko_raw),
    "dm_piv_ko_strip_debug": compressed_sizes(ko_debug_stripped),
    "dm_piv_ko_strip_unneeded": compressed_sizes(ko_unneeded_stripped),
    "pivsetup_release": compressed_sizes(piv_raw),
    "pivsetup_strip_all": compressed_sizes(piv_stripped),
    "combined_bundle_tar_bytes": bundle_tar.stat().st_size,
    "combined_bundle_tar_xz_9e_bytes": len(bundle_tar_xz),
    "combined_bundle_512_padded_bytes": padded_len,
}

# 5. Test end-to-end stash encryption in the unallocated tail of the LUKS2 keyslots area
# and unlocking with stock tools (cryptsetup --type plain --offset/--size + tar/xz and ext4).
STASH_OFFSET = 14 * 1024 * 1024  # 14 MiB offset inside the 16 MiB LUKS2 header
STASH_SIZE = 2 * 1024 * 1024     # 2 MiB slice [14 MiB, 16 MiB)
STASH_OFFSET_SECTORS = STASH_OFFSET // 512  # 28672
STASH_SIZE_SECTORS = STASH_SIZE // 512      # 4096
stash_pass_bytes = b"correct-horse-battery-staple-high-entropy-passphrase\n"
stash_key = work / "stash.key"
stash_key.write_bytes(hashlib.sha512(b"stash-kdf-derived-key").digest())  # 64 bytes (512 bits)

run([
    "cryptsetup", "open", "--batch-mode", "--type", "plain",
    "--offset", str(STASH_OFFSET_SECTORS), "--size", str(STASH_SIZE_SECTORS),
    "--cipher", "aes-xts-plain64", "--key-size", "512", "--hash", "sha512",
    DEV, "piv-stash-plain",
], input_bytes=stash_pass_bytes)
try:
    with open("/dev/mapper/piv-stash-plain", "r+b") as f:
        f.write(bundle_tar_xz)
        f.flush()
        os.fsync(f.fileno())
finally:
    run(["cryptsetup", "close", "piv-stash-plain"])

# Measure entropy of the 2 MiB stash region on disk after writing the encrypted archive.
stash_on_disk = read_hdr()[STASH_OFFSET:STASH_OFFSET + STASH_SIZE]

# Re-open read-only directly via --offset/--size (no losetup needed) and extract to tmpfs.
extract_dir = work / "extracted"
extract_dir.mkdir()
run([
    "cryptsetup", "open", "--batch-mode", "--readonly", "--type", "plain",
    "--offset", str(STASH_OFFSET_SECTORS), "--size", str(STASH_SIZE_SECTORS),
    "--cipher", "aes-xts-plain64", "--key-size", "512", "--hash", "sha512",
    DEV, "piv-stash-ro",
], input_bytes=stash_pass_bytes)
try:
    with open("/dev/mapper/piv-stash-ro", "rb") as f:
        recovered_xz = f.read(len(bundle_tar_xz))
    decomp = run(["xz", "-dc"], input_bytes=recovered_xz).stdout
    run(["tar", "-xf", "-", "-C", str(extract_dir)], input_bytes=decomp)
    # Also verify xz --single-stream directly on the block device without knowing length:
    single_stream_out = run(["xz", "--single-stream", "-dc", "/dev/mapper/piv-stash-ro"]).stdout
    assert single_stream_out == decomp, "xz --single-stream output mismatch"
finally:
    run(["cryptsetup", "close", "piv-stash-ro"])

# Also test an ext4 filesystem inside the 2 MiB dm-plain slice holding .xz files (using 64B --key-file):
run([
    "cryptsetup", "open", "--batch-mode", "--type", "plain",
    "--offset", str(STASH_OFFSET_SECTORS), "--size", str(STASH_SIZE_SECTORS),
    "--cipher", "aes-xts-plain64", "--key-size", "512",
    "--key-file", str(stash_key), DEV, "piv-stash-fs",
])
try:
    run(["mkfs.ext4", "-q", "-F", "-O", "^has_journal", "-b", "1024", "-m", "0",
         "/dev/mapper/piv-stash-fs"])
    mnt = work / "mnt"
    mnt.mkdir()
    run(["mount", "-t", "ext4", "/dev/mapper/piv-stash-fs", str(mnt)])
    try:
        (mnt / "pivsetup.xz").write_bytes(run(["xz", "-9e", "-c", str(piv_stripped)]).stdout)
        (mnt / "dm-piv.ko.xz").write_bytes(run(["xz", "-9e", "-c", str(ko_unneeded_stripped)]).stdout)
        (mnt / "unlock.sh").write_text("#!/bin/sh\nset -eu\n")
        os.sync()
        df_out = run(["df", "-B1", str(mnt)]).stdout.decode()
    finally:
        run(["umount", str(mnt)])
finally:
    run(["cryptsetup", "close", "piv-stash-fs"])
ext4_stash_on_disk = read_hdr()[STASH_OFFSET:STASH_OFFSET + STASH_SIZE]

# Verify stock cryptsetup luksDump and open on /dev/vdb still succeed with the stash present.
run(["cryptsetup", "open", DEV, "verify-with-stash", "--key-file", str(k0)])
run(["cryptsetup", "close", "verify-with-stash"])

# Inspect stock Debian initramfs contents if present in /boot.
initrds = sorted(Path("/boot").glob("initrd.img-*"))
initramfs_info = {"found": [str(p) for p in initrds]}
if initrds:
    listing = run(["lsinitramfs", str(initrds[0])], check=False).stdout.decode().splitlines()
    interesting = [
        line for line in listing
        if any(tok in line for tok in (
            "bin/busybox", "bin/sh", "sbin/cryptsetup", "sbin/dmsetup",
            "sbin/losetup", "bin/dd", "bin/xz", "bin/unxz", "bin/tar",
            "sbin/insmod", "sbin/modprobe", "askpass", "argon2",
        ))
    ]
    initramfs_info["matching_paths"] = interesting

results["initramfs"] = {
    "stash_offset_bytes": STASH_OFFSET,
    "stash_size_bytes": STASH_SIZE,
    "stash_on_disk_shannon_entropy": round(shannon_entropy(stash_on_disk), 6),
    "stash_on_disk_chi_square": round(chi_square_uniform(stash_on_disk), 2),
    "ext4_stash_on_disk_shannon_entropy": round(shannon_entropy(ext4_stash_on_disk), 6),
    "ext4_stash_on_disk_chi_square": round(chi_square_uniform(ext4_stash_on_disk), 2),
    "ext4_df": df_out.strip(),
    "extracted_files": sorted(p.name for p in extract_dir.iterdir()),
    "extracted_pivsetup_matches": (extract_dir / "pivsetup").read_bytes() == piv_stripped.read_bytes(),
    "extracted_ko_matches": (extract_dir / "dm-piv.ko").read_bytes() == ko_unneeded_stripped.read_bytes(),
    "boot_initramfs": initramfs_info,
}

out_path = Path("/mnt/piv-work/header-probe.json")
out_path.write_text(json.dumps(results, indent=2) + "\n")
print("Wrote", out_path)
PY
