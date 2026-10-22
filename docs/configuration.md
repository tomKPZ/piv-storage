# Choosing a configuration

This guide is for users setting up a volume. It lists each option, its
default, its trade-offs and measured numbers. The numbers come from the `bench`
suite (suite-077, format v5), so read [How the numbers were measured](#how-the-numbers-were-measured)
before comparing them with other systems.

Some options are fixed when the stock volume is created (`cryptsetup
luksFormat` and the first `cryptsetup open`). Others are chosen by
`pivsetup open-blocks`, mostly at `--initialize`. Changing a format-time option
later means `pivsetup migrate` into a new volume. Live re-encryption and
resize are not supported.

## Summary

| Option | Chosen at | Default | Alternatives | Main trade-off |
| --- | --- | --- | --- | --- |
| [Primary cipher](#primary-cipher-profile) | `luksFormat` | `aegis128-random` + `aead` | `aes-xts-random` + `hmac-sha256` | AEGIS is fastest; XTS + HMAC tolerates an IV repeat far better |
| [Sector size](#sector-size) | `luksFormat` | none from pivsetup; the test fixtures use 4096 | 512 | 512 gives 8× hidden capacity and faster hidden reads; 4096 gives faster decoy writes and 5–7% more decoy space |
| [Integrity journal](#integrity-journal) | first `cryptsetup open` | journal on (required) | none | No-journal volumes are refused |
| [A/B record slots](#ab-record-slots) | `--initialize` | off | `--ab` | A/B keeps the previous hidden block after an interrupted write, at half capacity and half hidden-read speed |
| [Reed–Solomon parity](#reedsolomon-parity) | `--initialize` | off | `--parity 4`, `8`, `16` | Survives up to p unreadable or damaged carrier sectors per lane, for 1.7–7% of hidden capacity |
| [Hidden key type](#hidden-key-file-or-passphrase) | `--initialize` and keyslot add | key file | `--hidden-passphrase-file` (Argon2id) | A key file cannot be guessed; a passphrase relies on the KDF cost |
| [Passphrase cost](#hidden-key-file-or-passphrase) | every passphrase open and keyslot add | `--kdf-cost 3` (1 GiB) | 1, 2, 4 | Higher tiers slow guessing and every open, and need more RAM; the tier is not recorded |
| [Full audit](#full-audit---verify) | every open | off | `--verify` | Authenticates every sector; time grows with volume size |

## Primary cipher profile

All supported profiles store a fresh random 16-byte IV per sector, which is
where the hidden data lives. The cipher is chosen with `luksFormat` and
recorded in plaintext in the LUKS2 header.

| Profile | luksFormat options | Tag bytes per sector |
| --- | --- | ---: |
| AEGIS-128 (default) | `--cipher aegis128-random --key-size 128 --integrity aead` | 16 |
| AES-XTS + HMAC-SHA256 | `--cipher aes-xts-random --key-size 512 --integrity hmac-sha256` | 32 |

`aegis128-random` is the original AEGIS-128, not AEGIS-128L. For XTS,
`--key-size` is the XTS key only (512 bits = AES-256-XTS; 256 is also
accepted); cryptsetup adds the 32-byte HMAC key. Other ciphers (Serpent,
Twofish) and HMAC digests (SHA-1, SHA-512) are refused.

**Security.** The kernel draws a fresh random IV for every write, so two writes
to one sector repeat an IV with small but nonzero probability. A decoy rewrite
of a sector keeps that sector's 6 hidden payload bytes and draws 80 fresh
random bits. So n rewrites of one sector repeat an IV with probability about
n²/2^81 (about 2^-33 for 16 million rewrites of one sector). A repeat has very
different consequences per profile:

- **AEGIS-128:** a repeated IV under the same key breaks the confidentiality and
  integrity guarantees for the affected sectors (treat it as key compromise).
- **XTS + HMAC:** a repeat reveals only which 16-byte blocks of that sector are
  equal across the two versions. Forgery still needs the HMAC key.

Both estimates assume a correctly seeded kernel RNG. VM snapshot restores,
cloned disk images and cloned RNG state make repeats far more likely; XTS +
HMAC fails much more gracefully there. See the
[security review](security-review.md) for the full nonce budget.

**Performance (4096-byte sectors).** AEGIS-128 is the fastest. AES-XTS + HMAC
costs about 0.04 s more per open, about 20–25% lower hidden-read speed and similar
write speed (writes are limited by the serialized write path, not the cipher).
Its larger tag also costs some space (see [Storage overhead](#storage-overhead)).

**Detectability.** The cipher name is visible to anyone who reads the LUKS2
header. Compare a dm-piv volume only against ordinary volumes of the same
profile. This project does not know which profile is more common in practice;
both are uncommon compared with unauthenticated `aes-xts-plain64`.

**Recommendation.** `aes-xts-random` + `hmac-sha256` is the conservative choice
if you worry about RNG state being duplicated (VMs, cloned images). AEGIS-128
is fine on a physical machine with a healthy RNG and is the faster default.

## Sector size

`luksFormat --sector-size 512` or `4096`. pivsetup accepts either; pass it
explicitly rather than relying on cryptsetup's device-dependent default.

| On a 128 MiB disk (AEGIS-128) | 512-byte sectors | 4096-byte sectors |
| --- | ---: | ---: |
| Decoy capacity | 109.1 MB | 115.6 MB |
| Hidden capacity (A/B) | 1,257,472 B (626,688 B) | 155,648 B (77,824 B) |
| Hidden share of decoy capacity | 1.15% | 0.135% |
| Raw bytes rewritten per 4 KiB hidden write | 344 KiB | 2.7 MiB |
| Decoy sequential write | 1.5 MiB/s | 5.7 MiB/s |
| Decoy random 4 KiB writes | 295 IOPS | 513 IOPS |
| Hidden sequential read | 1.9 MiB/s | 307 KiB/s |
| Hidden sequential write | 33 KiB/s | 25 KiB/s |
| `--initialize` | 39 s | 6.1 s |

Each 4096-byte hidden block needs 687 primary sectors (without parity), so
hidden capacity is about 4096/(687·S) of the decoy for sector size S, minus
the keyslots and the two directory records (112 + 2·687 sectors). Smaller
sectors therefore give 8× the hidden share. On a 128 MiB 4096-byte-sector
disk the 38 hidden blocks are too few for mke2fs (it needs about 55 blocks of
4 KiB). They also cost more per decoy byte: 8× as many sectors to
authenticate and journal, and a larger share of space for tags.

**Recommendation.** Use **512** if hidden capacity matters, which is usually
the point of this tool: 4096-byte sectors leave only about 0.14% of the volume
for hidden data. Use 4096 if the decoy is a heavily written filesystem and
hidden needs are small (keys, a few documents). Initialization time is
proportional to hidden capacity, so 512-byte volumes take longer to
initialize (see [Large volumes](#large-volumes-and-initialization-time)).

## Integrity journal

dm-integrity's journal makes each primary sector update atomic, and pivsetup
requires it: a volume whose LUKS2 header persists the `no-journal` flag
(`cryptsetup open --integrity-no-journal --persistent`), or any non-journal
lower table, is refused. Without the journal, a crash during a hidden write can
tear decoy sectors of that hidden record, not just the sectors being written
([journal-atomicity.md](journal-atomicity.md)). No-journal support was removed
because it barely helped dm-piv: in suite-072 (AEGIS-128, 4096-byte sectors) it
raised decoy writes by at most about 17% (5.8 → 6.8 MiB/s), and at 512-byte
sectors no dm-piv write test was faster. dm-piv's own write path, not the
journal, is the bottleneck.

## A/B record slots

`--initialize --ab` stores two record slots per hidden block. A write goes to
the slot holding the older version, so an interrupted write leaves the
previous version readable. Without A/B, an interrupted hidden write can leave
that block returning EIO until it is rewritten. Neither mode makes multi-block
updates atomic; a hidden filesystem can still be left inconsistent across
blocks.

| AEGIS-128 | 4096 single | 4096 A/B | 512 single | 512 A/B |
| --- | ---: | ---: | ---: | ---: |
| Hidden capacity | 155,648 B | 77,824 B | 1,257,472 B | 626,688 B |
| Hidden sequential read | 307 KiB/s | 142 KiB/s | 1.9 MiB/s | 900 KiB/s |
| Hidden random 4 KiB reads | 78 IOPS | 35 IOPS | 469 IOPS | 229 IOPS |
| Hidden sequential write | 25 KiB/s | 21 KiB/s | 33 KiB/s | 30 KiB/s |
| `--initialize` | 6.1 s | 4.0 s | 39 s | 22 s |

A/B reads both slots, so hidden reads take about twice as long. Writes cost the
same 687 sector rewrites. One 4 KiB hidden block is one record, so with A/B a
block is either all old or all new after an interruption. Initialization is faster because it writes only one
slot per block.

**Recommendation.** Keep A/B off by default for capacity. Turn it on for
small, valuable hidden data where losing a block to a power cut is worse than
halving capacity.

## Reed–Solomon parity

`--initialize --parity P` (P = 4, 8 or 16) appends 3P parity fragments to every
record (G = 687 + 3P carrier sectors). The 687 data fragments form three lanes
(by index mod 3); a block still decodes with up to P unreadable or
authentication-failing carrier sectors per lane (so any burst of up to 3P
consecutive sectors), or up to P/2 sectors per lane carrying foreign
fragments, such as after an uncoordinated stock write or an interrupted
rewrite. Decoding runs only when the record's tag fails, and a block is
accepted only through its tag, so parity never turns damage into wrong data.
Parity is recorded in the keyslot; later opens need no option.

| AEGIS-128, 128 MiB | 4096 no parity | 4096 `--parity 8` | 512 no parity | 512 `--parity 8` |
| --- | ---: | ---: | ---: | ---: |
| Hidden capacity | 155,648 B | 151,552 B | 1,257,472 B | 1,216,512 B |
| Hidden sequential read | 307 KiB/s | 324 KiB/s | 1.9 MiB/s | 1.8 MiB/s |
| Hidden sequential write | 25 KiB/s | 25 KiB/s | 33 KiB/s | 31 KiB/s |
| `--initialize` | 6.1 s | 6.4 s | 39 s | 39 s |

Capacity cost on large volumes: 1.7% (P = 4), 3.5% (P = 8), 7.0% (P = 16);
each hidden write rewrites 3P more sectors. Hidden writes still require every
carrier sector to be readable and authentic, so a block with a bad carrier
sector is readable but must be rewritten after the sector is repaired or
replaced by a decoy write.

**Recommendation.** Off by default. Consider `--parity 4` or `8` when hidden
blocks must survive isolated media errors or occasional uncoordinated writes;
it is not a substitute for backups.

## Hidden key file or passphrase

The hidden master key is wrapped in up to four encrypted keyslots. Each is
unlocked by a 32-byte key file (`--hidden-key-file`, generated by `pivsetup
keygen`) or a passphrase (`--hidden-passphrase-file`). Keyslots allow offline
guessing by anyone with a copy of the disk, so a passphrase is only as strong
as its entropy times the KDF cost. Passphrases use Argon2id (4 lanes) at the
cost tier `--kdf-cost`:

| Hidden key type | Added open time (measured) | Parameters |
| --- | ---: | --- |
| Key file | none | 256-bit random key |
| Passphrase, `--kdf-cost 1` | 0.13–0.19 s | 64 MiB, t = 3 |
| Passphrase, `--kdf-cost 2` | 0.52–0.56 s | 256 MiB, t = 3 |
| Passphrase, `--kdf-cost 3` (default) | 2.1–2.5 s | 1 GiB, t = 3 |
| Passphrase, `--kdf-cost 4` | 7.9–9.2 s | 2 GiB, t = 6 |

Added open time is the passphrase open minus the key-file open in suite-077
(guest, pivsetup's single-threaded Argon2id). Tier 3 matches cryptsetup's own
LUKS2 keyslot defaults (1 GiB, 4 lanes, about 2 s), so the hidden keyslot is
no longer the cheaper guessing target at the default. The tier is recorded
nowhere: pass the same `--kdf-cost` on every open (a wrong tier is rejected
exactly like a wrong passphrase), and keep enough free RAM (about 1 GiB at
tier 3 and 2 GiB at tier 4, also in an initramfs). Change the tier with
`keyslot add --kdf-cost N` followed by `keyslot remove` of the old slot.

**Recommendation.** Prefer a key file kept on separate media. If you use a
passphrase, make it long (for example six or more random diceware words) and
keep the default tier unless memory is short.

## Full audit (`--verify`)

By default setup authenticates only the 112-sector keyslot area, so opening
takes constant time. Every later read and write still authenticates the
sectors it touches. `--verify` first authenticates every primary sector and
refuses the volume on any failure.

| 128 MiB disk | Open (default) | Open with `--verify` |
| --- | ---: | ---: |
| AEGIS-128 4096 | 0.17 s | 0.71 s |
| AEGIS-128 512 | 0.15 s | 0.86 s |
| AES-XTS + HMAC-SHA256 4096 | 0.21 s | 0.82 s |
| AES-XTS + HMAC-SHA256 512 | 0.20 s | 0.87 s |

That is roughly 100–200 MiB/s of audit speed here; expect hours on multi-TB
volumes. Use it after a suspected corruption or before trusting a copied
image, not on every boot.

## Other format-time settings

- **LUKS keyslot KDF.** Keep cryptsetup's default Argon2id. The test fixtures
  use a deliberately weak PBKDF2 (1000 iterations) so they open quickly; the
  activation times below therefore exclude the about 2 seconds a default LUKS2
  keyslot adds.
- **Wiping.** Let `luksFormat` wipe the device (do not pass
  `--integrity-no-wipe`). Unwiped sectors fail authentication, and dm-piv has
  not been tested on such volumes.
- **Integrity padding and journal geometry.** Keep cryptsetup's defaults
  (integrity v4 with fixed padding). dm-piv validates the geometry and refuses
  others.

## Storage overhead

Measured on 128 MiB disks. The decoy is exactly as large as a stock volume of
the same profile: dm-piv takes no decoy space. The hidden volume lives only in
the IVs.

| Profile | Decoy bytes (share of raw) | Hidden bytes | Hidden with `--ab` | Hidden with `--parity 8` |
| --- | ---: | ---: | ---: | ---: |
| AEGIS-128 4096 | 115,572,736 (86.1%) | 155,648 | 77,824 | 151,552 |
| AES-XTS + HMAC-SHA256 4096 | 115,113,984 (85.8%) | 155,648 | 77,824 | 151,552 |
| AEGIS-128 512 | 109,060,096 (81.3%) | 1,257,472 | 626,688 | 1,216,512 |
| AES-XTS + HMAC-SHA256 512 | 105,377,792 (78.5%) | 1,216,512 | 606,208 | 1,175,552 |

On a 128 MiB disk, 16 MiB goes to the LUKS2 header. Beyond that, the
per-sector integrity metadata takes T/(S + T) of the remaining space, where T
is the tag plus the 16-byte IV (32 bytes for AEGIS, 48 for HMAC-SHA256):

| Integrity metadata share | S = 4096 | S = 512 |
| --- | ---: | ---: |
| AEGIS-128 (T = 32) | 0.8% | 5.9% |
| HMAC-SHA256 (T = 48) | 1.2% | 8.6% |

For a 1 TiB disk this gives roughly 1.5 GiB of hidden capacity at 4096-byte
sectors and 11.2 GiB at 512 (AEGIS-128, no parity; half with A/B). These are
extrapolations, not measurements: the test guard only admits 128 and 512 MiB
disks.

## Activation and boot time

Median of three opens on 128 MiB disks, warm caches, key file, weak LUKS
PBKDF (see above). Native open includes cryptsetup, the module's setup ioctl
and view creation; add the LUKS keyslot KDF time (about 2 s by default) and,
for a hidden passphrase, the KDF time from the table above.

| Profile | Stock open | dm-piv open | dm-piv close |
| --- | ---: | ---: | ---: |
| AEGIS-128 4096 / 512 | 0.03–0.04 s | 0.15–0.17 s | 0.20–0.22 s |
| AES-XTS + HMAC 4096 / 512 | 0.04 s | 0.20–0.21 s | 0.22 s |

Opening does not depend on volume size unless `--verify` is used. The same
`pivsetup open-blocks` runs unchanged from an initramfs (the early-boot suite
activates from a Python-free RAM-root initramfs).

## Throughput

Sequential I/O uses O_DIRECT 1 MiB requests for the decoy (16 MiB written,
then read back) and 64 KiB requests for the hidden volume (up to 1 MiB, or the
whole 4096-byte-sector hidden volume); a write includes the final fsync. Random
I/O uses 256 decoy 4 KiB requests and up to 64 hidden 4 KiB requests. Every byte read back is checked. "Stock" is
ordinary dm-crypt on the same fixture before dm-piv is activated.

| Profile | Stock seq write | Decoy seq write | Stock seq read | Decoy seq read | Stock / decoy random 4 KiB write | Hidden seq write | Hidden seq read |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| AEGIS-128 4096 | 71 MiB/s | 5.7 MiB/s | 718 MiB/s | 154 MiB/s | 13,126 / 513 IOPS | 25 KiB/s | 307 KiB/s |
| AEGIS-128 512 | 67 MiB/s | 1.5 MiB/s | 531 MiB/s | 148 MiB/s | 9,641 / 295 IOPS | 33 KiB/s | 1.9 MiB/s |
| AES-XTS + HMAC-SHA256 4096 | 67 MiB/s | 5.7 MiB/s | 484 MiB/s | 134 MiB/s | 12,197 / 536 IOPS | 21 KiB/s | 230 KiB/s |
| AES-XTS + HMAC-SHA256 512 | 66 MiB/s | 1.5 MiB/s | 351 MiB/s | 118 MiB/s | 9,818 / 287 IOPS | 30 KiB/s | 1.4 MiB/s |

Random 4 KiB decoy reads ran at stock speed in every profile (7,000–9,000
IOPS for both). Decoy numbers match format v4's (suite-072) within noise; the
decoy path did not change.

What to expect:

- **Decoy reads** are close to stock for random access and 3–5× slower for
  large sequential reads.
- **Decoy writes** are 12–45× slower than stock dm-crypt. dm-piv applies one
  write request at a time on an ordered worker: it authenticates the old
  sectors, re-encrypts and writes through the journal before starting the next
  request (a current implementation limit, not a format property). Throughput is
  bound by per-request latency, not by the cipher. This difference is visible
  to anyone timing writes on the running system.
- **Hidden writes** run at about 21–33 KiB/s (5–8 blocks of 4 KiB per second).
  Each hidden block write authenticates and rewrites a whole 687-sector record.
  Use the hidden volume for small, rarely changed data.
- **Hidden reads** authenticate 687 sectors per 4 KiB block regardless of
  request size: about 230–310 KiB/s at 4096-byte sectors and 1.4–1.9 MiB/s at
  512 (similar to or up to about 25% faster than format v4's 512-byte
  records).

## Large volumes and initialization time

`--initialize` writes every hidden record, which rewrites essentially every
primary sector: about 4,600 sectors/s at 4096-byte sectors (6.1 s for 128 MiB)
and 5,500 sectors/s at 512 (39 s). Extrapolated to a 1 TiB disk (AEGIS-128, no
A/B), that is about **16 hours** at 4096-byte sectors and **4–5 days** at 512. A/B halves
it. Initialization can be cancelled with SIGINT/SIGTERM; blocks not yet written
stay unavailable until a later `--initialize` completes
([cancellation.md](cancellation.md)).

The per-owner limit of 2^32 primary encryptions also bounds one
initialization (G encryptions per hidden block, about one per primary sector):
at 512-byte sectors it is reached around 2 TiB. These figures are extrapolated; the test guard admits
only 128 and 512 MiB disks ([large-volumes.md](large-volumes.md)).

## How the numbers were measured

- `bench` suite (scripts/guest-bench.sh, kernel/guest-bench-test.py) run
  sequentially (`--jobs 1`) in suite-077 (format v5, 2026-10-22) on the pinned
  Debian 6.12.113 guest: 2 vCPUs, `-cpu max` under KVM on an Intel Xeon @
  2.60 GHz host, 3.5 GiB guest RAM (for the 2 GiB Argon2id tier), 128 MiB raw
  virtio disk image.
- The disk image sits in the host page cache, and O_DIRECT bypasses only the
  guest page cache. Absolute numbers therefore reflect a fast cached virtual
  disk. Real storage adds latency, which hurts dm-piv's serialized writes
  more than stock dm-crypt. Compare rows with each other, not with other
  systems.
- Sequential numbers are single passes and activation numbers medians of
  three; there are no confidence intervals. Differences under about 15% are
  within noise.
- Each run starts from a pristine stock fixture, ends with stock Linux
  authenticating the whole primary volume, and checks that both decoy regions
  and the hidden data survived close and reopen.

Reproduce (results land in `PREFIX/*-bench/share/bench-results.json`):

```sh
python3 scripts/suite.py --prefix artifacts/bench-next \
  --control artifacts/suite-016/aegis-4096-control \
  --scaffold artifacts/v5-input-002/scaffold.tar --suites bench --jobs 1
```

## Example

A 512-byte-sector AES-XTS + HMAC-SHA256 volume with a journaled integrity
layer and a hidden key file:

```sh
cryptsetup luksFormat --type luks2 --cipher aes-xts-random --key-size 512 \
  --integrity hmac-sha256 --sector-size 512 --key-file passphrase.key /dev/vdb
pivsetup keygen --output hidden.key
pivsetup open-blocks --device /dev/vdb --key-file passphrase.key \
  --hidden-key-file hidden.key --initialize
```

Later opens omit `--initialize`, which would destroy the hidden contents.
