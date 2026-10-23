# Choosing a configuration

This guide is for users setting up a volume. It lists each option, its
default, its trade-offs and measured numbers. The numbers come from the `bench`
suite (suite-094, format v5 with concurrent requests), so read [How the numbers were measured](#how-the-numbers-were-measured)
before comparing them with other systems.

Some options are fixed when the stock volume is created (`cryptsetup
luksFormat` and the first `cryptsetup open`). Others are chosen by
`pivsetup open-blocks`, mostly at `--initialize`. Changing a format-time option
later means `pivsetup migrate` into a new volume. Live re-encryption and
resize are not supported.

## Summary

| Option | Chosen at | Recommended | Alternatives | Main trade-off |
| --- | --- | --- | --- | --- |
| [Primary cipher](#primary-cipher-profile) | `luksFormat` | `aes-xts-random` + `hmac-sha256`, 512-bit XTS key | `aegis128-random` + `aead` | An IV repeat under XTS + HMAC leaks only block equality (under AEGIS it is a key compromise); AEGIS reads 25–45% faster |
| [Sector size](#sector-size) | `luksFormat` | 512 (4096 on 4Kn drives); pivsetup has no default | 4096 | 512 gives 8× hidden capacity, about 2–3.5× faster hidden reads and 7–8× faster hidden writes; 4096 gives 5–9% more decoy space and slightly faster decoy writes |
| [Integrity journal](#integrity-journal) | first `cryptsetup open` | journal on (required) | none | No-journal volumes are refused |
| [A/B record slots](#ab-record-slots) | `--initialize` | `--ab` for a filesystem on the hidden view (pivsetup default: off) | single slot | A/B keeps the previous hidden block after a crash or interrupted write, at half capacity and up to half hidden-read speed |
| [Reed–Solomon parity](#reedsolomon-parity) | `--initialize` | off | `--parity 4`, `8`, `16` | Survives up to p unreadable or damaged carrier sectors per lane, for 1.7–7% of hidden capacity |
| [Hidden key type](#hidden-key-file-or-passphrase) | `--initialize` and keyslot add | key file | `--hidden-passphrase-file` (Argon2id) | A key file cannot be guessed; a passphrase relies on the KDF cost |
| [Passphrase cost](#hidden-key-file-or-passphrase) | every passphrase open and keyslot add | `--kdf-cost 3` (1 GiB) | 1, 2, 4 | Higher tiers slow guessing and every open, and need more RAM; the tier is not recorded |
| [Full audit](#full-audit---verify) | every open | off | `--verify` | Authenticates every sector; time grows with volume size |
| [Quick initialization](#large-volumes-and-initialization-time) | `--initialize` | off (full) | `--quick`, later `--fill` | Constant-time initialization, but unwritten hidden blocks read EIO until written or filled |

## Primary cipher profile

All supported profiles store a fresh random 16-byte IV per sector, which is
where the hidden data lives. The cipher is chosen with `luksFormat` and
recorded in plaintext in the LUKS2 header.

| Profile | luksFormat options | Tag bytes per sector |
| --- | --- | ---: |
| AES-XTS + HMAC-SHA256 (recommended) | `--cipher aes-xts-random --key-size 512 --integrity hmac-sha256` | 32 |
| AEGIS-128 | `--cipher aegis128-random --key-size 128 --integrity aead` | 16 |

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

**Performance.** AEGIS-128 is the fastest. AES-XTS + HMAC costs about
0.06–0.08 s more per open, about 25–30% of decoy sequential read speed and
30–47% of hidden read speed (each hidden block read authenticates 687 sectors,
so the cipher dominates), with similar decoy and hidden write speed (suite-094;
see [Throughput](#throughput)). Its larger tag also costs some space (see
[Storage overhead](#storage-overhead)).

**Detectability.** The cipher name is visible to anyone who reads the LUKS2
header. Compare a dm-piv volume only against ordinary volumes of the same
profile. This project does not know which profile is more common in practice;
both are uncommon compared with unauthenticated `aes-xts-plain64`.

**Recommendation.** Use `aes-xts-random` + `hmac-sha256` with a 512-bit XTS
key. Stock dm-crypt draws 128 fresh random bits per sector write, but a dm-piv
decoy rewrite draws only 80 (the other 48 carry the hidden fragment), so IV
repeats are far likelier than on a stock volume. Repeats concentrate on hot
sectors: the 112-sector keyslot area sits at the start of the volume, where a
decoy filesystem keeps its superblock and group descriptors and rewrites them
constantly. An AEGIS-128 repeat is a key compromise for the affected sectors;
an XTS + HMAC repeat leaks only which 16-byte blocks of one sector are equal
across two versions. Since batched writes, XTS writes as fast as AEGIS; it
costs read speed (above). AEGIS-128 remains supported and fully tested, for
example where hidden read speed matters and the RNG is known to be healthy
and never cloned.

## Sector size

`luksFormat --sector-size 512` or `4096`. pivsetup accepts either; pass it
explicitly rather than relying on cryptsetup's device-dependent default.

| On a 128 MiB disk (AEGIS-128) | 512-byte sectors | 4096-byte sectors |
| --- | ---: | ---: |
| Decoy capacity | 109.1 MB | 115.6 MB |
| Hidden capacity (A/B) | 1,257,472 B (626,688 B) | 155,648 B (77,824 B) |
| Hidden share of decoy capacity | 1.15% | 0.135% |
| Raw bytes rewritten per 4 KiB hidden write | 344 KiB | 2.7 MiB |
| Decoy sequential write | 100 MiB/s | 115 MiB/s |
| Decoy random 4 KiB writes | 6,050 IOPS | 6,180 IOPS |
| Hidden sequential read | 8.5 MiB/s | 3.2 MiB/s |
| Hidden sequential write | 1.3 MiB/s | 160 KiB/s |
| `--initialize` | 1.09 s | 0.94 s |

Each 4096-byte hidden block needs 687 primary sectors (without parity), so
hidden capacity is about 4096/(687·S) of the decoy for sector size S, minus
the keyslots and the two directory records (112 + 2·687 sectors). Smaller
sectors therefore give 8× the hidden share. On a 128 MiB 4096-byte-sector
disk the 38 hidden blocks are too few for mke2fs (it needs about 55 blocks of
4 KiB). They also cost a larger share of space for tags and 8× as many sectors
to authenticate and journal per decoy byte (decoy writes measured about 10%
slower at 512).

**Recommendation.** Use **512** (the hidden volume is usually the point of
this tool): 4096-byte sectors leave only about 0.14% of the volume for hidden
data, and hidden writes are 7–8× and hidden reads 2–3.5× faster at 512. The
costs are 6–9% less decoy capacity (metadata takes 5.9% of the raw space
instead of 0.8% for AEGIS-128, 8.6% instead of 1.2% for XTS + HMAC) and about
13% slower decoy sequential writes. Drives with 4096-byte logical sectors (4Kn)
cannot use 512-byte encryption sectors; use 4096 there. Initialization rewrites
almost every primary sector either way; at 512 it took about the same time on
128 MiB disks and up to 2.3× longer on 512 MiB disks (see [Large
volumes](#large-volumes-and-initialization-time)).

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
journal, was the bottleneck (measured before batched writes; not re-measured).

### Journal size and history

cryptsetup sizes the journal itself (it has no
`--journal-size` option for LUKS2 integrity; cryptsetup 2.8.8 rejects it and
the devices suite checks the guest's 2.7.5): on the 128 MiB test disks it is
about 1 MiB, and on real volumes of 8 GiB or more it is 64 MiB. The journal
keeps recently written sectors, so a single raw image shows the decoy-key
holder recent writes ([security
review](security-review.md#journal-history-and-the-decoy-key-holder)). A
64 MiB journal holds roughly the last 23 hidden-block writes at 4096-byte
sectors or about 190 at 512, and removed keyslots stay testable until the
journal wraps. Mitigation: after hidden use, write more than a journal's worth
(over 64 MiB) of ordinary decoy data. A smaller journal cannot be created with
stock cryptsetup, and a non-default journal size would itself distinguish the
volume from stock ones.

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
| Hidden sequential read | 3.2 MiB/s | 2.2 MiB/s | 8.5 MiB/s | 5.1 MiB/s |
| Hidden random 4 KiB reads | 540 IOPS | 262 IOPS | 1,206 IOPS | 401 IOPS |
| Hidden sequential write | 160 KiB/s | 170 KiB/s | 1.3 MiB/s | 1.2 MiB/s |
| `--initialize` | 0.94 s | 0.60 s | 1.09 s | 0.59 s |

A/B reads both slots, so hidden reads take up to about twice as long. A write
rewrites the same 687 sectors but first reads both slots to find the older one
and flushes the journal unless that version is already durable (so the
newest slot is durable before the other is overwritten); with concurrent requests A/B writes now run at about the
single-slot speed (90–105%; 40–50% before suite-094). One 4 KiB hidden block is one record, so with A/B a
block is either all old or all new after an interruption. Initialization is faster because it writes only one
slot per block (without reading either).

**Recommendation.** Use `--ab` when the hidden view holds a filesystem. Plain
hidden writes are not flushed per request (stock semantics), so after a crash
any single-slot block written since the last flush can read EIO instead of
returning its old or new contents, which a filesystem's journal replay does
not expect. In 16 simulated power cuts with ext4 on the hidden view, A/B never
showed an EIO block; single-slot showed one (in a block ext4 did not need, so
replay and fsck stayed clean), which shows the mechanism but not its odds
([ext4 power-cut test](native-faults.md#ext4-on-the-hidden-view-ext4power-suite)).
A/B costs half the capacity and up to half the hidden read speed, not write
speed. A raw key store or another consumer that tolerates a lost block (and
rewrites it) can stay single-slot for twice the capacity; pivsetup's default
remains single-slot.

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
| Hidden sequential read | 3.2 MiB/s | 3.5 MiB/s | 8.5 MiB/s | 6.4 MiB/s |
| Hidden sequential write | 160 KiB/s | 170 KiB/s | 1.3 MiB/s | 1.3 MiB/s |
| `--initialize` | 0.94 s | 1.04 s | 1.09 s | 1.05 s |

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
| Passphrase, `--kdf-cost 1` | 0.10–0.16 s | 64 MiB, t = 3 |
| Passphrase, `--kdf-cost 2` | 0.46–0.55 s | 256 MiB, t = 3 |
| Passphrase, `--kdf-cost 3` (default) | 2.10–2.15 s | 1 GiB, t = 3 |
| Passphrase, `--kdf-cost 4` | 8.1–8.3 s | 2 GiB, t = 6 |

Added open time is the passphrase open minus the median key-file open in
suite-112 (2026-10-22, all four profiles; guest, pivsetup's Argon2id with the
four lanes computed sequentially; suite-077 measured 0.13–0.19, 0.52–0.56,
2.1–2.5 and 7.9–9.2 s). Tier 3 matches cryptsetup's own
LUKS2 keyslot defaults (1 GiB, 4 lanes, about 2 s), so the hidden keyslot is
no longer the cheaper guessing target at the default. The tier is recorded
nowhere: pass the same `--kdf-cost` on every open (a wrong tier is rejected
exactly like a wrong passphrase), and keep enough free RAM (about 1 GiB at
tier 3 and 2 GiB at tier 4, also in an initramfs). Change the tier with
`keyslot add --new-passphrase-file F --new-kdf-cost N` followed by `keyslot
remove` of the old slot. Both are authorized by the current hidden key or
passphrase (`--hidden-key-file`, or `--hidden-passphrase-file` with its
`--kdf-cost`).

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
| AEGIS-128 4096 | 0.14 s | 0.18 s |
| AEGIS-128 512 | 0.12 s | 0.27 s |
| AES-XTS + HMAC-SHA256 4096 | 0.21 s | 0.36 s |
| AES-XTS + HMAC-SHA256 512 | 0.19 s | 0.44 s |

That is roughly 0.5–3 GiB/s of audit speed on this cached test disk
(it reads 1024 sectors per batch; before suite-094, 16 KiB at a time gave
100–200 MiB/s); on real storage it is bounded by the disk; expect hours on multi-TB
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
extrapolations, not measurements: the largest tested volumes are 3 GiB
(4096-byte sectors) and 2 GiB (512) ([large-volumes.md](large-volumes.md)).

## Activation and boot time

Median of three opens on 128 MiB disks, warm caches, key file, weak LUKS
PBKDF (see above). Native open includes cryptsetup, the module's setup ioctl
and view creation; add the LUKS keyslot KDF time (about 2 s by default) and,
for a hidden passphrase, the KDF time from the table above.

| Profile | Stock open | dm-piv open | dm-piv close |
| --- | ---: | ---: | ---: |
| AEGIS-128 4096 / 512 | 0.03 s | 0.12–0.14 s | 0.21–0.23 s |
| AES-XTS + HMAC 4096 / 512 | 0.04 s | 0.18–0.22 s | 0.20–0.23 s |

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
| AEGIS-128 4096 | 71 MiB/s | 115 MiB/s | 724 MiB/s | 604 MiB/s | 12,435 / 6,181 IOPS | 160 KiB/s | 3.2 MiB/s |
| AEGIS-128 512 | 68 MiB/s | 100 MiB/s | 606 MiB/s | 489 MiB/s | 12,904 / 6,053 IOPS | 1.3 MiB/s | 8.5 MiB/s |
| AES-XTS + HMAC-SHA256 4096 | 74 MiB/s | 116 MiB/s | 445 MiB/s | 434 MiB/s | 11,103 / 6,446 IOPS | 180 KiB/s | 1.7 MiB/s |
| AES-XTS + HMAC-SHA256 512 | 69 MiB/s | 102 MiB/s | 409 MiB/s | 375 MiB/s | 12,379 / 5,260 IOPS | 1.3 MiB/s | 6.0 MiB/s |

Random 4 KiB decoy reads ran at stock speed in every profile (7,900–9,700
IOPS for both). Compared with suite-083 (batched writes on one ordered worker
that flushed after every write), concurrent requests, stock flush semantics
and batched 1024-sector reads raised decoy sequential writes 7–12×, decoy
random writes 6–10×, decoy sequential reads 3–3.5×, hidden reads 3–14×
(sequential and random), hidden writes 1.5–1.8× at 512-byte sectors (unchanged
within noise at 4096) and A/B hidden writes 2–3×. Initialization of the
128 MiB disk did not change beyond noise; on 512 MiB disks it was 1.5–1.7×
faster than the previous module in the same session (see below).

Queue depth 16 (suite-120, 2026-10-23: the same number of random 4 KiB O_DIRECT
writes from 16 threads, then one fsync): decoy 14,750 / 13,070 / 14,830 /
10,210 IOPS (AEGIS-128 4096 / 512, AES-XTS + HMAC-SHA256 4096 / 512) against
stock 15,220 / 13,630 / 16,850 / 14,630, so concurrent decoy writes reach
70–97% of stock (40–63% at depth 1 in the same run). Hidden writes gain little from depth:
38–56 blocks/s at 4096-byte sectors and 250–330 at 512, single slot or A/B,
because each block rewrites a whole record through the journal. The review
fixes of suite-120 (per-batch AEAD requests, direct-to-bio reads, fewer
allocations, A/B flush skipping) compared with suite-113 (previous module, same
bench) changed nothing beyond the ±15% noise band except A/B hidden random
writes at queue depth 1 on 512-byte sectors, +26–34% (the pre-write flush is
skipped when the block's previous write is already durable; reproduced in a
second run). AEGIS-128 decoy random reads measured 13–20% lower in both runs
while stock rows in the same session were 2–10% lower (still at stock speed);
treat it as unresolved noise.

What to expect:

- **Decoy reads** are close to stock: random reads at stock speed, large
  sequential reads at 80–100% of stock.
- **Decoy writes** are about 2× slower than stock dm-crypt for random 4 KiB
  writes at queue depth 1 (each request reads and authenticates the old
  sectors before re-encrypting them), and measured faster than stock for
  large sequential writes here (dm-piv submits each 128 KiB request as a few
  large concurrent bios). Like stock dm-crypt, a plain write is not flushed;
  durability comes from fsync/FUA. Either difference is visible to anyone
  timing writes on the running system.
- **Hidden writes** run at about 160–180 KiB/s at 4096-byte sectors (about 45
  blocks of 4 KiB per second) and 1.3 MiB/s at 512. They are bound by the G×
  write amplification, not by the journal: each 4 KiB block rewrites G = 687
  primary sectors (2.7 MiB at 4096, 344 KiB at 512), which comes to about
  110 MiB/s of rewritten primary data at either sector size, the same rate as
  decoy sequential writes. The hidden volume suits small, rarely changed data.
- **Hidden reads** authenticate 687 sectors per 4 KiB block regardless of
  request size; concurrent requests overlap: about 1.7–3.2 MiB/s at 4096-byte
  sectors and 6–8.5 MiB/s at 512 for 64 KiB requests (suite-094).

## Large volumes and initialization time

Three ways to get a usable hidden volume:

- **Full** (`--initialize`, default): writes a zero record into every block.
  Every block reads (zeros) immediately; the time grows with the volume (below).
- **Quick** (`--initialize --quick`): writes only keyslot 0 and the directory,
  in constant time (about one open plus 715 sector rewrites). Unwritten blocks
  read EIO until written, which breaks tools that read blocks they did not
  write (filesystem probes, `mkfs` checks, whole-view `dd` or backups). Fine
  for a consumer that writes before it reads, e.g. a key store addressing its
  own blocks.
- **Fill** (`--fill` on a later open): writes zero records only into blocks
  whose record does not authenticate, skipping valid ones. Each block is read
  and checked first, so filling a whole quick-initialized volume takes about
  1.3–1.5× a full initialization, and checking a complete volume (nothing to
  write) about 60% of one (512 MiB, large-*-011: quick initialization 1.9 s /
  1.6 s at 4096/512-byte sectors, fill of every block 8.5 s / 22.3 s, full
  initialization 6.6 s / 15.2 s, fill with nothing to write 4.1 s / 9.1 s). It completes a quick or cancelled initialization and
  resumes itself after cancellation. It is **destructive**: a damaged block
  that no longer authenticates becomes zeros (blocks whose carrier cannot be
  read or authenticated are left alone and reported as `failed`). Never run
  it on a volume whose damaged blocks you still hope to recover.

`--initialize` writes every hidden record, which rewrites essentially every
primary sector: about 29,000 sectors/s (113 MiB/s) at 4096-byte sectors
(0.94 s for 128 MiB, open included) and 190,000 sectors/s (95 MiB/s) at 512
(1.09 s). Extrapolated to a 1 TiB disk (AEGIS-128, no A/B), that is about
**2.5–3 hours** at 4096-byte sectors and **3 hours** at 512 (suite-077,
before batched writes: 16 hours and 4–5 days). A/B halves it. Initialization
writes 8 records concurrently; on the 128 MiB test disk this was within noise
of the serial version, and on 512 MiB disks (large-*-009 against the previous
module in the same, slower host session) it took 6.9 s instead of 10.1 s at
4096-byte sectors and 15.7 s instead of 27.1 s at 512. The test disk
is cached by the host; on a real disk every carrier sector is read once and
written twice (journal, then in place), so expect initialization at roughly
**the disk's bandwidth divided by 3** (for example about 5–6 hours per TiB at
150 MiB/s), whichever limit is lower. Initialization can be cancelled with SIGINT/SIGTERM; blocks not yet written
stay unavailable until a `--fill` (or a new `--initialize`) completes them
([native-faults.md](native-faults.md#cancelling-activation-initialization-and-fill-cancel-suite)). A fill costs the same per written block
plus one authenticated read per block.

The per-owner limit of 2^40 primary encryptions (raised from 2^32, which a
512-byte-sector initialization reached around 2 TiB) also bounds one
initialization (G encryptions per hidden block, about one per primary sector):
at 512-byte sectors it is reached around 512 TiB. These figures are extrapolated beyond the largest tested
volumes (3 GiB and 2 GiB; [large-volumes.md](large-volumes.md)).

## How the numbers were measured

- `bench` suite (scripts/guest-bench.sh, kernel/guest-bench-test.py) run
  sequentially (`--jobs 1`) in suite-094 (format v5, concurrent requests,
  2026-10-22; KDF tier rows from suite-077, matched within 0.6 s; queue-depth-16
  rows from suite-120, with suite-113 as the previous-module baseline) on the pinned
  Debian 6.12.113 guest: 2 vCPUs, `-cpu max` under KVM on an Intel Xeon @
  2.60 GHz host, 3.5 GiB guest RAM (for the 2 GiB Argon2id tier), 128 MiB raw
  virtio disk image.
- The disk image sits in the host page cache, and O_DIRECT bypasses only the
  guest page cache. Absolute numbers therefore reflect a fast cached virtual
  disk. Real storage adds latency, which hurts dm-piv's read-before-write
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
  --scaffold artifacts/part2-input-002/scaffold.tar --suites bench --jobs 1
```

## Example

The recommended configuration: a 512-byte-sector AES-XTS + HMAC-SHA256 volume
with a journaled integrity layer, a hidden key file and A/B slots for a hidden
filesystem:

```sh
cryptsetup luksFormat --type luks2 --cipher aes-xts-random --key-size 512 \
  --integrity hmac-sha256 --sector-size 512 --key-file passphrase.key /dev/sdX2
pivsetup keygen --output hidden.key
pivsetup open-blocks --device /dev/sdX2 --key-file passphrase.key \
  --hidden-key-file hidden.key --initialize --ab
```

Later opens omit `--initialize`, which would destroy the hidden contents.
