# Hidden format v5

Format v5 is the only hidden format (design approved by the user on
2026-10-22; it replaced format v4 outright, with no migration path or dual
support, because no volume was in production). It is implemented in the kernel
module (`kernel/piv-native.inc`, Reed–Solomon code in `kernel/piv-rs.inc`) and
independently in the read-only Python decoder (`pivstore/records.py`,
`pivstore/rs.py`, `pivstore/format.py`); pivsetup (`rust/src/`) derives the
keyslot KEK and passes the public context. This document is an internal
specification, not an independent cryptographic review; tested behaviour is
recorded in commit messages.

**Status: frozen** (2026-10-22, after the final-review format changes: the
canonical UUID, the whole keyslot parameter block in the record context, the
exact setup context check, newest-first directory selection, revocation on
initialization and directory-listed keyslot authority). Later changes need a
new format version or must stay inside the reserved, must-be-zero fields.

Compared with v4, v5 keeps the stock primary profiles, fragment-local
re-randomization with 10 random + 6 payload bytes per IV, the LRW fragment
encoding, SIV records, encrypted keyslots with a directory, A/B slots and no
public magic, and changes four things:

1. **4 KiB hidden blocks.** One record carries 4096 data bytes, and the hidden
   view exposes a 4096-byte logical block size.
2. **Parameters inside the keyslot.** Block size and error-correction settings
   are recorded in the encrypted keyslot, so future parameter changes need no
   new format.
3. **Selectable passphrase cost.** Argon2id with a user-chosen cost tier. The
   default is much more expensive than v4's.
4. **Optional Reed–Solomon parity** (off by default). Parity fragments let a
   record survive a bounded number of unreadable or damaged carrier sectors.

| v4 limitation | v5 change |
| --- | --- |
| A filesystem block (4 KiB) spans 8 independent records, so an interrupted write can leave it part old, part new and part EIO, even with A/B | One record per 4 KiB block: with A/B a block is all-old or all-new, without A/B all-old/new or EIO |
| 28 bytes of tag and generation per 512 data bytes | 24 bytes per 4096: about 4.8% more hidden capacity per primary sector |
| A 4 KiB hidden read runs 8 SIV checks over 720 carrier sectors | One SIV check over 687 sectors |
| Passphrase cost fixed at 64 MiB, t = 3, below cryptsetup's own keyslots, and impossible to raise later | Cost tiers selected by the user; default 1 GiB |
| Settings beyond the A/B flag are hard-coded | Recorded in the keyslot |
| Any one lost carrier IV loses the block | Optional parity tolerates up to p lost sectors per lane (below) |

## Primary profiles

Format v5 stores everything in the 16-byte random IVs that stock LUKS2 +
dm-integrity already keep per primary encryption sector. It works with both
supported stock profiles (stored random 16-byte IVs, 512- or 4096-byte
sectors, journaled or stock persistent no-journal dm-integrity):

| LUKS2 encryption | Integrity | Volume key | Tag | Tuple (tag ‖ IV) |
| --- | --- | --- | ---: | ---: |
| `aegis128-random` (original AEGIS-128) | `aead` | 16 bytes | 16 | 32 |
| `aes-xts-random` (recommended) | `hmac-sha256` | XTS key (32 or 64) ‖ HMAC key (32) | 32 | 48 |

Primary authentication is unchanged Linux: AEGIS-128 uses AAD
`LE64(sector × S/512) ‖ IV`; AES-XTS + HMAC-SHA256 uses the IV as XTS tweak and
the tag `HMAC-SHA256(LE64(sector × S/512) ‖ IV ‖ ciphertext)`. The hidden format
depends on the profile only through the number of primary sectors N. Profiles
with 12-byte IVs cannot carry it; other XTS ciphers and HMAC digests are
refused.

## Why 10 random + 6 payload bytes

A decoy write must give the touched sector a new primary nonce while keeping
the hidden payload bytes it carries. Each IV therefore encodes `r ‖ d`: fresh
random bytes `r` and a fixed payload fragment `d`. Repeated decoy writes keep `d`
fixed, so a nonce collision at one sector needs a repeated `r`. A sector
rewritten n times collides with probability about n²/2^(8|r|+1):

| Payload bytes per IV | Random bits | n = 2^24 rewrites of one sector |
| ---: | ---: | --- |
| 6 (v5) | 80 | about 2^-33 |
| 8 | 64 | about 2^-17 |

A larger payload share (for example 8 + 8) for the XTS profile would give +33%
capacity but drop that bound to about 2^-17; both profiles keep 10 + 6.

## Fragments

Sector s carries `x_s = r_s[10] ‖ d_s[6]`, stored as the primary IV

```
Δ_s  = AES-256-Enc(K_tweak, LE128(s))
IV_s = AES-256-Enc(K_prp, x_s ⊕ Δ_s) ⊕ Δ_s
x_s  = AES-256-Dec(K_prp, IV_s ⊕ Δ_s) ⊕ Δ_s
```

This is LRW with a PRF-derived mask: a tweakable strong PRP with the sector
index as tweak. Keyslot k uses its outer keys OK_k; the directory, records and
everything up to the end of the record area use the record keys. A decoy write
keeps `d_s` and draws a fresh `r_s`.

## Record layout

A record carries `plain = LE64(gen) ‖ data[4096]` (4104 bytes):

```
tag     = HMAC-SHA256(K_mac, context ‖ "/record/" ‖ LE64(g) ‖ plain)[0:16]
ct      = ChaCha20(K_enc, counter 0, nonce = tag[0:12]) ⊕ plain
payload = tag ‖ ct ‖ 0x00 0x00          (4122 bytes = 687 fragments of 6 bytes)
```

Data fragment j (0 ≤ j < 687) is `payload[6j : 6j + 6]`. With parity enabled
(`p > 0`, below), 3p parity fragments follow. A record group therefore spans

```
G = 687 + 3p   primary sectors   (p = 0 by default: G = 687)
```

and fragment j of group g lives in sector `112 + G·g + j`.

## Geometry

| Region | Sectors | Contents |
| --- | --- | --- |
| Keyslots | 0 – 111 | 4 keyslots × 2 replicas × 14 sectors; keyslot k replica r at `(2k + r)·14` |
| Directory | 112 – 112 + 2G − 1 | groups 0 and 1, an A/B pair of ordinary records |
| Records | from 112 + 2G | without A/B block i is group 2 + i; with A/B block i uses groups 2 + 2i (slot 0) and 3 + 2i (slot 1) |
| Tail | rest | sectors after the last complete record: ordinary random IVs |

Hidden blocks: `⌊(N − 112)/G⌋ − 2`, halved (rounded down) with A/B, each 4096
bytes. Setup refuses volumes with fewer than `112 + 3G` sectors (A/B:
`112 + 4G`) and bounds `N·S` by the kernel's `MAX_LFS_FILESIZE`. Using the same
record size for the directory keeps a single record code path; the directory
costs 2G sectors, about 5% of a 128 MiB 4096-byte-sector volume and negligible
on large ones (a separate 90-sector directory record would win that back only
on small 4096-byte-sector volumes, at the cost of a second record size and code
path in the kernel, the Python decoder and the tests).

| 128 MiB fixture, AEGIS-128 | v4 (removed) | v5, p = 0 | v5, p = 8 |
| --- | ---: | ---: | ---: |
| 4096-byte sectors (N = 28,216) | 158,720 B | 155,648 B (38 blocks) | 151,552 B (37 blocks) |
| 512-byte sectors (N = 213,008) | 1,209,856 B | 1,257,472 B (307 blocks) | 1,216,512 B (297 blocks) |
| Bytes per primary sector, large volumes | 5.69 | 5.96 (+4.8%) | 5.76 (+1.3%) |

XTS + HMAC tuples are larger, so dm-integrity provides fewer primary sectors
(see [observed-layout.md](observed-layout.md)). Small 4096-byte-sector volumes
lose a little capacity to the larger directory; large volumes gain.

## Keyslots

Size and placement as above (14 sectors, 84-byte payload, 2 replicas). Plain
text, 64 bytes:

```
LE32(version = 5) ‖ LE32(flags) ‖ MK[32] ‖ block_log2 (u8) ‖ rs_parity (u8) ‖ zero[22]
```

- `flags`: bit 0 = A/B. Other bits must be zero.
- `block_log2`: must be 12 (4096-byte blocks). It is recorded so that a later
  block size needs no new format.
- `rs_parity`: p ∈ {0, 4, 8, 16} parity fragments per lane (below).
- Decoding rejects other versions, unknown flags, values outside these sets
  and non-zero reserved bytes.
- The **parameter block** P is this plaintext without MK (32 bytes):
  `LE32(version) ‖ LE32(flags) ‖ block_log2 ‖ rs_parity ‖ zero[22]`. It is
  bound whole into the record context (below).

The keyslot payload is the SIV layer of the records with `ctx = base`, label
`"/keyslot/"`, id `2k + r` and 16 + 64 + 4 zero bytes in 14 fragments. Every
keyslot of a volume holds the same MK and parameters. Initialization writes
them, and keyslot add copies them from the active owner. The keyslot itself
has no parity: its two replicas provide redundancy.

**Authority.** Only keyslots that the directory lists are authoritative. A
keyslot that authenticates but is not listed with its outer keys (left by an
interrupted keyslot add or remove) is rejected like a wrong key, by the kernel
and by the Python decoder. Every slot whose replica authenticates under the
KEK with the same MK and parameters as the first one found counts, so the
same KEK in an unlisted and a listed slot still opens through the listed one.

## Context and key derivation

```
base    = "pivstore/volume/v5\0" ‖ UUID ‖ "\0" ‖ LE64(primary_bytes) ‖ LE64(S)
context = base ‖ "/layout/" ‖ P            (P: the 32-byte keyslot parameter block)
```

`UUID` is the LUKS2 UUID in lower-case canonical 8-4-4-4-12 form (36 ASCII
characters `[0-9a-f-]`, as Python's `str(uuid.UUID(text))` and pivsetup's
`canonical_uuid` produce from `cryptsetup luksUUID`), so `base` is always
72 bytes; `primary_bytes` = N·S. The kernel refuses (EINVAL) any setup
context that is not exactly this for its own owner (prefix, UUID shape and
NUL, `primary_bytes` = profile sectors × S, S), so a frontend bug cannot bind
keys to a context the independent decoder would not reproduce.

All keys are 32 bytes: `HKDF-SHA256(ikm, salt, info = "pivstore/v5/" ‖ label)`.

| Keys | ikm | salt | labels |
| --- | --- | --- | --- |
| Record/directory keys | master key MK (32 random bytes) | `context` | `tweak`, `prp`, `mac`, `enc` |
| Keyslot k keys | KEK (32 bytes) | `base` | `keyslot-tweak`, `keyslot-prp` (outer keys OK), `keyslot-mac`, `keyslot-enc` (inner keys) |

Binding the layout parameters into `context` means a volume opened with
mismatched parameters fails the SIV check instead of misreading records.
Binding the whole parameter block (not three chosen bytes) also binds any
future parameter that changes record semantics, without a new context design. The
SIV layer is deterministic: identical data at the same address gives an
identical payload; freshness of stored bytes comes from the outer random `r`.
A record authenticates only as a whole; fragments of different versions fail
the tag except with probability 2^-128.

Generations: without A/B, the record generation is 0. With A/B, a read returns
the valid slot with the larger generation; a write targets the other slot with
generation max + 1 (slot 0, generation 1 if neither slot is valid). The
directory always uses this A/B rule on groups 0/1 (generation incremented per
directory write); readers select the newest authenticating group first and
then parse it (a malformed newest directory refuses setup with EUCLEAN; an
older malformed one is ignored). Ties go to group/slot 0.

## Passphrase cost tiers

The KEK is either a 32-byte key file or Argon2id (v1.3, p = 4 lanes, 32-byte
output) over the passphrase, computed by pivsetup:

```
salt = base ‖ "/kek/argon2id/" ‖ ASCII tier digit
```

| Tier (`--kdf-cost`) | Memory | Passes | Intended use |
| ---: | ---: | ---: | --- |
| 1 | 64 MiB | 3 | low-memory systems (v4's cost) |
| 2 | 256 MiB | 3 | small systems |
| 3 (default) | 1 GiB | 3 | cryptsetup's LUKS2 default memory cap and lanes |
| 4 | 2 GiB | 6 | high-value passphrases on large-memory hosts |

Measured open times per tier are in
[configuration.md](configuration.md#hidden-key-file-or-passphrase).

The default matches cryptsetup's LUKS2 Argon2id defaults (user decision
2026-10-22): 1 GiB of memory and 4 lanes. cryptsetup also calibrates passes to
about 2 seconds and records them in its header; v5 records nothing, so passes
are fixed per tier. Tier 3 was measured with pivsetup's Argon2id (RustCrypto
`argon2`, release build, lanes computed sequentially) on the bench host before
fixing its passes: 1.95 s at 3 passes and 2.61 s at 4 passes, so tier 3 uses 3
passes (2026-10-22; tiers 1, 2 and 4 took 0.12, 0.50 and 7.7 s). In the
suite-112 bench guests (2026-10-22) tier 3 added 2.10–2.15 s to an open (open
time minus a key-file open, all four profiles; see
[configuration.md](configuration.md)).
The other tiers' passes are the design targets.

**Lanes are computed sequentially (decided before freezing, 2026-10-22).** The
pinned RustCrypto `argon2` 0.5.3 has no `parallel` feature (it arrived with
rayon in the 0.6 line, which is not vendored and would add about six crates)
and its block-filling routine is private, so pivsetup cannot hand the four
lanes to threads without reimplementing Argon2's core, which the project
avoids (maintained primitives only). An attacker can run the four lanes in
parallel, so for the same wall time on a 4-core defender the tiers buy about a
quarter of the work a parallel implementation could; memory hardness (the
dominant cost for guessing hardware) is unaffected. Argon2id's output does not
depend on threading, so a later parallel implementation keeps every existing
KEK (the Python reference already agrees); the tier parameters themselves are
frozen by the salt, and a stronger tier can be added later as tier 5 without a
format change.

The tier is deliberately not recorded anywhere: nothing can be decrypted before
the KEK exists, and a clear-text parameter would be public magic. The user
must pass the same tier on every open. A wrong tier is indistinguishable from
a wrong passphrase (EKEYREJECTED); pivsetup's error note mentions both.
Different tiers derive unrelated KEKs because the tier is part of the salt.

Memory: tier 3 needs about 1 GiB of free RAM in pivsetup (tier 4 about 2 GiB),
including in an initramfs. The guest test VMs default to 1 GiB, so the suites
that open tier-3 passphrases (v5, bench) run with more guest memory; the early
initramfs test opens with a key file and keeps 1 GiB. An optional
`--kdf-cost auto` could try tiers in ascending order, at the cost of their
summed time; it is not implemented.

## Reed–Solomon parity (optional, off by default)

Enabled at `--initialize` with `--parity P` (P ∈ {4, 8, 16}) and recorded as
`rs_parity`.

**Code.** RS over GF(2^8) with the polynomial 0x11d, first consecutive root 0
and primitive element 2 with root step 1 (the parameters dm-verity's error
correction uses), so codewords are at most 255 symbols. The generator is
`g(x) = ∏_{i<p} (x − α^i)`; codewords are systematic, data symbols first, with
symbol 0 the highest-degree coefficient (shortened to n = 229 + p). The 687
data fragments split into 3 lanes by `j mod 3` (229 fragments each). Each lane
carries p parity fragments, stored at fragment indices `687 + 3i + lane` for
i < p. Within a lane, byte position b (0–5) of every fragment forms one
systematic RS(229 + p, 229) codeword. That makes 18 codewords per record, all
sharing the lane's erasure positions. Interleaving lanes across consecutive
sectors spreads a burst of bad sectors evenly.

**Tolerance.** Any p lost sectors per lane, so at least p anywhere in the
record and any run of up to 3p consecutive sectors; without erasure
information, up to p/2 sectors with foreign fragments per lane. Capacity cost:
3p/687 (1.7% at p = 4, 3.5% at p = 8, 7.0% at p = 16).

**Writing.** A hidden write computes parity over the new payload and encodes
all G fragments with fresh `r`, exactly like data fragments. Parity is a
deterministic function of the SIV payload and lives inside the LRW PRP input,
so the stored IVs stay pseudorandom.

**Reading.**
1. Collect all G fragments. Raw IVs of sectors that fail primary authentication
   are used as for any record.
2. Fast path: SIV-open the data fragments directly.
3. If the tag fails, mark as erasures the sectors that failed authentication
   or could not be read, RS-decode each lane (Forney syndromes for the
   erasures, Berlekamp–Massey for errors with the remaining parity, Chien
   search and Forney's formula; the corrected codeword must have zero
   syndromes), and SIV-open again.
4. Only a valid SIV tag accepts the record. RS decoding never publishes
   anything on its own, so a wrong correction is rejected like any other
   damage, and corruption never becomes authenticated data.

A record with unreadable carrier sectors that still does not authenticate
returns EIO (a medium error is never mere unavailability, so an A/B read never
falls back to the older slot over it); without parity an unreadable carrier
sector fails the read as before.

**Mixed versions.** An interrupted hidden write leaves some carrier sectors with
the old version's fragments. Those sectors authenticate, so they are errors,
not erasures. If few enough sectors carry the other version, errors-only
decoding may recover either version: the new one when few sectors kept old
fragments, the old one when few were rewritten. Both outcomes are whole,
SIV-checked records; otherwise the result is EIO or the older A/B slot. This
is a possible bonus, not a promise.

**Python decoder erasures.** `decode_image` (and `pivstore unpack`) know no
primary key by default and decode errors-only (p/2 damaged sectors per lane).
Given the LUKS volume key (`primary_key`, `unpack --volume-key-file`;
scripts/check_stateless.py passes it), carrier sectors failing primary
authentication become erasures as in the kernel (p per lane). An image file
has no unreadable sectors.

**Kernel implementation.** The pinned Debian 6.12 kernel builds
`REED_SOLOMON_DEC8` (selected by `DM_VERITY_FEC=y`), but nothing guarantees the
encoder or the decoder on other configurations (for example the 7.2 port). The
module therefore implements both in `kernel/piv-rs.inc` (about 200 lines, no
kernel dependencies). The Python decoder (`pivstore/rs.py`) implements both
independently; the v5 guest suite compiles `piv-rs.inc` unchanged into a
freestanding harness (`kernel/piv-rs-test.c`) and compares parity and
correction outcomes with the Python reference, and the host check of every
parity image requires the stored parity fragments to equal the Python encoder's.

## Hidden device and write rules

All writes go through the single coordinated owner and authenticate the old
primary data of every touched sector before modifying it.

- The hidden view exposes logical and physical block size 4096. Every hidden
  request is a whole number of aligned 4096-byte blocks; DM splits hidden bios
  per block, and the worker refuses anything else (EINVAL). No
  read-modify-write exists. The decoy view advertises the primary sector size
  as its logical and physical block size, as stock dm-crypt does, so a
  filesystem created through it also mounts through stock dm-crypt.
- **Hidden write (one block):** authenticate the primary data of all G carrier
  sectors (to obtain exact old IVs), seal, re-encode G fragments with fresh `r`
  and write through the lower device; primary plaintext is unchanged. A fresh
  IV equal to an old or another fresh IV of the same request triggers
  re-encoding (up to 16 attempts). Hidden writes stay strict: any failing or
  unreadable carrier sector fails the write. With A/B, write the other slot
  with generation max + 1. The write is flushed before it completes.
- **Write shaping (implementation, no format change):** every rewrite other
  than a decoy request (records, the directory, keyslot replicas, wipes) is
  extended to 4 KiB-aligned primary byte edges; the extra sectors (at most 7
  per side at 512-byte sectors, none at 4096) are authenticated and get
  decoy-write IVs (fragments kept), and a failing one fails the write
  ([write shaping](native-blocks.md#write-shaping)).
- **Decoy write** (≤ 128 KiB per work item): for each written primary sector,
  decode the old IV, keep its 6 payload bytes, draw fresh `r'` and re-encode
  (rejecting a result equal to the old IV); keyslot sectors use the listed
  OK_k, the directory, data and parity fragments use the record keys,
  unlisted keyslot areas and tail sectors get fresh random IVs. The new
  plaintext is encrypted under the new IV. One primary encryption per written
  sector; no hidden record is read or authenticated, so damage stays damage and
  a decoy write never turns a damaged record into a valid one.
- **Failing primary sector.** A decoy write covering an entire primary sector
  that fails authentication replaces it (fresh IV, the raw stored fragment is
  refreshed like any other; the record's SIV tag still decides hidden
  validity). A partial write to such a sector fails with EIO.
- **Hidden read:** as in the parity section. The newest valid A/B slot wins.

Every request reads, authenticates and re-encrypts all its sectors before the
first write through the lower dm-integrity device
([write path](native-blocks.md#write-path)); the journal's per-sector atomicity does not make a
G-sector record atomic. Without A/B, an interrupted hidden write leaves the
block unavailable (EIO) unless parity recovers it; with A/B the previous
version stays readable. There is no cross-block ordering.

## Reads and raw IVs

Decoy reads authenticate every sector before publishing bytes. Keyslot,
directory and hidden-record decoding take the raw stored IV of any carrier
sector whose primary data fails authentication: only the SIV tag can accept
it, so nothing unauthenticated is published. Primary data damage or a torn
decoy write (both IVs carry the same fragment) therefore leaves the hidden
block readable; IV damage or mixed fragments make it unavailable unless parity
corrects them.

## Keyslots and directory

The directory's 4096-byte data holds, for keyslot j, a 65-byte entry at offset
65j: `present (0 or 1) ‖ OK_tweak[32] ‖ OK_prp[32]`; absent entries and bytes
260–4095 must be zero.

- **Purpose.** An owner opened through one keyslot must still refresh the
  fragments of every other keyslot on decoy writes without knowing their KEKs.
  Keyslot areas not listed in the directory get ordinary random IVs.
- **Leak.** OK_k reveals only the outer randomization of keyslot k, never its
  inner keys or KEK, and only to holders of MK.
- **Key check.** Without `--initialize`, setup collects the 112 keyslot IVs from
  its scan and tries every keyslot replica under the KEK (no extra I/O). None
  authenticating returns `EKEYREJECTED`. A successful keyslot gives MK, the A/B
  flag and the parity; the directory must then authenticate and parse,
  otherwise setup refuses (`EUCLEAN`), because decoy writes would destroy the
  unlisted keyslots. Finally the unlocking keyslot must be listed (Authority,
  above), otherwise `EKEYREJECTED`. There is no mode for uninitialized stock
  carriers.
- **Keyslot add/remove** (`pivsetup keyslot`, NATIVE_KEYSLOT version 2 on an
  active owner): the request carries the caller's current hidden KEK, which
  must open a listed keyslot holding the active MK and parameters (the kernel
  re-reads the keyslot area tolerantly, as at setup), otherwise
  `EKEYREJECTED`; root with only the LUKS key cannot add a passphrase it knows
  or remove the user's keyslots. Add writes both replicas, then the directory;
  remove updates the directory, then overwrites both replicas with random IVs.
  The owner's keyslot state changes only with the directory write (restored if
  that fails before writing; any failure after a lower write fail-stops). The
  last keyslot cannot be removed. Records are untouched; a passphrase change
  (or a cost-tier change) is add + remove. A crash between the two writes
  leaves an unlisted keyslot, which is not authoritative.

## Setup and initialization

pivsetup passes `base` (checked exactly, see Context), the KEK and the parity choice (NATIVE_SETUP ABI 6:
flags INITIALIZE, AB, VERIFY, QUICK, FILL; AB, QUICK and a non-zero parity
only with INITIALIZE, FILL only without it; the kernel returns the fill counts
in the same structure). Setup scans only the 112 keyslot sectors by default;
`--verify` authenticates every primary sector first and refuses on any
failure. Pending signals are polled between ranges and rounds of records;
completed records stay written (cancellation is not rollback).

Initialization draws a fresh MK and first **revokes** all earlier state: it
overwrites keyslot areas 1–3 (both replicas) and directory group 1 with fresh
random IVs (keeping their primary plaintext, as a keyslot remove does; every
such sector must authenticate; shaped like every rewrite, so at 512-byte
sectors the edges reach into keyslot 0's second replica, which gets random
IVs too, and into the first record). It then writes keyslot 0 (both replicas) under
the KEK, writes the directory listing it into group 0, then writes a zero
record for every block (one slot per block with A/B; rounds of 8 blocks, even
then odd blocks of each run of 16, flushed after each round). Afterwards no earlier
keyslot or directory authenticates, so old passphrases are revoked and, after
a quick re-initialization, the old records are reachable through no keyslot
(only someone who already extracted the old MK could still decode them; a
full initialization overwrites them). An interrupted re-initialization may
leave not-yet-written blocks unavailable, and, if interrupted before keyslot 0
and the directory are written, neither the old nor the new volume openable.
Any failure once these writes began stops the owner.

**Quick initialization** (`--initialize --quick`, QUICK; not the default, user
decision 2026-10-22) stops after the directory. No record authenticates under
the new MK, so every hidden block reads EIO until it is written: a hidden
write always replaces the whole record (with A/B, a block without a valid slot
is written to slot 0 with generation 1, as before). Records left by a previous
MK do not authenticate either. Tools that read blocks they never wrote
(filesystem probes and `mkfs` discard/zero checks, `dd` or backups of the
whole view, partition scanners) therefore see I/O errors; write the blocks
first or run a fill.

**Fill** (`--fill`, FILL; on an existing volume, after the keyslot and
directory authenticate) visits every block in rounds of 8 concurrent blocks:
a block whose record authenticates under MK (any A/B slot; with parity,
also after RS correction) is skipped; otherwise it receives the same zero
record initialization writes (A/B: slot 0, generation 1). The write is the
ordinary strict hidden rewrite: every carrier sector must authenticate
first, so a carrier with an unreadable sector or a sector failing primary
authentication is left as it was and counted as failed (the block keeps
reading EIO) instead of aborting the fill; a block whose check itself hits a
medium error is treated the same way. Any failure once a write has begun, a
flush failure, or a non-local error (allocation, encryption cap, nonce
retries) fails the setup like an initialization failure. A fill completes a
quick initialization, resumes an interrupted `--initialize` (records it
completed authenticate and are skipped) and resumes itself after
cancellation. It is destructive: a damaged record that no longer
authenticates (and RS cannot correct) is replaced by zeros, so it is never
run implicitly. It does not rewrite RS-corrected blocks to restore their full
redundancy (a hidden write of the block does that).

## Amplification and nonce use

A 4 KiB hidden write rewrites G sectors (687 without parity), close to v4's
8 × 90 = 720 for the same 4 KiB, plus up to 14 shaping sectors at 512-byte
primary sectors (on average about 7, 1%). At 4096-byte primary sectors that is about
2.7 MiB of primary data per 4 KiB hidden write (plus journal), the same order
as v4. The per-sector collision analysis is unchanged (80 random bits per IV).
Hot hidden blocks raise the rewrite count of their carrier sectors.

## Security notes

- **Pseudorandomness argument (unreviewed).** Without MK, every IV written by
  the owner in the keyslot/directory/record areas is an LRW-AES output on a
  distinct (tweak, input) pair, hence indistinguishable from uniform 128-bit IVs
  up to the TPRP advantage (about q²/2^128 over all blocks) plus the per-sector
  repeat event. Tail and unlisted keyslot areas are uniform random, and after a
  quick initialization never-written record carriers keep their earlier IVs
  (stock random IVs, or LRW outputs under a previous MK), which look the same
  to anyone without MK. SIV
  payload, padding, parity and keyslot contents are inside the PRP input and
  never directly visible. Local collision rejection slightly conditions the
  distribution.
- **No public magic.** The version, layout, parity and A/B flag are only inside
  encrypted keyslots. The cost tier is recorded nowhere.
- **Offline guessing.** Keyslots are a fast key-check oracle; passphrases are
  only as strong as the KDF cost. The default tier is 16× v4's memory cost,
  comparable to cryptsetup's own keyslots. Key files remain the high-entropy
  option.
- **Context binding.** The context binds UUID, primary size, sector size and
  layout, not time, primary key or physical disk: whole-record rollback and
  copies to a clone with the same context are accepted (out of scope).
- **Hidden-write signature.** A hidden write re-encrypts G sectors with
  unchanged primary plaintext (a 4 KiB write touched 720 sectors in v4 anyway).
  A decoy-key holder who sees journal history or two snapshots can detect it;
  decoy writes have the stock footprint ([detectability.md](detectability.md)).
  Stock persistent `--integrity-no-journal` (the recommended mode) avoids
  on-disk journal history; a crash can then tear the decoy sectors of an
  in-flight record, leaving one record-shaped failing run
  ([journal-atomicity.md](journal-atomicity.md#no-journal-mode)).
- **RS** adds availability only. It does not change what authenticates, so it
  adds no forgery or confidentiality surface beyond more decoding attempts on
  damaged records.
- Nonce budgets, observers and limits: [security-review.md](security-review.md).

## Not changed (considered)

- **Payload split.** See "Why 10 random + 6 payload bytes".
- **Primitives.** The HMAC-SHA256 + ChaCha20 SIV and the PRF-masked LRW stay.
  Both are generic compositions, and the kernel has no AES-SIV. External
  review (ROADMAP) may revisit them.
- **Larger blocks** (16 KiB+) would increase capacity only marginally but
  amplify small writes. 4096 matches filesystem blocks, and `block_log2` keeps
  the option open.

## Resolved review questions (2026-10-22)

- **Default cost:** tier 3, matching cryptsetup's default (user decision).
- **Parity sizes:** keep the three choices {4, 8, 16} (user decision).
- **Directory record size:** a uniform G-sector record (implementation
  judgment; see Geometry).
- **Kernel RS decoder:** in-module rather than `decode_rs8`, so the 6.12 and
  7.2 kernels run the same code regardless of `REED_SOLOMON_DEC8`.
