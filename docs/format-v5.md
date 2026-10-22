# Hidden format v5 (proposal)

**Status: design approved by the user (2026-10-22), not implemented.** Format
v4 ([format-v4.md](format-v4.md)) remains the only implemented format until v5
lands. No volume
is in production, so v5 replaces v4 outright when it lands. There is no
migration path or dual-format support.

v5 keeps everything that works in v4: stock primary profiles, fragment-local
re-randomization with 10 random + 6 payload bytes per IV, the LRW fragment
encoding, SIV records, encrypted keyslots with a directory, A/B slots and no
public magic. It changes four things:

1. **4 KiB hidden blocks.** One record carries 4096 data bytes, and the hidden
   view exposes a 4096-byte logical block size.
2. **Parameters inside the keyslot.** Block size and error-correction settings
   are recorded in the encrypted keyslot, so future parameter changes need no
   new format.
3. **Selectable passphrase cost.** Argon2id with a user-chosen cost tier. The
   default is much more expensive than v4's.
4. **Optional Reed–Solomon parity** (off by default). Parity fragments let a
   record survive a bounded number of unreadable or damaged carrier sectors.

## Motivation

| v4 limitation | v5 change |
| --- | --- |
| A filesystem block (4 KiB) spans 8 independent records, so an interrupted write can leave it part old, part new and part EIO, even with A/B | One record per 4 KiB block: with A/B a block is all-old or all-new, without A/B all-old/new or EIO |
| 28 bytes of tag and generation per 512 data bytes | 24 bytes per 4096: about 4.8% more hidden capacity per primary sector |
| A 4 KiB hidden read runs 8 SIV checks over 720 carrier sectors | One SIV check over 687 sectors |
| Passphrase cost fixed at 64 MiB, t = 3, below cryptsetup's own keyslots, and impossible to raise later | Cost tiers selected by the user; default 1 GiB |
| Settings beyond the A/B flag are hard-coded | Recorded in the keyslot |
| Any one lost carrier IV loses the block | Optional parity tolerates up to p lost sectors per lane (below) |

## Primary profiles

Unchanged from v4: `aegis128-random` + `aead` (default) and `aes-xts-random` +
`hmac-sha256`, 512- or 4096-byte sectors, journaled dm-integrity. The hidden
format depends on the profile only through the number of primary sectors N.

## Fragments

Unchanged from v4. Sector s stores `IV_s = LRW-AES(x_s)` with `x_s = r_s[10] ‖
d_s[6]` under tweak s (record keys `K_tweak`, `K_prp`; keyslot k uses its outer
keys). A decoy write keeps `d_s` and draws a fresh `r_s`.

## Record layout

A record carries `plain = LE64(gen) ‖ data[4096]` (4104 bytes). SIV as in v4:

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
| Keyslots | 0 – 111 | as v4: 4 keyslots × 2 replicas × 14 sectors |
| Directory | 112 – 112 + 2G − 1 | groups 0 and 1, an A/B pair of ordinary records |
| Records | from 112 + 2G | without A/B block i is group 2 + i; with A/B block i uses groups 2 + 2i and 3 + 2i |
| Tail | rest | ordinary random IVs |

Hidden blocks: `⌊(N − 112)/G⌋ − 2`, halved (rounded down) with A/B, each 4096
bytes. Minimum volume: `112 + 3G` sectors (A/B: `112 + 4G`). Using the same
record size for the directory keeps a single record code path. The directory
costs 2G sectors, about 5% of a 128 MiB 4096-byte-sector volume and negligible
on large ones.

| 128 MiB fixture, AEGIS-128 | v4 | v5, p = 0 | v5, p = 8 |
| --- | ---: | ---: | ---: |
| 4096-byte sectors (N = 28,216) | 158,720 B | 155,648 B (38 blocks) | 151,552 B (37 blocks) |
| 512-byte sectors (N = 213,008) | 1,209,856 B | 1,257,472 B (307 blocks) | 1,216,512 B (297 blocks) |
| Bytes per primary sector, large volumes | 5.69 | 5.96 (+4.8%) | 5.76 (+1.3%) |

Small 4096-byte-sector volumes lose a little capacity to the larger directory.
Large volumes gain.

## Keyslots

Size and placement as in v4 (14 sectors, 84-byte payload, 2 replicas). Plain
text, 64 bytes:

```
LE32(version = 5) ‖ LE32(flags) ‖ MK[32] ‖ block_log2 (u8) ‖ rs_parity (u8) ‖ zero[22]
```

- `flags`: bit 0 = A/B. Other bits must be zero.
- `block_log2`: must be 12 (4096-byte blocks) in v5. It is recorded so that a
  later block size needs no new format.
- `rs_parity`: p ∈ {0, 4, 8, 16} parity fragments per lane (below).
- Decoding rejects other versions, unknown flags, values outside these sets
  and non-zero reserved bytes.

Every keyslot of a volume holds the same MK and parameters. Initialization
writes them, and keyslot add copies them from the active owner. The keyslot
itself has no parity: its two replicas provide redundancy.

## Context and key derivation

```
base    = "pivstore/volume/v5\0" ‖ UUID ‖ "\0" ‖ LE64(primary_bytes) ‖ LE64(S)
context = base ‖ "/layout/" ‖ ab (u8) ‖ block_log2 (u8) ‖ rs_parity (u8)
```

Keys are `HKDF-SHA256(ikm, salt, info = "pivstore/v5/" ‖ label)`, with the same
labels and salts as v4 (record keys use `context`, keyslot keys use `base`).
Binding the layout parameters into `context` means a volume opened with
mismatched parameters fails the SIV check instead of misreading records.

## Passphrase cost tiers

The KEK is either a 32-byte key file or Argon2id (v1.3, p = 4 lanes, 32-byte
output) over the passphrase:

```
salt = base ‖ "/kek/argon2id/" ‖ ASCII tier digit
```

| Tier (`--kdf-cost`) | Memory | Passes | Intended use |
| ---: | ---: | ---: | --- |
| 1 | 64 MiB | 3 | low-memory systems (v4's cost; about 0.13 s on the bench host) |
| 2 | 256 MiB | 3 | small systems |
| 3 (default) | 1 GiB | 4 | cryptsetup's LUKS2 default memory cap and lanes |
| 4 | 2 GiB | 6 | high-value passphrases on large-memory hosts |

The tier is deliberately not recorded anywhere: nothing can be decrypted before
the KEK exists, and a clear-text parameter would be public magic. The user
must pass the same tier on every open. A wrong tier is indistinguishable from
a wrong passphrase (EKEYREJECTED); pivsetup's error note mentions both.
Different tiers derive unrelated KEKs because the tier is part of the salt.

The default matches cryptsetup's LUKS2 Argon2id defaults (user decision
2026-10-22): 1 GiB of memory and 4 lanes. cryptsetup also calibrates passes to
about 2 seconds and records them in its header; v5 records nothing, so passes
are fixed per tier. The implementation must measure tier 3 with `bench` and set
its passes so it takes about 2 seconds on the reference host (4 is the starting
estimate), and confirm it runs within the pinned initramfs memory budget. The
other tiers' times are design targets. An optional `--kdf-cost auto` could try tiers in
ascending order, at the cost of their summed time. It is not part of the core
proposal.

## Reed–Solomon parity (optional, off by default)

Enabled at `--initialize` with `--parity P` (P ∈ {4, 8, 16}) and recorded as
`rs_parity`.

**Code.** RS over GF(2^8) with the polynomial 0x11d, first consecutive root 0
and primitive element 1 (the parameters dm-verity's error correction uses), so
codewords are at most 255 symbols. The 687 data fragments split into 3 lanes
by `j mod 3` (229 fragments each). Each lane carries p parity fragments, stored
at fragment indices `687 + 3i + lane` for i < p. Within a lane, byte position b
(0–5) of every fragment forms one systematic RS(229 + p, 229) codeword. That
makes 18 codewords per record, all sharing the lane's erasure positions.
Interleaving lanes across consecutive sectors spreads a burst of bad sectors
evenly.

**Tolerance.** Any p lost sectors per lane, so at least p anywhere in the
record and any run of up to 3p consecutive sectors. Capacity cost: 3p/687
(1.7% at p = 4, 3.5% at p = 8, 7.0% at p = 16).

**Writing.** A hidden write computes parity over the new payload and encodes
all G fragments with fresh `r`, exactly like data fragments. Parity is a
deterministic function of the SIV payload and lives inside the LRW PRP input,
so the stored IVs stay pseudorandom.

**Reading.**
1. Collect all G fragments. Raw IVs of sectors that fail primary authentication
   are used as in v4.
2. Fast path: SIV-open the data fragments directly.
3. If the tag fails, mark as erasures the sectors that failed authentication
   or could not be read, RS-decode each lane (erasures, then errors with
   whatever parity remains), and SIV-open again.
4. Only a valid SIV tag accepts the record. RS decoding never publishes
   anything on its own, so a wrong correction is rejected like any other
   damage, and corruption never becomes authenticated data.

**Mixed versions.** An interrupted hidden write leaves some carrier sectors with
the old version's fragments. Those sectors authenticate, so they are errors,
not erasures. If few enough, errors-only decoding may recover the new version;
otherwise the result is the v4 behaviour (EIO, or the older A/B slot). This is
a possible bonus, not a promise.

**Kernel implementation.** The pinned Debian 6.12 kernel builds
`REED_SOLOMON_DEC8` (selected by `DM_VERITY_FEC=y`), but nothing guarantees
the encoder (`REED_SOLOMON_ENC8`). dm-piv therefore implements the systematic
encoder itself. Decoding uses the exported `decode_rs8` where it is available
(verify on the 7.2 port config), otherwise an in-module decoder. The Python
decoder implements both independently as the cross-check.

## Hidden device and write rules

- The hidden view exposes logical and physical block size 4096. Every hidden
  request is a whole number of aligned 4096-byte blocks; DM splits hidden bios
  per block. No read-modify-write exists.
- **Hidden write (one block):** authenticate all G carrier sectors (strict, as
  v4), seal, re-encode G fragments with fresh `r` and collision rejection (16
  attempts), and write through the journal. With A/B, write the other slot
  with generation max + 1.
- **Decoy write:** unchanged from v4. The parity fragments are ordinary
  fragments: payload kept, `r` refreshed.
- **Hidden read:** as above. The newest valid A/B slot wins.
- **Initialization, quick init and fill** follow the roadmap. v5 makes them
  cheaper per byte because one record covers 4 KiB.

## Amplification and nonce use

A 4 KiB hidden write rewrites G sectors (687 without parity), close to v4's
8 × 90 = 720 for the same 4 KiB. At 4096-byte primary sectors that is about
2.7 MiB of primary data per 4 KiB hidden write (plus journal), the same order
as v4. The per-sector collision analysis is unchanged (80 random bits per IV).
Hot hidden blocks raise the rewrite count of their carrier sectors as in v4.

## Security notes

- The v4 pseudorandomness argument carries over: every owner-written IV in the
  keyslot, directory and record areas is an LRW-AES output on a distinct
  (tweak, input) pair. Parity is inside the PRP input.
- No public magic. The version, layout, parity and A/B flag are only inside
  encrypted keyslots. The cost tier is recorded nowhere.
- The hidden-write signature grows from 90 to G re-encrypted sectors with
  unchanged plaintext per write, but a 4 KiB write touched 720 sectors in v4
  anyway. Visibility to a decoy-key holder with journal history or two
  snapshots is unchanged.
- Offline guessing: the default tier is about 16× v4's memory cost, comparable
  to cryptsetup's own keyslots. Key files remain the high-entropy option.
- Context binding, rollback and clones: as v4 (out of scope).
- RS adds availability only. It does not change what authenticates, so it adds
  no forgery or confidentiality surface beyond more decoding attempts on
  damaged records.

## Not changed (considered)

- **Payload split.** A larger payload share per IV (for example 8 + 8) for the
  XTS profile would give +33% capacity but drop the per-sector collision bound
  for 2^24 rewrites from about 2^-33 to 2^-17. Both profiles keep 10 + 6.
- **Primitives.** The HMAC-SHA256 + ChaCha20 SIV and the PRF-masked LRW stay.
  Both are generic compositions, and the kernel has no AES-SIV. External
  review (ROADMAP) may revisit them.
- **Larger blocks** (16 KiB+) would increase capacity only marginally but
  amplify small writes. 4096 matches filesystem blocks, and `block_log2` keeps
  the option open.

## Implementation plan (after approval)

1. **Spec:** freeze this document, with any changes from review.
2. **Python reference:** encoder/decoder for v5 records, keyslots and RS, with
   unit vectors.
3. **Kernel:** 4 KiB record path, keyslot v5, layout context, hidden view block
   size 4096, RS encoder, RS decode on tag failure. NATIVE_SETUP ABI 5 carries
   the parity choice for initialization.
4. **pivsetup:** `--kdf-cost`, `--parity`, Argon2id tiers (Rust and Python
   vectors per tier).
5. **Tests:**
   - v4 suite becomes a v5 suite;
   - RS tests with k unreadable or corrupted sectors (k ≤ p per lane recovers,
     k > p returns EIO, never wrong data);
   - mixed-version tests;
   - tier mismatch rejected;
   - fault, power, cancel, lifecycle and fuzz suites updated;
   - sanitizer run;
   - `bench` for tier times and capacity.
6. **Cleanup:** remove v4 code, tests and docs; update AGENTS.md (format v5
   is the only format), README, configuration.md and security-review.md.

## Resolved review questions (2026-10-22)

- **Default cost:** tier 3, matching cryptsetup's default (user decision).
- **Parity sizes:** keep the three choices {4, 8, 16} (user decision).
- **Directory record size:** a uniform G-sector record for the directory (left
  to implementation judgment). A separate 90-sector directory record would win
  back about 5% of hidden capacity only on small 4096-byte-sector volumes, at
  the cost of a second record size and code path in the kernel, the Python
  decoder and the tests. It is not worth that maintenance.
