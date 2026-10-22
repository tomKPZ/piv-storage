# Hidden format v4 (fragment-local re-randomization)

Format v4 is the only hidden format. It is implemented in the kernel module
(`kernel/piv-native.inc`) and independently in the read-only Python decoder
(`pivstore/records_v4.py`, `pivstore/format.py`); pivsetup (`rust/src/`) derives
the keyslot KEK and passes the public context. This document is an internal
specification, not an independent cryptographic review; tested behaviour is
recorded in commit messages.

## Primary profiles

Format v4 stores everything in the 16-byte random IVs that stock LUKS2 +
dm-integrity already keep per primary encryption sector. It works with both
supported stock profiles (stored random 16-byte IVs, 512- or 4096-byte sectors):

| LUKS2 encryption | Integrity | Volume key | Tag | Tuple (tag ‖ IV) |
| --- | --- | --- | ---: | ---: |
| `aegis128-random` (original AEGIS-128, default) | `aead` | 16 bytes | 16 | 32 |
| `aes-xts-random` | `hmac-sha256` | XTS key (32 or 64) ‖ HMAC key (32) | 32 | 48 |

Primary authentication is unchanged Linux: AEGIS-128 uses AAD
`LE64(sector × S/512) ‖ IV`; AES-XTS + HMAC-SHA256 uses the IV as XTS tweak and
the tag `HMAC-SHA256(LE64(sector × S/512) ‖ IV ‖ ciphertext)`. The hidden format does not
depend on the profile except through the number of primary sectors. Profiles
with 12-byte IVs cannot carry v4; other XTS ciphers and HMAC digests are
refused.

## Why 10 random + 6 payload bytes

A decoy write must give the touched sector a new primary nonce while keeping
the hidden payload bytes it carries. Each IV therefore encodes `r ‖ d`: fresh
random bytes `r` and a fixed payload fragment `d`. Repeated decoy writes keep `d`
fixed, so a nonce collision at one sector needs a repeated `r`. A sector
rewritten n times collides with probability about n²/2^(8|r|+1):

| Payload bytes per IV | Random bits | n = 2^24 rewrites of one sector |
| ---: | ---: | --- |
| 6 (v4) | 80 | about 2^-33 |
| 8 | 64 | about 2^-17 |

## Geometry

Let `N` be the number of primary encryption sectors (sector size `S`). All
indices below are 0-based primary sector indices.

| Region | Sectors | Contents |
| --- | --- | --- |
| Keyslots | 0 – 111 | 4 keyslots × 2 replicas × 14 sectors; keyslot k replica r at `(2k + r)·14` |
| Directory | 112 – 291 | groups 0 and 1 (A/B pair), 90 sectors each |
| Records | from 292 | group g at `112 + 90·g`; without A/B block i is group `2 + i`, with A/B block i uses groups `2 + 2i` (slot 0) and `3 + 2i` (slot 1) |
| Tail | rest | sectors after the last complete record: ordinary random IVs |

Hidden blocks: `⌊(N − 292)/90⌋`, halved (rounded down) with A/B; each holds
512 bytes. Setup refuses volumes with fewer than `292 + 90` (A/B: `292 + 180`)
sectors and bounds `N·S` by the kernel's `MAX_LFS_FILESIZE`. The payload
fraction is 512/(90·S): 0.139% at 4096-byte sectors, 1.11% at 512-byte sectors.
On the 128 MiB fixtures this gives 158,720 bytes (AEGIS, 4096) and 1,209,856
bytes (AEGIS, 512); XTS + HMAC tuples are larger, so dm-integrity provides fewer
primary sectors (for example 158,208 / 1,168,896 bytes with HMAC-SHA256; see
[observed-layout.md](observed-layout.md)).

## Public context and key derivation

```
base    = "pivstore/volume/v4\0" ‖ UUID (ASCII, as in LUKS2) ‖ "\0"
          ‖ LE64(primary_bytes) ‖ LE64(S)
context = base ‖ "/ab"        (A/B layout)
        = base                (otherwise)
```

All keys are 32 bytes: `HKDF-SHA256(ikm, salt, info = "pivstore/v4/" ‖ label)`.

| Keys | ikm | salt | labels |
| --- | --- | --- | --- |
| Record/directory keys | master key MK (32 random bytes) | `context` | `tweak`, `prp`, `mac`, `enc` |
| Keyslot k keys | KEK (32 bytes) | `base` | `keyslot-tweak`, `keyslot-prp` (outer keys OK), `keyslot-mac`, `keyslot-enc` (inner keys) |

Because the A/B suffix is in the record context, every record key differs
between layouts. The KEK is a 32-byte random key file or a passphrase KDF
computed by pivsetup with Argon2id (v1.3, m = 64 MiB, t = 3, p = 4, salt =
`base ‖ "/kek/argon2id"`). The KDF parameters are fixed and not recorded.

## Fragment encoding

Sector s carries `x_s = r_s[10] ‖ d_s[6]`, stored as the primary IV

```
Δ_s  = AES-256-Enc(K_tweak, LE128(s))
IV_s = AES-256-Enc(K_prp, x_s ⊕ Δ_s) ⊕ Δ_s
x_s  = AES-256-Dec(K_prp, IV_s ⊕ Δ_s) ⊕ Δ_s
```

This is LRW with a PRF-derived mask: a tweakable strong PRP with the sector
index as tweak. Keyslot k uses its outer keys OK_k; the directory, records and
everything up to the end of the record area use the record keys.

## SIV layer (records, directory, keyslots)

```
tag     = HMAC-SHA256(K_mac, ctx ‖ label ‖ LE64(id) ‖ plain)[0:16]
ct      = ChaCha20(K_enc, block counter 0, nonce = tag[0:12]) ⊕ plain
payload = tag ‖ ct ‖ zero padding,  fragment j = payload[6j : 6j + 6]
```

| Object | ctx | label | id | plain | payload / fragments |
| --- | --- | --- | --- | --- | --- |
| Record or directory group g | `context` | `"/record/"` | g | `LE64(gen) ‖ data[512]` | 16 + 520 + 4 zero = 540 B / 90 |
| Keyslot k, replica r | `base` | `"/keyslot/"` | 2k + r | `LE32(4) ‖ LE32(flags) ‖ MK[32] ‖ zero[24]` | 16 + 64 + 4 zero = 84 B / 14 |

Decoding rejects (as unavailable) non-zero padding, a tag mismatch, and for
keyslots a version other than 4, unknown flags (only bit 0 = A/B) or non-zero
reserved bytes. The layer is deterministic: identical data at the same address
gives identical payload; freshness of stored bytes comes from the outer random
`r`. A record authenticates only as a whole; fragments of different versions
fail the tag except with probability 2^-128.

Generations: without A/B, record generation is 0. With A/B, a read returns the
valid slot with the larger generation; a write targets the other slot with
generation max + 1 (slot 0, generation 1 if neither slot is valid). The
directory always uses this A/B rule on groups 0/1 (generation incremented per
directory write).

## Keyslots and directory

The directory's 512-byte data holds, for keyslot j, a 65-byte entry at offset
65j: `present (0 or 1) ‖ OK_tweak[32] ‖ OK_prp[32]`; absent entries and bytes
260–511 must be zero.

- **Purpose.** An owner opened through one keyslot must still refresh the
  fragments of every other keyslot on decoy writes without knowing their KEKs.
  Keyslot areas not listed in the directory get ordinary random IVs.
- **Leak.** OK_k reveals only the outer randomization of keyslot k, never its
  inner keys or KEK, and only to holders of MK.
- **Key check.** Without `--initialize`, setup collects the 112 keyslot IVs from
  its scan and tries every keyslot replica under the KEK (no extra I/O). None
  authenticating returns `EKEYREJECTED`. A successful keyslot gives MK and the
  A/B flag; the directory must then authenticate and parse, otherwise setup
  refuses (`EUCLEAN`), because decoy writes would destroy the unlisted
  keyslots. There is no mode for uninitialized stock carriers.
- **Keyslot add/remove** (`pivsetup keyslot`, NATIVE_KEYSLOT on an active
  owner): add writes both replicas, then the directory; remove updates the
  directory, then overwrites both replicas with random IVs. The last keyslot
  cannot be removed. Records are untouched; a passphrase change is add + remove.

## Write rules

All writes go through the single coordinated owner and authenticate the old
primary data of every touched sector before modifying it.

**Decoy write** (≤ 16 KiB per work item): for each written primary sector,
decode the old IV, keep its 6 payload bytes, draw fresh `r'` and re-encode
(rejecting a result equal to the old IV); keyslot sectors use the listed OK_k,
unlisted keyslot areas and tail sectors get fresh random IVs. The new plaintext
is encrypted under the new IV. One primary encryption per written sector; no
hidden record is read or authenticated, so damage stays damage and a decoy
write never turns a damaged record into a valid one.

**Failing primary sector.** A decoy write covering an entire primary sector
that fails authentication replaces it (fresh IV, the raw stored fragment is
refreshed like any other; the record's SIV tag still decides hidden validity).
A partial write to such a sector fails with EIO.

**Hidden write** (exactly one 512-byte block): authenticate the primary data of
all 90 carrier sectors (to obtain exact old IVs), seal the record and re-encode
all 90 fragments with fresh `r`; primary plaintext is unchanged. A fresh IV equal
to an old or another fresh IV of the same request triggers re-encoding (up to 16
attempts). Hidden writes stay strict: any failing carrier sector fails the write.

Every request prepares all tuples before the first APPLY through the lower
dm-integrity journal; the journal's per-sector atomicity does not make a
90-sector record atomic. Without A/B, an interrupted hidden write leaves the
block unavailable (EIO); with A/B the previous version stays readable. There is
no cross-block ordering.

## Reads and raw IVs

Decoy reads authenticate every sector before publishing bytes. Keyslot, directory
and hidden-record decoding take the raw stored IV of any carrier sector whose
primary data fails authentication: only the SIV tag can accept it, so nothing
unauthenticated is published. Primary data damage or a torn decoy write (both
IVs carry the same fragment) therefore leaves the hidden block readable; IV
damage or mixed fragments make it unavailable.

## Setup and initialization

pivsetup passes `base` and the KEK (NATIVE_SETUP ABI 4, flags INITIALIZE, AB,
VERIFY; AB only with INITIALIZE). Setup scans only the 112 keyslot sectors by
default; `--verify` authenticates every primary sector first and refuses on any
failure. Pending signals are polled between ranges and records; completed
records stay written (cancellation is not rollback).

Initialization draws a fresh MK, writes keyslot 0 (both replicas) under the KEK,
writes the directory listing it, then writes a zero record for every block (one
slot per block with A/B). Because MK is replaced first, an interrupted
re-initialization leaves not-yet-written blocks unavailable rather than holding
their previous contents. The keyslot areas 1–3 keep their existing IVs.

## Security notes

- **Pseudorandomness argument (unreviewed).** Without MK, every IV written by
  the owner in the keyslot/directory/record areas is an LRW-AES output on a
  distinct (tweak, input) pair, hence indistinguishable from uniform 128-bit IVs
  up to the TPRP advantage (about q²/2^128 over all blocks) plus the per-sector
  repeat event. Tail and unlisted keyslot areas are uniform random. SIV payload,
  padding and keyslot contents are inside the PRP input and never directly
  visible. Local collision rejection slightly conditions the distribution.
- **No public magic.** Nothing identifies a v4 volume without a key; the A/B
  flag is only inside encrypted keyslots.
- **Offline guessing.** Keyslots are a fast key-check oracle; passphrases are
  only as strong as the KDF cost. Prefer 32-byte key files.
- **Context binding.** The context binds UUID, primary size, sector size and
  layout, not time, primary key or physical disk: whole-record rollback and
  copies to a clone with the same context are accepted (out of scope).
- **Hidden-write signature.** A hidden write re-encrypts 90 sectors with
  unchanged primary plaintext. A decoy-key holder who sees journal history or
  two snapshots can detect it; decoy writes have the stock footprint
  ([detectability.md](detectability.md)). Stock `--integrity-no-journal` would
  avoid on-disk journal history but is refused, because a crash could then tear
  decoy sectors ([journal-atomicity.md](journal-atomicity.md)).
- Nonce budgets, observers and limits: [security-review.md](security-review.md).
