# Hidden format v4 design (fragment-local re-randomization)

Status (2026-10-21): phases 1-3 implemented (fragments, records, keyslots and
directory, A/B slots) in the kernel and the independent Python decoder; phase 4
(`--integrity-no-journal`) is supported as an explicit opt-in since 2026-10-21
(docs/journal-atomicity.md). v4 is the only hidden format: format v3
and the 12-byte-IV profiles were removed on 2026-10-21 (user decision), so
Primary profiles: AEGIS-128 (default) or XTS + HMAC authenc, all with stored
16-byte random IVs. Nothing here is an independent
cryptographic review; tested behaviour is recorded in commit messages.

## Goals

1. A coordinated decoy write changes only the IVs of the primary sectors it
   writes, as stock random-IV dm-crypt does. The removed v3 re-randomized a
   whole 36/48-sector group, the 192-vs-7 footprint in docs/detectability.md
   and the main source of write amplification, nonce-budget use and wear.
2. Whole-block authentication of hidden data, with no silent mixing of old and
   new fragments.
3. An encrypted header without public magic: fast key check, wrapped master
   key (passphrase change, several passphrases) and version/flags.
4. Optional A/B record slots: an interrupted hidden write leaves the previous
   version readable.
5. Every stored IV byte stays pseudorandom without the hidden key.

## Why 16-byte IVs only

A decoy write must give the touched sector a new primary nonce while keeping
the hidden payload bytes it carries. So each IV holds `r || d`: fresh random
bytes `r` and a fixed payload fragment `d`. Repeated decoy writes keep `d` fixed,
so a nonce collision at that sector needs a repeated `r`. A sector rewritten n
times collides with probability about n²/2^(8|r|+1).

| IV | payload bytes per sector | random bits | n = 2^24 rewrites of one sector |
| --- | ---: | ---: | --- |
| 16 (AEGIS-128) | 6 | 80 | about 2^-33 |
| 16 (AEGIS-128) | 8 | 64 | about 2^-17 |
| 12 (AES-GCM/ChaCha) | 4 | 64 | about 2^-17 |

v4 uses 6 payload bytes and 10 random bytes per 16-byte IV. 12-byte profiles
cannot meet a comparable bound with a useful payload, which is why they were
removed together with v3. This matches
the decision to make AEGIS-128 the recommended profile.

## Fragment encoding

Primary encryption sector `s` (0-based) carries a 16-byte value
`x_s = r_s[10] || d_s[6]`, stored as

```
Δ_s  = AES-256(K_tweak, LE128(s))
IV_s = AES-256(K_prp, x_s ⊕ Δ_s) ⊕ Δ_s
```

This is LRW with a PRF-derived mask: a tweakable strong PRP with the sector
number as the tweak. Outputs at different sectors behave as independent
random values. At one sector, distinct `x_s` give distinct IVs. Decoding is
`x_s = AES-256⁻¹(K_prp, IV_s ⊕ Δ_s) ⊕ Δ_s`.

**Decoy write** of sector s, after primary authentication:
1. Decode `d_s` from the old IV.
2. Draw a fresh `r'`. Encode `IV'_s = PRP_s(r' || d_s)`, rejecting `IV'_s == IV_s`.
3. Encrypt the new primary plaintext under `IV'_s`.

There are no group reads, no record authentication and no invalid markers. A
damaged or absent record keeps its (garbage) payload bytes and stays
unavailable. Corruption is never turned into valid data. Tail sectors and
sectors outside any record or keyslot get ordinary fresh random IVs.

## Records

Hidden block i (512 bytes) is one record of 536 payload bytes in G = 90
fragments (540 bytes; the last 4 bytes are zero and must decode as zero).
Record group g starts at primary sector 112 + 90·g; the context is
`"pivstore/volume/v4\0" || UUID || NUL || LE64(primary_bytes) || LE64(sector_size)`,
followed by `"/ab"` for the A/B layout. Because the layout is part of the
context, every key differs between modes, and opening in the wrong mode fails
the key guard instead of returning another group's data:

```
gen    = LE64 generation (0 without A/B)
group  = record group (2 + i without A/B; groups 0-1 are the directory)
tag    = HMAC-SHA256(K_mac, context || "/record/" || LE64(group) || gen || data)[0:16]
ct     = ChaCha20(K_enc, counter = 0, nonce = tag[0:12]) XOR (gen || data)
payload= tag[16] || ct[520] || zero[4]
```

This is a deterministic authenticated encryption (SIV) layer. Freshness and
pseudorandomness of stored bytes come from the outer per-fragment
randomization, so identical data at the same address may give identical
payload. A record authenticates only as a whole. Fragments from different
versions fail the tag except with probability 2^-128. Whole-record rollback,
and valid records from different times, are still accepted (out of scope).

- **Hidden write:** read and authenticate the record's G primary sectors (to get
  exact old IVs for PREPARE/APPLY), then re-encode every fragment with fresh `r`.
- **Amplification:** a hidden write re-encrypts G primary sectors, 2.5x the removed v3
  AEGIS (90 vs 36). Decoy writes have no hidden amplification at all.
- **Capacity:** 512/(90·S): 0.139% at 4096-byte sectors, 1.11% at 512-byte
  sectors. That is about 40% of the removed v3 on AEGIS; A/B halves it again.

## Keys, keyslots and directory

A 32-byte random master key MK derives all record keys:
`K_* = HKDF-SHA256(MK, salt = context, info = label)` for the labels
tweak, prp, mac and enc.

**Keyslots.** The first 8·14 primary sectors hold four keyslots, each with two
replicas. A keyslot plaintext is 64 bytes:

```
version LE32 (=4) || flags LE32 (bit0 = A/B) || MK[32] || reserved[24] = 0
```

It is SIV-encoded with keys derived from a key-encryption key KEK_k: outer
tweak/prp keys OK_k and inner mac/enc keys IK_k, each by HKDF with distinct
labels. Payload is 16 + 64 = 80 bytes, which fills 14 fragments (84 bytes,
zero padded).

**Directory.** Groups 0 and 1 after the keyslots hold an A/B record under MK
keys. Its data lists, for each keyslot in use, that keyslot's outer keys OK_k
(never KEK_k or IK_k).

- **Why the directory exists:** the owner, opened through any one keyslot, must
  still refresh the fragments of every other keyslot on decoy writes without
  knowing their KEKs. Keyslots absent from the directory hold ordinary random
  IVs and receive fresh random IVs.
- **What leaks:** OK_k reveals only the outer randomization of keyslot k, not
  its MK wrapping (IK_k).
- **KEK:** derived in userspace (pivsetup). Either a 32-byte random key file,
  or a passphrase KDF: Argon2id (default since 2026-10-21; RFC 9106 second
  recommendation: m = 64 MiB, t = 3, p = 4; salt = base context ||
  "/kek/argon2id") or scrypt (`--kdf scrypt`; N = 2^17, r = 8, p = 1; salt =
  base context || "/kek"). Parameters and the KDF choice are fixed per keyslot
  but not recorded, because nothing is stored in clear: opening with the wrong
  KDF simply fails the key check. All keyslot
  keys use HKDF with the base context (without "/ab") as salt.
- **Fast key check:** setup collects the keyslot fragments by scanning the
  keyslot area and authenticates them. A wrong KEK fails immediately (EKEYREJECTED)
  without any record decryption.
- **Corruption:** replicas defend a keyslot. A lost directory still allows
  unlocking, but decoy writes would then destroy the other keyslots. Setup
  therefore refuses to expose the decoy writable unless the directory
  authenticates.
- **Passphrase change / added passphrase:** an ioctl rewrites keyslot k (both
  replicas) and the directory. Records are untouched.

## A/B slots (optional, flag in the keyslot)

Block i uses record slots 2i and 2i+1. A read authenticates both and returns
the valid one with the larger gen. A write targets the other slot (or an
invalid one) with gen = max+1. A torn write invalidates only the target slot,
so the previous version stays readable. Both slots' fragments go through the
same fragment-local decoy refresh. Interrupted writes can still leave both
slots valid at different generations. Readers pick the newest, so this is
crash-safe per block but has no cross-block ordering.

## Pseudorandomness argument (to be reviewed)

Without the hidden key, every IV written by the coordinated owner is an LRW-AES
output on a distinct (tweak, input) pair. It is therefore indistinguishable
from uniform 128-bit IVs up to the TPRP advantage (birthday bound in the total
number of blocks, about q²/2^128), plus the per-sector repeat event above.
Unused regions and tails are uniform random. The SIV payload, magic-free
keyslots and zero padding are inside the PRP input and never directly visible.
Stock-written sectors remain uniform random.

## Remaining observability

- A hidden write still re-encrypts G sectors with unchanged primary plaintext.
  A decoy-key holder who sees journal history or two snapshots can detect it.
  Decoy writes no longer have this signature.
- Use stock `--integrity-no-journal` (pivsetup `--allow-no-journal`) to avoid
  retaining history on disk, accepting the torn-decoy-sector hazard documented
  in docs/journal-atomicity.md.

## Activation and detection

Userspace (pivsetup) passes the v4 base context and the keyslot KEK (SETUP ABI
4: flags INITIALIZE, AB and VERIFY). Setup scans the 112 keyslot sectors (all
sectors with VERIFY), collects their IVs (raw stored IVs for sectors failing
authentication, which only the keyslot SIV tag can accept; hidden reads and the
directory do the same for their carriers) and tries
every keyslot replica. A keyslot that authenticates selects the A/B layout from
its flags; the directory must then authenticate too. Otherwise setup fails with
EKEYREJECTED. Initialization creates a random master key, keyslot 0 under the
KEK and the directory before writing zero records. Because the master key is
replaced first, an interrupted re-initialization leaves the not-yet-written
blocks unavailable (EIO) rather than holding their previous contents.

## Implementation phases

1. **Fragment codec and v4 records** (no header, raw master key, no A/B): kernel
   path for 16-byte-IV profiles, fragment-local decoy refresh, independent Python
   decoder and host tests, guest suites.
2. **Keyslots and directory:** KDF in userspace, fast key check replacing the
   record-probe guard for v4, passphrase add/change ioctl.
3. **A/B slots** as an initialization option, plus interrupted-write tests.
4. **`--integrity-no-journal` support** — done as an opt-in; the journal stays
   the default (docs/journal-atomicity.md).
