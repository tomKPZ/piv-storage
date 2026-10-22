# Persistent-IV auxiliary storage

Research prototype exposing two writable Linux device-mapper devices: a decoy
volume and an independently encrypted hidden volume carried in the decoy's
persistent random IVs. The primary volume is an ordinary LUKS2 volume with the
original AEGIS-128 AEAD (`aegis128-random`, 16-byte random IVs); the hidden
volume uses the fragment-local [format v4](docs/format-v4.md). Both devices
expose plaintext block I/O and support their own filesystem. Setup exits; the
kernel owns subsequent I/O.

Since 2026-10-21 AEGIS-128 with format v4 is the only supported profile. The
earlier format v3 and the AES-GCM / ChaCha20-Poly1305 profiles (12-byte IVs)
were removed: v4 needs 16-byte IVs to keep enough per-sector randomness while
carrying hidden fragments (see [format-v4.md](docs/format-v4.md)). Their code and
evidence remain in Git history before that date.

The current architecture has **no external persistent metadata, nonce ledger or
recovery file**. It retains the ordinary LUKS2/dm-integrity layout and journal.
Volatile ownership locks live in /run. A separate mounted root filesystem is not
an architectural requirement: activation needs only the static `pivsetup`
binary, cryptsetup/dmsetup, the keys and the matching module (verified on a
Python-free RAM-root initramfs). Deployment remains restricted to our pinned
QEMU guest and synthetic 128 or 512 MiB disks, not general host or production
use. [Larger-volume support](docs/large-volumes.md) goes beyond the former
256 MiB primary cap; live resizing is not implemented.
[Read and activation profiling](docs/read-performance.md) records measured costs
and bounded primary read batching. Every sector still authenticates before
plaintext or carrier IVs are returned.

The separate `dm-piv.ko` module registers `piv-crypt` and `piv-view`, alongside
the stock `dm-crypt` module's `crypt` target. Stock encrypted filesystems may
remain mounted while our module loads, serves its paired devices and unloads.
It is a standalone implementation of the per-sector AEAD path (no dm-crypt
fork); it does not hook or replace the stock target. Builds still need the
matching kernel headers.

README and ROADMAP are provisional research notes. This is not a proven
indistinguishability construction or reliable production storage. The internal
[security and threat-model review](docs/security-review.md) defines the observer
boundaries and open assumptions; independent cryptographic review remains open.

## Use

Setup is the static Rust `pivsetup` binary (rust/), built rootlessly on the
host with `python3 scripts/build_pivsetup.py` and shared into the guest; the
Python package keeps only independent read-only diagnostics. Follow
[build and test instructions](docs/native-blocks.md). Inside the guest:

```sh
pivsetup open-blocks --device /dev/vdb \
  --key-file /mnt/piv-work/passphrase.key \
  --hidden-key-file /mnt/piv-work/hidden.key --initialize
```

This returns /dev/mapper/piv-native-decoy and /dev/mapper/piv-native-hidden.
Both 512- and 4096-byte primary sectors are supported; activation reads the
geometry from LUKS metadata. Both public devices use 512-byte logical blocks.
For our 128 MiB disk fixtures:

| Sector bytes | Decoy bytes | Hidden bytes | Hidden bytes with `--ab` |
| ---: | ---: | ---: | ---: |
| 4096 | 115,572,736 | 158,720 | 79,360 |
| 512 | 109,060,096 | 1,209,856 | 604,672 |

A decoy write re-randomizes only the IVs of the sectors it writes (one primary
encryption per written sector, as stock dm-crypt). A hidden write re-encodes its
whole 90-sector record. `--ab` keeps two record slots per block so an
interrupted hidden write leaves the previous version readable, at half the
capacity. A random master key lives in up to four encrypted keyslots (no public
header); the hidden key file is a keyslot key, or use `--hidden-passphrase-file`
(Argon2id by default, `--kdf scrypt` as the alternative; use the same KDF on
every open). Later opens read the layout from the keyslot.
`pivsetup keyslot add|remove --slot N` adds or retires keys on active views
without rewriting hidden data. `pivsetup migrate` copies both views into a new,
freshly formatted volume (primary rekey, resize or sector-size change) and
verifies both copies; see [rust/README.md](rust/README.md).

The hidden volume is already encrypted underneath its block interface. Setup
never creates filesystems. **--initialize destroys all existing hidden contents**
(it writes a new master key, keyslot 0 and the directory, then authenticated
zeros), while preserving every decoy plaintext byte. Reopen without this flag.
Ctrl-C or SIGTERM can [cancel activation/initialization](docs/cancellation.md);
an interrupted initialization leaves the not-yet-written blocks unavailable, and
lower I/O can delay interruption. Unmount both filesystems before:

```sh
pivsetup close-blocks --device /dev/vdb \
  --key-file /mnt/piv-work/passphrase.key
```

A failed setup attempts to remove only its own mappings. Conflicting names are
preserved, and cleanup failures are reported with the original error. Close also
validates both view mappings before removal and can release an idle private owner.
Cleanup releases resources; it does not roll back a partial initialization.

Opening without `--initialize` requires a keyslot to authenticate under the
hidden key (or passphrase KDF) and the keyslot directory to be readable;
otherwise setup fails (EKEYREJECTED for a wrong key) and removes its mappings.
This **wrong-key guard** uses keyslot IVs collected by setup's scan of the
112-sector keyslot area. Setup does not read the rest of the volume (constant
time on any size); every later request authenticates exactly the sectors it
touches, so a damaged sector returns EIO when accessed, as in stock dm-crypt.
`--verify` instead authenticates every primary sector first and refuses the
volume on any failure (an O(volume) audit). A decoy write covering a whole
damaged sector replaces it (fresh IV; its hidden fragment is kept only if the
record still authenticates).

Stock `--integrity-no-journal` volumes (LUKS2 persistent flag) open only with
`--allow-no-journal`: they keep no journal history on disk, but a crash during a
hidden write can destroy decoy sectors of that record, not just sectors being
written (docs/journal-atomicity.md). The journal remains the default. A stock carrier has no keyslot: initialize it, or use stock
cryptsetup for decoy-only access. A damaged hidden record returns EIO locally;
decoy writes preserve its (damaged) fragments, so corruption never becomes valid
zeros. Repair an unavailable block with a complete 512-byte direct-I/O write: a
smaller buffered write can trigger a page-sized read that also includes
unavailable neighbors.

There is no compatibility with previous hidden formats or external state. There
is no legacy decoder, bootstrap, compaction command, FUSE/NBD or offline writer.

## Integrity and crash limits

Each 512-byte hidden block is one SIV record (tag over context, address,
generation and data) in 90 primary IVs, after 112 keyslot sectors and two
directory records. A record authenticates only as a whole, so old and new
fragments never mix silently; whole-record rollback and independently valid
records from different times are still accepted. Original primary data is
authenticated before modification, and only requested decoy bytes change.

The stock dm-integrity journal protects individual primary ciphertext/tag/IV
updates. It does **not** make a 90-sector hidden record update atomic (see
[journal-atomicity.md](docs/journal-atomicity.md)). Without `--ab`, power loss or
storage errors can leave a hidden block unreadable; with `--ab` the previous
version stays readable. No cross-block ordering, rollback protection or hidden
filesystem recovery is promised. Failures that leave storage unchanged are local
to the request: lower read errors, primary or hidden authentication failures,
allocation and preparation failures return EIO (or the specific error) and both
views keep serving other requests. A failed flush, or any failure once a write
has begun applying tuples, leaves storage or durability unknown and stops the
shared owner; remove and recreate the stack after fixing the underlying fault.

Primary IV uniqueness is probabilistic. A decoy rewrite of a sector keeps its 6
hidden bytes and draws 10 fresh random bytes, so n rewrites of one sector repeat
a nonce with probability about n²/2^81; across distinct sectors the IVs behave
as independent 128-bit values. Every encoding uses fresh seeded kernel
randomness, with rejection of duplicates within the proposed update and its
replaced IVs. There is **no historical collision detection**. A 2^32 per-owner
encryption cap is only a diagnostic guard: reopening resets it. All writes,
retries, failed preparations and clones count toward the real per-key budget.
A 512-byte hidden write reencrypts 90 primary sectors (360 KiB at 4096-byte
sectors, 45 KiB at 512), before ordinary journal overhead; decoy writes have no
hidden amplification. Measured write costs are in ROADMAP.md (guest-v4-test).

Never rely on snapshot-restored RNG state or replay cached encryption plans. A
repeated primary IV under one key is AEAD nonce reuse. VM snapshot restores,
image clones and cloned RNG state all invalidate the estimates above.

## Disk format and diagnostics

Supported profile: one LUKS2 AEGIS-128/random segment (`--cipher
aegis128-random --integrity aead --key-size 128`), zero IV tweak, 512- or
4096-byte primary sectors, 128-bit primary tags, integrity v4 fixed padding,
32-byte metadata tuples (128-bit IV), 32768-sector interleaving (512-byte units)
and an unencrypted/un-MACed stock journal. Native activation delegates journal
replay to Linux. Offline image diagnostics reject a dirty journal and
unsupported geometry. Linux `aegis128` is the original five-state algorithm,
**not AEGIS-128L**. The selected cipher is visible in LUKS metadata; compare
detectability against a matched ordinary AEGIS-128 volume.

```sh
python3 -m pivstore inspect artifacts/control-001/control.img
python3 -m pivstore verify artifacts/control-001/control.img \
  --volume-key-file artifacts/control-001/share/volume.key
python3 -m pivstore unpack artifacts/suite-next/aegis-4096-native/share/dual-final.img \
  --hidden-key-file artifacts/control-001/hidden.key --output artifacts/hidden.raw
PIV_FIXTURE=artifacts/control-001 python3 -W error::ResourceWarning -m unittest discover -v
```

Primary verification needs the pinned optional x86 AES-NI
[AEGIS-128 diagnostic reference](docs/development.md#original-aegis-128-diagnostics).
Native activation, early boot and hidden extraction do not need that library.
unpack opens a keyslot with the given key file, authenticates all hidden blocks
and publishes a new private output file only after success; no primary key is
needed. verify authenticates the complete primary image and prints its
plaintext hash. extract-ivs performs no primary verification. Keys belong in
private files, never command arguments or commits.

Gross IV carrier capacity is 16/S of primary capacity for encryption-sector
size S; the v4 payload fraction is 512/(90·S): 0.139% at 4096 bytes or 1.11% at
512 bytes (half with `--ab`). Smaller primary sectors require more ordinary
tag/IV metadata, reducing decoy capacity on a fixed raw disk.

Every stored IV is an LRW-AES output over fresh randomness and a hidden
fragment, expected to look uniformly random without the hidden key under the
primitive assumptions in [format-v4.md](docs/format-v4.md). Layout compatibility
and statistical tests are not a deniability proof. Even a single raw image can
contain journal history. Keyslots allow offline key guessing, so prefer
independent high-entropy key files; passphrases are only as strong as the KDF
cost allows. Multiple snapshots, ordinary journal traces, hidden-write
amplification, memory, installed software, keys and other host artifacts remain
explicit limitations. There is no protection against root, a compromised
kernel, live-memory or crash dumps, swap, or malicious storage firmware. A
holder of the decoy key can decrypt retained journal entries and may see a
hidden write's 90 sectors reencrypted with unchanged plaintext (see the
[security review](docs/security-review.md#journal-history-and-the-decoy-key-holder)).
[Matched ordinary-Linux controls](docs/detectability.md) show that a v4 decoy
write changes exactly the IVs an ordinary write changes. These results provide
no multi-snapshot/workload-observing deniability guarantee. See
[roadmap](ROADMAP.md) for results and next work, and
[observed layout](docs/observed-layout.md) for source evidence.
