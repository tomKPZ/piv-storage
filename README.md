# Persistent-IV auxiliary storage

Research prototype exposing two writable Linux device-mapper devices: a decoy
volume and an independently encrypted hidden volume carried in the decoy's
persistent random IVs. The primary volume is an ordinary stock LUKS2 volume over
dm-integrity that stores a fresh random 16-byte IV per sector; the hidden volume
uses [format v4](docs/format-v4.md). Both devices expose plaintext 512-byte
logical-block I/O and can hold their own filesystem. Setup exits; the kernel
owns all subsequent I/O.

This is not a proven indistinguishability construction or reliable production
storage. README and ROADMAP are provisional research notes; the internal
[security and threat-model review](docs/security-review.md) defines observer
boundaries and open assumptions. Independent cryptographic review remains open.

## Components

- `kernel/dm-piv.ko`: standalone out-of-tree module (no dm-crypt fork or patch)
  registering `piv-crypt` (private owner over stock dm-integrity) and
  `piv-view` (the public decoy and hidden views). It reproduces the Linux LUKS2
  per-sector AEAD layout and coexists with stock dm-crypt/dm-integrity, even
  while stock encrypted filesystems are mounted. See
  [kernel/README.md](kernel/README.md) and [native-blocks.md](docs/native-blocks.md).
- `pivsetup`: static Rust setup binary ([rust/README.md](rust/README.md)) that
  drives cryptsetup/dmsetup and the module's control device. Keys are read from
  files into mlocked, zeroized buffers and never appear in argv.
- `pivstore` (Python): independent read-only diagnostics (`inspect`, `verify`,
  `extract-ivs`, `unpack`) and guest test instrumentation. Not needed at runtime.

There is **no external persistent metadata, nonce ledger, WAL or recovery
file**: only ordinary LUKS2/dm-integrity structures and encrypted records inside
IVs. Volatile ownership locks live in /run. Activation needs only `pivsetup`,
cryptsetup/dmsetup, the keys and the matching module; it has been tested from a
Python-free RAM-root initramfs. Use is restricted to the pinned disposable QEMU
guest and synthetic 128 or 512 MiB disks (`/dev/vdb`), not real hosts or disks.

## Supported primary profiles

| Cipher | Integrity | Tag | Metadata tuple |
| --- | --- | ---: | ---: |
| `aegis128-random` (default; original AEGIS-128, **not AEGIS-128L**) | `aead` | 16 | 32 |
| `aes-xts-random` | `hmac-sha256` | 32 | 48 |

512- or 4096-byte encryption sectors, integrity v4 fixed padding and the stock
journaled dm-integrity mode. AES-XTS uses dm-crypt's authenc key encoding: a
32- or 64-byte XTS key followed by the 32-byte HMAC key. Under XTS + HMAC a
repeated IV reveals only equal plaintext at that sector (HMAC still prevents
forgery); under AEGIS-128 it is a key compromise (see the
[security review](docs/security-review.md)). The cipher is visible in LUKS
metadata; compare detectability against a matched ordinary volume of the same
profile.

Stock `--integrity-no-journal` volumes (persistent LUKS2 `no-journal` flag)
are refused: without the journal a crash during a hidden write can tear decoy
sectors of that record, and the measured write gain for dm-piv was small
([journal-atomicity.md](docs/journal-atomicity.md)).

## Usage

Choose the primary cipher, sector size and A/B with
[configuration.md](docs/configuration.md) (trade-offs, defaults and measured
performance). Build on the host with `python3 scripts/build_pivsetup.py`; see
[development.md](docs/development.md) for the VM harness and
[native-blocks.md](docs/native-blocks.md) for the module. Inside the guest:

```sh
pivsetup keygen --output /mnt/piv-work/hidden.key
pivsetup open-blocks --device /dev/vdb \
  --key-file /mnt/piv-work/passphrase.key \
  --hidden-key-file /mnt/piv-work/hidden.key --initialize
# ... use /dev/mapper/piv-native-decoy and /dev/mapper/piv-native-hidden ...
pivsetup close-blocks --device /dev/vdb --key-file /mnt/piv-work/passphrase.key
```

`--key-file` is the stock LUKS passphrase. Options of `open-blocks`:

- `--initialize` **destroys all existing hidden contents**: it writes a new
  random master key, keyslot 0, the directory and authenticated zero blocks,
  preserving every decoy plaintext byte. Reopen without it. Stock carriers must
  be initialized before hidden use (stock cryptsetup still opens the decoy).
- `--ab` (with `--initialize`): two record slots per block, so an interrupted
  hidden write leaves the previous version readable, at half capacity.
- `--hidden-passphrase-file F` instead of `--hidden-key-file`; the passphrase
  KEK is always Argon2id (64 MiB, t=3, p=4).
- `--verify`: authenticate every primary sector first and refuse the volume on
  any failure (an O(volume) audit). By default setup scans only the 112-sector
  keyslot area, in constant time.
- `--name` (default `piv-native`), `--device` (default `/dev/vdb`).

Other commands: `pivsetup keyslot add|remove --slot 0-3` manages up to four
keyslots on active views without rewriting hidden data (the last keyslot cannot
be removed). `pivsetup migrate` copies both views into a freshly luksFormatted
volume, initializes it and compares both copies; it is the offline path for
primary rekey, resize or sector-size change, since live resize/rekey is
unsupported (stock cryptsetup refuses reencrypt and resize on integrity
volumes). See [rust/README.md](rust/README.md).

Capacity on the 128 MiB fixtures (AEGIS-128; XTS + HMAC-SHA256 tuples are
larger, so slightly fewer sectors):

| Sector bytes | Decoy bytes | Hidden bytes | Hidden bytes with `--ab` |
| ---: | ---: | ---: | ---: |
| 4096 | 115,572,736 | 158,720 | 79,360 |
| 512 | 109,060,096 | 1,209,856 | 604,672 |

The hidden payload fraction is 512/(90·S) of primary capacity for sector size
S: 0.139% at 4096 bytes, 1.11% at 512 (half with `--ab`). Setup never creates
filesystems. Unmount both filesystems before `close-blocks`. Larger geometry
uses checked kernel bounds ([large-volumes.md](docs/large-volumes.md)), but the
fixture guard admits only 128 and 512 MiB disks.

## Format v4 in brief

The first 112 primary sectors hold four encrypted keyslots (two replicas each,
no public magic), then two directory records (A/B), then one record per hidden
512-byte block: block i at sector 112 + 90·(2 + i) (two slots per block with
`--ab`). Each stored IV is LRW-AES(10 fresh random bytes ‖ 6 payload bytes)
tweaked by sector; 90 fragments form one SIV record (HMAC-SHA256 tag,
ChaCha20) authenticating context, address, generation and data. Keys derive via
HKDF-SHA256 from the master key with public context. Tail sectors beyond the
last whole record carry nothing. Details: [format-v4.md](docs/format-v4.md).

A decoy write re-randomizes only the IVs of the sectors it writes (one primary
encryption per written sector, as stock dm-crypt), keeping their fragments. A
hidden write re-encodes its whole 90-sector record with a fresh generation.

## Authentication, failures and crashes

- Without `--initialize`, a keyslot must authenticate under the hidden key (the
  **wrong-key guard**, EKEYREJECTED otherwise) and the directory must be
  readable; setup then removes its own mappings.
- Every request authenticates exactly the primary sectors it touches; damage
  returns EIO when accessed, as in stock dm-crypt. Original primary data is
  authenticated before modification and only requested decoy bytes change.
- A decoy write covering an entire primary sector that fails authentication
  replaces it (fresh IV, refreshed fragment); partial writes to it fail EIO.
- Hidden reads, keyslots and the directory use raw stored IVs of sectors whose
  decoy data fails authentication; only the record's SIV tag decides validity,
  so damage confined to decoy data does not make a hidden block unavailable
  (IV damage does). Hidden writes stay strict: all 90 carrier sectors must
  authenticate first.
- A damaged hidden record returns EIO for that block only; decoy writes preserve
  its damaged fragments, so corruption never becomes valid zeros. Repair a block
  with a complete 512-byte direct-I/O write (buffered sub-page writes may first
  read unavailable neighbours).
- Errors before the first applied tuple (lower reads, authentication,
  allocation, preparation) fail only that bio. A failed flush or any failure
  after a write begins applying tuples stops the shared owner (fail-stop);
  remove and recreate the stack after fixing the fault
  ([native-faults.md](docs/native-faults.md)).
- The stock journal makes individual primary sector updates atomic, **not** a
  90-sector hidden record. Without `--ab`, power loss can leave a hidden block
  unreadable; with `--ab` the previous version stays readable. No cross-block
  ordering, rollback protection or hidden filesystem recovery is promised.
  Whole-record rollback is accepted.
- SIGINT/SIGTERM [cancel setup](docs/cancellation.md) between authenticated
  ranges and initialization records. Completed records stay; an interrupted
  `--initialize` leaves later blocks unavailable. Cleanup removes only the
  attempt's own identity-checked mappings and never rolls back disk writes.

## Nonces and limitations

Primary IV uniqueness is probabilistic. A decoy rewrite keeps a sector's 6
payload bytes and draws 10 fresh random bytes, so n rewrites of one sector
repeat an IV with probability about n²/2^81; IVs of distinct sectors behave as
independent 128-bit values. Encodings use fresh seeded kernel randomness and
reject duplicates only within one update and its replaced IVs; there is **no
historical collision detection**. The 2^32 per-owner encryption cap resets on
reopen and does not enforce the per-key lifetime budget, to which all writes,
retries, failed preparations and clones count. VM snapshot restores, image
clones and cloned RNG state invalidate these estimates. A 512-byte hidden write
reencrypts 90 primary sectors (360 KiB at 4096-byte sectors, 45 KiB at 512)
plus journal overhead; decoy writes have no hidden amplification.

Each stored IV is expected to look uniformly random without the hidden key under
the assumptions in [format-v4.md](docs/format-v4.md); layout compatibility and
statistical tests are not a deniability proof.
[Matched ordinary-Linux controls](docs/detectability.md) show a decoy write
changes exactly the IVs an ordinary write changes. Explicit limitations: a
single raw image can contain journal history; a decoy-key holder can decrypt
retained journal entries and may see a hidden write's 90 sectors reencrypted
with unchanged plaintext
([security review](docs/security-review.md#journal-history-and-the-decoy-key-holder));
multiple snapshots, hidden-write amplification, memory, installed software, keys
and host artifacts; no protection against root, a compromised kernel, memory or
crash dumps, swap or malicious firmware. Keyslots allow offline guessing, so
prefer high-entropy key files; passphrases are only as strong as the KDF cost.
Multi-snapshot observers, rollback resistance and coercion-resistant alternative
openings are out of scope.

## Diagnostics

```sh
python3 -m pivstore inspect PREFIX/aegis-4096-control/control.img
python3 -m pivstore verify PREFIX/aegis-4096-control/control.img \
  --volume-key-file PREFIX/aegis-4096-control/share/volume.key
python3 -m pivstore unpack PREFIX/aegis-4096-native/share/dual-final.img \
  --hidden-key-file PREFIX/aegis-4096-control/hidden.key --output hidden.raw
```

`verify` authenticates the complete primary image and prints its plaintext hash;
AEGIS-128 needs the pinned [SUPERCOP diagnostic
reference](docs/development.md#original-aegis-128-diagnostics) and AES-XTS +
HMAC-SHA256 uses `cryptography`; both profiles are fully decrypted on the host.
`unpack` opens a keyslot,
authenticates every hidden block and publishes a private output file only on
success. `extract-ivs` performs no primary verification. Offline diagnostics
reject a dirty journal; native activation lets Linux replay it. Keys belong in
private files, never command arguments or commits.

## Further reading

[configuration.md](docs/configuration.md) (choosing options, performance),
[ROADMAP.md](ROADMAP.md) (remaining work), [development.md](docs/development.md)
(harness and tests), [native-blocks.md](docs/native-blocks.md),
[native-faults.md](docs/native-faults.md),
[read-performance.md](docs/read-performance.md),
[observed-layout.md](docs/observed-layout.md) (source evidence),
[sanitizer.md](docs/sanitizer.md), [kernel-port.md](docs/kernel-port.md).
Executed test runs are recorded in commit messages.
