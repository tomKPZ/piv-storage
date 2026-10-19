# Persistent-IV auxiliary storage

Research prototype exposing two writable Linux device-mapper devices: a decoy
volume and an independently encrypted hidden volume carried in the decoy's
persistent random IVs (AES-GCM, ChaCha20-Poly1305 or original AEGIS-128). Both devices expose
plaintext block I/O and support their own filesystem. Setup exits; the kernel owns subsequent I/O.

The current architecture has **no external persistent metadata, nonce ledger or
recovery file**. It retains the ordinary LUKS2/dm-integrity layout and journal.
Volatile ownership locks live in /run. A separate mounted root filesystem is not
an architectural requirement; keys, userspace setup tools and the matching module
must be available when activating it. Deployment remains restricted to our pinned
QEMU guest and synthetic 128 or 512 MiB disks, not general host or production
use. [Larger-volume support](docs/large-volumes.md) is verified beyond the former
256 MiB primary cap at both sector sizes; live resizing is not implemented.
[Read and activation profiling](docs/read-performance.md) records measured costs
and bounded primary read batching. Every sector still authenticates before
plaintext or carrier IVs are returned.

The separate `dm-piv.ko` module registers `piv-crypt` and `piv-view`, alongside
the stock `dm-crypt` module's `crypt` target. Stock encrypted filesystems may
remain mounted while our module loads, serves its paired devices and unloads.
It retains a private copy of pinned dm-crypt code; it does not hook or replace
the stock target. Exact kernel build compatibility is still required.

README and ROADMAP are provisional research notes. This is not a proven
indistinguishability construction or reliable production storage. The internal
[security and threat-model review](docs/security-review.md) defines the observer
boundaries and open assumptions; independent cryptographic review remains open.

## Use

Follow [build and test instructions](docs/native-blocks.md). Inside the guest:

```sh
python3 -m pivstore open-blocks --device /dev/vdb \
  --key-file /mnt/piv-work/passphrase.key \
  --hidden-key-file /mnt/piv-work/hidden.key --initialize
```

This returns /dev/mapper/piv-native-decoy and /dev/mapper/piv-native-hidden.
All three primary ciphers support both 512- and 4096-byte
sectors. Activation detects the cipher and geometry from LUKS metadata without
an override flag. Both public devices use 512-byte logical
blocks. For our 128 MiB disk fixtures:

| Primary cipher | Sector bytes | Decoy bytes | Hidden bytes |
| --- | ---: | ---: | ---: |
| AES-GCM / ChaCha20-Poly1305 | 4096 | 115,687,424 | 301,056 |
| AES-GCM / ChaCha20-Poly1305 | 512 | 109,977,600 | 2,291,200 |
| AEGIS-128 | 4096 | 115,572,736 | 400,896 |
| AEGIS-128 | 512 | 109,060,096 | 3,028,992 |

The hidden volume is already encrypted underneath its block interface. Setup
never creates filesystems. **--initialize destroys all existing hidden contents**
and writes authenticated zeros, while preserving every decoy plaintext byte.
Reopen without this flag. Unmount both filesystems before:

```sh
python3 -m pivstore close-blocks --device /dev/vdb \
  --key-file /mnt/piv-work/passphrase.key
```

A failed setup attempts to remove only its own mappings. Conflicting names are
preserved, and cleanup failures are reported with the original error. Close also
validates both view mappings before removal and can release an idle private owner.
Cleanup releases resources; it does not roll back a partial initialization.

A stock, uninitialized carrier can be opened without initialization: decoy I/O
works, hidden reads return EIO, and full hidden-block writes initialize individual
blocks. Repair of an unavailable block should use a complete 512-byte direct-I/O
write: a smaller buffered write can trigger a page-sized read that also includes
unavailable neighbors. Initialize the full hidden volume before ordinary
filesystem use. A damaged or wrong-key hidden record likewise returns EIO locally.
Decoy writes preserve valid hidden data; touching an unavailable hidden record
writes a fresh encrypted invalid marker, so it cannot silently become valid zeros.
A wrong hidden key cannot be distinguished from damaged/absent data. **Decoy writes
with a wrong hidden key can destroy hidden data.** Key provisioning must be correct.

There is no compatibility with previous hidden formats or external state. Old
volumes must be extracted using the old Git revision before migration. There is
no legacy decoder, bootstrap, compaction command, FUSE/NBD or offline writer.

## Integrity and crash limits

Each 512-byte hidden block has one authentication tag and occupies 48 primary IVs
for AES-GCM/ChaCha20-Poly1305 or 36 for AEGIS-128.
Every hidden update freshly encodes its whole block; every overlapping decoy
write refreshes affected hidden records before reencrypting primary sectors.
Decoy I/O is processed in batches of up to 16 KiB, refreshing each intersecting
record once per batch. Separate small writes still repeat that work.
Original primary data is authenticated before modification. Only requested decoy
bytes may change. Authentication binds hidden blocks to their address and volume.

The stock dm-integrity journal protects individual primary ciphertext/tag/IV
updates. It does **not** make a multi-sector hidden update atomic. Power loss or
storage errors can leave a hidden block unreadable; no cross-sector recovery,
rollback protection, redundancy or hidden filesystem recovery is promised.
A whole hidden block authenticates before any of its bytes are returned. This
prevents silent authenticated fragment mixing, but cannot detect whole-block
rollback or a mixture of independently valid blocks from different times.
Primary I/O/authentication failures stop the shared owner; remove and recreate
the stack after fixing the underlying fault. Hidden unavailability alone does not.

Primary IV uniqueness is probabilistic (96 bits for AES-GCM/ChaCha20-Poly1305;
128 bits for AEGIS-128). Every encoding uses fresh seeded
kernel randomness, with rejection of duplicates within the proposed update and
its replaced IVs. There is **no historical collision detection**. For q uniformly
random primary IVs under one key, collision probability is approximately
q(q-1)/2^97 for 96-bit IVs, or q(q-1)/2^129 for 128-bit IVs. A 2^32 per-owner
encryption cap is only a diagnostic guard: reopening
resets it. For random-IV AES-GCM, the 2^32 limit applies across all
instances using the key, not separately to each activation; this prototype does
not enforce that lifetime requirement. All stock writes, retries, failed
preparations and clones count
toward the real per-key lifetime budget. Manage that budget externally.
2^32 invocations represent 16 TiB at 4096 bytes per encryption or 2 TiB at 512 bytes, including rewrite amplification. These are primary encryption bytes,
not application-write allowances. For AES/ChaCha, a 512-byte hidden write reencrypts 192 KiB of
primary data with 4096-byte sectors (384 times as many bytes), or 24 KiB with
512-byte sectors (48 times), before ordinary journal overhead.
AEGIS-128 rewrites 144 KiB (288 times) or 18 KiB (36 times), respectively. Each primary AEAD also has per-message and
aggregate security constraints; collision probability alone is not a full bound.
Never rely on snapshot-restored RNG state or replay cached encryption plans.

## Disk format and diagnostics

Supported profiles: one LUKS2 AES-GCM/random, ChaCha20-Poly1305/random or
AEGIS-128/random segment, zero IV tweak, 512- or 4096-byte primary sectors,
128-bit primary tags, integrity v4 fixed padding, 28-byte metadata tuples
(96-bit IV) or AEGIS-128's stock 32-byte tuples (128-bit IV), 32768-sector interleaving (512-byte units) and an unencrypted/un-MACed
stock journal. Native activation delegates journal replay to Linux. Offline
image diagnostics reject a dirty journal and unsupported geometry.

Stock cryptsetup selections (when formatting a new volume) are:

| Primary cipher | Cipher option | Integrity option | Primary key |
| --- | --- | --- | --- |
| AES-GCM | `--cipher aes-gcm-random` | `--integrity aead` | 256 bits |
| ChaCha20-Poly1305 | `--cipher chacha20-random` | `--integrity poly1305` | 256 bits |
| Original AEGIS-128 | `--cipher aegis128-random` | `--integrity aead` | 128 bits |

AES-GCM and ChaCha20-Poly1305 use the same 12-byte IV/16-byte tag layout and have the same carrier
capacity and probabilistic nonce-collision limits. Hidden records continue to
use their independent ChaCha20-Poly1305 keys regardless of the primary cipher.
Linux `aegis128` is the original five-state algorithm, **not AEGIS-128L**. Its
16-byte IVs and 16-byte tags are ordinary cryptsetup defaults for that cipher.
The selected cipher is visible in LUKS metadata; compare detectability against
a matched ordinary volume using that same cipher, not against an AES volume.
Selecting a different primary cipher requires a newly formatted volume; there
is no in-place cipher conversion command in this prototype.

```sh
python3 -m pivstore inspect artifacts/control-003/control.img
python3 -m pivstore verify artifacts/control-003/control.img \
  --volume-key-file artifacts/control-003/share/volume.key
python3 -m pivstore unpack artifacts/stateless-004/share/dual-final.img \
  --hidden-key-file artifacts/control-003/hidden.key --output artifacts/hidden.raw
PIV_FIXTURE=artifacts/control-003 python3 -W error::ResourceWarning -m unittest discover -v
```

For AEGIS-128 primary verification, build the pinned optional x86 AES-NI
[diagnostic reference](docs/development.md#original-aegis-128-diagnostics).
Native activation, early boot and hidden extraction do not need that library.

unpack authenticates all hidden blocks and publishes a new private output file
only after success; no primary key is needed. verify authenticates the complete
primary image and prints its plaintext hash. extract-ivs performs no primary
verification. Keys belong in private files, never command arguments or commits.

Gross IV carrier capacity is IV_bytes/S of primary capacity for encryption-sector size
S. The v3 payload fraction is 512/(group*S), excluding incomplete tail groups.
For 48-sector groups this is 0.2604% at 4096 bytes or 2.0833% at 512 bytes;
AEGIS-128's 36-sector groups yield 0.3472% or 2.7778%.
Smaller primary sectors require more ordinary tag/IV metadata, reducing decoy
capacity on a fixed raw disk. Each profile retains stock cryptsetup's layout,
cipher-specific IV size and 128-bit tags; changing sector size requires a newly formatted
volume, not an activation switch. Do not override a cipher's normal IV size to increase capacity.

The encoded salt/ciphertext/tag is expected to look random under the primitive
assumptions in [the format notes](docs/hidden-format.md). Layout compatibility
and statistical tests are not a deniability proof. Even a single raw image can
contain journal history. Hidden records allow
offline key guessing, so the hidden key must be independent high-entropy key
material, not a password. Multiple snapshots, ordinary
journal traces, write amplification, memory, installed software, keys and other
host artifacts remain explicit limitations. [Matched ordinary-Linux controls](docs/detectability.md)
show that the current prototype's extra reencryption is visible under a known
primary workload: AES/4096 changed 192 IVs where ordinary writes changed 7.
Ordinary whole-group rewrites matched those 192 positions too, so this footprint
alone does not establish hidden payload existence. These results provide no
multi-snapshot/workload-observing deniability guarantee. See [roadmap](ROADMAP.md) for results
and next work, and [observed layout](docs/observed-layout.md) for source evidence.
