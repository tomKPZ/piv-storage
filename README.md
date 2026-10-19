# Persistent-IV auxiliary storage

Research prototype exposing two writable Linux device-mapper devices: a decoy
volume and an independently encrypted hidden volume carried in the decoy's
persistent AES-GCM IVs. Both devices expose plaintext block I/O and support their
own filesystem. Setup exits; the kernel owns subsequent I/O.

The current architecture has **no external persistent metadata, nonce ledger or
recovery file**. It retains the ordinary LUKS2/dm-integrity layout and journal.
Volatile ownership locks live in /run. A separate mounted root filesystem is not
an architectural requirement; keys, userspace setup tools and the matching module
must be available when activating it. Deployment remains restricted to our pinned
QEMU guest and synthetic 128 MiB disk, not general host or production use.

README and ROADMAP are provisional research notes. This is not a proven
indistinguishability construction or reliable production storage.

## Use

Follow [build and test instructions](docs/native-blocks.md). Inside the guest:

```sh
python3 -m pivstore open-blocks --device /dev/vdb \
  --key-file /mnt/piv-work/passphrase.key \
  --hidden-key-file /mnt/piv-work/hidden.key --initialize
```

This returns /dev/mapper/piv-native-decoy and /dev/mapper/piv-native-hidden.
The fixture capacities are 115,687,424 and 301,056 bytes respectively.
The hidden volume is already encrypted underneath its block interface. Setup
never creates filesystems. **--initialize destroys all existing hidden contents**
and writes authenticated zeros, while preserving every decoy plaintext byte.
Reopen without this flag. Unmount both filesystems before:

```sh
python3 -m pivstore close-blocks --device /dev/vdb \
  --key-file /mnt/piv-work/passphrase.key
```

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

Each 512-byte hidden block has one authentication tag and occupies 48 primary IVs.
Every hidden update freshly encodes its whole block; every overlapping decoy
write refreshes affected hidden records before reencrypting primary sectors.
Original primary data is authenticated before modification. Only requested decoy
bytes may change. Authentication binds hidden blocks to their address and volume.

The stock dm-integrity journal protects individual primary ciphertext/tag/IV
updates. It does **not** make a 48-sector hidden update atomic. Power loss or
storage errors can leave a hidden block unreadable; no cross-sector recovery,
rollback protection, redundancy or hidden filesystem recovery is promised.
A whole hidden block authenticates before any of its bytes are returned. This
prevents silent authenticated fragment mixing, but cannot detect whole-block
rollback or a mixture of independently valid blocks from different times.
Primary I/O/authentication failures stop the shared owner; remove and recreate
the stack after fixing the underlying fault. Hidden unavailability alone does not.

Primary 96-bit IV uniqueness is probabilistic. Every encoding uses fresh seeded
kernel randomness, with rejection of duplicates within the proposed update and
its replaced IVs. There is **no historical collision detection**. For q uniformly
random primary IVs under one key, collision probability is approximately
q(q-1)/2^97. A 2^32 per-owner encryption cap is only a diagnostic guard: reopening
resets it, and all stock writes, retries, failed preparations and clones count
toward the real per-key lifetime budget. Manage that budget externally. At 4096
bytes per encryption, 2^32 invocations represent 16 TiB including rewrite
amplification, not 16 TiB of application writes. A 512-byte hidden write
reencrypts 192 KiB of primary data (384 times as many bytes), before ordinary
journal overhead. GCM also has per-message and
aggregate security constraints; collision probability alone is not a full bound.
Never rely on snapshot-restored RNG state or replay cached encryption plans.

## Disk format and diagnostics

Supported profile: one LUKS2 AES-GCM/random segment, zero IV tweak, 4096-byte
primary sectors, 96-bit IVs, 128-bit primary tags, integrity v4 fixed padding,
28-byte metadata tuples, 32768-sector interleaving and an unencrypted/un-MACed
stock journal. Native activation delegates journal replay to Linux. Offline
image diagnostics reject a dirty journal and unsupported geometry.

```sh
python3 -m pivstore inspect artifacts/control-003/control.img
python3 -m pivstore verify artifacts/control-003/control.img \
  --volume-key-file artifacts/control-003/share/volume.key
python3 -m pivstore unpack artifacts/stateless-004/share/dual-final.img \
  --hidden-key-file artifacts/control-003/hidden.key --output artifacts/hidden.raw
PIV_FIXTURE=artifacts/control-003 python3 -W error::ResourceWarning -m unittest discover -v
```

unpack authenticates all hidden blocks and publishes a new private output file
only after success; no primary key is needed. verify authenticates the complete
primary image and prints its plaintext hash. extract-ivs performs no primary
verification. Keys belong in private files, never command arguments or commits.

Gross IV carrier capacity is 12/4096 of primary capacity. The v3 payload fraction
is 512/(48*4096), approximately 0.2604%, excluding incomplete tail groups.
512-byte primary encryption sectors would increase gross capacity eightfold but
are unsupported here. Increasing IV lengths or changing ordinary format defaults
would change the control profile and potentially make the configuration unusual.
We retain the tested stock 4096/96-bit-IV profile.

The encoded salt/ciphertext/tag is expected to look random under the primitive
assumptions in [the format notes](docs/hidden-format.md). Layout compatibility
and statistical tests are not a deniability proof. Multiple snapshots, ordinary
journal traces, write amplification, memory, installed software, keys and other
host artifacts remain explicit limitations. See [roadmap](ROADMAP.md) for results
and next work, and [observed layout](docs/observed-layout.md) for source evidence.
