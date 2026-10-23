# Persistent-IV auxiliary storage

Research prototype exposing two writable Linux device-mapper devices: a decoy
volume and an independently encrypted hidden volume carried in the decoy's
persistent random IVs. The primary volume is an ordinary stock LUKS2 volume over
dm-integrity that stores a fresh random 16-byte IV per sector; the hidden volume
uses [format v5](docs/format-v5.md). The decoy device exposes 512-byte and the
hidden device 4096-byte logical blocks of plaintext; each can hold its own
filesystem. Setup exits; the kernel
owns all subsequent I/O.

> [!CAUTION]
> Research prototype: not a proven indistinguishability construction and not
> reliable production storage. **No external cryptographic review has been
> conducted** (see [Nonces and limitations](#nonces-and-limitations)). It has
> only been tested in disposable QEMU guests on synthetic disks. Use it only
> on storage whose loss you can tolerate, keep backups of both views, and read
> the internal [security and threat-model review](docs/security-review.md)
> (observer boundaries and open assumptions) first.

README and ROADMAP are provisional research notes.

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
cryptsetup/dmsetup, the keys and the matching module, on any block device or
partition holding the LUKS2 volume; it has been tested from a Python-free
RAM-root initramfs and from a stock initramfs-tools boot
([packaging/README.md](packaging/README.md): DKMS, module signing, boot
integration).

## Supported primary profiles

| Cipher | Integrity | Tag | Metadata tuple |
| --- | --- | ---: | ---: |
| `aes-xts-random` (recommended; 512-bit XTS key) | `hmac-sha256` | 32 | 48 |
| `aegis128-random` (original AEGIS-128, **not AEGIS-128L**) | `aead` | 16 | 32 |

512- or 4096-byte encryption sectors (512 recommended; 4096 on 4Kn drives),
integrity v4 fixed padding and the stock
journaled dm-integrity mode. AES-XTS uses dm-crypt's authenc key encoding: a
32- or 64-byte XTS key followed by the 32-byte HMAC key. Under XTS + HMAC a
repeated IV reveals only equal plaintext at that sector (HMAC still prevents
forgery); under AEGIS-128 it is a key compromise, and dm-piv decoy rewrites
draw only 80 fresh IV bits, so XTS + HMAC is the recommended profile (see
[configuration.md](docs/configuration.md#primary-cipher-profile) and the
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
performance). Install `pivsetup` and the module (DKMS) as described in
[packaging/README.md](packaging/README.md); [development.md](docs/development.md)
covers the VM test harness and [native-blocks.md](docs/native-blocks.md) the
module. Format the volume with stock cryptsetup (the recommended
configuration: AES-XTS + HMAC-SHA256, 512-byte sectors, `--ab` for a hidden
filesystem), then, as root:

```sh
cryptsetup luksFormat --type luks2 --cipher aes-xts-random --key-size 512 \
  --integrity hmac-sha256 --sector-size 512 --key-file /root/luks.key /dev/sdX2
pivsetup keygen --output /root/hidden.key
pivsetup open-blocks --device /dev/sdX2 --key-file /root/luks.key \
  --hidden-key-file /root/hidden.key --initialize --ab
# ... use /dev/mapper/piv-native-decoy and /dev/mapper/piv-native-hidden ...
pivsetup close-blocks --device /dev/sdX2 --key-file /root/luks.key
```

`--device` (required, no default) is the block device or partition holding
the LUKS2 volume; symlinks such as `/dev/disk/by-partuuid/...` are followed.
`--key-file` is the stock LUKS passphrase. Setup refuses non-block paths, a
whole disk with a partition table (give the partition), a device that is
mounted, mapped or opened exclusively, an owner name used by another mapping
and a volume whose /run owner lock is held. **Never open the volume for
writing with stock cryptsetup** (e.g. through `/etc/crypttab`): stock writes do
not refresh the hidden records they overwrite and destroy hidden data.
Options of `open-blocks`:

- `--initialize` **destroys all existing hidden contents**: it writes a new
  random master key, keyslot 0, the directory and authenticated zero blocks,
  preserving every decoy plaintext byte. Reopen without it. Stock carriers must
  be initialized before hidden use (stock cryptsetup still opens the decoy).
- `--quick` (with `--initialize`; not the default): write only the master key,
  keyslot 0 and the directory, in constant time. Every hidden block then
  **reads EIO until it is first written**, so tools that read blocks they never
  wrote (filesystem probes, `mkfs` checks, `dd` or backups of the whole view)
  fail; run `--fill` before using such tools.
- `--fill` (without `--initialize`; **destructive**): write zeros into every
  hidden block whose record does not authenticate and skip the valid ones. It
  completes a quick or interrupted `--initialize` and resumes itself after
  cancellation, but it also turns damaged blocks into zeros, so it never runs
  implicitly. The JSON output adds `"fill": {"valid", "written", "failed"}`
  block counts; failed blocks (carrier unreadable or failing authentication)
  are left as they were.
- `--ab` (with `--initialize`; off by default, recommended for a filesystem on
  the hidden view): two record slots per block, so a crash or interrupted
  hidden write leaves the previous version readable, at half capacity.
- `--parity 4|8|16` (with `--initialize`; off by default): Reed–Solomon parity
  fragments per record lane, so a hidden block survives up to that many
  unreadable or damaged carrier sectors per lane, for 1.7–7% of the capacity.
- `--hidden-passphrase-file F` instead of `--hidden-key-file`; the passphrase
  KEK is Argon2id at cost tier `--kdf-cost 1-4` (64 MiB, 256 MiB, 1 GiB
  (default 3) or 2 GiB; 4 lanes). The tier is recorded nowhere: give the same
  tier on every open (a wrong tier looks like a wrong passphrase). Tier 3
  needs about 1 GiB of free RAM.
- `--verify`: authenticate every primary sector first and refuse the volume on
  any failure (an O(volume) audit). By default setup scans only the 112-sector
  keyslot area, in constant time.
- `--name` (default `piv-native`; `piv-` plus up to 40 letters, digits, `_` or `-`).

A/B and parity are recorded in the encrypted keyslot; later opens read them
from there. Other commands: `pivsetup keyslot add|remove --slot 0-3` manages up
to four keyslots on active views without rewriting hidden data. It requires
the current hidden key or passphrase of a listed keyslot (`--hidden-key-file`
or `--hidden-passphrase-file` with its `--kdf-cost`); `--new-kdf-cost` sets a
new passphrase's tier, and the last keyslot cannot be removed. Re-initializing
revokes every earlier keyslot. `pivsetup migrate` copies both views into a freshly luksFormatted
volume, initializes it and compares both copies; it is the offline path for
primary rekey, resize or sector-size change, since live resize/rekey is
unsupported (stock cryptsetup refuses reencrypt and resize on integrity
volumes). See [rust/README.md](rust/README.md).

The hidden payload fraction is about 4096/(687·S) of primary capacity for
sector size S: 0.146% at 4096 bytes, 1.16% at 512 (half with `--ab`, 3p/687
less with parity), minus a fixed 112 + 2G sectors for keyslots and the
directory; measured capacities, performance and initialization times are in
[configuration.md](docs/configuration.md). A 128 MiB 4096-byte-sector volume
has too few hidden blocks for mke2fs. Setup never creates
filesystems. Unmount both filesystems before `close-blocks`. Larger geometry
uses checked kernel bounds ([large-volumes.md](docs/large-volumes.md)); the
largest tested volumes are 3 GiB (4096-byte sectors) and 2 GiB (512).

## Format v5 in brief

The first 112 primary sectors hold four encrypted keyslots (two replicas each,
no public magic; they carry the master key, the A/B flag and the parity), then
two directory records (A/B), then one record per hidden 4096-byte block: block
i at sector 112 + G·(2 + i) with G = 687 + 3p (two slots per block with `--ab`).
Each stored IV is LRW-AES(10 fresh random bytes ‖ 6 payload bytes) tweaked by
sector; 687 fragments form one SIV record (HMAC-SHA256 tag, ChaCha20)
authenticating context, layout, address, generation and data, followed by 3p
Reed–Solomon parity fragments when enabled. Keys derive via HKDF-SHA256 from
the master key with public context. Tail sectors beyond the last whole record
carry nothing. Details: [format-v5.md](docs/format-v5.md).

A decoy write re-randomizes only the IVs of the sectors it writes (one primary
encryption per written sector, as stock dm-crypt), keeping their fragments. A
hidden write re-encodes its whole G-sector record with a fresh generation.

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
  (IV damage does, unless parity corrects it). Hidden writes stay strict: all
  G carrier sectors must authenticate first.
- A damaged hidden record returns EIO for that block only; decoy writes preserve
  its damaged fragments, so corruption never becomes valid zeros. Repair a block
  with a complete 4096-byte write. With `--parity`, a record decodes despite up
  to p unreadable or authentication-failing carrier sectors per lane (or p/2
  sectors with foreign fragments); RS output is accepted only through the SIV
  tag.
- Errors before the first lower write (lower reads, authentication,
  allocation, encryption) fail only that bio. A failed flush or any failure
  once a request has begun writing stops the shared owner (fail-stop);
  remove and recreate the stack after fixing the fault
  ([native-faults.md](docs/native-faults.md)).
- The stock journal makes individual primary sector updates atomic, **not** a
  G-sector hidden record. Without `--ab`, power loss can leave a hidden block
  unreadable; with `--ab` the previous version stays readable. No cross-block
  ordering, rollback protection or hidden filesystem recovery is promised.
  Whole-record rollback is accepted.
- SIGINT/SIGTERM [cancel setup](docs/native-faults.md#cancelling-activation-initialization-and-fill-cancel-suite) between authenticated
  ranges and rounds of initialization or fill records. Completed records stay;
  an interrupted `--initialize` leaves later blocks unavailable until `--fill`
  completes it. Cleanup removes only the
  attempt's own identity-checked mappings and never rolls back disk writes.

## Nonces and limitations

**No external cryptographic review.** The stored encoding (LRW-AES fragments,
SIV records, keyslots and directory, passphrase KDF), the use of the AEGIS-128
and AES-XTS + HMAC-SHA256 primary profiles and the nonce-budget guidance have
only had internal review ([security review](docs/security-review.md)). Treat
every security claim here as unreviewed.

Primary IV uniqueness is probabilistic. A decoy rewrite keeps a sector's 6
payload bytes and draws 10 fresh random bytes, so n rewrites of one sector
repeat an IV with probability about n²/2^81; IVs of distinct sectors behave as
independent 128-bit values. Encodings use fresh seeded kernel randomness and
reject duplicates only within one update and its replaced IVs; there is **no
historical collision detection**. The 2^40 per-owner encryption cap resets on
reopen and does not enforce the per-key lifetime budget, to which all writes,
retries, failed preparations and clones count. VM snapshot restores, image
clones and cloned RNG state invalidate these estimates. A 4096-byte hidden
write reencrypts G = 687 + 3p primary sectors (2.7 MiB at 4096-byte sectors,
344 KiB at 512, without parity) plus journal overhead; decoy writes have no
hidden amplification.

Each stored IV is expected to look uniformly random without the hidden key under
the assumptions in [format-v5.md](docs/format-v5.md); layout compatibility and
statistical tests are not a deniability proof.
[Matched ordinary-Linux controls](docs/detectability.md) show a decoy write
changes exactly the IVs an ordinary write changes. Explicit limitations: a
single raw image can contain journal history; a decoy-key holder can decrypt
retained journal entries and may see a hidden write's G sectors reencrypted
with unchanged plaintext
([security review](docs/security-review.md#journal-history-and-the-decoy-key-holder));
multiple snapshots, hidden-write amplification, memory, installed software, keys
and host artifacts; no protection against root, a compromised kernel, memory or
crash dumps, swap or malicious firmware. Keyslots allow offline guessing, so
prefer high-entropy key files; passphrases are only as strong as the KDF cost
tier.
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

## Before production use

Read this list before trusting real data to the prototype.

- **No external cryptographic review** ([Nonces and
  limitations](#nonces-and-limitations)); treat every security claim as
  unreviewed.
- **Never open the volume read-write with stock tools.** Keep it out of
  `/etc/crypttab`, and disable udisks/desktop auto-unlock and
  systemd-gpt-auto-generator for it: a stock read-write open destroys hidden
  data. There is no decoy-only dm-piv mode, so daily use needs the hidden key,
  and boot activation reveals that a hidden volume is configured (/etc/pivtab
  and the initramfs; [packaging/README.md](packaging/README.md)).
- **Journal history.** Real volumes of 8 GiB or more get a 64 MiB integrity
  journal that keeps recent writes (roughly the last 190 hidden-block writes at
  512-byte sectors) and removed keyslots visible to a decoy-key holder with one
  raw image. Write more than a journal's worth of decoy data after hidden use
  ([configuration.md](docs/configuration.md#journal-size-and-history)).
- **Crashes.** Without `--ab`, any hidden block written since the last flush
  may read EIO after a crash or power cut, which can break a hidden
  filesystem; use `--ab` for filesystems. Failures show only as EIO and dmesg
  messages; there is no status command or non-destructive hidden scrub
  (`--fill` is destructive). See [native-faults.md](docs/native-faults.md).
- **Kernel upgrades.** Only Debian 6.12.113 and 7.2.9 are tested. A failed DKMS
  build makes `update-initramfs` fail for the new kernel; keep the previous
  kernel bootable. The safe fallback without dm-piv is a stock read-only open
  of the decoy (`cryptsetup open --readonly`).
- **Version lockstep.** Install pivsetup and the module from the same release
  (packaging/VERSION); a control-ABI mismatch is refused with both versions
  named (`pivsetup --version`).
- **Capacity planning.** There is no resize, rekey or cipher change except the
  offline `pivsetup migrate`, which needs a second device and is not
  resumable. Choose the size and options up front.
- **Backups.** Back up plaintext copied from the hidden view (and the decoy).
  Raw images carry journal history, and restoring a VM snapshot or image clone
  reuses RNG state and nonce budget.
- **Memory.** Passphrase tier 3 needs about 1 GiB of free RAM, also in the
  initramfs; pivsetup refuses early when less is available.
- **Scale.** Tested up to 3 GiB volumes on a host-cached virtual disk; times
  for larger disks are extrapolations (initialization on real disks runs at
  roughly disk bandwidth / 3). There is no discard/TRIM support.

## Further reading

[configuration.md](docs/configuration.md) (choosing options, performance),
[packaging/README.md](packaging/README.md) (installation, DKMS, signing, boot),
[ROADMAP.md](ROADMAP.md) (remaining work), [development.md](docs/development.md)
(harness, test suites, sanitizer and newer-kernel guests),
[native-blocks.md](docs/native-blocks.md) (module, I/O path, bounded reads),
[native-faults.md](docs/native-faults.md) (failure scope, fault and
cancellation tests), [format-v5.md](docs/format-v5.md) (hidden format),
[security-review.md](docs/security-review.md) (threat model, limits),
[journal-atomicity.md](docs/journal-atomicity.md),
[large-volumes.md](docs/large-volumes.md),
[detectability.md](docs/detectability.md) (matched controls),
[observed-layout.md](docs/observed-layout.md) (source evidence).
Executed test runs are recorded in commit messages.
