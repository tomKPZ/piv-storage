# Persistent-IV auxiliary storage

Research prototype for an independently encrypted hidden volume stored in the
persistent random IVs of an authenticated Linux encrypted block volume. The
native backend exposes **two writable device-mapper devices, decoy and hidden**.
Both support independent filesystems; the kernel coordinates their writes,
nonce history and recovery. Setup exits without an I/O daemon.

This is restricted to a pinned disposable QEMU guest and one synthetic 128 MiB
LUKS2 profile. It is not production storage or a proven deniability mechanism.
README and ROADMAP remain revisable research notes, not a security specification.

## Native interface

See [setup and usage](docs/native-blocks.md) and [kernel build instructions](kernel/README.md).
Supply a backing device and private credential/hidden-key files inside the guest:

```sh
python3 -m pivstore open-blocks --device /dev/vdb \
  --key-file /mnt/piv-work/passphrase.key \
  --hidden-key-file /mnt/piv-work/hidden.key --initialize
```

This creates /dev/mapper/piv-native-decoy and /dev/mapper/piv-native-hidden.
The fixture decoy has 115,687,424 bytes and the hidden device 281,600 bytes.
Setup does not format filesystems. Use --initialize only for fresh adoption;
reopen without it. Unmount both filesystems before close-blocks.

Persistent encrypted recovery state belongs on the independent guest root ext4
filesystem. It is required for recovery and is observable evidence. Arbitrary
host disks, independent overlapping mappings and lost/rolled-back state are not
supported. No additional host tools or root privileges are needed for VM tests.

The FUSE/NBD frontends, regular-file online service and offline copy-output
mutation commands have been retired. Git history retains them. A small native
bootstrap initializes fixed-capacity records and imports nonce history using the
existing recoverable ledger/pending-v2 encoding; subsequent I/O belongs to the
kernel. Existing adopted native volumes and their state remain compatible.

## Independent diagnostics and tests

The image parser, Linux-compatible sector codec, hidden-record decoder and native
log authenticator remain independent correctness checks for kernel output.
These tools read input images and never rewrite volume data. unpack writes a new
extracted payload file and needs only the hidden key. Legacy v1 decoding remains
available for archived fixtures; native volumes use --incremental.

```sh
python3 -m pivstore inspect artifacts/control-003/control.img
python3 -m pivstore verify artifacts/control-003/control.img \
  --volume-key-file artifacts/control-003/share/volume.key
python3 -m pivstore unpack artifacts/dual-final-007/share/dual-power-final.img \
  --incremental --hidden-key-file artifacts/control-003/hidden.key \
  --output artifacts/extracted-hidden-volume
PIV_FIXTURE=artifacts/control-003 python3 -W error::ResourceWarning -m unittest discover -v
```

Other retained commands are keygen, extract-ivs and close-blocks. Extraction
outputs must not already exist. See [development and fixture creation](docs/development.md),
[record format](docs/incremental-records.md), [observed layout](docs/observed-layout.md),
[storage-error experiments](docs/native-faults.md) and [test results/handoff](ROADMAP.md).
Only native backend and diagnostic tests
remain active; retired frontends' tests and guest scripts were removed with them.

Only one narrow profile is accepted: LUKS2 with one ordinary dynamic AES-GCM/random
segment, zero IV tweak, 4096-byte sectors, an integrity v4 superblock with fixed
padding, 28-byte tuples, 32768-sector interleaving, and an unencrypted,
un-MACed journal. Offline image commands require an empty journal; native setup
uses stock dm-integrity replay before authenticated carrier access. Other profiles are rejected. LUKS2 header validation/selection
is delegated to cryptsetup; the primary volume key is supplied separately.
`verify` authenticates every primary sector and prints its SHA-256 digest without
writing plaintext. `extract-ivs` copies IV bytes in logical-sector order without
authenticating the primary data; its output must not exist, and a failed run may
leave a partial output.

## Capacity and configuration tradeoffs

For primary logical capacity V, sector size S, and 12 IV bytes per sector,
gross carrier capacity is floor(V/S) * 12.

| Encryption sector | Gross fraction of primary capacity | Per 1 TiB primary |
| --- | --- | --- |
| 4096 bytes | 0.293% | 3 GiB |
| 512 bytes | 2.344% | 24 GiB |

Actual auxiliary capacity is smaller after hidden-format overhead. Physical
device capacity must also accommodate LUKS/integrity metadata and journal space.
Smaller sectors provide eight times the carrier capacity but eight times the
GCM invocations per full-volume write and more primary metadata overhead.

Linux's ordinary gcm(aes) interface uses 96-bit IVs. A 128-bit nonce is not a
simple setting for this implementation; the 128-bit GCM tag is separate. Larger
metadata tuples do not automatically enlarge the IV. Alternative modes or
custom formats must be evaluated separately for security, compatibility, and
how unusual their visible configuration is. Establish an ordinary control
configuration before optimizing capacity.

## Limitations and threat model

Target the narrow case of a completed single image examined without the hidden
key, potentially with the primary key disclosed. The primary encrypted volume
itself is visible; the intended secret is the presence/content of the auxiliary
payload. Uniform-looking IVs alone do not prove deniability.

- Multiple snapshots or live write monitoring can expose changed primary
  ciphertext/IV/tag tuples whose decrypted primary plaintext is unchanged.
- Journals, backups, snapshots, SSD remapping, swap, crash dumps, logs, tools,
  shell history, and memory can preserve evidence or keys.
- Primary writes regenerate IVs and can destroy auxiliary records. First support
  offline auxiliary updates and primary read-only use; do not promise survival
  of arbitrary stock primary writes. The v2 coordinated write path preserves
  hidden records by refreshing their complete encodings with fresh IVs.
- Authentication detects corruption, not necessarily freshness. Same-address
  rollback may authenticate; rollback resistance needs trusted external state
  or a different explicit assumption.
- Compromise of the primary key permits destruction or replacement of carrier
  bytes. Hidden authentication can detect changes, not prevent erasure.
- Hidden writes amplify into primary-sector rewrites. Crash consistency,
  lifetime GCM limits, and physical-device behavior constrain practical use.
- A recognizable configuration or installed tool can weaken a plausible cover
  story even when the carrier bytes pass statistical checks.

Do not use the prototype for valuable data or describe it as proven deniable
encryption. Statistical tests find some mistakes; they cannot establish
cryptographic indistinguishability or erase historical evidence.


## Development environment

Host tools are Python 3, cryptography (requirements.txt), cryptsetup, QEMU/qemu-img,
git and archive/download tools. QEMU TCG avoids host root/KVM requirements.
Guest kernel/source/headers are pinned to Debian 6.12.113-1 (release
6.12.113+deb13-amd64), cryptsetup 2:2.7.5-2 and GCC 14.2.0-19.
Never load the experimental module on the host or use real disks. Sources, keys,
build products and VM images stay in ignored vendor/downloads/secrets/artifacts
locations. See environment manifests for hashes and provenance limitations.
