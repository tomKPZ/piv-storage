# Persistent-IV auxiliary storage

Research prototype for storing an independently encrypted auxiliary payload in
the persistent random IVs of a Linux authenticated encrypted block volume,
while preserving the primary volume's plaintext and authentication.

**Status:** the offline and userspace prototypes are implemented. The new native
interface exposes two writable device-mapper block devices, decoy and hidden,
with encryption and coordinated updates in the kernel. Setup returns without
leaving an NBD/FUSE service running. See [native block usage](docs/native-blocks.md).
The implementation remains restricted to a pinned disposable QEMU guest and one
supported authenticated LUKS2 profile; it is not production storage or a
proven deniability mechanism.
This README and [ROADMAP.md](ROADMAP.md) are working
hypotheses, not a fixed specification. Change them when experiments or source
inspection provide better evidence; record consequential decisions and why.

## Goal and current scope

The implemented offline compatibility baseline can:

1. Inspect a supported authenticated volume and extract its persistent IVs.
2. Encode/decode an authenticated, independently encrypted auxiliary blob there.
3. Reencrypt affected primary sectors using the primary volume key without
   changing their plaintext.
4. Produce an image readable by unmodified Linux dm-crypt and cryptsetup.

The current target is two writable block devices suitable for independent
filesystems, supplied keys, and disposable VM storage. Earlier one-file FUSE
and NBD backends remain regression references. The offline
tool and its tests remain the compatibility reference. Broader offline hardening,
systematic steganalysis/benchmarks, extra profiles and production deployment work
are deferred so they do not block the online demonstration.

Earlier coordinated online backends remain available. The regular-file backend uses
whole-image replacement, a read-only NBD primary export and FUSE. The original native
backend uses an opt-in dm-crypt extension, a read-only device-mapper primary view,
and the same one-file FUSE interface. It authenticates and reencrypts unchanged
primary sectors through the existing dm-integrity target, without raw metadata
edits or full-image replacement. An encrypted external recovery journal and
persistent nonce reservations support interrupted whole-record updates.

The native prototype milestones K0–K3 are complete on the pinned disposable
Debian QEMU guest. See [native build/run instructions](kernel/README.md),
[implemented protocol and recovery limits](docs/kernel-implementation.md),
[regular-file usage](docs/online-implementation.md), and [test evidence](ROADMAP.md).
The opt-in v2 backend adds independently encrypted records and coordinated
read-write primary access through NBD, with encryption/integrity I/O in the
kernel. Legacy direct crypt views and v1 primary exports remain read-only. The current
piv-view block interface is writable on both sides. See
[incremental records and writable usage](docs/incremental-records.md).
Native setup deliberately
rejects arbitrary host devices and requires private recovery state on guest root
ext4. External state is observable evidence and is required for interrupted-update
recovery; this is not a deniability guarantee.

## Running the current prototype

The current host uses Python 3 with the maintained `cryptography` library and
the installed cryptsetup CLI. Python was chosen because these are already
available and support small, inspectable format/crypto code without a new
toolchain. Tested library version is in requirements.txt. Run from this checkout:

```sh
python3 scripts/fetch_sources.py
python3 scripts/vm.py prepare
python3 scripts/vm.py run --script scripts/guest-control.sh --run-dir artifacts/control-003
python3 -m pivstore inspect artifacts/control-003/control.img
python3 -m pivstore verify artifacts/control-003/control.img --volume-key-file artifacts/control-003/share/volume.key
python3 -m pivstore extract-ivs artifacts/control-003/control.img --output artifacts/control-003/carrier.bin
PIV_FIXTURE=artifacts/control-003 python3 -m unittest discover -v
```

To create a synthetic hidden blob in a new image (use a new destination/key name
if any example path already exists):

```sh
mkdir -p secrets
python3 -m pivstore keygen --output secrets/hidden.key
python3 -m pivstore pack artifacts/control-003/control.img --output artifacts/packed.img --payload path/to/synthetic-payload --volume-key-file artifacts/control-003/share/volume.key --hidden-key-file secrets/hidden.key
python3 -m pivstore unpack artifacts/packed.img --output artifacts/recovered-payload --hidden-key-file secrets/hidden.key
python3 -m pivstore verify artifacts/packed.img --volume-key-file artifacts/control-003/share/volume.key
```

`pack` authenticates the input, rewrites the entire carrier with freshly randomized
hidden encryption, verifies the complete primary output, and publishes a separate
private image. It never replaces an existing destination or edits the input.
`unpack` requires only the hidden key. The prototype v1 format uses a random
32-byte salt, HKDF-SHA256 and ChaCha20-Poly1305 with all framing/padding inside
encryption. Read [the format and its assumptions](docs/hidden-format.md) before
changing it. At the tested size, usable hidden capacity is 338,864 bytes.
Every v1 update rewrites all 28,244 primary sectors. Opt-in native v2 rewrites
only changed 32-sector records and has 281,920 bytes of hidden capacity on this
fixture; it is a distinct format with no automatic v1 migration.

Use disposable known-lineage images only: the CLI cannot establish historical
GCM nonce usage, enforce a primary-key lifetime budget, or make clone branches
and rollback safe. Cryptographic review and stronger persistence evaluation
remain outstanding. Python does not guarantee erasure of key/plaintext buffers.

Choose a fresh run directory if that path exists. The VM runner needs no host
root; it uses software emulation by default. See [development instructions](docs/development.md)
for dependencies, provenance limitations, artifacts, and the observed 9p failure.

Only one narrow profile is accepted: LUKS2 with one ordinary dynamic AES-GCM/random
segment, zero IV tweak, 4096-byte sectors, an integrity v4 superblock with fixed
padding, 28-byte tuples, 32768-sector interleaving, and an unencrypted,
un-MACed journal. Offline image commands require an empty journal; native setup
uses stock dm-integrity replay before authenticated carrier access. Other profiles are rejected. LUKS2 header validation/selection
is delegated to cryptsetup; the primary volume key is supplied separately.
`verify` authenticates every primary sector and prints its SHA-256 digest without
writing plaintext. `extract-ivs` copies IV bytes in logical-sector order without
authenticating the primary data; its output must not exist, and a failed run may
leave a partial output. Copy-output publication has process-crash tests, but
hardware power-loss durability has not been established.

The validated control volume has 28,244 primary sectors, 115,687,424 primary
bytes, and 338,928 gross carrier bytes. Both stock Linux and the userspace
verifier produced the same full primary plaintext digest. See the
[observed layout](docs/observed-layout.md) for details and evidence.

## Running the online demonstration

The QEMU runner installs FUSE/NBD dependencies inside the guest and exports the
package source read-only. No additional host package or host root is required.
Use disposable input: this integration script creates a new primary filesystem
on a copied volume and deliberately discards any incoming hidden payload.

```sh
python3 scripts/vm.py run --code --script scripts/guest-online.sh --data-image artifacts/control-003/control.img --share-file artifacts/control-003/share/passphrase.key --share-file artifacts/control-003/share/volume.key --share-file artifacts/control-003/hidden.key --run-dir artifacts/online-002 --timeout 1500
```

Choose a fresh run directory and generate a disposable hidden.key with `keygen`
if one does not exist. The guest mounts a primary filesystem read-only through
NBD and a single hidden file through FUSE, edits/truncates/fsyncs it, restarts,
and independently checks the final primary through stock Linux. See the online
usage document for manual commands, session-budget limits and recovery caveats.
The regular-file API/CLI is experimental: raw block devices, arbitrary editors requiring
rename/create operations, ordinary primary writes, and production durability are
outside scope. `serve --initialize` starts empty and replaces any existing hidden
payload on its next flush; omit it when reopening an existing hidden record.

## Proposed mechanism

The primary stack is filesystem -> dm-crypt AEAD -> dm-integrity -> device.
The candidate configuration is LUKS2, AES-256-GCM with random persistent IVs,
4096-byte encryption sectors, 96-bit IVs, and 128-bit authentication tags.
Confirm the exact cryptsetup syntax and resulting parameters on the pinned
test versions before publishing executable setup instructions.

For each sector i, primary encryption conceptually computes:

    (ciphertext_i, tag_i) = AEAD(primary_key, IV_i, plaintext_i, AAD_i)

The auxiliary ciphertext supplies the stored IV bytes. To change those bytes,
authenticate/decrypt the existing primary sector, select the new IV, and
recompute its ciphertext and tag. Never change only the IV. The current Linux
AEAD path authenticates a little-endian sector value and the original IV as
associated data; reproduce the exact version-specific address/offset semantics,
not an assumed logical sector number.

Ordinary AES-XTS volumes generally derive tweaks from addresses and have no
equivalent persistent random-IV channel. Authentication tags are constrained by
primary authentication and are not free payload space. Extra tuple padding is
not presumed available: the current dm-crypt AEAD path zero-fills unused bytes.

### Format inspection and primary crypto

First pin and record kernel/cryptsetup versions and source revisions. Establish:

- LUKS2 header selection, segment offsets, cipher parameters and sector units.
- dm-integrity superblock, tuple ordering, interleaving, padding, journal state,
  and mapping from logical sectors to ciphertext and IV/tag locations.
- AES key length, actual IV length, tag length, exact AAD serialization, and
  distinction between 512-byte addressing units and encryption sectors.

Use existing cryptographic libraries. Do not implement AES, GCM, a password KDF,
or a new AEAD primitive. Separate the format reader, primary-sector codec,
carrier mapping, hidden-record codec, and transactional image writer.
Reject unsupported variants explicitly, validate bounds and arithmetic, and
authenticate original sectors before accepting or modifying their plaintext.
Do not parse password keyslots initially: use an explicitly supplied primary
volume key through a protected input mechanism. Never expose keys in process
arguments, logs, fixtures, or repository files.

### Auxiliary record format

Treat concatenated IV slots as a byte-addressable carrier. Begin with fixed-size
records spanning many sectors and a single auxiliary blob. Define a versioned
format only after a crypto/design review. It needs:

- Independent hidden key material and domain-separated subkeys where needed.
- Fresh randomized encryption on every rewritten record, including repeated
  plaintext; ordinary deterministic mapping of payload bytes to IVs is unsafe.
- Integrity covering record identity, ordering, lengths, and transaction state.
- Random-looking external encoding: no public magic, fixed header, clear length,
  or recognizable padding in the IV carrier.
- Space accounting for nonce/randomization material, tags, encrypted metadata,
  commit records, padding, and any redundancy.
- Explicit initialization and unused-space rules, and a documented policy for
  rollback, retries, record relocation, and restoring old images.

Do not assume every secure encryption format has pseudorandom serialized output.
Select and document a vetted construction whose complete encoding fits the
carrier threat model. A randomized AEAD record is a candidate, not a settled
choice. Hidden authentication gives a key-guess verifier, so password-derived
keys need an appropriate memory-hard KDF and a salt/bootstrap design that does
not introduce a visible signature. A supplied high-entropy hidden key is an
acceptable first milestone.

### Nonce safety

GCM nonce uniqueness is global per primary key, not per sector. Different AAD
or a different sector address does not cure nonce reuse. Never restore earlier
carrier IVs and reencrypt changed primary data under them. Unchanged records
should remain untouched. Specify retry behavior and snapshot/clone handling
before enabling updates; initial tooling may reject workflows it cannot make
safe. Instrument nonce histories in test runs without claiming that a production
tool can reconstruct all historical nonces from the current image.

For independent uniform 96-bit nonces, collision probability is approximately
q(q-1)/2^97 after q encryptions under a key. NIST SP 800-38D section 8.3 limits
the random-IV construction to 2^32 invocations per key. At 4096-byte sectors that
is 16 TiB of cumulative encryption; at 512 bytes it is 2 TiB. Initialization,
ordinary primary writes, and auxiliary updates all consume this budget. These
are upper bounds, not recommended lifetime targets or a complete GCM security
analysis. Define a conservative supported budget before calling a profile safe.

### Update and crash model

The existing offline tool requires a closed primary mapping and exclusive access to a cleanly
shut-down image. A filesystem mounted read-only is insufficient coordination;
filesystem recovery, other mappings, and cached metadata can still matter.

The first writer creates a separate complete output image and never edits its
input. Report success only after validation and the documented durability steps.
This avoids requiring an in-place transaction scheme for the first experiment.
Do not claim atomic publication until filesystem rename/fsync semantics and
crash tests establish it.

Later in-place work must preserve the ciphertext/IV/tag tuple and transact hidden
records spanning multiple primary sectors. dm-integrity journaling protects
writes through its supported path; arbitrary raw image edits bypass it. A dirty
journal can replay stale tuples over edits. Initially reject dirty/unsupported
states rather than inventing journal repair. Offline in-place writes require a
separate reviewed protocol or supported kernel path.

The native backend now implements coordinated ownership and external roll-forward
recovery. Its tested ordering and remaining failure assumptions are documented
in docs/kernel-implementation.md; they do not establish hardware power-loss safety.

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

## Test approach

Use pure userspace image tests first, then stock-kernel integration inside a
disposable QEMU/KVM VM. Verify complete primary plaintext hashes before/after,
all-sector authentication, hidden round trips, rejection of malformed formats,
wrong keys, corruption, record swaps, repeated writes, and version rollback.
Compare AAD/crypto outputs against kernel-generated fixtures rather than only
testing a codec against itself. Inject crashes at persistence boundaries and
test ordinary and dirty journal states. Compare modified images to matched
ordinary control volumes, including snapshot and journal differences.

VM snapshots are useful test artifacts, not evidence of realistic power-loss
durability. Later test storage ordering and real hardware only when justified.
Keep test keys disposable, images outside version control, and small fixtures
reproducible. See [ROADMAP.md](ROADMAP.md) for milestones and exit criteria.

## Tools and environment

Updated inspection (2026-10-18): WSL2 kernel 6.18.33.2-microsoft-standard-WSL2;
QEMU/qemu-img 10.2.1, cryptsetup/integritysetup 2.8.4, Python cryptography
46.0.5, OpenSSL development libraries 3.5.5, git, a C compiler, make, pkg-config,
curl, wget, xz and cpio are available. OpenSSL AES-GCM compile/link/run and QEMU
TCG startup/QMP shutdown smoke tests passed. /dev/kvm exists but this user cannot
access it; software emulation works without root. KVM group access is an optional
performance improvement. libcryptsetup and libargon2 were not found via
pkg-config; neither is required for the initial supplied-key userspace path.
Guest boot and authenticated block-device support subsequently passed using the
pinned Debian environment described in docs/development.md.
Recheck this inventory before relying on it.

Use vendor/ for pinned external source checkouts, downloads/ for downloaded guest
assets, artifacts/ or work/ for generated images/results, and secrets/ for local
test key files. These directories are ignored by git. Keep provenance manifests
and reproduction scripts in tracked directories instead.

Needed before kernel integration:

- QEMU system emulator and qemu-img, plus a reproducible Linux guest image with
  root access and cryptsetup/dm-integrity support. KVM is optional; software
  emulation is adequate for small correctness tests.
- Guest kernel with device mapper, dm-crypt, dm-integrity, AES/GCM and loop-device
  support; filesystem tools appropriate to the selected test filesystem.
- Exact source files or pinned checkouts for the guest kernel and cryptsetup,
  plus the relevant LUKS2 format documentation. A full Linux checkout/build
  toolchain is unnecessary until kernel modification is justified.
- A maintained userspace crypto library and its development dependencies.
  Choose the implementation language after inspecting available libraries;
  install Rust/Cargo only if that choice calls for it.
- Network/package access for guest images, source and dependencies, sufficient
  disk space for disposable copies, and permission for guest execution.

No host raw-device access, FUSE, custom kernel, or native driver is needed for
the first userspace prototype. Host device-mapper access is optional if all
privileged integration work runs in the guest.

## References

These describe upstream behavior, not a verified profile for this project.
Pin source revisions and preserve experimental findings during implementation.

- [Linux dm-crypt documentation](https://docs.kernel.org/admin-guide/device-mapper/dm-crypt.html)
- [Linux dm-integrity documentation](https://docs.kernel.org/admin-guide/device-mapper/dm-integrity.html)
- [dm-crypt source](https://github.com/torvalds/linux/blob/master/drivers/md/dm-crypt.c)
- [Linux GCM source](https://github.com/torvalds/linux/blob/master/crypto/gcm.c)
- [Linux GCM constants](https://github.com/torvalds/linux/blob/master/include/crypto/gcm.h)
- [cryptsetup source and documentation](https://gitlab.com/cryptsetup/cryptsetup)
- [NIST SP 800-38D](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf)
