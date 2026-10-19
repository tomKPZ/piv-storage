# Native decoy and hidden block devices

The native backend exposes two writable device-mapper devices sharing one kernel
owner. Both devices present decrypted logical bytes. Hidden encryption is already
handled underneath its device; neither filesystem needs its own encryption layer.
The two data paths require no NBD server, FUSE mount or userspace I/O daemon.

This remains a disposable QEMU prototype on the pinned Debian kernel and the
supported 128 MiB LUKS2 test disk. Arbitrary host disks and other profiles are
rejected by setup. The on-disk primary format remains stock-Linux compatible.
README, roadmap and these design notes remain provisional, not a security proof.

## Setup and use

Build/load the matching experimental module inside the prepared guest following
kernel/README.md. Source, headers, config and symbol versions must match; never
force-load or install it on the host. Supply the ordinary LUKS unlock credential
and an independent 32-byte hidden key through private files:

```sh
python3 -m pivstore open-blocks --device /dev/vdb \
  --key-file /mnt/piv-work/passphrase.key \
  --hidden-key-file /mnt/piv-work/hidden.key --initialize
```

The command returns and prints two writable paths:

```text
/dev/mapper/piv-native-decoy
/dev/mapper/piv-native-hidden
```

The decoy device has 115,687,424 bytes on the fixture. The hidden device has a
fixed 281,600-byte capacity (550 logical 512-byte sectors). You can place any
filesystem that supports the device's size and block semantics on either view,
or use the devices directly. For example, the tests mount existing ext4 on the
decoy and ext2 on the small hidden device simultaneously. Larger filesystems may
need more space than this fixture provides. Setup does not format either view.
Initialization replaces the hidden carrier with a zero-filled raw block volume;
extract existing hidden payloads before deliberately choosing this new layout.
The initial hidden rewrite preserves all decoy plaintext.

Use --initialize only for fresh adoption. Reopen with the same command without
it. Recovery completes in the kernel before either public view is created. A
setup process exiting does not stop the devices: loaded keys and shared state
belong to the kernel. Unmount both filesystems before teardown:

```sh
python3 -m pivstore close-blocks --device /dev/vdb \
  --key-file /mnt/piv-work/passphrase.key
```

Teardown refuses busy devices; it does not force unmounts. Private crypt/integrity
mappings exist underneath the two public devices. Do not access the private
owner or independently activate another mapping over the backing device. Raw
owner bios and legacy mutation/read controls are blocked while native ownership
is active, preventing an alternative cached view from bypassing coordination.
A udev probe of that private owner can therefore emit a Buffer I/O error during
setup; the two public devices remain the supported I/O paths.

By default persistent state lives under /var/lib/pivstore/<volume-UUID>. Override
it with --state-directory pointing to a new private directory on the guest's
independent root ext4 filesystem. Keep it across reopen/reboot. It must never be
on either exposed volume, 9p, or storage depending on this target. The kernel
checks a private regular ext4 log; the privileged setup policy additionally
requires the guest root filesystem. Bypassing that placement policy can create
recursive filesystem I/O/deadlocks. There is no generic host installer yet.

## Shared kernel implementation

The patched dm-crypt module also registers a small piv-view target. One instance
presents the decoy, another the hidden volume; both reference the same opted-in
crypt owner and integrity device. They share record crypto, nonce history,
recovery state and a serialization lock. No second primary crypto implementation
or global "next IV" variable is introduced.

map() only queues bounded work. A kernel workqueue performs authenticated reads,
record encryption, primary-sector preparation and data/metadata writes using the
existing dm-crypt AEAD helper and lower dm-integrity bio path. Each view's own
block cache contains its logical plaintext. Hidden writes preserve decoy
plaintext, and decoy writes preserve hidden plaintext, so those separate caches
remain coherent. An independent view that bypasses this owner would not.

The exposed logical sector size is 512 bytes. The decoy request limit is 4096
bytes; the hidden request limit is 512 bytes. Device mapper splits larger bios.
Unaligned primary encryption-sector updates use authenticated 4096-byte RMW.
The target advertises flush support and completes every write durably under the
tested virtual-device/fsync assumptions, including FUA requests. Discard,
write-zeroes passthrough and unsupported operations are not advertised. Device
suspend/removal uses DM lifetime rules; generation/owner binding and references
keep queued requests from dereferencing a destroyed crypt instance. Native
ownership blocks legacy key changes and direct control updates.

Hidden block addresses map into the existing independent 32-sector carrier
records (320 payload bytes each), skipping record 0. Record 0 holds the fixed
block capacity; residual hidden bytes outside that capacity are zero. Reads
authenticate both primary sectors and hidden records. A hidden write refreshes
only intersecting records; a decoy write refreshes intersecting records while
retaining their hidden contents and changing only requested decoy bytes. The
kernel uses maintained HMAC-SHA256/HKDF and RFC7539 ChaCha20-Poly1305 primitives,
matching the existing v2 encoding exactly. Every refreshed IV must be fresh
against the persistent history and the rest of its transaction.

One-time setup uses the standalone NativeBootstrap and v2 codec to initialize/adopt the fixed
raw volume and import its complete recorded nonce history. Thereafter record
crypto, reservations, transactions and recovery are kernel-owned. A durable native.phase marker records adoption before public views are created.
After adoption, missing/empty native history is refused; stale bootstrap history
is never used to rebuild it. Bootstrap state
is historical input only; it must not be reused to reconstruct native history after native writes.
The old userspace services have been removed. No automatic variable-file-to-block migration is provided.
After closure, unpack --incremental can independently extract the hidden raw
volume using only the hidden key, with no primary key or native recovery log.

## Persistent native recovery log

The kernel holds an open private native.log file on the independent root ext4.
The append-only format has authenticated, hash-chained frames. Public framing
contains PIVNLOG1, sequence, type, bounded length, random salt[32] and prior-frame
SHA256. Payloads use AES-256-GCM with a fresh HKDF-derived key per random salt,
nonce 0 under that fresh key, and header plus volume/geometry context as AAD.
The existing wire-format HKDF info is exactly the 21-byte ASCII string
pivstore/native/log/v followed by the volume context (the final digit of the
original C string literal is outside its copy length). Keep those bytes stable;
changing that historical encoding requires migration. Version is authenticated
in the PIVNLOG1 header. All decrypted fields are parsed only after authentication. The full carrier
encoding still has no public magic; this external log is an explicit observable
artifact, not deniable metadata. The construction has no independent review.

Frames carry reserved IVs, exact prepared ciphertext/tag/IV tuples with logical
indices and primary-change flags, completion, or initial READY state. The
sequence is:

1. Read/authenticate intersecting records and original primary data.
2. Generate fresh record encodings; persist/fsync all nonce reservations BEFORE
   any primary encryption. Abandoned reservations remain spent.
3. Prepare exact new primary tuples without writing the primary device.
4. Persist/fsync the complete WAL BEFORE applying any tuple.
5. Apply through the same integrity target, flush every 32 sectors and finally
   flush the entire transaction. Authenticate affected hidden records.
6. Append/fsync DONE, then acknowledge the originating block write.

Recovery authenticates the log chain, reservations, indices, flags, nonce
uniqueness and complete-record coverage before replaying any pending WAL. Exact
current tuples are idempotent copies, never new encryption. A final authenticated
unchanged-tuple checkpoint ensures native journal entries are cleared on clean
shutdown, including replay-only activations. Startup verifies every primary
sector, current IV uniqueness/history membership, all hidden records and fixed
capacity before exposing either view.

A partial final append can be truncated to the last authenticated frame: no
primary encryption/application is permitted before its reservation/WAL fsync.
A complete frame with a bad tag is refused. This depends on the tested filesystem
and device honoring fsync/flush; it is not a guarantee for arbitrary torn writes
or hardware power loss. Prefix rollback and simultaneous disk/state rollback
are not prevented. Losing state can lose hidden data or leave a partially applied
primary request; record authentication is distinct from transaction freshness.

The experimental limits are 2^20 recorded nonces and a 512 MiB log. Neither is
an assertion about unknowable encryption before adoption. This requires known
synthetic key lineage; stock primary writes, rekeys, clones and independent
controllers invalidate it. Closed-volume [log compaction](compaction.md) preserves all reservations and
removes completed WALs; it does not reset the per-key budget. There is no online
compaction or primary rekey yet. Write amplification is substantial:
a single 512-byte hidden request can refresh 96 primary sectors and append almost
400 KiB of WAL. The small concurrent-filesystem demonstration generated about
384 MB of log. Close both views and compact between sessions to reclaim log space. Batching
and online compaction need separate durability designs. Writes
fail closed at a limit or persistence/device error. After a native device error,
repair/recreate the stack and replay the log; automatic rebuilding underneath
mounted filesystems is unsupported.

## Reproduce tests

Use new staging and artifact directories, preserving previous runs:

```sh
python3 scripts/fetch_kernel.py vendor/kernel-build/dual-next
mkdir -p artifacts/dual-input-next
tar -cf artifacts/dual-input-next/scaffold.tar -C vendor/kernel-build/dual-next .
python3 scripts/vm.py run --code --script scripts/guest-dual.sh \
  --power-cut-script scripts/guest-dual-recover.sh \
  --run-dir artifacts/dual-next --data-image artifacts/control-003/control.img \
  --share-file artifacts/dual-input-next/scaffold.tar \
  --share-file kernel/guest-dual-test.py --share-file kernel/guest-dual-power.py \
  --share-file kernel/check-config.py \
  --share-file artifacts/control-003/share/passphrase.key \
  --share-file artifacts/control-003/hidden.key --timeout 7200
```

Omit the power script share and --power-cut-script for the filesystem-only test.
All formatting and block I/O occur on guest-owned synthetic disks. See ROADMAP.md
for actual results, failed experiments, exact environment and remaining tests.
No new host dependency or root access is needed.

The final validation also exercises wrong-key rejection, missing/empty adopted
history rejection, invalid userspace seed pointers and fresh initialization.
Seed copying happens before taking the owner mutex. Native lower-device write EIO and root-ext4 log ENOSPC now have direct-I/O
fail-stop, replay and nonce-history tests; see [storage error experiments](native-faults.md).
An EIO request with durable WAL can be rolled forward on reopen; failed writes
are not promised rollback. Arbitrary log fsync errors, completion-frame failures,
exhaustive lifecycle races, lockdep/KASAN and hardware power loss remain untested.
Older control-backend tests do not establish these properties. See the latest roadmap handoff for exact passing artifacts.
