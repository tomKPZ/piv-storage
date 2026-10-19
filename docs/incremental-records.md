# Incremental records and coordinated primary writes (experimental v2)

This opt-in format replaces the native backend's whole-carrier v1 blob with
independently encrypted records. It supports writable primary block access while
preserving hidden contents and using fresh primary GCM IVs for every encryption.
The original offline, regular-file and native v1 modes remain available.

## User interface and compatibility

Only the pinned disposable QEMU guest and synthetic /dev/vdb are supported.
Build/load the matching experimental dm-crypt module as in kernel/README.md.
Use a NEW private persistent root-ext4 state directory for v2:

```sh
python3 -m pivstore serve-kernel --device /dev/vdb \
  --key-file /mnt/piv-work/passphrase.key \
  --hidden-key-file /mnt/piv-work/hidden.key \
  --state-directory /var/tmp/piv-incremental/state \
  --mountpoint /run/piv-hidden --incremental --socket /run/piv-rw.sock --initialize
```

Use --initialize only for fresh adoption; omit it on restart. This starts an
EMPTY hidden file and replaces existing hidden carrier contents on first flush.
There is no automatic migration: extract any v1 data first, then import it into
the v2 FUSE payload. Existing v1 state cannot be reopened as v2 (different key
context). Do not delete state or bypass an error to force initialization.

Connect the private socket using nbd-client inside the guest, then mount the
resulting device normally read-write:

```sh
modprobe nbd nbds_max=4
nbd-client -unix /run/piv-rw.sock /dev/nbd0
mount /dev/nbd0 /run/piv-primary
```

Create the mountpoint first; a filesystem must already exist. Read/write primary
files under /run/piv-primary and edit the hidden /run/piv-hidden/payload file.
Unmount the primary filesystem, disconnect NBD, then unmount hidden FUSE for a
clean shutdown. Do not exit the service with a mounted primary filesystem.

Writable access MUST use this coordinated NBD path. Primary encryption and
integrity I/O remain native kernel operations, but the direct dm-crypt owner
continues to reject ordinary mutation bios. This is not a direct writable DM
mapping or an in-kernel filesystem-write broker. The incremental CLI removes an
unused read-only presentation and refuses removal if it is in use. Do not mount
an independent primary view, read its cached filesystem concurrently, or use raw
primary control writes behind the NBD filesystem. Old direct-view caches would
not reflect independent primary plaintext changes.

Writes are synchronous through the complete transaction before their NBD reply;
FLUSH and FUA are supported. Trim, write-zeroes, multi-connection consistency
promises and structured NBD replies are not advertised. Requests are bounded to
1 MiB. The service serializes both frontends with one lock. Primary writes also
flush any buffered hidden edits first; hidden write alone remains buffered until
flush/fsync. The hidden key is therefore required while serving primary writes.

After closing the stack and letting Linux recover its integrity journal, extract
hidden contents without the primary key or recovery directory:

```sh
python3 -m pivstore unpack closed-image.img --incremental \
  --hidden-key-file secrets/hidden.key --output recovered-payload
```

The output must not already exist. Offline image parsing still rejects a nonempty
native journal. v1 unpack remains the default; no public on-disk selector is added.

## Carrier and encryption

A record occupies 32 primary sectors: 384 IV bytes, of which 320 bytes are payload
capacity under the existing salted HKDF/ChaCha20-Poly1305 encoding. Record 0 holds
an encrypted 8-byte file size. Remaining complete records hold fixed 320-byte
chunks, padded with zeroes inside encryption. All records, including unused file
capacity, are authenticated and initialized. The residual fewer-than 32 primary
sectors carry no hidden data and receive ordinary fresh random IVs when written.

The context is v1's UUID/geometry context followed by /incremental/v2 and
/records/v2/ plus LE64(record index). Every record has its own fresh 32-byte salt;
there is no public magic, length or record header in the IV carrier. The encoding
reuses the v1 primitives and their assumptions, not an independently reviewed
construction. Record swaps, wrong key/context, bad length and malformed padding
are rejected. Record authentication does not prove freshness across records.

The 28,244-sector fixture has 882 complete records, 20 unused tail sectors and
281,920 usable hidden bytes. A same-length hidden edit inside one chunk refreshes
32 primary sector tuples, rather than 28,244. END additionally copies the
current sector 0 tuple unchanged for journal checkpointing; its IV does not change.
A length change also refreshes record 0;
truncation clears formerly occupied chunks before acknowledgment. Startup still
authenticates the whole primary and reads/decodes every hidden record. Buffering
and comparison remain in memory; this is not a hidden allocator or general FS.

## Coordinated primary transaction

For each primary request:

1. Commit pending hidden changes, then read/authenticate affected primary sectors
   through a bounded native control read. Merge unaligned writes in memory.
2. Select all hidden records intersecting those sectors. Preserve their committed
   logical payloads, but encode each entire record with fresh randomness.
3. Suspend/drain the native owner and BEGIN. Authenticate current IVs, validate
   their lineage, generate collision-free fresh IVs for every selected sector,
   and persist nonce reservations BEFORE any new primary encryption.
4. PREPARE_PRIMARY authenticates the old sector and encrypts the supplied new
   plaintext with its fresh IV. Neighbor sectors use the original PREPARE,
   preserving plaintext. Neither operation writes the backing device.
5. Publish/fsync an encrypted sparse journal of exact prepared tuples. It binds
   volume/geometry/format context, logical sector indices, expected old IVs and
   the planned new-IV digest. Authenticate the complete immutable ciphertext,
   then validate ordering, bounds, reservations and full-record coverage BEFORE
   applying any entry.
6. APPLY_PRIMARY authenticates current and proposed tuples and checks the old IV,
   while permitting intended plaintext changes. Exact tuple equality is an
   idempotent retry; it performs no encryption. END copies one authenticated
   current sector tuple unchanged through the journal before flushing, so native
   dm-integrity checkpoints even replay-only entries on shutdown. This copy
   consumes no nonce; it also occurs during otherwise read-only startup. The original APPLY still rejects
   changed primary plaintext. Submit through the SAME dm-integrity target, sync
   every 32 entries, verify selected IVs/hidden records, END-flush, persist
   initialization, remove/fsync the journal, resume, then acknowledge the write.

The sparse protocol is roll-forward, not rollback. A crash after durable journal
publication can install an entire primary request even if its reply was lost.
Before publication, no primary sector is changed. Reservations remain spent even
for abandoned plans. On restart the owner adopts the suspended transaction and
replays exact tuples before exposing either frontend. The record size is smaller
than the journal capacity, but complete-request recovery still relies on the
external journal: native journal atomicity alone is insufficient.

The new kernel operations use the existing 4168-byte bounded update structure:
READ_PRIMARY=9 returns authenticated 4096-byte plaintext and its IV while active;
PREPARE_PRIMARY=10 accepts 4096-byte plaintext, zero tag bytes and a fresh IV;
APPLY_PRIMARY=11 applies authenticated tuples. Query flag 8 advertises this
capability (total flags 15). All require CAP_SYS_ADMIN; mutations require the
suspended transaction's controller. The control API now carries primary plaintext
for ordinary logical I/O; it still exports no primary key. Python and kernel
buffers, recovery state and frontend artifacts are not concealed.

## Limits

One 4 KiB primary write normally rewrites 128 KiB of primary data plus integrity
metadata, unchanged checkpoint copies, reservation state and the sparse external
journal. Crossing a record
boundary doubles that data work. Initialization still rewrites all complete
records. Unchanged records keep their IVs. This improves locality, not speed or
production suitability. No benchmark or deniability result is implied.

Per-key GCM nonce uniqueness remains mandatory across ALL sectors and time.
Primary writes spend reservations just like hidden writes. The default 2^20
recorded-work ceiling is deliberately small and can be exhausted quickly by a
filesystem; it is not proof of the key's historical encryption count. Use known
synthetic key lineages only. No safe ordinary stock read-write activation, rekey,
clone branching, disk-and-state rollback or hardware power-loss workflow is
provided. Stock read-only access remains compatible after recovery/closure.
External journal loss can lose hidden data and leave a partially applied primary
request; lower journal replay alone cannot reconstruct a complete request.
Without the external journal, a mixture of individually valid old/new records
can authenticate; v2 has no independent cross-record generation commitment.

Device errors remain fail-stop and require repair/recreation; no transparent
rebuild under a mounted primary filesystem is implemented. After controller
failure an NBD client must be disconnected/reconnected and its filesystem
recovered as appropriate. Stale NBD sockets are not automatically removed: use a
new private socket after confirming the old controller is dead. Hidden stale
FUSE cleanup retains the existing UUID policy. No open client descriptor survives
a dead FUSE/NBD session automatically. An interrupted multi-request filesystem
operation has ordinary filesystem crash semantics, not whole-operation atomicity.

## Reproduction

Use a new staged source directory and run directory:

```sh
python3 scripts/fetch_kernel.py vendor/kernel-build/incremental-next
mkdir -p artifacts/incremental-input-next
tar -cf artifacts/incremental-input-next/scaffold.tar -C vendor/kernel-build/incremental-next .
python3 scripts/vm.py run --code --script scripts/guest-incremental.sh \
  --power-cut-script scripts/guest-incremental-recover.sh \
  --run-dir artifacts/incremental-next --data-image artifacts/control-003/control.img \
  --share-file artifacts/incremental-input-next/scaffold.tar \
  --share-file kernel/check-config.py --share-file kernel/guest-incremental-test.py \
  --share-file artifacts/control-003/share/passphrase.key \
  --share-file artifacts/control-003/hidden.key --timeout 7200
```

The guest installs nbd-client; no new host package, root access or full kernel
build is required. The test uses disposable synthetic plaintext and test keys.
See ROADMAP.md for actual run results and diagnostic limitations.
