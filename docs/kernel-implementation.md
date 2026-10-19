# Experimental native backend implementation

The opt-in dm-crypt patch now supports native authenticated IV reads and
prepared-tuple updates. Hidden encryption and FUSE stay in userspace. The
regular-file/NBD backend remains available; native payload commits use the same
v1 carrier format and can be unpacked offline after closing the native stack.
This describes the older native v1 control adapter. Current two-block-device
usage and kernel-owned recovery are in [native blocks](native-blocks.md). The optional v2 writable adapter is described in
[incremental records](incremental-records.md); it retains the private filtered
owner and adds coordinated primary I/O. This is a disposable QEMU prototype,
not a stable kernel ABI or a security proof.

## Ownership and supported format

GuestOwner restricts setup to root in the pinned Debian QEMU guest and the
128 MiB virtio test disk. Test-only code may interpose explicitly named delay or
fault devices. No host module installation, arbitrary device formatting or host
root is required. The guest source/config/symbol checks described in kernel/README
remain mandatory; no forced module loading is used.

The supported LUKS2 profile remains AES-256-GCM/random, encryption sector4096,
IV12, tag16, tuple28, IV tweak0, crypt lower offset0. Static integrity superblock
fields are independently checked against the existing version4/fixed-padding
parser. Setup verifies one lower journaled dm-integrity target, block_size4096,
journal_sectors1848, interleave_sectors32768, buffer_sectors32, watermark50,
commit_time10000 and fix_padding, with the expected source device and offset.
The kernel itself checks crypto/integrity shape; privileged userspace must verify
lower journal configuration. It does not expose a general lower-table inspection
API. Changing that stack independently of the owner is unsupported.

A stable global UUID lock excludes another project controller even with a
different state directory. A second stable lock protects the recovery directory.
Neither lock file is unlinked. Backing-device holders, LUKS UUID, native control
owner/lower device numbers and geometry are checked before use. A read-only
linear wrapper presents primary plaintext. The writable owner is private: its bio
filter rejects primary mutations, but a bio filter alone cannot stop buffered
writes from dirtying a writable block device's page cache. Only the read-only
wrapper is the user-facing primary device. Mount its filesystem ro,noload.

Stock cryptsetup 2.7.5 cannot parse the experimental optional DM token. Setup uses
cryptsetup to unlock, then reloads an opted-in table through protected stdin;
test activation disables its private keyring references to permit that reload.
Key material never enters argv/logs or the control ABI. A temporary table string
exists in setup-process memory; there is no secure-memory or live-system
concealment claim. Closing uses explicit DM teardown, not stock active-table
parsing. The stopped volume's format remains stock-readable.

## Kernel protocol

All commands require CAP_SYS_ADMIN, including use of inherited/passed fds. The
misc device is mode0600. Query returns version1/size48, owner generation,
encryption-sector count and sizes; capability bits1/2/4 identify lower write access,
primary mutation filtering and update support. Updated modules also advertise
bit8 (total15) for explicit primary-I/O controls; legacy flags7 are accepted
only by the v1 adapter. A separate device query binds the
control to exact owner/lower major/minor numbers. Generation is module-local,
not a persistent disk identity or nonce log.

| Operation | Semantics |
| --- | --- |
| QUERY / DEVICES | Immutable profile/device snapshots; no key or plaintext. |
| READ_IV | Authenticate one current sector and return its IV while active. |
| READ_QUIESCED | Same read while the owner is fully suspended. |
| BEGIN | Start/adopt a controller-owned transaction on an activated, suspended target. |
| PREPARE | Authenticate current tuple and expected old IV, encrypt identical plaintext with a supplied fresh IV, return new ciphertext/tag/IV; no disk write. |
| APPLY | Authenticate current and proposed tuples, enforce identical primary plaintext, submit the exact proposed bytes through the SAME integrity target. |
| SYNC | Flush the lower journal without ending the transaction. |
| END | Flush successfully, then clear transaction ownership and allow resume. |

Read/state requests are fixed48 bytes. Update requests are fixed4168 bytes:
version/size, generation, encryption-sector index, expected IV12, flags,
tuple4124 (ciphertext4096 + tag16 + IV12), reserved word. All reserved fields
must be zero. PREPARE input ciphertext/tag must be zero; only the proposed IV is
provided. Unsupported sizes/flags/indices/owners fail explicitly. Plaintext stays
in private wiped pages. AEAD uses the existing conversion helper and loaded
transform with exact native sector_LE64/IV AAD. The override IV is request-local;
ordinary dm-crypt still calls the same path with no override and random IVs.

APPLY defaults to FUA plus explicit flush. Flag1 permits staged application;
its successful completion is NOT a durability acknowledgment. The backend syncs
every32 entries, below the pinned224-entry journal capacity, and END performs a
final flush. The reviewed dm-integrity path commits pending entries with FUA
journal writes before releasing flush completions. Durability still depends on
the underlying devices honoring ordering/flushes. The kernel cannot make the
whole v1 record atomic in that journal; external recovery provides that property.

Exact current-tuple equality is an idempotent replay, including after a lost
acknowledgment. It does not reencrypt. END resubmits one authenticated current
sector tuple unchanged before flushing, ensuring native dm-integrity also
checkpoints replay-only journal entries on subsequent shutdown. This copy is not
an encryption invocation and spends no nonce. It can write integrity journal
metadata even during otherwise read-only service startup. Other applies require the expected old IV;
a valid proposed tuple with changed primary plaintext is refused. Reusing the
current IV for new encryption is refused. Global/historical nonce uniqueness is
the controller's responsibility, not solved by one-sector checks.

A lifecycle mutex protects the borrowed crypt_config pointer across synchronous
I/O/crypto. Presuspend drains/blocks controls before primary suspend completes.
Only fully suspended targets admit mutations. Key operations and resume are
serialized with the same mutex; pending transactions prevent key manipulation
and resume. Controller-file release leaves the transaction pending and clears
its owner, so a fresh controller can adopt it. Destruction drains controls before
freeing native state; dead descriptors return ENODEV and pin the module until
closed. No userspace fault occurs while holding this mutex. Requests allocate
bounded GFP_NOIO buffers under a no-I/O allocation scope. This is not a timeout
guarantee for stalled devices or proof of all possible kernel races.

## External whole-record recovery

Recovery files live on a separate private local filesystem, normally the guest
root ext4, not 9p and not the read-only primary filesystem. They are explicit
host artifacts and weaken deniability. Losing them during an interrupted update
can lose the auxiliary record. Ordinary primary plaintext is unchanged; stock
Linux can still recover its integrity journal and authenticate primary data.

The nonce ledger is authenticated/encrypted with a fresh salted derived key.
It retains current/adopted IVs and ALL newly reserved plans, including plans
abandoned before publication. The default work ceiling is2^20 entries. Reservation
is atomically persisted and directory-fsynced before any PREPARE encryption.
Every hidden update freshly salts the v1 encoding and checks every proposed IV
against the ledger and other IVs in the plan. Direct control callers must enforce
the same policy; the raw ioctl is not a complete nonce-policy service.

This ledger starts at explicit --initialize adoption. It cannot reconstruct
formatting, filesystem or other writes before adoption. Its count is a bound on
recorded/reserved work, NOT a proof of total historical per-key use. Use only a
trusted disposable key lineage with an independently adequate historical budget.
Rolling back/cloning BOTH disk and state is not detected. Re-keying, offline
updates, primary writes or independent controllers invalidate this lineage.

Commit order:

1. Suspend/drain primary I/O; BEGIN. Authenticate/read the current carrier.
2. Encode a fresh whole-carrier blob; persist all nonce reservations.
3. PREPARE every sector once. Stream the exact tuples into an encrypted external
   journal, fsync its file, atomically rename it and fsync its parent directory.
   No primary writes occur before publication completes.
4. Authenticate and validate the ENTIRE immutable journal before any APPLY.
   Replay all exact tuples, syncing every32. Primary access remains suspended.
5. Read/authenticate the complete resulting carrier and decode its hidden record.
   END flushes it durably under the tested virtual-device assumptions.
6. Persist ledger initialization state; unlink/fsync the external journal; resume
   primary I/O. Only then acknowledge FUSE fsync.

The journal uses maintained streaming AES-256-GCM with HKDF-SHA256 and a fresh
32-byte salt/derived key per file, nonce0 under that fresh key, and UUID/geometry
context in AAD. Contents include sequential indices, old IVs, exact new tuples
and a whole-carrier hash, all encrypted. The complete ciphertext is held immutable
for validation/replay. A full authentication pass precedes any decrypted metadata
parsing; plaintext is streamed in bounded chunks and never written
to a plaintext temporary file. This composition has not had independent review.
Publication uses rename under the exclusive private-directory lock, avoiding a
crash window with two hardlinks to the canonical journal. Orphan preparation
files are ignored; never recover from them.

On restart, acquire ownership, suspend/adopt before exposing either view, validate
state, replay any canonical journal, authenticate the whole record, then resume.
A journaled transaction rolls forward to the new record even if no fsync reply
was delivered. No canonical journal means preparation never reached mutation,
or the complete new state was already verified before journal removal. Prepared
nonces stay spent in either case. Recovery never regenerates tuples or blindly
retries encryption. A missing/invalid/wrong-key journal/ledger fails closed.

Native device errors are fail-stop: failed transaction state blocks resume. After
repairing the underlying device, recreate the quiesced/closed native stack and
replay the external journal. The prototype does not rebuild a failed integrity
instance underneath a mounted primary filesystem automatically. Controller death
without a device error recovers on the existing suspended mapping.

## FUSE lifecycle and limits

serve-kernel exposes the existing one-file FUSE interface and native primary
wrapper, without NBD. Its store holds only the hidden key; setup briefly handles
a stock DM table as above. Startup cleans only a stale FUSE mount whose source
matches this volume UUID after acquiring global ownership. Open file descriptors
to the old dead FUSE session cannot be revived; clients must reopen after restart.
Primary readers can block for the whole carrier commit/recovery. Every hidden
flush still prepares and applies all28244 fixture sectors. This is a correctness
demo, not an incremental or performance-optimized hidden filesystem.

Power tests kill QEMU with a dm-delay write in flight, reboot the same disks,
confirm a nonempty native journal before replay, then recover and verify stock
primary hashes. Host page cache survives; this is guest/kernel/device-process
loss, not host power loss or exhaustive torn-write testing. A dm-flakey test also
forces journal-write EIO and recovery after repair/recreation. KASAN/lockdep,
allocation fault injection, exhaustive races, production key/rollback policy,
independent crypto review and systematic steganalysis remain deferred.

Even a single current disk may retain historical tuples in its native journal or
underlying storage. The experiments establish selected correctness and recovery
properties, not single-image indistinguishability. No systematic steganalysis or
independent cryptographic review has been completed.
