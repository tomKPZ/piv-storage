# Paired native block devices

`dm-piv.ko` is a standalone module (no dm-crypt fork or patch) that implements
the Linux LUKS2 per-sector AEAD path itself over the stock dm-integrity journal
and registers `piv-crypt` (private owner) and `piv-view` (public views). Stock
dm-crypt keeps its `crypt` target and can stay loaded with unrelated encrypted
filesystems mounted throughout setup, I/O and removal of dm-piv. No stock
symbols are hooked or replaced; only ordinary exported block, device-mapper and
crypto APIs are used, but builds need matching kernel headers/config/symbols.

Both public views (`NAME-decoy`, `NAME-hidden`) reference one private owner,
lower dm-integrity device, lifecycle and range locks and record cipher. They expose
plaintext logical I/O; there is no userspace I/O service or persistent state
file. Loading the module does not convert existing stock mappings.

## Setup (pivsetup open-blocks)

Setup is privileged (root) and works on any block device or partition holding
the LUKS2 volume ([rust/README.md](../rust/README.md);
installation: [packaging/README.md](../packaging/README.md)). It:

1. checks the device (a block device, not a whole disk with partitions),
   validates the LUKS2 segment for a
   [supported profile](../README.md#supported-primary-profiles), takes an
   exclusive per-volume /run lock and, for a new owner, refuses a device with
   any holder or exclusive opener (EBUSY) before parsing the integrity
   superblock against the device's real size;
2. opens the volume with cryptsetup (Linux replays the journal), suspends the
   crypt mapping, reloads its private table as `piv-crypt ... piv_control`,
   resumes, and checks the owner table against the validated LUKS cipher;
3. begins coordinated ownership and issues NATIVE_SETUP (ABI 6) with the
   keyslot KEK, the v5 base context and (at initialization) the RS parity. The kernel waits for a seeded CRNG
   (without holding the owner lifecycle lock), then scans the 112-sector keyslot
   area (every primary sector with `--verify`, refusing on any failure);
4. with `--initialize`, writes a new master key, keyslot 0, the directory and
   (unless `--quick`) authenticated zero blocks; otherwise a keyslot must
   authenticate under the KEK using IVs from that scan (EKEYREJECTED otherwise)
   and the directory must authenticate, and with `--fill` every block whose
   record does not authenticate receives a zero record
   ([format-v5.md](format-v5.md#setup-and-initialization));
5. creates both views.

There is no uninitialized-carrier mode. Hidden availability of individual
records never gates the decoy. Runtime locks use /run, which may be tmpfs.
Setup polls SIGINT/SIGTERM between authenticated ranges and rounds of
initialization or fill records ([cancellation](native-faults.md#cancelling-activation-initialization-and-fill-cancel-suite)).

Setup tracks mappings created by its attempt, including commands that fail
after kernel creation. Failed setup removes matching view UUIDs, then the newly
created owner/lower mappings after checking their captured device numbers and
UUIDs; it may errorize only that private owner to drain probes. Cleanup never
rolls back disk writes: a failed `--initialize` can leave hidden contents
changed or unavailable. An existing active stack is preserved when another open
is rejected; an idle private owner must first be removed with close-blocks.

`close-blocks` checks both public view tables, owner generation and device
binding before removing either name, refuses unrelated or changed mappings and
can remove a validated idle owner. Cleanup errors are reported with the
original error; busy resources or process/VM death can still require explicit
teardown. These checks do not protect against a concurrently racing privileged
administrator using dmsetup. Stock cryptsetup does not manage the custom
targets; use it for unrelated volumes and for stock readback after closing.

## I/O path

The private `piv-crypt` mapping never accepts ordinary writes; before native
ownership it serves bounded authenticated reads, and while ownership is active
it rejects all bios. Public `piv-view` map callbacks queue one work item per
bio (held in DM per-bio data, so mapping never allocates or requeues) to the
owner's own unbound, reclaim-capable `piv-native-<generation>` workqueue (at
most 16 work items of that owner run at once; a stalled owner does not occupy
other owners' workers); work runs in NOIO allocation scope.
Hidden bios are split per 4096-byte block (the hidden view's logical and
physical block size; the worker refuses anything else), decoy bios at 128 KiB
power-of-two boundaries (at most 256 primary sectors per work item). The decoy
view advertises the primary sector size as its logical and physical block
size, exactly as stock dm-crypt does (`crypt_io_hints`), so filesystems made
through it keep mounting through stock dm-crypt and the view's geometry is not
a distinguisher; on 4096-byte volumes the block layer refuses sub-sector
requests before the module sees them. Batching is
within one bio: no cross-bio accumulation, writeback cache or delay.

### Concurrency

Independent bios run concurrently. Requests serialize only where they touch
the same sectors (`piv_range_lock` in kernel/piv-control.inc):

| Request | Range lock over primary sectors |
| --- | --- |
| Decoy write | exclusive, the sectors it rewrites |
| Hidden write | exclusive, the block's whole record group (both slots with A/B) |
| Hidden read | shared, the block's record group(s) |
| Decoy read, flush | none |

So two writes to overlapping primary sectors (including sub-sector decoy
writes into one 4096-byte sector), or a decoy write and a hidden write of the
same record, never interleave their read–authenticate–re-encrypt–write
sequences, and a hidden read never collects a half-written record (it returns
the old or the new block, not EIO). Decoy reads need no lock: dm-integrity keeps
each sector whole and every sector is authenticated on its own. Entries queue in
arrival order and wait only for earlier conflicting entries, so there is no
starvation, and a request holds at most one range, so there is no deadlock.
Concurrent requests to the same bytes complete in an unspecified order, as on
any block device.

Workers hold the owner's `io` read–write semaphore shared. Everything that
changes state workers read takes it exclusively after the lifecycle mutex:
keyslot add/remove (keyslot and directory state), owner presuspend/resume and
owner destruction, which therefore drain in-flight requests first. View
suspend and removal drain through DM as before (a view's bios complete before
it suspends or is destroyed; workers touch owner state only before completing
their bio). The encryption counter is atomic: each request reserves its
encryptions before encrypting. Exception: while no view exists and the owner
is suspended, setup and BEGIN/END change the native state under the lifecycle
mutex alone (no worker can reach it); detach also takes `io` exclusively.

Suspending the private owner (`dmsetup suspend piv-native`) while views are
active is outside the supported lifecycle: view requests issued while it is
suspended fail with EIO instead of waiting (the owner's state is "blocked");
suspend the views instead. A controller that exits between BEGIN and END
leaves the owner's transaction set: resume stays refused (EBUSY) until another
controller brackets a setup or the owner is removed (pivsetup's cleanup
removes it). Range-lock waits are uninterruptible: on a stalled lower device,
waiting requests (and an owner presuspend waiting for `io`) appear as hung
tasks rather than failing.

### Memory pressure

Mapping uses per-bio data, so it never fails or requeues for memory. A view
request that fails with -ENOMEM before writing or flushing anything is retried
by its worker with back-off (up to 240 times, about 28 s in total) outside the
`io` lock, so writeback through the views does not see I/O errors from a
transient allocation failure, and owner state changes are not held up by the
wait. Allocations are bounded per request (below); order-0 GFP_NOIO page
allocations do not fail outside OOM-victim context. Each owner's workqueue is
reclaim-capable (a rescuer thread). An -ENOMEM after writing began stops the
owner like any other failure once writing began.

- **Decoy write**: authenticated primary-sector read-modify-write. Each written
  sector gets a fresh IV: keyslot (listed in the directory), directory and
  record sectors keep their fragment and redraw its random part; other sectors
  get uniformly random IVs. A write covering an entire sector that fails
  authentication replaces it. A partial write to such a sector would fail EIO;
  the module keeps that check, but since the view's logical block is the
  primary sector, the block layer no longer issues partial-sector writes.
- **Hidden read**: reads the G-sector record (G = 687 + 3p; both slots with
  A/B), using raw IVs of sectors whose decoy data fails authentication; the SIV
  tag decides. With parity, a failing tag triggers RS decoding with the
  failing or unreadable sectors as erasures, then a second SIV check.
- **Hidden write**: with A/B, reads both slots' IVs to pick the slot not
  holding the newest valid version and flushes the lower device (see below);
  then authenticates all G carrier sectors of the target slot, seals the block
  with a fresh generation and fresh fragments and rewrites the carrier (below).
  There is no durable cross-sector plan; without A/B a crash can destroy the
  block.

### Write path

Every write (decoy request, hidden record, keyslot, directory, initialization
record) is one rewrite of a set of primary sectors (`piv_batch_*` in
kernel/piv-control.inc):

1. read all of them with a few multi-sector bios carrying their integrity
   tuples, submitted together, and authenticate every sector with its own
   address/IV AAD (a decoy write may replace a sector that fails
   authentication only if it covers all of it; anything else fails the
   request);
2. merge the request bytes (decoy) and draw the fresh IVs (record fragments or
   decoy IVs), rejecting local collisions with the stored IVs or each other;
3. reserve the encryptions and encrypt every sector in place in RAM under its
   fresh IV;
4. submit the ciphertext and tuples as a few multi-sector bios through the
   lower journal (at most 128 KiB of data and one page of tuples each: 22 bios
   for a 687-sector record at 4096-byte sectors, 6 at 512 with AEGIS-128, 9
   with HMAC-SHA256's 48-byte tuples) and wait for all of them.

Steps 1–3 finish for the whole request before the first lower write. A
request holds its plaintext/ciphertext and tuples in RAM: 2.7 MiB for a record
at 4096-byte sectors, 344 KiB at 512, at most 128 KiB plus tuples for a decoy
request. Nothing re-reads a sector between authentication and its write: the
former expected-IV recheck served the userspace PREPARE/APPLY interface; every
mutation now runs in the owner under a range lock (view requests) or the
exclusive `io` lock (control calls), and the private owner rejects other bios
while views are active. Freshly produced ciphertext is not decrypted again
(that guarded userspace-supplied tuples); later reads authenticate every sector.

**Flush semantics** follow stock dm-crypt: a plain write completes once its
lower write bios complete, without a flush, so it is durable only after a
later flush or FUA request (dm-integrity commits its journal on flush/FUA, when
half full, or on its commit timer). A FUA write flushes the lower device after
its write and before completing. WRITE|PREFLUSH flushes before its payload, and
an empty flush flushes the lower device; both cover every write completed
before they were issued, since a request completes only after its lower writes
did. An A/B hidden write also flushes before rewriting a slot, so the slot
holding the newest version is durable before the other one is overwritten
([journal atomicity](journal-atomicity.md)), unless that version is already
durable: the owner counts completed lower write batches and records, at each
successful flush, the count sampled when the flush started; each hidden write
records the count after it (per hash of the block index, 1024 buckets, so a
collision costs only a flush). The pre-write flush is skipped when a
successful flush started after the block's previous write completed. Keyslot and directory writes
flush after each write. Initialization flushes every 16 records and before
returning, also when cancelled. Batches are not atomic writes; the stock
journal may commit part of a record at any time. No discard or write-zeroes is
advertised. Suspend/removal uses DM references and generation binding; see the
[lifecycle notes](native-faults.md#concurrent-lifecycle-and-flushfua-ordering-lifecycle-suite).

Failures before the first lower write (reads, authentication, allocation,
encryption) fail only that bio; failures once writing began and flush failures
(including the A/B pre-write flush) stop both views until teardown
([failure scope](native-faults.md)). A concurrent request that has not started
writing when the owner stops writes nothing and fails; a write or flush still
in flight then reports EIO. Hidden authentication failure returns EIO for that
block without stopping the owner. Internally, hidden unavailability is the
positive sentinel `PN_UNAVAILABLE`; Linux `BLK_STS_MEDIUM` (-ENODATA) is a
storage error, never mistaken for it.

Damaged hidden blocks are repaired by a full 4096-byte block write (the only
write size the hidden view accepts).

Initialization writes records in rounds of 8 concurrent work items on the same
workqueue (setup holds the lifecycle mutex and no views exist yet); it polls for
cancellation between rounds, when every record written so far is complete.

### Bounded authenticated reads

Setup's keyslot/directory scan (and the `--verify` full audit), decoy reads,
hidden-read carrier collection and private owner reads use `piv_read_range`:
at most 1024 primary sectors per call (a whole record; 4 MiB at 4096-byte
sectors, 512 KiB at 512) plus their tag/IV metadata, read as one batch of
multi-sector bios to dm-integrity in flight together (the same batch code as
writes, up to 128 KiB of data and one page of tuples per bio). Writes read
their sectors through the batch path ([write path](#write-path)). The
per-sector AEAD helper (`piv_aead`) runs once per sector, advancing the sector
AAD (address/IV) and tag offset, so per-sector authentication is identical to
stock dm-crypt, and nothing (plaintext or IVs) is published until the whole
range authenticates; hidden reads take the raw IVs of failing sectors for
SIV-checked decoding only. Public decoy and owner reads copy authenticated
plaintext straight from the batch pages into the bio, only after the whole
range authenticates (no intermediate buffer); read-only batches allocate no
rewrite bookkeeping, and one AEAD request and buffer set serves every sector of
a batch. Private pages and metadata are bounded and wiped on release, including
after a partial authentication failure.

There is no persistent cache, lazy verification or cross-bio accumulation: DM
splits decoy bios at 128 KiB and hidden bios per 4096-byte block, and one
hidden block read authenticates its whole carrier (G = 687 + 3p sectors) with
one range call, so hidden reads cost 687 primary authentications per 4096-byte
block regardless of request size (without parity; RS decoding runs only after
a failed tag). Concurrent requests overlap their reads
([concurrency](#concurrency)). Large application reads can span several work
items and are not whole-request transactions.

One range call submits one batch of reads to dm-integrity; the lower target may
split them or serve them from its journal/cache, so call counts are not
physical-media read counts. Fewer submissions must never skip a per-sector
check; the `profile` suite asserts exact call and authentication counts
([development.md](development.md#profile-suite)) and the `faults` suite the
late-sector corruption/no-output regression
([native-faults.md](native-faults.md#lower-device-errors-and-setup-cleanup-faults-suite)).
User-facing read/write/activation numbers are in
[configuration.md](configuration.md).

## Control ABI (kernel/piv-control.h)

The control device exposes QUERY (version 2: sector size, encryption-sector
count, IV/tag/tuple sizes), DEVICES, BEGIN/END, NATIVE_SETUP, NATIVE_DETACH,
NATIVE_STATUS and NATIVE_KEYSLOT. There is no userspace IV, tuple or primary
read/write access; all rewriting happens inside the kernel and other ioctl
numbers return ENOTTY.

- NATIVE_SETUP ABI 6 (216 bytes, read/write): version/size, generation, flags,
  context_length, key[32] (keyslot KEK), context[128] (the exact 72-byte v5
  base context of this owner, checked field by field; anything else EINVAL),
  parity (0, 4, 8 or 16; non-zero only with initialize), reserved, then the
  fill output counts valid, written, failed (u64; zero on input). Flags: 1
  initialize, 8 A/B (with initialize), 16 verify, 32 quick (with initialize),
  64 fill (without initialize); other bits are rejected. After a successful
  setup the kernel copies the structure back with the key zeroed. ABI 6
  (2026-10-22) added quick, fill and the counts.
- NATIVE_KEYSLOT (version 2, 96 bytes, 2026-10-22): version/size, generation,
  slot, op (1 add, 2 remove), kek[32] (the new keyslot's KEK; zero for remove),
  auth[32] (the caller's current hidden KEK; it must open a directory-listed
  keyslot with the active master key and parameters, else EKEYREJECTED),
  reserved[2]. The last keyslot cannot be removed; the owner's keyslot state
  changes only with the directory write; failures after a lower write
  fail-stop the owner.
- NATIVE_STATUS (version 4): generation, hidden_bytes, encryptions (u64);
  active, views, failed, version (u32). `failed` is the sticky owner fail-stop
  (also after a failed setup, when active = 0). Counters are volatile, not
  lifetime history.

No user paths or file descriptors enter the persistence path.

## Primary crypto

The owner accepts `capi:aegis128-random` (16-byte key, IV and tag) and
`capi:authenc(hmac(sha256),xts(aes))-random` (dm-crypt authenc key encoding:
32- or 64-byte XTS key plus the 32-byte HMAC key; 16-byte IV; 32-byte tag), hex
keys only. `piv_aead` reproduces dm-crypt's
layout: AAD = LE64(address in 512-byte units) ‖ IV, tuple = tag ‖ IV. Every
encryption is counted even if the write later fails. Geometry uses checked
kernel file-offset bounds ([large-volumes.md](large-volumes.md)).

Source split: dm-piv.c owns the owner target and per-sector AEAD;
piv-control.inc the privileged controls, authenticated batch
reads and rewrites, range locks and lifetime gates; piv-native.inc the hidden v5
crypto, both views and the concurrent workqueue; piv-rs.inc the Reed–Solomon
encoder and errors-and-erasures decoder. The independent Python codec and
primary verifier remain cross-checks of kernel output.

## Reproduce

`scripts/suite.py` (see [development.md](development.md)) runs everything below
automatically: it builds and shares pivsetup, runs scripts/guest-stateless.sh
per profile (module build in the guest, dual-view test, early-boot initramfs
build, stock readback) and verifies outputs on the host. A manual native run:

```sh
python3 scripts/vm.py run --code --script scripts/guest-stateless.sh \
  --run-dir artifacts/native-next --data-image CONTROL/control.img \
  --share-file artifacts/scaffold-next.tar \
  --share-file scripts/guest-dual.sh --share-file scripts/guest-early-build.sh \
  --share-file kernel/guest-early-test.sh --share-file kernel/guest-dual-test.py \
  --share-file kernel/check-config.py \
  --share-file CONTROL/share/passphrase.key --share-file CONTROL/hidden.key \
  --share-file rust/target/x86_64-unknown-linux-gnu/release/pivsetup --timeout 3600
```

`CONTROL` is a stock fixture run directory; tests derive geometry from LUKS and
the queried owner. guest_code installs a shared pivsetup as
/usr/local/sbin/pivsetup and records its SHA-256. No host module, root or extra
host packages are needed.

The early-boot test then boots the run's private initramfs with no OS disk:

```sh
python3 scripts/early_vm.py \
  --kernel artifacts/native-next/share/early-test.vmlinuz \
  --initrd artifacts/native-next/share/early-test.initrd \
  --data-image artifacts/native-next/share/dual-final.img \
  --run-dir artifacts/native-early-next
```

The initramfs contains synthetic test credentials and must stay private and
ignored. It holds static pivsetup, cryptsetup/dmsetup, a few coreutils, kmod
decompression libraries and the required crypto modules, and no Python; it
mounts only RAM/pseudo filesystems. early_vm.py copies the data image and
attaches a blank first disk so that the data disk stays /dev/vdb, the device
the test script opens.

The `deploy` suite (scripts/guest-deploy.sh, scripts/guest-deploy-boot.sh)
covers the installable boot path instead: packaging/install.sh installs
pivsetup, the DKMS-built and DKMS-signed module and the initramfs-tools hook;
after a reboot of the same disks, the stock initramfs-tools boot must have
loaded dm-piv before mounting root and opened both views from an
`embed-keys` /etc/pivtab entry ([packaging/README.md](../packaging/README.md)).

The `devices` suite (scripts/guest-devices.sh, kernel/guest-devices-test.py)
activates volumes on a 300 MiB second disk, a loop device over a guest-root
file (two owners at once), a dm-linear mapping at a 2 MiB offset and a GPT
partition reached through /dev/disk/by-partlabel, reopens through symlinks and
checks the remaining refusals: unprivileged callers, a missing `--device`,
non-block paths, invalid names, a partitioned whole disk, an independent stock
holder, an exclusive opener, a held /run owner lock, a second owner on an owned
device and a stock mapping under the owner name. The loop and partition images
are verified on the host.

Before loading dm-piv, the shared guest loader creates a disposable
stock-encrypted ext4 filesystem on a guest-root-backed loop image; it stays
mounted and is checked writable after dm-piv teardown (coexistence-result.txt,
loaded-targets.txt). The stock module is never unloaded or replaced.

The `profile` suite also runs kernel/guest-batch-test.py (formerly the separate
`batch` suite; both images are host-verified), which checks the
128 KiB split contract on a closed native image: exact primary encryption counts
and O_DSYNC write timings for 4 KiB to 1 MiB, unaligned, record-boundary and
tail requests, followed by full verification, reopen, stock readback and unload.
Single timings are diagnostic, not a throughput benchmark.

The stress suite (scripts/guest-stress.sh, kernel/guest-stress-test.py) runs 8
threads of concurrent O_DIRECT decoy and hidden writers and readers through a
linear test wrapper: interleaved 512-byte decoy stripes (sharing 4096-byte
sectors and record carriers between threads), large DM-split decoy writes and
hidden blocks whose carriers lie in the striped region, with fsyncs and
O_DSYNC writes mixed in. Owners read back exact values; other threads' reads
must return a value that was written (old or new), never EIO or a torn 512-byte
unit. A second phase writes overlapping ranges and one shared hidden block from
every thread; every unit must end as one written value. A third phase switches
the wrapper to `error_writes` while all threads run: every request must return,
the owner must stop, and after recreation every primary sector is whole and
every hidden block holds a written value (EIO only for blocks written in that
phase, then repaired). Reopen, stock full-primary readback and host
verification of `stress-final.img` follow.
