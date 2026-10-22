# Paired native block devices

`dm-piv.ko` is a standalone module (no dm-crypt fork or patch) that implements
the Linux LUKS2 per-sector AEAD path itself over the stock dm-integrity journal
and registers `piv-crypt` (private owner) and `piv-view` (public views). Stock
dm-crypt keeps its `crypt` target and can stay loaded with unrelated encrypted
filesystems mounted throughout setup, I/O and removal of dm-piv. No stock
symbols are hooked or replaced; only ordinary exported block, device-mapper and
crypto APIs are used, but builds need matching kernel headers/config/symbols.

Both public views (`NAME-decoy`, `NAME-hidden`) reference one private owner,
lower dm-integrity device, serialization lock and record cipher. They expose
plaintext logical I/O; there is no userspace I/O service or persistent state
file. Loading the module does not convert existing stock mappings.

## Setup (pivsetup open-blocks)

Setup is privileged and restricted to QEMU, the pinned guest kernels and a
disposable 128 or 512 MiB /dev/vdb ([rust/README.md](../rust/README.md)). It:

1. validates the LUKS2 segment and integrity geometry for a
   [supported profile](../README.md#supported-primary-profiles) and takes an
   exclusive /run lock;
2. opens the volume with cryptsetup (Linux replays the journal), suspends the
   crypt mapping, reloads its private table as `piv-crypt ... piv_control`,
   resumes, and checks the owner table against the validated LUKS cipher;
3. begins coordinated ownership and issues NATIVE_SETUP (ABI 5) with the
   keyslot KEK, the v5 base context and (at initialization) the RS parity. The kernel waits for a seeded CRNG
   (without holding the owner lifecycle lock), then scans the 112-sector keyslot
   area (every primary sector with `--verify`, refusing on any failure);
4. with `--initialize`, writes a new master key, keyslot 0, the directory and
   authenticated zero blocks; otherwise a keyslot must authenticate under the
   KEK using IVs from that scan (EKEYREJECTED otherwise) and the directory must
   authenticate;
5. creates both views.

There is no uninitialized-carrier mode. Hidden availability of individual
records never gates the decoy. Runtime locks use /run, which may be tmpfs.
Setup polls SIGINT/SIGTERM between authenticated ranges and initialization
records ([cancellation.md](cancellation.md)).

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
it rejects all bios. Public `piv-view` map callbacks queue bounded work to the
ordered reclaim-capable `piv-native` workqueue; work runs under the shared lock
in NOIO allocation scope. Hidden bios are split per 4096-byte block (the hidden
view's logical and physical block size; the worker refuses anything else),
decoy bios at 16 KiB power-of-two boundaries (at most 32 primary sectors per
work item). Batching is within one bio: no
cross-bio accumulation, writeback cache or delay.

- **Decoy write**: authenticated primary-sector read-modify-write. Each written
  sector gets a fresh IV: keyslot (listed in the directory), directory and
  record sectors keep their fragment and redraw its random part; other sectors
  get uniformly random IVs. A write covering an entire sector that fails
  authentication replaces it; a partial write to such a sector fails EIO.
- **Hidden read**: reads the G-sector record (G = 687 + 3p; both slots with
  A/B), using raw IVs of sectors whose decoy data fails authentication; the SIV
  tag decides. With parity, a failing tag triggers RS decoding with the
  failing or unreadable sectors as erasures, then a second SIV check.
- **Hidden write**: with A/B, reads both slots' IVs to pick the slot not
  holding the newest valid version; then authenticates all G carrier sectors of
  the target slot, seals the block with a fresh generation and fresh fragments
  and rewrites the carrier (below). There is no durable cross-sector plan;
  without A/B a crash can destroy the block.

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
3. encrypt every sector in place in RAM under its fresh IV;
4. submit the ciphertext and tuples as a few multi-sector bios through the
   lower journal (at most 128 KiB of data and one page of tuples each: 22 bios
   for a 687-sector record at 4096-byte sectors, 6 at 512 with AEGIS-128, 9
   with HMAC-SHA256's 48-byte tuples), wait for all of them, and flush once.

Steps 1–3 finish for the whole request before the first lower write. A
request holds its plaintext/ciphertext and tuples in RAM: 2.7 MiB for a record
at 4096-byte sectors, 344 KiB at 512 (previously about 3 MiB of fixed-size
prepared tuples plus three authenticated reads per sector). Nothing re-reads a
sector between authentication and its write: the former expected-IV recheck
served the userspace PREPARE/APPLY interface; every mutation now runs in the
owner under its lock, and the private owner rejects other bios while views are
active. Freshly produced ciphertext is not decrypted again (that guarded
userspace-supplied tuples); later reads authenticate every sector.

Request writes flush once before completion, satisfying FUA;
WRITE|PREFLUSH drains the lower journal before its payload, and flush bios use
the same ordered workqueue. Initialization flushes every 16 records and before
returning, also when cancelled. Batches are not atomic writes; the stock
journal may commit part of a record before the final flush (it commits when
half full). No discard or write-zeroes is advertised. Suspend/removal uses DM
references and generation binding; see the
[lifecycle notes](native-faults.md#concurrent-lifecycle-and-flushfua-ordering-lifecycle-suite).

Failures before the first lower write (reads, authentication, allocation,
encryption) fail only that bio; failures once writing began and flush failures
stop both views until teardown ([failure scope](native-faults.md)). Hidden authentication
failure returns EIO for that block without stopping the owner. Internally,
hidden unavailability is the positive sentinel `PN_UNAVAILABLE`; Linux
`BLK_STS_MEDIUM` (-ENODATA) is a storage error, never mistaken for it.

Damaged hidden blocks are repaired by a full 4096-byte block write (the only
write size the hidden view accepts).

### Bounded authenticated reads

Setup scans, decoy reads and hidden-read carrier collection use
`piv_read_range`, gathering at most 16 KiB through the integrity target (writes
read through the batch path above). Every primary sector still passes
the AEAD check with its own address/IV AAD and tag offset, and nothing (plaintext
or IVs) is published until the whole range authenticates. Public reads copy to
the bio only on full success; large application reads can span several work
items and are not whole-request transactions. Private pages and metadata are
wiped after use. Measurements: [read-performance.md](read-performance.md).

## Control ABI (kernel/piv-control.h)

The control device exposes QUERY (version 2: sector size, encryption-sector
count, IV/tag/tuple sizes), DEVICES, BEGIN/END, NATIVE_SETUP, NATIVE_DETACH,
NATIVE_STATUS and NATIVE_KEYSLOT. There is no userspace IV, tuple or primary
read/write access; all rewriting happens inside the kernel and other ioctl
numbers return ENOTTY.

- NATIVE_SETUP ABI 5 (192 bytes): version/size, generation, flags,
  context_length, key[32] (keyslot KEK), context[128] (v5 base context),
  parity (0, 4, 8 or 16; non-zero only with initialize), reserved. Flags: 1
  initialize, 8 A/B (with initialize), 16 verify; other bits are rejected.
- NATIVE_KEYSLOT (version 1, 64 bytes): version/size, generation, slot, op
  (1 add, 2 remove), kek[32], reserved[2]. The last keyslot cannot be removed;
  failures after a lower write fail-stop the owner.
- NATIVE_STATUS (version 4): generation, hidden_bytes, encryptions (u64);
  active, views, failed, version (u32). Counters are volatile, not lifetime
  history.

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
rewrites and lifetime gates; piv-native.inc the hidden v5
crypto, both views and the ordered workqueue; piv-rs.inc the Reed–Solomon
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
attaches a blank disk only to preserve the /dev/vdb guard.

Before loading dm-piv, the shared guest loader creates a disposable
stock-encrypted ext4 filesystem on a guest-root-backed loop image; it stays
mounted and is checked writable after dm-piv teardown (coexistence-result.txt,
loaded-targets.txt). The stock module is never unloaded or replaced.

The batch suite (scripts/guest-batch.sh, kernel/guest-batch-test.py) checks the
16 KiB split contract on a closed native image: exact primary encryption counts
and O_DSYNC write timings for 4/16/32 KiB, unaligned, record-boundary and tail
requests, followed by full verification, reopen, stock readback and unload.
Single timings are diagnostic, not a throughput benchmark.
