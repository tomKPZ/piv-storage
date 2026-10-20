# Paired native block devices

The separate dm-piv.ko module contains a private fork of pinned dm-crypt to reuse
its exact primary AEAD/AAD handling and stock dm-integrity journal. It registers
piv-crypt and paired piv-view targets. Stock dm-crypt keeps its crypt target and
can remain loaded with unrelated encrypted filesystems mounted throughout setup,
I/O and removal of our module. No stock symbols are hooked or replaced. The fork
still needs upstream fixes and exact matching kernel headers/config/symbols.

Both public views reference one private piv-crypt owner, lower dm-integrity
device, serialization lock and record cipher. They expose plaintext logical I/O;
there is no userspace I/O service or persistent state file. Existing mounted
stock mappings are not converted into paired volumes by loading this module.

Setup tracks mappings created by its attempt, including commands that fail after
kernel creation. Failed setup removes matching view UUIDs, then the newly created
owner/lower mappings after checking their captured device numbers and UUIDs. It
does not checkpoint native records during exception cleanup. Normal lower-target
teardown may still drain the stock journal. Cleanup never rolls back disk writes;
a failed --initialize can leave hidden contents changed or unavailable.

An existing active stack is preserved when another open is rejected. An existing
idle private owner must first be removed with close-blocks. Close checks BOTH
public view tables, owner generation and device binding before removing either
name, and refuses unrelated mappings. It can also remove a validated idle owner.
A changed mapping identity is not deleted. Cleanup errors are reported alongside
the original error; busy resources or process/VM death can still require explicit
teardown. Do not manipulate the same stack concurrently with external dmsetup
commands; these checks do not protect against a racing privileged administrator.

Setup remains privileged and intentionally restricted to QEMU, the pinned
6.12.113+deb13-amd64 guest and disposable 128 or 512 MiB /dev/vdb. It invokes cryptsetup
for ordinary LUKS opening and journal replay, suspends the new crypt mapping,
reloads its private table as piv-crypt with piv_control, resumes it, then suspends
and begins coordinated ownership, authenticates every primary sector,
and loads the hidden key/context through ABI 3. Optional destructive initialization
writes zero hidden blocks before exposing devices. Without initialization,
setup requires one hidden record (data or invalid marker) to authenticate under
the key, using carriers collected by the primary scan, unless the caller sets
the uninitialized-carrier flag; otherwise it returns EKEYREJECTED. Hidden
availability beyond that one record never gates the decoy. CRNG readiness is awaited before setup takes the
owner lock. Runtime ownership locks use /run, which may be tmpfs.

The private piv-crypt mapping rejects ordinary bios while native ownership is active.
Public piv-view map callbacks queue bounded work to an ordered reclaim-capable
workqueue. Work runs under the shared lock and NOIO allocation scope. Hidden bios
are split to 512 bytes, decoy bios at 16 KiB boundaries. Decoy writes use
authenticated primary-sector RMW and refresh each intersecting carrier group
once per work item. At most two carrier groups / 96 primary tuples are prepared;
the 16 KiB limit is smaller than the smallest primary carrier span (36 * 512
bytes).
Incomplete tail sectors receive fresh random IVs without hidden records. No
cross-bio accumulation, extra writeback cache, delay or on-disk format is added.
Separate small writes can still refresh the same group repeatedly.

No discard or write-zeroes bypass is advertised. WRITE|PREFLUSH drains the lower
journal before its payload; each write batch flushes every 32 applied sectors and
at completion, satisfying FUA before completion as well. Flush bios reach the
lower journal through the same ordered workqueue. Suspend/removal uses DM
references and generation binding. Public-view concurrency, busy teardown and
exact flush/FUA trace tests are described in [the lifecycle notes](native-faults.md#concurrent-lifecycle-and-explicit-flushfua-evidence).
Larger batches are not atomic writes; an
interrupted decoy batch may damage either touched hidden record. Opening still
authenticates the full primary volume sector by sector; setup overhead remains.

On a write, authenticate the complete affected carrier groups, preserve valid
hidden data (or mark unavailable data invalid), generate fresh encodings and
prepare all primary tuples in RAM. Then apply exact tuples through the lower
journal, flushing every 32 sectors and at completion. There is no durable
cross-sector plan. A crash can destroy affected hidden blocks. Failures before
the first applied tuple (reads, authentication, allocation, preparation) fail
only that bio; APPLY-time or flush failures stop both views until teardown. See
[failure scope](native-faults.md). Hidden authentication failure returns EIO for
that block without stopping the owner.

ABI 3 SETUP is 192 bytes: version/size, generation, flags/context_length, hidden
key32, context128, reserved2. Flag 1 destructively initializes all hidden blocks;
flag 2 accepts a carrier where no record authenticates (fresh/uninitialized).
Other flag bits are rejected.
STATUS is 48 bytes: generation, hidden_bytes, encryptions, invalidations (u64),
active/views/failed/version (u32). Counters are volatile; invalidations count group writes in successfully
completed invalid-marker requests, not durable lifetime history.
No user paths or file descriptors enter the native persistence path.

The primary cipher whitelist includes capi:gcm(aes)-random and
capi:rfc7539(chacha20,poly1305)-random (32-byte keys, 12-byte stored IVs),
and capi:aegis128-random (16-byte key, 16-byte IV). All use 16-byte tags. The pinned dm-crypt AEAD helper handles either transform with
AAD LE64(address_in_512_byte_units) || IV. Setup checks the actual owner table
against the validated LUKS cipher on creation and reuse. The independent verifier
selects AESGCM, ChaCha20Poly1305 or the pinned diagnostic AEGIS-128 reference from the same validated public metadata; setup
continues to require only the Python standard library. The v3 hidden encoding is unchanged; AEGIS groups contain 36 primary sectors
instead of 48. No persistent format is added outside the IVs.

QUERY reports the primary sector size and encryption-sector count. Primary
controls use version 2; old control requests are rejected. QUERY/READ remain
48 bytes; UPDATE is 4176 bytes. Its tuple is 4128 bytes: ciphertext[S], zero
padding up to 4096, tag16, IV[12 or 16], zero padding up to 16 IV bytes. Expected
IV fields likewise have zero padding up to 16 bytes. All nonzero padding is
rejected. Padding exists only in RAM, never on disk. The integrity tuple is
28 or 32 bytes according to the validated primary profile. Native SETUP/STATUS
retain ABI 3, separate from the primary-sector controls. The old 256 MiB primary
cap has been replaced by checked kernel file-offset bounds. Public setup still permits only 128 or 512 MiB raw test disks; see
[larger geometry](large-volumes.md) for tested extents and limitations.

Uninitialized/damaged blocks need a full 512-byte direct-I/O write for targeted
repair. Buffered sub-page writes may first read a 4096-byte page containing
unavailable blocks and fail before reaching the target. Destructive full-volume
initialization avoids this issue for normal filesystem use.

Use the project close-blocks command to remove the private stack. Stock cryptsetup
does not directly manage our custom target. The controller tears down our DM
mappings explicitly; ordinary cryptsetup remains available for unrelated volumes
and for stock readback after closing ours. No primary or hidden disk format or
control ABI changed with module separation.

The integration patch is kernel/dm-crypt-piv.patch. piv-control.inc owns privileged
controls, authenticated primary tuple preparation/application and lifetime gates;
piv-native.inc owns hidden crypto, both views and the ordered workqueue. The
independent Python codec remains a cross-check for kernel output. Exact-current
application and journal checkpoints copy existing authenticated tuples without
new encryption. Fresh preparation spends an encryption invocation even if later
application fails. The test-only raw controls are not a nonce-policy service.

Hidden unavailability uses positive internal sentinels: PN_UNAVAILABLE, and
PN_INVALID for an authenticated invalid marker (which also proves the key to
the setup guard). Linux BLK_STS_MEDIUM maps to negative -ENODATA, a storage
error that must never be mistaken for hidden unavailability: it is local only
before mutation and stops the owner once APPLY has begun.

## Reproduce

Use a fresh destination for every source stage and run:

```sh
python3 scripts/fetch_kernel.py vendor/kernel-build/stateless-next
mkdir -p artifacts/stateless-input-next
tar -cf artifacts/stateless-input-next/scaffold.tar -C vendor/kernel-build/stateless-next .
python3 scripts/vm.py run --code --script scripts/guest-stateless.sh \
  --run-dir artifacts/stateless-next --data-image artifacts/control-003/control.img \
  --share-file artifacts/stateless-input-next/scaffold.tar \
  --share-file scripts/guest-dual.sh --share-file scripts/guest-early-build.sh \
  --share-file kernel/guest-early-test.py \
  --share-file kernel/guest-dual-test.py --share-file kernel/check-config.py \
  --share-file artifacts/control-003/share/passphrase.key \
  --share-file artifacts/control-003/hidden.key --timeout 3600
```

Create the ordinary control fixture using docs/development.md if absent.
For the 512-byte profile, use control-512-001/control.img and that fixture's
passphrase.key instead; hidden.key is an independently generated 32-byte test key.
The same guest tests derive their geometry from LUKS and the queried owner. The
script builds only the matched module inside the VM, records package/config
provenance, exercises both filesystems and reopens with stock Linux for full
primary readback. No host module, root privileges or extra host packages are
needed. Independent host extraction verifies that the kernel wrote the v3 codec.
See ROADMAP.md for actual tested runs and remaining early-boot/fault coverage.

After that run succeeds, boot its private test initramfs with no OS filesystem:

```sh
python3 scripts/early_vm.py \
  --kernel artifacts/stateless-next/share/early-test.vmlinuz \
  --initrd artifacts/stateless-next/share/early-test.initrd \
  --data-image artifacts/stateless-next/share/dual-final.img \
  --run-dir artifacts/stateless-early-next
```

The initramfs includes synthetic test credentials and must stay private/ignored.
It supplies Python's standard library, cryptsetup/dmsetup, decompression libraries
for kmod and all required crypto modules, including aegis128. It mounts only RAM/pseudo filesystems.
Activation runs with Python -S; Python cryptography is needed only for independent
offline diagnostics. early_vm.py copies the data image and attaches a blank disk
solely to preserve the /dev/vdb test guard. It never attaches an OS/root disk.
The builder-only guest-early-only.sh can reuse an already built exact-kernel
module and closed fixture; it is a test optimization, not an installer.

vm.py automatically freezes guest-common.sh for setup guards, package installation,
module build/load and provenance recording. Tests keep their scenario logic in
separate scripts. guest-stateless-prebuilt.sh reuses the same guest-dual.sh test
body with PIV_PREBUILT=1; share guest-dual.sh and guest-early-build.sh when using it.

The shared guest loader creates a separate disposable stock-encrypted ext4
filesystem on a guest-root-backed loop image before loading dm-piv. It remains
mounted and is checked writable after custom-module teardown. Never put that
loop backing file on the 9p share. See coexistence-result.txt and loaded-targets.txt.
The stock module is never unloaded or replaced by these tests. This independent
sentinel is test data, not runtime metadata or a persistent-root requirement.
The RAM-root test deliberately starts with its first stock/private owner, which
also checks that per-module workqueue IDs cannot collide across the two targets.


## Bounded decoy I/O measurements

scripts/guest-batch.sh and kernel/guest-batch-test.py use a CLOSED native fixture
and complete expected views. Supplying scaffold.tar builds the current module;
supplying only experimental-dm-piv.ko reuses a current matched module. Both
check the documented 16 KiB split contract. Historical pre-batching baselines
retain their frozen harness at the old Git revision. Use a fresh VM run for each:

```sh
python3 scripts/vm.py run --code --script scripts/guest-batch.sh \
  --run-dir artifacts/batch-next \
  --data-image artifacts/separate-native-4096-002/share/dual-final.img \
  --share-file artifacts/stateless-input-next/scaffold.tar \
  --share-file kernel/check-config.py --share-file kernel/guest-batch-test.py \
  --share-file artifacts/control-003/share/passphrase.key \
  --share-file artifacts/control-003/hidden.key \
  --share-file artifacts/separate-native-4096-002/share/expected-hidden-volume \
  --share-file artifacts/separate-native-4096-002/share/expected-primary.sha256 \
  --timeout 3600
```

The test measures exact primary encryption invocations and elapsed direct
O_DSYNC write/fsync time, writes nontrivial data, reads it back and restores the
original bytes. Cases include 4/16/32 KiB, unaligned requests, carrier boundaries
and incomplete tails. Complete primary/hidden verification, clean reopen, stock
readback and custom unload follow. batch-results.json stores each sample; single
QEMU TCG timings are diagnostic, not a stable throughput benchmark. Work scales
with the carrier groups intersected by each 16 KiB split, rather than just the
application byte count. No throughput gain is promised for isolated small I/O.

## Bounded authenticated reads

Native setup scans, decoy reads and carrier collection use piv_read_range,
gathering at most 16 KiB through the ordinary integrity target. Every primary
sector still passes the original Linux AEAD helper with its own address/IV AAD
and tag offset. The helper publishes no plaintext or IVs until its complete
range authenticates. Public read work likewise copies to the bio only on full
success; larger application reads can span multiple work items and are not
whole-request transactions. Private pages and metadata are wiped after use.
Scalar privileged mutation controls are unchanged. No cache or lazy setup
verification was introduced. Measurements and exact authentication/submission
counts are in [read-performance.md](read-performance.md).

Setup can now be cancelled cooperatively with SIGINT; see
[cancellation.md](cancellation.md) for safe boundaries, partial initialization,
private error-table cleanup and signal/I/O limits. No setup progress file or
lazy authentication path is introduced.
