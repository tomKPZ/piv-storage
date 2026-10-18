# Experimental dm-crypt backend: K0

This is an opt-in patch to Linux 6.12.113 dm-crypt, not a standalone IV plugin.
It adds a query-only character device and rejects ordinary primary mutations.
It does **not** read or replace carrier IVs, commit hidden records, or connect to
FUSE. The existing regular-file backend remains the working payload backend.

Use only a disposable guest. Never install this module on the host, force-load
it, or point the harness at real storage. Loading an unsigned experimental module
taints the guest; this does not disable ABI checks.

## Reproduction

From the repository root, after obtaining the ordinary control fixture:

```sh
python3 scripts/fetch_sources.py
python3 scripts/fetch_kernel.py vendor/kernel-build/k0
# This directory must not already exist.
tar -cf artifacts/scaffold.tar -C vendor/kernel-build/k0 .
python3 scripts/vm.py run --script scripts/guest-kernel.sh \
  --run-dir artifacts/kernel-next \
  --data-image artifacts/control-003/control.img \
  --share-file artifacts/scaffold.tar --share-file kernel/guest-test.py \
  --share-file kernel/check-config.py \
  --share-file artifacts/control-003/share/passphrase.key \
  --share-file artifacts/control-003/share/expected.sha256 --timeout 1200
```

The source archives are SHA-256 pinned in environment/kernel-sources.json, using
checksums from Debian's HTTPS-served 6.12.113-1 source descriptor. We have not
independently verified that descriptor's OpenPGP signature. The staging script
checks that Debian's orig dm-crypt equals the previously reviewed upstream file
and refuses Debian patches mentioning dm-crypt.c or its private dm-audit.h header.
It copies only those two source files, the local patch and control code. The guest
obtains exact-version Debian headers, kbuild and Module.symvers through signed
APT, uses GCC 14, and checks header configuration against its boot configuration.
Debian headers add four build-salt/signing entries omitted from the boot config; check-config.py
allows only these exact additions and rejects every other difference.
APT dependencies other than explicitly versioned packages still use live repos.
No full kernel build or additional host package installation is needed.

The guest builds on its local ext4 root, unloads the unused stock dm_crypt module,
and inserts the replacement. It never force-loads. Module information, boot/header configs, the symbol-table hash,
package versions, dmesg and test results are exported into the private run share.
All mappings are removed with dmsetup before restoring the stock module for
final readback. Stock cryptsetup 2.7.5's active-table parser rejects unknown
feature tokens, so it is not an active-stack management interface for the opted-in
target. Creation/reload/removal use low-level DM operations in this experiment;
cryptsetup integration belongs to the later service/setup work. The stopped
on-disk format is unchanged and stock activation/readback remains required.
Keys and DM tables containing them stay in protected files or process memory;
the test does not pass key material through argv or print those tables. Initial
test activation uses --disable-keyring so the separate table-reload process can
reuse the file-provisioned test key through protected stdin; cryptsetup-generated
keyring references are not accessible to that process in this guest. This is
harness provisioning, not a key extraction interface on the control device.

## Control and ownership

The optional DM table token `piv_control` selects the tested profile only:
`capi:gcm(aes)-random`, key32, sector4096, IV12, tag16, tuple28, offsets0,
without iv_large_sectors. K0 checks the crypto and block-integrity shape; it does
not parse LUKS metadata or validate the lower target's journal mode/recovery state.
The harness supplies the known fixture. K1 must establish those lower-target
requirements before adding writes. The owning table must be writable, so its existing
lower dm-integrity mapping is opened with write access. This is not equivalent
to cryptsetup --readonly. Present a read-only dm-linear wrapper above the owner
and mount the primary filesystem read-only. The target itself rejects write bios
even if its block-device read-only flag is unset.
Only READ and a zero-data WRITE with PREFLUSH are permitted at its map entry,
before the existing flush/discard bypass. General writes, write-zeroes, discard,
and other operations cannot reach the old path through that entry point.
The writable owner is a private implementation device, not the primary user
interface: buffered writes to a writable block device can dirty page cache before
a rejected bio reaches the target. Its filter alone cannot promise that a write
syscall fails immediately or that its page cache stays clean. The read-only
wrapper prevents that buffering; the guest tests the filter with aligned direct
I/O separately from buffered write rejection on the wrapper.

`/dev/pivctl-<generation>` is mode0600. Open and every ioctl require CAP_SYS_ADMIN.
The only command is PIV_QUERY from piv-control.h: a fixed 48-byte output struct
with version, length, generation, encryption-sector count, profile sizes and two
flags. Flag1 means the owner's lower access mode includes WRITE; flag2 means the
primary mutation filter is enabled. No key, IV or hidden data is returned.
Unknown commands fail ENOTTY; invalid output pointers fail EFAULT. The fixed
layout has no embedded pointers and implements compat-pointer translation; the
current guest test exercises only 64-bit userspace.

The control object holds an immutable nonsecret snapshot, not a crypt_config
pointer. Target destruction marks it dead before misc deregistration; open
handles retain refcounted storage, return ENODEV and pin the module until close.
Linux misc_open's mutex serializes its open callback with deregistration. Query
may finish just before invalidation; it is not an I/O reservation. Generation
counts only this module instance and resets after reload; it is not a persistent
volume identity or a future mutation authorization token. A device node and table
token reveal the experimental feature to a running-system observer.

## Next gate

K1 needs bounded authenticated tuple reads and request-local IV replacement using
the same lower dm-integrity instance. It must establish data/metadata pairing,
I/O synchronization and flush completion. This scaffold's snapshot lifetime does
not solve the lifetime of future asynchronous crypto or control I/O. K2 must then
resolve whole-record recovery before kernel-backed hidden fsync is enabled.
See docs/kernel-backend.md and ROADMAP.md.

## Observed result

artifacts/kernel-008 passed the complete build/query/filter/lifetime/stock-readback
workflow on the pinned guest. Ordinary-mode writes preserved the expected primary
plaintext, queries and permission/error checks passed, direct writes were rejected
at the owner, buffered writes were rejected by its read-only wrapper, a surviving
control returned ENODEV after target removal, and its fd pinned the module until
close. The final full primary hash matched after restoring stock dm-crypt.
Transient wrapper EBUSY was handled by bounded --retry teardown. Guest dmesg had
no BUG/Oops/WARNING; unsigned-module taint was expected. No KASAN/lockdep,
32-bit compat, stress or device-crash test was performed. Existing userspace
regressions also passed all 31 tests. These results establish K0, not IV updates
or hidden-record recovery.
