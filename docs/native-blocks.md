# Paired native block devices

The patched dm-crypt module registers piv-view alongside its opted-in crypt
owner. The decoy and hidden targets reference that owner, lower dm-integrity
device, serialization lock and record cipher. Both expose plaintext logical I/O;
there is no userspace I/O service or persistent state file.

A failed setup can leave private mappings behind. In this disposable prototype,
tear down that stack or discard the guest before retrying; never work around
it by creating an overlapping independent mapping.

Setup remains privileged and intentionally restricted to QEMU, the pinned
6.12.113+deb13-amd64 guest and disposable 128 MiB /dev/vdb. It invokes cryptsetup
for ordinary LUKS opening and journal replay, opts the crypt mapping into
piv_control, suspends it, begins ownership, authenticates every primary sector,
and loads the hidden key/context through ABI 3. Optional destructive initialization
writes zero hidden blocks before exposing devices. Opening never requires that
any hidden record authenticate. CRNG readiness is awaited before setup takes the
owner lock. Runtime ownership locks use /run, which may be tmpfs.

The private crypt mapping rejects ordinary bios while native ownership is active.
Public piv-view map callbacks queue bounded work to an ordered reclaim-capable
workqueue. Work runs under the shared lock and NOIO allocation scope. Hidden bios
are split to 512 bytes, decoy bios to 4096 bytes. Decoy writes use authenticated
4096-byte RMW. No discard or write-zeroes bypass is advertised. Writes finish with
a lower-device flush, including FUA requests; flush bios also reach the lower
journal. Suspend/removal uses DM references and generation binding.

On a write, authenticate the complete affected carrier groups, preserve valid
hidden data (or mark unavailable data invalid), generate fresh encodings and
prepare all primary tuples in RAM. Then apply exact tuples through the lower
journal, flushing every 32 sectors and at completion. There is no durable
cross-sector plan. A crash can destroy affected hidden blocks; any primary
I/O/authentication failure stops both views until teardown. Hidden authentication
failure returns EIO for that block without stopping the owner.

ABI 3 SETUP is 192 bytes: version/size, generation, flags/context_length, hidden
key32, context128, reserved2. Flag 1 destructively initializes all hidden blocks.
STATUS is 48 bytes: generation, hidden_bytes, encryptions, invalidations (u64),
active/views/failed/version (u32). Counters are volatile; invalidations count group writes in successfully
completed invalid-marker requests, not durable lifetime history.
No user paths or file descriptors enter the native persistence path.

Uninitialized/damaged blocks need a full 512-byte direct-I/O write for targeted
repair. Buffered sub-page writes may first read a 4096-byte page containing
unavailable blocks and fail before reaching the target. Destructive full-volume
initialization avoids this issue for normal filesystem use.

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

Create the ordinary control fixture using docs/development.md if absent. The
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
for kmod and all required crypto modules. It mounts only RAM/pseudo filesystems.
Activation runs with Python -S; Python cryptography is needed only for independent
offline diagnostics. early_vm.py copies the data image and attaches a blank disk
solely to preserve the /dev/vdb test guard. It never attaches an OS/root disk.
The builder-only guest-early-only.sh can reuse an already built exact-kernel
module and closed fixture; it is a test optimization, not an installer.
