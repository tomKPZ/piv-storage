# Paired native block devices

The module extends pinned dm-crypt to reuse its exact primary AEAD/AAD handling
and stock dm-integrity journal, avoiding a second primary crypto implementation.
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
are split to 512 bytes, decoy bios to the primary encryption-sector size
(512 or 4096 bytes). Decoy writes use authenticated primary-sector RMW. No
discard or write-zeroes bypass is advertised. Writes finish with
a lower-device flush, including FUA requests; flush bios also reach the lower
journal. Suspend/removal uses DM references and generation binding. The current
backend processes one primary encryption sector per work item: a 4096-byte decoy
write on the 512-byte profile can refresh the same carrier group eight times.
Opening authenticates the full primary volume sector by sector. Smaller sectors
therefore add substantial request/setup overhead; bounded batching remains future
work, even though each individual hidden write rewrites fewer primary bytes.

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
retain ABI 3, separate from the primary-sector controls. The native test cap is 256 MiB of primary bytes, rather than a
sector-count cap; public setup still restricts the raw guest disk to 128 MiB.

Uninitialized/damaged blocks need a full 512-byte direct-I/O write for targeted
repair. Buffered sub-page writes may first read a 4096-byte page containing
unavailable blocks and fail before reaching the target. Destructive full-volume
initialization avoids this issue for normal filesystem use.

The integration patch is kernel/dm-crypt-piv.patch. piv-control.inc owns privileged
controls, authenticated primary tuple preparation/application and lifetime gates;
piv-native.inc owns hidden crypto, both views and the ordered workqueue. The
independent Python codec remains a cross-check for kernel output. Exact-current
application and journal checkpoints copy existing authenticated tuples without
new encryption. Fresh preparation spends an encryption invocation even if later
application fails. The test-only raw controls are not a nonce-policy service.

Hidden unavailability uses a positive internal PN_UNAVAILABLE sentinel. Linux
BLK_STS_MEDIUM maps to negative -ENODATA, which must retain shared fail-stop
semantics rather than being mistaken for local hidden unavailability.

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
