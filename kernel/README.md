# Separate persistent-IV kernel module

dm-piv.ko is a standalone module (dm-piv.c plus piv-control.inc and
piv-native.inc) registering piv-crypt and paired piv-view targets. It no longer
vendors or patches dm-crypt: dm-piv.c implements only the per-sector AEAD path
over stock dm-integrity, reproducing the Linux LUKS2 layout (AAD =
LE64(512-byte sector) || IV, tuple = tag || IV) for the pinned profiles. It coexists with unmodified dm-crypt/crypt and does not require
unloading stock crypt, including when an ordinary encrypted filesystem is busy.
The hidden views share one owner, hidden-record crypto and stateless authentication.
Primary encryption supports AES-GCM, ChaCha20-Poly1305 and original AEGIS-128 with stored random IVs.
See [native interface and end-to-end tests](../docs/native-blocks.md).
The userspace FUSE/NBD adapters have been removed; their historical test results
remain in ROADMAP.md and Git history. Authenticated sector controls remain for
focused kernel regression tests. Both 512- and 4096-byte primary encryption
sectors are supported; the tests derive sector and interleave boundaries from
the selected stock fixture.

Build/load ONLY inside the pinned disposable guest, never on the host or real
disks. Source/header/config/symbol versions must match; do not force-load a module.
Unsigned-module taint is expected.
Module aliases are dm-piv-crypt and dm-piv-view; no stock target alias is
claimed. Workqueues are named piv-native and kpiv_io, distinct from stock
kcryptd names (during a suspended table reload old stock and new private
targets share a device number). The owner accepts the stock crypt table syntax
for the pinned profiles plus `piv_control`, rejects every other feature, key
format (hex only) or offset, never accepts ordinary writes, serves bounded
authenticated reads until native ownership starts, and never prints its key in
status. No kernel source archive or full kernel build is needed: the module
builds against the guest's signed headers package. Other APT dependencies are
live and recorded per run. Four exact Debian build-salt/signing config
additions are allowlisted. The reviewed upstream dm-crypt source remains pinned
in environment/sources.json only as the layout reference.

## Reproduce

Create the ordinary fixture using docs/development.md, then follow the full
paired-device build/run command in docs/native-blocks.md. For focused native
sector/control checks, stage the same module and create corruption offsets:

```sh
python3 scripts/fetch_kernel.py vendor/kernel-build/native-next
mkdir -p artifacts/native-input
tar -cf artifacts/native-input/scaffold.tar -C vendor/kernel-build/native-next .
python3 kernel/read-fixture.py artifacts/control-003/control.img > artifacts/read-layout.json
python3 scripts/vm.py run --script scripts/guest-kernel.sh \
  --run-dir artifacts/native-sector-next --data-image artifacts/control-003/control.img --code \
  --share-file artifacts/native-input/scaffold.tar --share-file kernel/guest-test.py \
  --share-file kernel/check-config.py --share-file artifacts/read-layout.json \
  --share-file artifacts/control-003/share/passphrase.key \
  --share-file artifacts/control-003/share/volume.key \
  --share-file artifacts/control-003/share/expected.sha256 --timeout 1200
```

For original AEGIS-128, additionally share the pinned diagnostic library described
in docs/development.md as libaegis128-reference.so. Native paired-device and
early-boot tests do not require this reference.

Use fresh staging/run names. vm.py freezes sources for each run, including reboot.
Never force module loading. Independent host parsing/authentication and hidden
extraction remain the cross-check for stock/kernel results. Older K0-K3 protocol
notes describe historical control behavior; current usage is the paired interface.
