# dm-piv kernel module

`dm-piv.ko` is a standalone out-of-tree module (dm-piv.c plus piv-control.inc,
piv-native.inc and piv-rs.inc; no dm-crypt fork or patch) registering `piv-crypt` and the
paired `piv-view` targets. dm-piv.c implements only the per-sector AEAD path
over stock dm-integrity, reproducing the Linux LUKS2 layout (AAD =
LE64(512-byte sector) ‖ IV, tuple = tag ‖ IV) for the supported stock profiles:
original AEGIS-128 (default) or AES-XTS + HMAC-SHA256 authenc, always with stored random
16-byte IVs, 512- or 4096-byte sectors, hidden format v5 (4096-byte hidden
blocks, optional Reed–Solomon parity in `piv-rs.inc`). It coexists with
unmodified dm-crypt and never requires unloading it, even while an ordinary
encrypted filesystem is busy. Interfaces and tests:
[native-blocks.md](../docs/native-blocks.md).

## Rules

- Development and agent testing build and load the module only inside
  disposable guests, never on the development host or real disks. Source,
  headers, config and symbol versions must match; never force-load.
  Unsigned-module taint is expected there. Tested kernels are the pinned
  Debian 6.12.113, its sanitizer build ([sanitizer.md](../docs/sanitizer.md))
  and the 7.2.9 port ([kernel-port.md](../docs/kernel-port.md)).
- Installation on a real system (research prototype, no external review):
  DKMS (`packaging/dkms/dkms.conf`, `packaging/install.sh dkms`), module
  signing for Secure Boot and the initramfs-tools hook are described in
  [packaging/README.md](../packaging/README.md); the `deploy` suite builds,
  signs, installs and boots with them in a disposable guest.
- The module builds against the guest's headers package; no kernel source tree
  or full kernel build is needed. kernel/check-config.py allowlists four exact
  Debian build-salt/signing config additions. The pinned upstream dm-crypt
  source in environment/sources.json serves only as the layout reference.
- Module aliases are dm-piv-crypt and dm-piv-view; no stock target alias is
  claimed. Workqueues are `piv-native` and `kpiv_io`, distinct from stock
  kcryptd names (during a suspended table reload the old stock and new private
  targets share a device number).
- The owner accepts the stock crypt table syntax for the supported profiles plus
  `piv_control`, rejects every other feature, key format (hex only) or offset,
  never accepts ordinary writes, serves bounded authenticated reads until native
  ownership starts and never prints its key in status.
- The control device exposes only QUERY, DEVICES, BEGIN/END, NATIVE_SETUP,
  NATIVE_DETACH, NATIVE_STATUS and NATIVE_KEYSLOT (kernel/piv-control.h). There
  is no userspace IV, tuple or primary read/write control; rewriting happens
  only inside the kernel.
- kernel/piv-io-test.c is a separate guest-only exact-bio-flags helper; never
  link it into dm-piv or load it on the host. kernel/piv-rs-test.c is a
  guest-only freestanding userspace harness that compiles piv-rs.inc unchanged
  for the v5 suite's RS cross-check against pivstore/rs.py; never link it into
  dm-piv or load it on the host.

## Staging and tests

```sh
python3 scripts/fetch_kernel.py vendor/kernel-build/next
tar -cf artifacts/scaffold-next.tar -C vendor/kernel-build/next .
python3 scripts/suite.py --prefix artifacts/suite-next --profile aegis-4096 \
  --scaffold artifacts/scaffold-next.tar
```

Use fresh staging and run names; vm.py freezes sources for each run, including
across reboots. The kernel/guest-*-test.py scripts are guest test bodies driven
by scripts/guest-*.sh and scripts/suite.py ([development.md](../docs/development.md)).
Every kernel-written image is decoded and authenticated independently on the
host (scripts/check_stateless.py), the cross-check for kernel results.
