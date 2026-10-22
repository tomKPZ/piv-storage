# dm-piv kernel module

`dm-piv.ko` is a standalone out-of-tree module (dm-piv.c plus piv-control.inc
and piv-native.inc; no dm-crypt fork or patch) registering `piv-crypt` and the
paired `piv-view` targets. dm-piv.c implements only the per-sector AEAD path
over stock dm-integrity, reproducing the Linux LUKS2 layout (AAD =
LE64(512-byte sector) ‖ IV, tuple = tag ‖ IV) for the supported stock profiles:
original AEGIS-128 (default) or XTS + HMAC authenc, always with stored random
16-byte IVs, 512- or 4096-byte sectors, hidden format v4. It coexists with
unmodified dm-crypt and never requires unloading it, even while an ordinary
encrypted filesystem is busy. Interfaces and tests:
[native-blocks.md](../docs/native-blocks.md).

## Rules

- Build and load ONLY inside the pinned disposable guest, never on the host or
  real disks. Source, headers, config and symbol versions must match; never
  force-load. Unsigned-module taint is expected. Supported guest kernels are
  the pinned Debian 6.12.113, its sanitizer build
  ([sanitizer.md](../docs/sanitizer.md)) and the 7.2.9 port
  ([kernel-port.md](../docs/kernel-port.md)).
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
  is no userspace IV, tuple or primary read/write control; prepare/apply exists
  only inside the kernel.
- kernel/piv-io-test.c is a separate guest-only exact-bio-flags helper; never
  link it into dm-piv or load it on the host.

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
