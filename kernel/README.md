# Experimental native dm-crypt backend

The kernel backend now includes authenticated IV reads, prepared-tuple updates,
transaction gates and a userspace recovery/FUSE adapter. It preserves the same
v1 hidden encoding and stock-readable AES-GCM/integrity format. Detailed protocol,
recovery ordering and limitations are in [implementation notes](../docs/kernel-implementation.md).
Final guest runs are recorded in ROADMAP.md; the regular-file backend remains
available as a reference/fallback.

Build/load ONLY inside the pinned disposable guest, never on the host or real
disks. Source/header/config/symbol versions must match; do not force-load a module.
Unsigned-module taint is expected. No full kernel build or new host package is
needed. Source archives are SHA-256 pinned using Debian's HTTPS source descriptor;
its OpenPGP signature has not been independently verified. The staging script
checks orig dm-crypt equality with the reviewed upstream file and refuses distro
patches mentioning it or dm-audit.h. Guest headers/kbuild use signed APT. Other
APT dependencies are live and recorded per run; complete snapshot pinning remains
deferred. Four exact Debian build-salt/signing config additions are allowlisted.

## Reproduce

Use the successful ordinary control fixture, not failed earlier experiments.
These commands create NEW ignored run directories and disposable disk copies.

```sh
python3 scripts/fetch_sources.py
python3 scripts/fetch_kernel.py vendor/kernel-build/native-next
mkdir -p artifacts/native-input
tar -cf artifacts/native-input/scaffold.tar -C vendor/kernel-build/native-next .
python3 kernel/read-fixture.py artifacts/control-003/control.img > artifacts/read-layout.json
```

Focused control/sector checks:

```sh
python3 scripts/vm.py run --script scripts/guest-kernel.sh \
  --run-dir artifacts/native-sector-next --data-image artifacts/control-003/control.img --code \
  --share-file artifacts/native-input/scaffold.tar --share-file kernel/guest-test.py \
  --share-file kernel/check-config.py --share-file artifacts/read-layout.json \
  --share-file artifacts/control-003/share/passphrase.key \
  --share-file artifacts/control-003/share/volume.key \
  --share-file artifacts/control-003/share/expected.sha256 --timeout 1200
```

Mounted native-primary/FUSE workflow, interrupted fsync and stale-mount cleanup:

```sh
python3 scripts/vm.py run --script scripts/guest-kernel-online.sh \
  --run-dir artifacts/native-online-next --data-image artifacts/control-003/control.img --code \
  --share-file artifacts/native-input/scaffold.tar --share-file kernel/check-config.py \
  --share-file kernel/guest-kernel-online-test.py --share-file kernel/guest-kernel-fuse-crash.py \
  --share-file artifacts/control-003/share/passphrase.key \
  --share-file artifacts/control-003/hidden.key --timeout 7200
```

Abrupt QEMU/device-write interruption, same-disk reboot, native journal replay,
external record recovery, injected journal-write EIO and repaired-stack recovery:

```sh
python3 scripts/vm.py run --script scripts/guest-kernel-power.sh \
  --power-cut-script scripts/guest-kernel-power-recover.sh \
  --run-dir artifacts/native-power-next --data-image artifacts/control-003/control.img --code \
  --share-file artifacts/native-input/scaffold.tar --share-file kernel/check-config.py \
  --share-file kernel/guest-kernel-power-test.py --share-file kernel/guest-kernel-fault-test.py \
  --share-file artifacts/control-003/share/passphrase.key \
  --share-file artifacts/control-003/hidden.key --timeout 7200
```

vm.py freezes a package copy for each run, including across reboot. Bootstrap
credentials remain only in host memory and are excluded from logs. Source/build
outputs, disks, runtime keys and private journals remain ignored. Do not modify
an executing shared task script. Read scripts and the implementation notes before
changing test storage; never use a guest loop block workload backed by 9p.

## Manual service inside the prepared guest

After loading the matching experimental module, use only /dev/vdb:

```sh
python3 -m pivstore serve-kernel --device /dev/vdb \
  --key-file /mnt/piv-work/passphrase.key --hidden-key-file /mnt/piv-work/hidden.key \
  --state-directory /var/tmp/piv-native/state --mountpoint /run/piv-hidden --initialize
```

The command prints the native read-only primary path, normally
/dev/mapper/piv-native-view. Mount its filesystem ro,noload. Use --initialize ONLY
for a fresh trusted adoption, not a restart; existing state rejects reinitializing.
Keep state on private persistent local ext4 outside the primary volume, never 9p.
Restart without --initialize. Normal FUSE unmount flushes pending edits; an
interrupted journaled update rolls forward before startup exposes the hidden file.
Do not delete the ledger, pending journal or stable locks to work around an error.

This prototype has no generic host-device installer or production key-management
interface. Runtime misc nodes/DM tokens, private external files, memory, journals
and multiple snapshots limit deniability. Work limits/nonce history cover recorded
adoption and future reservations, not unknowable pre-adoption encryption history
or rollback/clones. Statistical/cryptographic deniability is not established.
