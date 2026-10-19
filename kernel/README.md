# Experimental native dm-crypt backend

The experimental module extends dm-crypt and registers paired piv-view targets
sharing one crypt owner, hidden-record crypto, stateless record authentication.
See [native interface and end-to-end tests](../docs/native-blocks.md).
The userspace FUSE/NBD adapters have been removed; their historical test results
remain in ROADMAP.md and Git history. Authenticated sector controls remain for
focused kernel regression tests. Both 512- and 4096-byte primary encryption
sectors are supported; the tests derive sector and interleave boundaries from
the selected stock fixture.

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

Use fresh staging/run names. vm.py freezes sources for each run, including reboot.
Never force module loading. Independent host parsing/authentication and hidden
extraction remain the cross-check for stock/kernel results. Older K0-K3 protocol
notes describe historical control behavior; current usage is the paired interface.
