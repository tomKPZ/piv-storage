# Development environment and control fixture

Run from the repository root as an ordinary host user:

```sh
python3 scripts/fetch_sources.py
python3 scripts/vm.py prepare
python3 scripts/vm.py run --script scripts/guest-control.sh --run-dir artifacts/control-001
```

Choose a new run directory each time; the runner refuses to overwrite one.
The first download is approximately 390 MiB. Allow several minutes under TCG.
No host root, host device mapper, host loop devices, SSH server, ISO authoring
tools, or custom kernel is required. Optional `--accel kvm` requires actual
permission to use /dev/kvm. Default `--timeout 1200` covers boot and task execution.

The guest base is the SHA-512-pinned Debian 13 nocloud build 20261017-2634.
It boots the Debian 6.12.113+deb13-amd64 kernel. The runner creates a separate
qcow2 OS overlay and a sparse 128 MiB raw data disk exposed as /dev/vdb by
default. --blank-mib 512 explicitly selects the other approved fixture size; see
[large-volumes.md](large-volumes.md). Copied images must be regular 128/512 MiB
files; the runner copies them before attaching the private copy. The
base stays unchanged. Network access uses QEMU user networking without forwarded
ports. The runner completes first-boot setup with a random ephemeral root login
credential, logging console output only after login to avoid credential echo.
Only the private run/share directory is exported through 9p; the repository and
host home directory are not shared. Scripts passed to this runner are trusted
guest-root programs and can modify the contents of that share.

The control script installs cryptsetup-bin and libcryptsetup12 version 2:2.7.5-2
in the guest and records all installed package versions. Repositories remain
live; dependency resolution is not fully snapshot-pinned. If the explicit
cryptsetup versions disappear, fail and revise the environment deliberately.
Do not silently test a different version. The base image checksum was obtained
from Debian's HTTPS checksum list; detached-signature verification has not been
implemented. Package downloads use the guest's normal APT signature verification.

The test formats /dev/vdb as LUKS2 AES-256-GCM/random with 4096-byte encryption
sectors and AEAD integrity by default. To create the separate stock 512-byte
fixture, run:

```sh
python3 scripts/vm.py run --script scripts/guest-control-512.sh \
  --share-file scripts/guest-control.sh --run-dir artifacts/control-512-next --timeout 1800
```

For ChaCha20-Poly1305, use scripts/guest-control-chacha.sh (4096-byte sectors)
or scripts/guest-control-chacha-512.sh, also sharing scripts/guest-control.sh:

```sh
python3 scripts/vm.py run --script scripts/guest-control-chacha-512.sh \
  --share-file scripts/guest-control.sh --run-dir artifacts/chacha-control-512-next --timeout 1800
```

These use --cipher chacha20-random --integrity poly1305 --key-size 256. Native
activation and independent diagnostics detect the profile from LUKS metadata.
The explicit wrappers select only formatting options; all control generation
and stock readback checks share the same body.

Each profile writes distinct deterministic synthetic plaintext
to every primary sector, closes the mapping, reopens it read-only using stock
cryptsetup, and hashes every primary byte. Password-keyslot PBKDF2 uses a very low
iteration count solely to accelerate disposable tests. This is not a recommended
real-volume password configuration.

## Faster runs: provisioned image and parallel matrix

Without /dev/kvm every run is QEMU TCG emulation, and first boot plus live APT
setup costs one to several minutes per run. `python3 scripts/vm.py provision`
boots the pinned base once, installs the union of pinned guest packages
(cryptsetup 2:2.7.5-2, Python, cryptography, matched 6.12.113 headers, gcc-14,
make, patch), enables serial root autologin, sets no root password, masks the
persisted random seed and records the installed package list. The result is a
read-only qcow2 in ignored downloads/, keyed by the base checksum, package list
and provisioning script; changing any of them builds a new image.

`vm.py run --provisioned` backs the disposable overlay with that image and
copies its metadata to `guest-image.json` in the run directory. guest_packages
then resolves the same pinned packages offline (`apt-get --no-download`), and
falls back to the normal network path if anything is missing. Every run, with
or without provisioning, receives host entropy through virtio-rng. Per-run
`packages.tsv` remains the provenance record. Provisioning repositories were
live; re-provision deliberately rather than assuming a snapshot pin.

`scripts/suite.py` runs the matrix in parallel, one fresh run directory per VM:

```sh
python3 scripts/suite.py --prefix artifacts/suite-next \
  --profile aes-512 --profile chacha-4096 --control artifacts/control-001 \
  --scaffold artifacts/stage-next/scaffold.tar   # or --module experimental-dm-piv.ko
```

Per profile it creates a stock fixture (or uses --control), runs the native
dual-view/early-build test, then runs the selected suites concurrently
(default faults, profile, cancel, lifecycle, batch, early; optional power,
controls, sector, v4 and migrate) and independently verifies every closed output image with
check_stateless.py. `--jobs` bounds concurrent VMs; `--fresh` disables the
provisioned image; `--accel` defaults to kvm when /dev/kvm is usable (else tcg). summary.json records pass/fail, timings and host checks; a
suite that was not run counts as a failure. Original AEGIS-128 host checks need
PIV_AEGIS_REFERENCE (below).

## Artifacts

- `control.img`: raw test volume, outside the guest OS overlay.
- `guest.qcow2`: disposable OS overlay; may contain guest login state and caches.
- `console.log`: post-login console transcript, including task failures.
- `share/volume.key`, `share/passphrase.key`: randomly generated disposable test
  keys; never display, commit or reuse them for real data.
- `share/luks.json`, `integrity-dump.txt`, `integrity-table.txt`,
  `primary-status.txt`: observed configuration without exposed volume keys.
- `share/expected.sha256`, `actual.sha256`: full primary plaintext digests.
- `share/image.sha256`: final raw disk digest.
- `share/kernel.txt`, `kernel.config`, `cryptsetup-version.txt`, `packages.tsv`:
  guest provenance.
- `share/result.txt`: created only after all task checks succeed.

Success requires the runner to exit zero AND the matching full-volume hashes.
An existing image or a kernel fault is not a successful fixture. If the guest
times out, preserve its transcript for diagnosis and discard that run as a
source of trusted fixtures. These VM checks establish primary compatibility for
the attached image, not hardware crash durability or plausible deniability.

## Verify an output image with stock Linux

The runner copies the supplied image into a new private run before attachment.
It never attaches the supplied image directly. Use the original control volume's
synthetic passphrase and expected primary digest:

```sh
python3 scripts/vm.py run --script scripts/guest-verify.sh --data-image artifacts/native-closed.img --share-file artifacts/control-003/share/passphrase.key --share-file artifacts/control-003/share/expected.sha256 --run-dir artifacts/verify-native-next
```

The verification task opens the volume read-only, reads/authenticates every
primary byte, checks the expected plaintext hash, and verifies that the raw
image digest did not change. It records package/kernel provenance and a result
marker. This passed for both a four-sector random-IV experiment and a complete
hidden-payload pack in earlier revisions. Current stateless v3 records are
documented in docs/hidden-format.md; use current native tests for that format.

## Source subset

`environment/sources.json` records URLs, upstream versions, and SHA-256 hashes.
`scripts/fetch_sources.py` validates them into ignored vendor/. These are upstream
files, not the complete Debian-patched kernel source. Inspect distro changes if
behavior differs. A full Linux checkout is unnecessary for the initial review.

## Native integration

See docs/native-blocks.md for the paired writable-device tests and kernel/README.md
for module staging/control regressions. Use vm.py run --code to freeze the setup
package for each run. Only independent diagnostics remain from the offline tools;
FUSE/NBD services, mutation commands and their guest tests have been retired.

## Observed infrastructure failure

The first control attempt used a guest loop device backed by a writable file on
9p. Under Debian kernel 6.12.113 and QEMU TCG, this triggered list corruption and
kernel BUG traces involving p9_release_pages/p9_virtio_zc_request during format.
Root cause has not been established. Do not infer an AEAD failure from it.

The revised harness attaches the host raw file directly as a virtio block disk.
Use 9p only for scripts and small result files, not loop-backed block workloads.
Failed run artifacts remain ignored and must not be used as golden fixtures.

## Original AEGIS-128 diagnostics

Use scripts/guest-control-aegis.sh or guest-control-aegis-512.sh, sharing the
same guest-control.sh body. They select --cipher aegis128-random --integrity aead
--key-size 128. This is Linux's original AEGIS-128, not AEGIS-128L. Native
activation needs no additional userspace cryptography library.

Python cryptography and modern libaegis do not implement the original variant.
The optional independent diagnostic oracle uses the AES-NI implementation from
SUPERCOP revision 200cd30ca1f501463bd5cdd3da115a20d688d8fb, SHA-256 pinned in
environment/sources.json. This historical reference is test instrumentation,
not a new production crypto dependency or an implementation maintained here.
Actual primary I/O uses the maintained pinned Linux crypto implementation.
The wrapper accepts only our sector sizes, checks authentication before returning
plaintext and wipes its output buffer on success/failure; it does not promise
complete reference-stack/Python key erasure. Only use disposable synthetic keys.

On an x86 host with AES-NI and an existing C compiler:

```sh
python3 scripts/fetch_sources.py
python3 scripts/build_aegis_reference.py vendor/aegis-reference-next
export PIV_AEGIS_REFERENCE="$PWD/vendor/aegis-reference-next/libaegis128-reference.so"
PIV_FIXTURE=artifacts/aegis-control-4096-next python3 -W error::ResourceWarning -m unittest discover -v
python3 -m pivstore verify artifacts/aegis-control-4096-next/control.img \
  --volume-key-file artifacts/aegis-control-4096-next/share/volume.key
```

No host root or installed crypto package is required for this helper. The library
path is an explicit trusted diagnostic input; never point it at untrusted code.
Native open/close, hidden extraction and initramfs activation do not load it.
For the focused guest sector test, additionally share this library as
libaegis128-reference.so; QEMU's max CPU provides AES-NI. Full paired-device,
interruption and early-boot tests use kernel crypto alone.
