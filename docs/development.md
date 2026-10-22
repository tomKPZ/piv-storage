# Development environment and control fixture

Run from the repository root as an ordinary host user:

```sh
python3 scripts/fetch_sources.py
python3 scripts/vm.py prepare
python3 scripts/suite.py --prefix artifacts/control-001 --profile aegis-4096 --scaffold <staged scaffold.tar>
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

scripts/guest-control.sh formats /dev/vdb with stock cryptsetup. Its environment
selects the profile: `PIV_PRIMARY_CIPHER` (default `aegis128-random`, or
`aes-`/`serpent-`/`twofish-xts-random` with `PIV_INTEGRITY=hmac-sha1|hmac-sha256|hmac-sha512`),
`PIV_SECTOR_SIZE` (4096 default, or 512) and `PIV_NO_JOURNAL=1`. suite.py writes
a one-line task per profile (`--profile aegis-4096`, `aes-sha256-512`, ...):

```sh
python3 scripts/suite.py --prefix artifacts/suite-next --profile aes-sha256-4096 \
  --scaffold artifacts/stage-next/scaffold.tar
```

All control generation and stock readback checks share the same
body.

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
  --profile aegis-4096 --profile aegis-512 \
  --scaffold artifacts/stage-next/scaffold.tar
```

Per profile it creates a stock fixture (or uses --control), runs the native
dual-view/early-build test, then runs the selected suites concurrently
(`--suites routine`, the default: faults, profile, cancel, lifecycle, batch,
early, power and v4; `--suites all` adds the opt-in controls, sector, migrate
and fuzz, meant for changes in their own areas; migrate attaches a second 512 MiB blank
disk, /dev/vdc, via `vm.py --second-blank-mib`; fuzz runs
kernel/guest-table-fuzz.py (table/constructor fuzzing) and
kernel/guest-ioctl-fuzz.py, seeded control-ioctl fuzzing with
`PIV_FUZZ_STEPS`/`PIV_FUZZ_SEED` overrides, best on the sanitizer image). Profiles are aegis-4096 and aegis-512, the XTS + HMAC profiles
`<aes|serpent|twofish>-<sha1|sha256|sha512>-<4096|512>`, plus aegis-4096-nojournal
and aegis-512-nojournal (fixtures persisting stock --integrity-no-journal; guest_code
then exports PIV_ALLOW_NO_JOURNAL=1 so the test client passes --allow-no-journal). `--suites-for PROFILE=LIST` narrows the suites of matching profiles.
`--reuse-native PREFIX` skips the native step and starts the suites from a
previous matrix's passed, host-verified native run when the module input
(scaffold or module SHA-256, recorded in summary.json) and base image match;
use it to iterate on one suite in about a minute instead of rerunning native.

Rerun policy: the routine set (about 6 minutes on KVM for both profiles) after
kernel or pivsetup changes; only the affected suite (with --reuse-native) for
test-only changes; opt-in suites when their area changes; the sanitizer matrix
at milestones or after significant kernel C changes. It independently verifies every closed output image with
check_stateless.py. `--jobs` bounds concurrent VMs; `--fresh` disables the
provisioned image; `--accel` defaults to kvm when /dev/kvm is usable (else tcg).
It also builds the static Rust setup frontend once (scripts/build_pivsetup.py:
system rustc/cargo, CARGO_HOME under ignored downloads/cargo, committed
Cargo.lock, static glibc) and shares it into every VM; summary.json records its
SHA-256. summary.json records pass/fail, timings and host checks; a
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

## Verify an output image

Every suite verifies its closed output images on the host with
`scripts/check_stateless.py` (independent primary authentication and hidden
decoding) and inside the guest with stock dm-crypt readback; there is no
separate verification VM task.

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

The aegis-* profiles select --cipher aegis128-random --integrity aead
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
