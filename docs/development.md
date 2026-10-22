# Development environment and test harness

Everything runs from the repository root as an ordinary host user. No host root,
host device mapper, loop devices, SSH server or custom host kernel is needed;
experimental kernel code is built and loaded only inside disposable guests.

```sh
python3 scripts/fetch_sources.py          # pinned upstream sources into vendor/
python3 scripts/vm.py prepare             # pinned Debian base image (~390 MiB)
python3 scripts/vm.py provision           # optional cached provisioned image
python3 scripts/build_pivsetup.py         # static pivsetup; prints path and SHA-256
python3 scripts/fetch_kernel.py vendor/kernel-build/next
tar -cf artifacts/scaffold-next.tar -C vendor/kernel-build/next .
python3 scripts/suite.py --prefix artifacts/suite-next \
  --profile aegis-4096 --profile aegis-512 --scaffold artifacts/scaffold-next.tar
```

Use a new run directory or prefix each time; the runners refuse to overwrite.

## Guest VM (scripts/vm.py)

The guest base is the SHA-512-pinned Debian 13 nocloud build 20261017-2634,
booting 6.12.113+deb13-amd64. `vm.py run` creates a disposable qcow2 OS overlay
and a sparse raw data disk exposed as /dev/vdb: 128 MiB by default,
`--blank-mib 512` for the other approved size ([large-volumes.md](large-volumes.md)),
or `--data-image` to attach a private copy of an existing 128/512 MiB image.
`--second-blank-mib` adds /dev/vdc (migration tests), `--power-cut-script`
reboots the same disks after a simulated power cut, and `--code` exports the
package source read-only. vm.py freezes scripts/guest-common.sh (guards,
package setup, module build/load, provenance) into every run; reuse it rather
than duplicating guards.

Networking is QEMU user mode without forwarded ports; host entropy is supplied
through virtio-rng. Only the private run/share directory is exported via 9p;
the repository and home directory are not shared. Scripts passed to the runner
are trusted guest-root programs. Use 9p only for scripts and small results,
never for loop-backed block workloads (an early loop-on-9p attempt triggered
unexplained 9p kernel BUGs).

The guest installs cryptsetup-bin/libcryptsetup12 2:2.7.5-2 and records all
package versions in `packages.tsv`. Repositories are live; dependency resolution
is not snapshot-pinned. If the pinned versions disappear, fail and revise the
environment deliberately. The base checksum comes from Debian's HTTPS checksum
list; detached-signature verification is not implemented.

`vm.py provision` boots the base once and installs the union of guest packages
(cryptsetup, Python, cryptography, matching headers, gcc-14, make) with serial
root autologin and a masked persisted random seed. The read-only qcow2 in
ignored downloads/ is keyed by base checksum, package list and provisioning
script. `vm.py run --provisioned` uses it and resolves packages offline,
falling back to the network if anything is missing.

## Test matrix (scripts/suite.py)

Per profile, suite.py creates a stock fixture with scripts/guest-control.sh
(or uses `--control DIR`), runs the native dual-view and early-build test, then
runs the selected suites concurrently, one fresh VM per suite.

- Profiles: `aegis-4096`, `aegis-512`, `aes-sha256-4096` and `aes-sha256-512`
  (AES-XTS + HMAC-SHA256).
- `--suites routine` (default): faults, profile, cancel, lifecycle, batch,
  early, power, v4. `--suites all` adds controls, migrate (second 512 MiB disk)
  and fuzz (seeded control-ioctl fuzzing with `PIV_FUZZ_STEPS`/`PIV_FUZZ_SEED`,
  plus dm table/constructor fuzzing; best on the sanitizer image). `bench`
  (the [configuration.md](configuration.md) measurements, on the pristine
  fixture) is never in a set; request it explicitly and run it with
  `--jobs 1`. An explicit comma list also works; `--suites-for PROFILE=LIST`
  narrows per profile.
- `--reuse-native PREFIX` skips the native step and starts from a previous
  passed, host-verified native run with the same module input and base image.
- `--base-image` selects a derived guest image (sanitizer or port, below);
  `--memory-mib`, `--jobs`, `--fresh` (no provisioned image) and `--accel`
  (default kvm when usable, else tcg).

suite.py builds pivsetup once and shares it into every VM, verifies every closed
output image on the host with scripts/check_stateless.py (independent primary
authentication and hidden decoding; AEGIS needs `PIV_AEGIS_REFERENCE`, below),
fails any run whose console shows kernel reports (KASAN, UBSAN, lockdep, BUG,
WARNING, Oops, kmemleak), and writes `summary.json` with pass/fail, timings, host checks
and module/pivsetup SHA-256s. A suite that did not run counts as a failure.

Rerun policy: the routine set after kernel or pivsetup changes; only the
affected suite (with `--reuse-native`) for test-only changes; opt-in suites when
their area changes; the sanitizer matrix at milestones or after significant
kernel C changes. Executed runs are recorded in commit messages.

## Guest kernels

- Default: pinned Debian 6.12.113 (module built against the guest headers).
- Sanitizer: KASAN/UBSAN/lockdep/kmemleak kernel from
  scripts/build_debug_kernel.py; see [sanitizer.md](sanitizer.md).
- Port: Debian trixie-backports 7.2.9 image from scripts/build_port_image.py;
  see [kernel-port.md](kernel-port.md).

Guards accept the derived images only with their marker files.

## Stock fixtures

scripts/guest-control.sh formats /dev/vdb with stock cryptsetup, selected by
`PIV_PRIMARY_CIPHER` (default `aegis128-random`, or `aes-xts-random` with
`PIV_INTEGRITY=hmac-sha256`) and `PIV_SECTOR_SIZE` (4096 default, or 512), always
with the default journaled integrity mode. It writes
distinct deterministic synthetic plaintext to every primary sector, reopens
read-only with stock cryptsetup and hashes every primary byte. Keyslot PBKDF2
uses a very low iteration count solely to speed up disposable tests.

Control run artifacts: `control.img` (raw test volume), `guest.qcow2`
(disposable overlay), `console.log` (post-login transcript), `share/volume.key`
and `share/passphrase.key` (disposable test keys; never display, commit or
reuse), `hidden.key` (from `pivsetup keygen`), `share/luks.json` and integrity
dumps/tables (no keys), `share/expected.sha256`/`actual.sha256`,
`share/image.sha256`, provenance (`kernel.txt`, `kernel.config`,
`cryptsetup-version.txt`, `packages.tsv`) and `share/result.txt` (written only
after all checks pass). Success requires a zero exit and matching full-volume
hashes. Timed-out or failed runs must not become trusted fixtures. These checks
establish primary compatibility, not hardware crash durability or deniability.

## Source subset

`environment/sources.json` records URLs, versions and SHA-256 hashes;
scripts/fetch_sources.py validates them into ignored vendor/. These are
upstream files (the reviewed dm-crypt/dm-integrity layout reference and the
AEGIS reference), not the Debian-patched kernel tree. scripts/fetch_kernel.py
stages the complete module source for guest builds.

## Original AEGIS-128 diagnostics

The aegis profiles use `--cipher aegis128-random --integrity aead --key-size
128`, Linux's original AEGIS-128, not AEGIS-128L. Python cryptography and
libaegis do not implement it, so host primary verification uses the AES-NI
implementation from SUPERCOP revision 200cd30ca1f501463bd5cdd3da115a20d688d8fb
(SHA-256 pinned). It is test instrumentation, not a runtime dependency: native
activation, hidden extraction and initramfs activation never load it. The
wrapper accepts only supported sector sizes, checks authentication before
returning plaintext and wipes its output buffer; it does not promise complete
key erasure. Use only disposable keys.

On an x86 host with AES-NI and a C compiler:

```sh
python3 scripts/build_aegis_reference.py vendor/aegis-reference-next
export PIV_AEGIS_REFERENCE="$PWD/vendor/aegis-reference-next/libaegis128-reference.so"
PIV_FIXTURE=artifacts/suite-next/aegis-4096-control \
  python3 -W error::ResourceWarning -m unittest discover -v
```

The library path is a trusted diagnostic input; never point it at untrusted
code. AES-XTS + HMAC-SHA256 images are decrypted and verified with
`cryptography`.

See [native-blocks.md](native-blocks.md) for the module and paired devices and
[kernel/README.md](../kernel/README.md) for module build rules.
