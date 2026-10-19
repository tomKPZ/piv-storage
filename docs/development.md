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
qcow2 OS overlay and a sparse 128 MiB raw data disk exposed as /dev/vdb. The
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
sectors and AEAD integrity. It writes distinct deterministic synthetic plaintext
to every primary sector, closes the mapping, reopens it read-only using stock
cryptsetup, and hashes every primary byte. Password-keyslot PBKDF2 uses a very low
iteration count solely to accelerate disposable tests. This is not a recommended
real-volume password configuration.

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
