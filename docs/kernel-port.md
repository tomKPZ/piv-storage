# Newer-kernel port (Debian trixie-backports 7.2.9)

Status (2026-10-21): dm-piv builds warning-free and passes the guest suites on
Debian's trixie-backports kernel `7.2.9+deb13-amd64` (package 7.2.9-1~bpo13+1)
as well as on the pinned 6.12.113 kernel, from one source tree. Everything ran
inside disposable guests; nothing touched the host kernel.

## Image

`scripts/build_port_image.py --prefix artifacts/port-image-next --scaffold
artifacts/<stage>/scaffold.tar` boots the provisioned image, installs the pinned
backports kernel and headers (scripts/guest-port-install.sh), test-compiles the
module against them (`port-build.log` in the install run), selects that kernel,
writes the explicit marker `/etc/piv-port-kernel`, freezes the overlay as the
read-only `downloads/port-kernel-<hash>.qcow2` (provenance in the matching
.json; apt repositories were live) and verifies the boot. The guards (shell,
Python, Rust) accept `7.2.9+deb13-amd64` only with that marker; module builds
on it use the normal boot/header config comparison (check-config.py now takes
the release for the `CONFIG_BUILD_SALT` packaging entry).

Run suites with `suite.py --base-image downloads/port-kernel-<hash>.qcow2`.

## API differences handled (kernel/dm-piv.c)

| Change | Handling |
| --- | --- |
| `hex2bin` moved to `<linux/hex.h>` | included when `__has_include` finds it |
| `struct blk_integrity.tuple_size` renamed `metadata_size` | `PIV_BI_TUPLE_SIZE()`, threshold 6.14 |
| AES library: `struct aes_key`/`aes_enckey` with `aes_preparekey()`/`aes_prepareenckey()` replace `crypto_aes_ctx`/`aes_expandkey()` for `aes_encrypt`/`aes_decrypt` | `PIV_AES_KEY_API`, threshold 7.0; the LRW tweak key is encryption-only |
| `chacha_generic`/`sha256_generic` modules renamed `chacha`/`sha256` | the early initramfs hook adds both names (missing ones are skipped); without this, SETUP failed with ENOENT allocating chacha20 |

The version thresholds are where the upstream changes are believed to have
landed; only 6.12.113 and 7.2.9 were built and tested. A wrong threshold shows
up as a build failure on an untested version, not as silent misbehaviour,
because the old and new APIs are type-incompatible.

## Evidence

- artifacts/port-image-001: install, module compile (exit 0, no warnings) and
  boot verification of downloads/port-kernel-3a70cfae7df48a4b.qcow2.
- suite-046-port (`--suites all`, both profiles): native, faults, profile,
  cancel, lifecycle, batch, power, controls, v4, migrate and fuzz passed with
  16/16 host checks and no kernel reports; early failed (initramfs module
  names, fixed) and sector failed on its stock-release assertion (by design).
- suite-048-port-early: native and early passed for both profiles after the
  initramfs fix; suite-049-early and suite-047 (routine, 18/18) confirm the
  same source still passes on the pinned 6.12 kernel.

Not covered: sanitizer builds of 7.2, other distributions, and kernels between
6.12 and 7.2.
