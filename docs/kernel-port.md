# Newer-kernel port (Debian trixie-backports 7.2.9)

dm-piv builds warning-free from one source tree for the pinned 6.12.113 kernel
and Debian's trixie-backports kernel `7.2.9+deb13-amd64` (package
7.2.9-1~bpo13+1), and the guest suites pass on both. Everything runs inside
disposable guests; nothing touches the host kernel. The current image is
`downloads/port-kernel-3a70cfae7df48a4b.qcow2`.

## Image

```sh
python3 scripts/build_port_image.py --prefix artifacts/port-image-next \
  --scaffold artifacts/stage-next/scaffold.tar
```

This boots the provisioned image, installs the pinned backports kernel and
headers (scripts/guest-port-install.sh), test-compiles the module against them
(`port-build.log` in the install run), selects that kernel, writes the marker
`/etc/piv-port-kernel`, freezes the overlay as the read-only
`downloads/port-kernel-<hash>.qcow2` (provenance in the matching .json; apt
repositories were live) and verifies the boot (scripts/guest-port-verify.sh).
The guards (shell, Python, Rust) accept `7.2.9+deb13-amd64` only with that
marker. Module builds on it use the normal boot/header config comparison;
kernel/check-config.py takes the release for the `CONFIG_BUILD_SALT` entry.

Run suites with
`suite.py --base-image downloads/port-kernel-3a70cfae7df48a4b.qcow2 ...`.

## API differences handled

| Change | Handling |
| --- | --- |
| `hex2bin` moved to `<linux/hex.h>` | included when `__has_include` finds it (kernel/dm-piv.c) |
| `struct blk_integrity.tuple_size` renamed `metadata_size` | `PIV_BI_TUPLE_SIZE()`, threshold 6.14 |
| AES library: `struct aes_key`/`aes_enckey` with `aes_preparekey()`/`aes_prepareenckey()` replace `crypto_aes_ctx`/`aes_expandkey()` for `aes_encrypt`/`aes_decrypt` | `PIV_AES_KEY_API`, threshold 7.0; the LRW tweak key is encryption-only |
| `chacha_generic`/`sha256_generic` modules renamed `chacha`/`sha256` | the early initramfs hook (scripts/guest-early-build.sh) adds both names, skipping missing ones; without this SETUP fails with ENOENT allocating chacha20 |

The version thresholds are where the upstream changes are believed to have
landed; only 6.12.113 and 7.2.9 were built and tested. A wrong threshold shows
up as a build failure on an untested version rather than silent misbehaviour,
because the old and new APIs are type-incompatible.

## Coverage and limits

The full suite set (`--suites all`) passed on the port image for the AEGIS-128
4096 and 512 profiles, including the early-boot suite, with no kernel reports;
runs are recorded in commit messages. The XTS + HMAC profiles were added after
the port; on 7.2.9 only aes-sha256-4096 and twofish-sha512-512 have run
(the routine suites, passing). Not covered: sanitizer builds of
7.2, other distributions, and kernels between 6.12 and 7.2.
