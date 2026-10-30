# Deployment (packaging/)

> [!CAUTION]
> Research prototype. **No external cryptographic review has been
> conducted**, the hidden format and the module have only been tested in
> disposable QEMU guests (Debian 13, kernels 6.12.113 and 7.2.9), and an
> interrupted hidden write can leave a hidden block unreadable. Read the
> [security review](../docs/security-review.md) and
> [limitations](../README.md#nonces-and-limitations) first; keep backups of
> both views and do not rely on deniability against an observer who sees
> more than one snapshot or a host where `pivsetup` and `dm-piv.ko` are
> installed.

The pieces: the static `pivsetup` binary and the out-of-tree `dm-piv` module
(DKMS). `install.sh` installs each one on a Debian-style system; run it as root
from a checkout.

Boot hooks, root-filesystem integration and LUKS2-header stashing are
intentionally **out of scope**: installing `pivsetup` or `dm-piv.ko` on a
persistent decoy OS reveals that the machine can open hidden volumes, `dm-piv`
has no decoy-only mode, and mounting hidden storage inside a persistent decoy
OS leaks traces into decoy logs, caches and indexers. For deniability, keep the
LUKS2 + `dm-integrity` carrier on a secondary partition or external drive and
open it only from a clean RAM-only live environment (see
[header-stash.md](../docs/header-stash.md)). Use `packaging/` only on dedicated
or trusted hosts where convenience outweighs hiding the tooling itself.

## Requirements

- Linux with dm-integrity, dm-crypt and the crypto of the chosen profile:
  `authenc`, `xts`, `aes`, `hmac` and `sha256` (recommended profile) or
  `aegis128`; format v5 also needs `chacha20` and `hmac(sha256)`. Tested only
  on Debian 13's 6.12.113 and trixie-backports 7.2.9 kernels.
- cryptsetup and dmsetup (tested with cryptsetup 2.7.5) in /usr/sbin, /usr/bin,
  /sbin or /bin: pivsetup runs them with a cleared environment and that fixed
  `PATH`, never the caller's.
- For DKMS: `dkms` (tested 3.2.2) and the headers of every kernel to build for.

## pivsetup

Build on any x86-64 Linux machine with the pinned Rust toolchain
([rust/README.md](../rust/README.md)) and install the static binary:

```sh
python3 scripts/build_pivsetup.py        # prints the path and SHA-256
sudo packaging/install.sh pivsetup rust/target/x86_64-unknown-linux-gnu/release/pivsetup
```

It goes to `/usr/local/sbin/pivsetup`. Compare the printed SHA-256 when
copying the binary to another machine; it needs no runtime libraries.
`install.sh` refuses the guest-test build (`build_pivsetup.py --test-hooks`,
cargo feature `test-hooks`), which honours `PIVSETUP_TEST_*` variables;
`pivsetup --version` prints the version, the control ABI versions it speaks
and whether test hooks are compiled in. A dm-piv module speaking other ABI
versions is refused with both versions in the message: install the module and
pivsetup from the same tree (both carry the version in packaging/VERSION).

Key, passphrase and LUKS key files must be regular files owned by root and not
accessible by group or others (`chmod 600`); pivsetup refuses others. Hidden
passphrases at Argon2id tiers 2–4 need 256 MiB–2 GiB of free memory; pivsetup
checks `MemAvailable` first. A rejected key or passphrase prints a hint: the
tier (`--kdf-cost`) is not recorded and must match the keyslot's.

## dm-piv with DKMS

```sh
sudo apt install dkms linux-headers-$(uname -r)
sudo packaging/install.sh dkms           # kernel/ sources -> /usr/src/dm-piv-VERSION
sudo modprobe dm-piv
```

DKMS rebuilds the module for each newly installed kernel (`AUTOINSTALL`). If
that build fails (for example a kernel whose internal APIs changed), DKMS
reports the error during the kernel package installation and the new kernel has
no dm-piv; keep booting the previous kernel until the module builds.
`install.sh dkms-remove` removes it again. Without DKMS, build against the
running kernel's headers and install by hand:

```sh
make -C /lib/modules/$(uname -r)/build M=$PWD/kernel modules
sudo install -D -m 0644 kernel/dm-piv.ko /lib/modules/$(uname -r)/updates/dm-piv.ko
sudo depmod -a
```

Never force-load a module built for another kernel. dm-piv coexists with the
stock dm-crypt module; it never needs dm-crypt unloaded.

### Module signing and Secure Boot

With Secure Boot (kernel lockdown) the kernel loads only modules signed by a
trusted key. DKMS 3.x signs every module it builds with
`/var/lib/dkms/mok.key` (generated on first use; certificate
`/var/lib/dkms/mok.pub`). Enroll that certificate as a Machine Owner Key once:

```sh
sudo mokutil --import /var/lib/dkms/mok.pub   # choose a one-time password
# reboot; in MokManager choose "Enroll MOK" and enter that password
mokutil --test-key /var/lib/dkms/mok.pub      # "is already enrolled"
```

To sign a hand-built module with your own key instead (keep the private key
offline and never commit it):

```sh
openssl req -new -x509 -newkey rsa:3072 -sha256 -days 3650 -nodes \
  -subj "/CN=dm-piv module signing/" -outform DER -keyout mok.key -out mok.der
/usr/lib/linux-kbuild-$(uname -r | cut -d. -f1,2)/scripts/sign-file sha256 mok.key mok.der dm-piv.ko
# Ubuntu: kmodsign sha512 mok.key mok.der dm-piv.ko
modinfo -F signer dm-piv.ko
```

then enroll `mok.der` with `mokutil --import`. Note that enrolling a custom MOK
is visible in UEFI NVRAM (`mokutil --list-enrolled`). The deploy test verifies
that DKMS signs the module and that the appended PKCS#7 signature verifies
against the DKMS certificate; enrollment and Secure Boot enforcement were
**not** tested (the test guests boot without Secure Boot).

## Creating and opening a volume

Format with stock cryptsetup ([configuration.md](../docs/configuration.md)
explains the choices), then initialize the hidden volume once:

```sh
sudo cryptsetup luksFormat --type luks2 --cipher aes-xts-random --key-size 512 \
  --integrity hmac-sha256 --sector-size 512 /dev/disk/by-partuuid/XXXX
# Persist stock no-journal mode once (omit for a journaled volume).
sudo cryptsetup open --integrity-no-journal --persistent /dev/disk/by-partuuid/XXXX piv-tmp
sudo cryptsetup close piv-tmp
pivsetup keygen --output /root/hidden.key
sudo pivsetup open-blocks --device /dev/disk/by-partuuid/XXXX --key-file /root/luks.key \
  --hidden-key-file /root/hidden.key --initialize --ab
```

This is the recommended configuration: AES-XTS + HMAC-SHA256, 512-byte
sectors (use 4096 on drives with 4096-byte logical sectors), no integrity
journal (deniability; [configuration.md](../docs/configuration.md#integrity-journal)) and `--ab` for a
filesystem on the hidden view (a raw key store can omit it for twice the
capacity). AEGIS-128 (`--cipher aegis128-random --key-size 128 --integrity
aead`) remains supported.

`--device` is required (there is no default), may be any block device or
partition holding the LUKS2 volume, and may be a symlink. pivsetup refuses
non-block paths, a whole disk that has a partition table (give the partition),
a device that is mounted, mapped or opened exclusively, an owner name already
in use by another mapping, and a volume whose owner lock in /run is held.
Close with `pivsetup close-blocks --device ... --key-file ...` after unmounting
both views.

Health checks need no key: `sudo pivsetup status` (exit 2 when the owner has
failed) and `sudo pivsetup scrub --decoy` (read-only; exit 4 or 5 when parity
recovered blocks or blocks/decoy sectors are unavailable). Run the scrub after
a crash and periodically; repair steps are in
[native-faults.md](../docs/native-faults.md#status-scrub-and-repair).

**Never open the same volume with stock cryptsetup for writing** (for example
from `/etc/crypttab` or a desktop auto-unlock): stock writes do not refresh the
hidden records they overwrite, so they destroy hidden data. Keep the volume out
of `/etc/crypttab`.

Verified in a disposable guest (suite `deploy`): release binary installation
(no test hooks, refusal of the test build, `--version`), key-file permission
refusals, DKMS build/install/remove and PKCS#7 module signature verification,
activation and hidden block write/readback/restore from the installed binary
and module, stock read-only verification, and clean detachment of active
unmounted views by Debian's `systemd-shutdown` at power-off (with the disk
host-verified afterwards). **Not verified:** Secure Boot enforcement or
non-Debian distributions.

## Uninstall

```sh
sudo packaging/install.sh dkms-remove
sudo rm /usr/local/sbin/pivsetup
```
