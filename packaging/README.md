# Deployment (packaging/)

> [!CAUTION]
> Research prototype. **No external cryptographic review has been
> conducted**, the hidden format and the module have only been tested in
> disposable QEMU guests (Debian 13, kernels 6.12.113 and 7.2.9), and an
> interrupted hidden write can leave a hidden block unreadable. Read the
> [security review](../docs/security-review.md) and
> [limitations](../README.md#nonces-and-limitations) first; keep backups of
> both views and do not rely on deniability against an observer who sees
> more than one snapshot, your installed software or your boot configuration.

The pieces: the static `pivsetup` binary, the out-of-tree `dm-piv` module
(DKMS), and optional initramfs-tools integration that opens the views before
the root filesystem is mounted. `install.sh` installs each one on a
Debian-style system; run it as root from a checkout.

## Requirements

- Linux with dm-integrity, dm-crypt and the crypto of the chosen profile:
  `aegis128` (default) or `authenc`, `xts`, `aes`, `hmac` and `sha256`; format
  v5 also needs `chacha20` and `hmac(sha256)`. Tested only on Debian 13's
  6.12.113 and trixie-backports 7.2.9 kernels.
- cryptsetup and dmsetup (tested with cryptsetup 2.7.5), `blockdev`.
- For DKMS: `dkms` (tested 3.2.2) and the headers of every kernel to build for.
- For boot activation: initramfs-tools (tested 0.148.4); for `ask` prompts,
  cryptsetup-initramfs (`/lib/cryptsetup/askpass`).

## pivsetup

Build on any x86-64 Linux machine with the pinned Rust toolchain
([rust/README.md](../rust/README.md)) and install the static binary:

```sh
python3 scripts/build_pivsetup.py        # prints the path and SHA-256
sudo packaging/install.sh pivsetup rust/target/x86_64-unknown-linux-gnu/release/pivsetup
```

It goes to `/usr/local/sbin/pivsetup`. Compare the printed SHA-256 when
copying the binary to another machine; it needs no runtime libraries.

## dm-piv with DKMS

```sh
sudo apt install dkms linux-headers-$(uname -r)
sudo packaging/install.sh dkms           # kernel/ sources -> /usr/src/dm-piv-0.1
sudo modprobe dm-piv
```

DKMS rebuilds the module for each newly installed kernel (`AUTOINSTALL`).
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

then enroll `mok.der` with `mokutil --import`. The deploy test verifies that
DKMS signs the module and that the appended PKCS#7 signature verifies against
the DKMS certificate; enrollment and Secure Boot enforcement were **not**
tested (the test guests boot without Secure Boot).

## Creating and opening a volume

Format with stock cryptsetup ([configuration.md](../docs/configuration.md)
explains the choices), then initialize the hidden volume once:

```sh
sudo cryptsetup luksFormat --type luks2 --cipher aegis128-random --key-size 128 \
  --integrity aead --sector-size 4096 /dev/disk/by-partuuid/XXXX
pivsetup keygen --output /root/hidden.key
sudo pivsetup open-blocks --device /dev/disk/by-partuuid/XXXX --key-file /root/luks.key \
  --hidden-key-file /root/hidden.key --initialize
```

`--device` is required (there is no default), may be any block device or
partition holding the LUKS2 volume, and may be a symlink. pivsetup refuses
non-block paths, a whole disk that has a partition table (give the partition),
a device that is mounted, mapped or opened exclusively, an owner name already
in use by another mapping, and a volume whose owner lock in /run is held.
Close with `pivsetup close-blocks --device ... --key-file ...` after unmounting
both views.

**Never open the same volume with stock cryptsetup for writing** (for example
from `/etc/crypttab` or a desktop auto-unlock): stock writes do not refresh the
hidden records they overwrite, so they destroy hidden data. Keep the volume out
of `/etc/crypttab`.

## Boot activation (initramfs-tools)

```sh
sudo packaging/install.sh initramfs
sudoedit /etc/pivtab                     # see /etc/pivtab.example
sudo update-initramfs -u
```

The hook (`/etc/initramfs-tools/hooks/pivsetup`) validates `/etc/pivtab`,
copies pivsetup, cryptsetup, dmsetup, blockdev, the dm-piv module of the target
kernel and the profile crypto modules, and fails `update-initramfs` on any
configuration error or a missing module. The local-top script loads the
modules, waits up to `ROOTDELAY` (default 30 s) for each device and runs
`pivsetup open-blocks`, logging to `/run/pivsetup/initramfs.log` (visible after
boot); a failure is logged and boot continues. A root filesystem on a view is
named `root=/dev/mapper/NAME-decoy` (or `-hidden`).

Each `/etc/pivtab` line is `NAME DEVICE LUKS-KEY HIDDEN-SECRET OPTIONS`. A key is
either `ask` (prompted at boot through cryptsetup's askpass; hidden secrets
then must be a passphrase, option `hidden-passphrase`, with `kdf-cost=N`) or a
key file path, which requires `embed-keys`. Security trade-offs:

- `embed-keys` copies both keys into the initramfs. The image is created mode
  0600 (`conf.d/pivsetup` sets `UMASK=0077`), but it normally lies unencrypted
  in /boot: anyone who reads it can open both views and prove the hidden volume
  exists. Use it only for testing or where the boot partition is protected as
  well as the keys.
- `ask` keeps keys out of the image; the typed secrets live briefly in the
  initramfs tmpfs (overwritten and deleted after use) and pivsetup's locked
  memory. A hidden passphrase is only as strong as its Argon2id cost tier.
- Either way `/etc/pivtab`, the hook and the initramfs reveal that a hidden
  view is configured, and pivsetup always opens both views (there is no
  decoy-only mode of dm-piv). For deniability, do not configure boot activation
  of the hidden view at all; open it manually when needed.

Verified in a disposable guest (suite `deploy`): DKMS build, install and
signature; activation from the installed binary and module; the hook's
rejection of invalid configurations; and a reboot whose stock initramfs-tools
boot opened both views from an `embed-keys` entry before root was mounted,
with hidden and decoy contents intact. The suite also leaves unmounted views active at power-off: Debian's
systemd-shutdown detached all four mappings (views, owner, integrity) and the
disk verified on the host afterwards. Still unmount and close the views
before shutdown where possible: a filesystem on a view must be unmounted
before its mapping can go. **Not verified:** `ask` prompts, a root
filesystem on a view, Secure Boot, other distributions or dracut.

## Uninstall

```sh
sudo rm /etc/pivtab /etc/initramfs-tools/hooks/pivsetup \
  /etc/initramfs-tools/scripts/local-top/pivsetup /etc/initramfs-tools/conf.d/pivsetup
sudo update-initramfs -u
sudo packaging/install.sh dkms-remove
sudo rm /usr/local/sbin/pivsetup
```
