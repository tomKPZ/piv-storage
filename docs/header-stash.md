# Storing tooling and keys inside the LUKS2 header

Design note and disposable-guest measurements (`scripts/probe-luks2-header.sh`,
run `artifacts/header-stash-probe-003` on Debian 13 kernel `6.12.113+deb13-amd64`
with `cryptsetup` `2:2.7.5-2`). **Research only; no implementation is included
without user approval.**

## Problem statement

Format v5 keeps all hidden-volume data and metadata inside the 16-byte random
IVs of a stock LUKS2 + `dm-integrity` carrier. However, an installation on the
host root filesystem or `/boot` (`/usr/local/sbin/pivsetup`,
`/lib/modules/.../dm-piv.ko`, `/etc/pivtab`, the `initramfs-tools` hook, and
key files; see [packaging/README.md](../packaging/README.md)) reveals that the
machine is configured to open a hidden volume.

For users who prioritize deniability over convenience, the question is whether
`dm-piv.ko`, `pivsetup`, an unlock script, and optional key files can be stored
inside the LUKS2 header itself as ciphertext indistinguishable from bytes that
stock `cryptsetup` already writes, and unlocked manually from a stock initramfs
before mounting the root filesystem.

---

## 1. Where bytes can live in a stock LUKS2 header

A default LUKS2 header occupies the first **16 MiB (`16,777,216` bytes)** of the
device (`LUKS2_DEFAULT_HDR_SIZE` in `lib/luks2/luks2.h`):

| Byte range | Size | Contents written by stock `luksFormat` |
| --- | ---: | --- |
| `[0, 4096)` | 4 KiB | Primary binary header (`LUKS\xba\xbe`, version 2, `hdr_size = 16384`, `seqid`, `uuid`, 32-byte random `salt1` at `[236, 268)`, SHA-256 checksum; zero-padded after byte 512) |
| `[4096, 16384)` | 12 KiB | Primary JSON metadata (`json_size = 12288`), NUL-padded to `16384` (enforced by `validate_json_area` in `lib/luks2/luks2_disk_metadata.c`) |
| `[16384, 20480)` | 4 KiB | Secondary binary header (`SKUL\xba\xbe`, 32-byte random `salt2` at `[16620, 16652)`, SHA-256 checksum) |
| `[20480, 32768)` | 12 KiB | Secondary JSON metadata (`json_size = 12288`), NUL-padded |
| `[32768, 16777216)` | 15.96875 MiB (`16,744,448` B) | Binary keyslots area (`keyslots_size = 16744448`) |
| `16777216` (`0x1000000`) | — | Start of `dm-integrity` superblock and data (`segments.0.offset = 16777216`) |

### `luksFormat` random fill of the entire keyslots area

In `LUKS2_wipe_header_areas` (`lib/luks2/luks2_json_format.c`), `luksFormat`
first zero-fills `[0, 16777216)` and then calls:

```c
offset = get_min_offset(hdr);   /* 2 * hdr->hdr_size = 32768 */
length = LUKS2_keyslots_size(hdr); /* 16744448 */
crypt_wipe_device(cd, crypt_metadata_device(cd), CRYPT_WIPE_RANDOM,
                  offset, length, wipe_block, NULL, NULL);
```

Every byte of `[32768, 16777216)` is overwritten with fresh CSPRNG output
(`CRYPT_RND_NORMAL`) before keyslot 0 is written.

To verify this empirically without trusting uninitialized disk bytes, the guest
probe pre-filled the first 20 MiB of `/dev/vdb` with `0xA5`, ran `cryptsetup
luksFormat` for each supported profile, and measured the unallocated remainder
of `[32768, 16777216)`:

| Profile | Combined VK (`key_size`) | `AFEKSize` (`4000 × VK`) | Slot 0 `area.size` (4 KiB-aligned) | Slot 0 4 KiB tail (`area.size - AFEKSize`) | Unallocated keyslots range | Unallocated bytes | Zero 4 KiB pages | Shannon entropy (bits/B) | $\chi^2$ (255 d.o.f.) |
| --- | ---: | ---: | ---: | ---: | --- | ---: | ---: | ---: | ---: |
| `aes-xts-random` (512-bit) + `hmac-sha256` | 96 B | `384,000` B | `385,024` B | `1,024` B (random) | `[417792, 16777216)` | `16,359,424` B (15.60 MiB) | 0 | `7.999988` | `278.45` |
| `aes-xts-random` (256-bit) + `hmac-sha256` | 64 B | `256,000` B | `258,048` B | `2,048` B (random) | `[290816, 16777216)` | `16,486,400` B (15.72 MiB) | 0 | `7.999989` | `251.34` |
| `aegis128-random` (128-bit) + `aead` | 16 B | `64,000` B | `65,536` B | `1,536` B (random) | `[98304, 16777216)` | `16,678,912` B (15.91 MiB) | 0 | `7.999989` | `249.90` |

### Why the upper 4.22 MiB of a default 16 MiB header is unreachable by stock keyslots

In `LUKS2_find_area_gap` (`lib/luks2/luks2_json_format.c`), every new keyslot
is placed in the **lowest free 4 KiB-aligned gap** starting at `get_min_offset(hdr) = 32,768`.
LUKS2 allows at most `LUKS2_KEYSLOTS_MAX = 32` keyslots (`0..31`), and each
keyslot's JSON `area.size` is `round_up(4000 * key_size, 4096)`. Even if all 32
keyslots are simultaneously populated, the highest byte offset that stock
`LUKS2_find_area_gap` can ever allocate is:

- **96-byte volume key** (`385,024` B/slot): $32{,}768 + 32 \times 385{,}024 = 12{,}353{,}536$ B (`11.78` MiB), leaving **`4,423,680` B (`4.22` MiB)** at `[12353536, 16777216)` permanently unreachable.
- **64-byte volume key** (`258,048` B/slot): $32{,}768 + 32 \times 258{,}048 = 8{,}290{,}304$ B (`7.91` MiB), leaving **`8,486,912` B (`8.09` MiB)** unreachable.
- **16-byte volume key** (`65,536` B/slot): $32{,}768 + 32 \times 65{,}536 = 2{,}129{,}920$ B (`2.03` MiB), leaving **`14,647,296` B (`13.97` MiB)** unreachable.

Non-default `--luks2-keyslots-size` or `--luks2-metadata-size` values are
recorded in plaintext JSON (`config.json_size` and `config.keyslots_size`) and
shift `segments.0.offset` away from `16,777,216`, creating an immediate tell.
The default 16 MiB header already provides `4.22` MiB of unreachable random-filled
space without altering any public header parameter.

---

## 2. Stock `cryptsetup` operations on the keyslots area

The guest probe planted a 64 KiB pseudorandom marker at offset `14 MiB`
(`[14680064, 14745600)`) on a `luksFormat`ted `aes-xts-random` (512-bit +
`hmac-sha256`, 96-byte VK) volume and diffed all 4,096 pages of the 16 MiB
header across each stock `cryptsetup` `2:2.7.5-2` operation:

| Operation | Changed 4 KiB byte ranges | Keyslot `offset` / `size` after | `14 MiB` tail marker intact? | Notes |
| --- | --- | --- | :---: | --- |
| `cryptsetup open` + `close` | None (`[]`) | Slot 0: `32768` / `385024` | Yes | Read-only header access |
| `cryptsetup open --integrity-no-journal --persistent` + `close` | `[0, 8192)`, `[16384, 24576)` | Slot 0: `32768` / `385024` | Yes | Updates JSON `flags` and `seqid` only |
| `cryptsetup config --label data-vol` | `[0, 4096)`, `[16384, 20480)` | Slot 0: `32768` / `385024` | Yes | Updates binary/JSON header copies only |
| `cryptsetup token import` + `token remove` | `[0, 4096)`, `[16384, 20480)` | Slot 0: `32768` / `385024` | Yes | Updates JSON metadata only |
| `cryptsetup repair` (healthy) | None (`[]`) | Slot 0: `32768` / `385024` | Yes | No-op when both headers validate |
| `cryptsetup repair` (corrupted 2nd header at `16384`) | `[16384, 20480)` | Slot 0: `32768` / `385024` | Yes | Reconstructs bad metadata copy from good copy; never touches `[32768, 16777216)` |
| `cryptsetup luksAddKey` (adds slot 1) | `[0, 8192)`, `[16384, 24576)`, `[417792, 802816)` | Slot 0: `32768`, Slot 1: `417792` | Yes | Allocates lowest gap `[417792, 802816)` |
| `cryptsetup luksKillSlot 1` | `[0, 8192)`, `[16384, 24576)`, `[417792, 802816)` | Slot 0: `32768` / `385024` | Yes | Random-wipes `[417792, 802816)` (`CRYPT_WIPE_SPECIAL` $\to$ `CRYPT_WIPE_RANDOM` on non-rotational media) |
| `cryptsetup luksChangeKey` (slot 0, 1st call) | `[0, 8192)`, `[16384, 24576)`, `[32768, 802816)` | **Slot 0: `417792` / `385024`** | Yes | Allocates new area at `417792`, swaps slot IDs, and random-wipes old area `[32768, 417792)` (`setup.c:4549`) |
| `cryptsetup luksChangeKey` (slot 0, 2nd call) | `[0, 8192)`, `[16384, 24576)`, `[32768, 802816)` | **Slot 0: `32768` / `385024`** | Yes | Allocates free gap `[32768, 417792)`, swaps slot IDs, and random-wipes `[417792, 802816)` |
| `cryptsetup luksConvertKey` (slot 0) | `[0, 8192)`, `[16384, 24576)`, `[32768, 802816)` | **Slot 0: `417792` / `385024`** | Yes | Calls `crypt_keyslot_change_by_passphrase`; same area ping-pong and wipe as `luksChangeKey` |
| `cryptsetup luksHeaderBackup` | None (reads `[0, 16777216)`) | Slot 0: `32768` / `385024` | Yes (in `16,777,216` B backup file) | `LUKS2_hdr_backup` copies the entire `16,777,216` B header + keyslots area (`luks2_json_metadata.c:1341`) |
| `cryptsetup luksHeaderRestore` | Restores any modified pages in `[0, 16777216)` | Slot 0: `32768` / `385024` | Yes (restored from backup) | `LUKS2_hdr_restore` writes the full `16,777,216` B backup back to `[0, 16777216)` |
| `cryptsetup reencrypt` | Refused (`rc = 1`) | Unchanged | Yes | `"Reencryption of device with integrity profile is not supported."` |

---

## 3. Active-keyslot chosen AF-stripe construction

### How LUKS2 keyslot encryption and `AF_merge` interact

In `luks2_keyslot_set_key` and `luks2_keyslot_get_key`
(`lib/luks2/luks2_keyslot_luks2.c`):

1. The keyslot's KDF (`argon2id` or `pbkdf2`) derives a 64-byte XTS key
   `derived_key` from the passphrase and 32-byte salt.
2. The volume key $\text{VK}$ of length $L = \text{key\_size}$ bytes (`96`,
   `64`, or `16`) is split into $N = 4000$ stripes $d_0, d_1, \dots, d_{3999}$
   of $L$ bytes each (`AFEKSize = 4000 * L` bytes, which is already an exact
   multiple of 512 for $L \in \{16, 64, 96\}$).
3. In `AF_merge` (`lib/luks1/af.c`), starting from $b_0 = 0^L$:
   $$b_{i+1} = \text{diffuse}_{\text{SHA-256}}(d_i \oplus b_i) \quad (0 \le i \le 3998), \qquad \text{VK} = d_{3999} \oplus b_{3999}$$
4. `luks2_encrypt_to_storage` encrypts the contiguous $4000 L$-byte buffer
   $P = d_0 \parallel \dots \parallel d_{3999}$ in place using `aes-xts-plain64`
   with 512-byte sectors and 64-bit little-endian sector numbers
   $s \in [0, 4000 L / 512)$ starting at `0` for the start of the keyslot area.

Because $3999 L$ is an exact multiple of the 16-byte AES block size for all
three key sizes ($3999 \times 96 = 383{,}904 = 23{,}994 \times 16$;
$3999 \times 64 = 255{,}936 = 15{,}996 \times 16$;
$3999 \times 16 = 63{,}984 = 3{,}999 \times 16$) and `aes-xts-plain64` operates
independently on each 16-byte block within a 512-byte sector, the on-disk
ciphertext bytes $C[0 \dots 3999 L - 1]$ of an active keyslot can be set to
**any chosen $3999 L$-byte ciphertext blob $B$**:

1. Given the keyslot passphrase (hence `derived_key`) and $\text{VK}$, decrypt
   $B \parallel 0^L$ under `aes-xts-plain64` with `derived_key` and take the
   first $3999 L$ bytes as $d_0 \parallel \dots \parallel d_{3998}$.
2. Run the 3999-step `AF_merge` diffusion chain over $d_0, \dots, d_{3998}$ to
   obtain $b_{3999}$, and set $d_{3999} = \text{VK} \oplus b_{3999}$.
3. Encrypt $d_0 \parallel \dots \parallel d_{3998} \parallel d_{3999}$ under
   `aes-xts-plain64` with `derived_key` and write the resulting $4000 L$ bytes
   to `area.offset`.

### Live verification in the disposable guest

`scripts/probe-luks2-header.sh` (`af_stripe_proof`) executed this construction
on active keyslot 0 (`offset = 32768`, `L = 96` B, `4000` stripes = `384,000` B)
of the `/dev/vdb` `aes-xts-random` + `hmac-sha256` volume:

- **Chosen payload size**: `383,904` bytes (`3999 × 96` B), followed by the
  `96`-byte solved stripe $d_{3999}$.
- **On-disk byte identity**: `disk[32768 : 32768 + 383904] == chosen_blob`
  (`true`, 100% match).
- **Stock compatibility**: `cryptsetup open /dev/vdb af-test --key-file ...`
  unlocked keyslot 0 cleanly and verified the primary volume's plaintext.
- **Indistinguishability**: On-disk keyslot entropy was `7.999532` bits/byte;
  decrypted AF-stripe entropy (visible to a coerced decoy-key holder who knows
  the LUKS passphrase for slot 0) was `7.999496` bits/byte, because AES-XTS
  decryption of uniform ciphertext $B$ under an independent key `derived_key`
  is also uniform pseudorandom.

### Why the unallocated keyslot tail is strictly preferable to active AF stripes

| Property | Active keyslot AF stripes (`0..3998`) | Unallocated keyslot tail (`[14 MiB, 16 MiB)`) |
| --- | --- | --- |
| Usable capacity (96 B / 64 B / 16 B VK) | `383,904` B / `255,936` B / `63,984` B per active slot | Up to `4,423,680` B (`4.22` MiB) on any profile |
| Fits unmodified static `pivsetup` + `dm-piv.ko` (`679,740` B `.tar.xz`)? | **No** (needs 2 active slots on 96 B VK, 3 on 64 B VK, or a separate custom binary) | **Yes** (~33% of a 2 MiB slice, ~15% of the 4.22 MiB unreachable tail) |
| Survives `luksChangeKey` / `luksConvertKey` on slot 0? | **No** — `cryptsetup` swaps slot 0 to `417,792` and random-wipes `[32768, 417792)` | **Yes** — `LUKS2_find_area_gap` never reaches above `12.35` MiB |
| Survives `luksAddKey` / `luksKillSlot`? | Survives on slot 0, destroyed if that slot is killed | **Yes** across all 32 possible keyslots |
| Preserved by `luksHeaderBackup` / `luksHeaderRestore`? | Yes | **Yes** (`LUKS2_hdr_backup` copies all 16 MiB) |
| Requires LUKS passphrase / VK when updating `dm-piv.ko` on kernel upgrade? | **Yes** (must recompute $d_{3999}$ for the new payload) | **No** (only needs the stash key) |
| Single-snapshot byte distribution vs fresh `luksFormat` | Uniform random (`~7.9995` bits/B) | Uniform random (`~7.9999` bits/B; matches `CRYPT_WIPE_RANDOM`) |

---

## 4. Payload sizes

Measured in the disposable guest (`6.12.113+deb13-amd64`, gcc 14.2.0, static
release `pivsetup`):

| Artifact | Raw bytes | `gzip -9` bytes | `xz -9e` bytes | Notes |
| --- | ---: | ---: | ---: | --- |
| `dm-piv.ko` (unstripped build output) | `1,422,968` | `406,042` | `309,464` | Includes DWARF debug and BTF sections |
| `dm-piv.ko` (`strip --strip-debug`) | `182,056` | `53,497` | `41,480` | Removes debug sections |
| `dm-piv.ko` (`strip --strip-unneeded`) | `174,688` | `51,197` | **`39,924`** | Verified to load cleanly with `insmod` and unload with `rmmod` in guest |
| `pivsetup` (release static binary) | `1,900,552` | `847,948` | `691,044` | `rust/target/x86_64-unknown-linux-gnu/release/pivsetup` |
| `pivsetup` (`strip --strip-all`) | `1,693,048` | `786,012` | **`640,692`** | Static musl/glibc-independent Rust binary |
| **Combined bundle** (`pivsetup` + `dm-piv.ko` + `luks.key` + `hidden.key` + `unlock.sh`) | `1,873,920` (`.tar`) | — | **`679,740`** (`.tar.xz`) | `679,936` B (`664` KiB) padded to 512 B sectors |

The complete unmodified userland and kernel payload (`664` KiB compressed) fits
more than **3×** inside a 2 MiB slice at `[14 MiB, 16 MiB)` (`[14680064, 16777216)`),
leaving the lower 14 MiB of the LUKS2 header untouched for up to 35 normal
keyslots.

---

## 5. Candidate boot and unlock procedures

### What a stock Debian 13 initramfs provides

When a system uses stock LUKS for its decoy root or swap (`cryptsetup-initramfs`
installed, which is expected on any encrypted Linux installation), the stock
initramfs already includes:

- `/sbin/cryptsetup` and `/sbin/dmsetup`
- `/bin/busybox` (providing `sh`, `dd`, `tar`, `xz` / `unxz`, `mount`, `umount`, `mkdir`, `rm`, `insmod`, `modprobe`)
- Kernel modules `dm-mod`, `dm-crypt`, `dm-integrity`, `xts`, `aes`, `hmac`, `sha256`, `authenc`, `chacha20`

No custom hook, `/etc/pivtab`, or extra KDF binary exists in `/boot/initrd.img-*`
if `cryptsetup open --type plain` is used directly.

### Candidate A: Unallocated keyslot tail `[14 MiB, 16 MiB)` via `cryptsetup --type plain`

#### One-time embedding (or after a kernel upgrade)

1. Build `pivsetup` (`strip --strip-all`) and `dm-piv.ko` (`strip --strip-unneeded`,
   plus `sign-file` if Secure Boot is enabled) for the target kernel, and place
   them with an `unlock.sh` script (and optional key files) into a `.tar.xz`
   archive `bundle.tar.xz` (~664 KiB).
2. Open the 2 MiB slice `[14 MiB, 16 MiB)` (512-byte sectors `28672`..`32768`,
   length `4096` sectors) with `cryptsetup --type plain` using a high-entropy
   stash passphrase (or a 64-byte key file; note that in `cryptsetup` `plain`
   mode, stdin passphrases pass through `--hash sha512`, whereas `--key-file`
   reads 64 raw key bytes directly without hashing):
   ```sh
   cryptsetup open --type plain --offset 28672 --size 4096 \
     --cipher aes-xts-plain64 --key-size 512 --hash sha512 \
     /dev/disk/by-partuuid/XXXX piv-stash
   dd if=bundle.tar.xz of=/dev/mapper/piv-stash bs=4096 conv=fsync
   cryptsetup close piv-stash
   ```
   Because `[14 MiB, 16 MiB)` was already filled with CSPRNG bytes by
   `luksFormat`, the sectors beyond `bundle.tar.xz` remain uniform random bytes
   on disk (`7.999909` bits/byte, $\chi^2 = 265.26$ measured in the guest).
   Alternatively, formatting `/dev/mapper/piv-stash` with `mkfs.ext4 -O ^has_journal -b 1024 -m 0`
   and copying `pivsetup.xz`, `dm-piv.ko.xz`, and `unlock.sh` into it uses 36%
   of the 2 MiB slice and produces `7.999906` bits/byte ($\chi^2 = 274.03$) on
   disk (`aes-xts-plain64` produces distinct sector/block tweaks across zeroed
   filesystem blocks).

#### Manual unlock at boot (from stock initramfs shell)

1. Boot with `break=premount` on the kernel command line (edited interactively
   in GRUB/systemd-boot for that boot only, never persisted in `/boot/grub/grub.cfg`).
2. At the `(initramfs)` shell, open the `[14 MiB, 16 MiB)` slice read-only,
   extract the bundle into RAM (`/run/piv-stash`), and **immediately close
   `piv-stash` before running `pivsetup open-blocks`** (because `pivsetup`
   refuses to open a device that has active device-mapper holders):
   ```sh
   mkdir -p /run/piv-stash
   cryptsetup open --readonly --type plain --offset 28672 --size 4096 \
     --cipher aes-xts-plain64 --key-size 512 --hash sha512 \
     /dev/disk/by-partuuid/XXXX piv-stash
   xz --single-stream -dc /dev/mapper/piv-stash | tar -xf - -C /run/piv-stash
   cryptsetup close piv-stash
   ```
   (If `busybox xz` in the target initramfs lacks `--single-stream`, storing the
   files inside the 2 MiB `ext4` image on `/dev/mapper/piv-stash` and mounting it
   read-only avoids any trailing-garbage framing issue.)
3. Run `/run/piv-stash/unlock.sh /dev/disk/by-partuuid/XXXX` (which runs
   `insmod /run/piv-stash/dm-piv.ko` and `/run/piv-stash/pivsetup open-blocks ...`),
   then wipe `/run/piv-stash` from tmpfs before exiting the initramfs shell to
   resume boot:
   ```sh
   /run/piv-stash/unlock.sh /dev/disk/by-partuuid/XXXX
   rm -rf /run/piv-stash
   exit
   ```

#### Optional Argon2id KDF for the stash key

Because `cryptsetup open --type plain --hash sha512` hashes a typed passphrase
with a single un-salted SHA-512 pass, a weak passphrase can be brute-forced
offline by an attacker who guesses that `[14 MiB, 16 MiB)` holds a `dm-plain`
container and tests candidate decryptions for an `xz` header (`\xfd7zXZ\x00`) or
`ext4` superblock magic (`0xef53` at byte `1080`).

To get Argon2id protection for the stash without storing a visible salt:
- The LUKS2 primary binary header already contains a 32-byte random salt at
  bytes `[236, 268)` (`hdr_disk.salt`, generated by `luksFormat`).
- An `argon2` KDF invocation can read those 32 bytes (`dd if=/dev/... bs=1 skip=236 count=32`)
  as its salt and derive a 64-byte raw key piped to `cryptsetup open --type plain --key-file -`.
- **Catch**: a stock Debian initramfs does **not** ship `/usr/bin/argon2`. Adding
  `argon2` (or an initramfs hook that copies it) into `/boot/initrd.img-*`
  creates a visible artifact in `/boot`. Thus, on a stock initramfs without
  removable media, the user must use a high-entropy passphrase (e.g. 6+ random
  Diceware words, $\ge 77$ bits of entropy) with `--hash sha512`.

### Candidate B: Removable media (USB boot / unlock stick)

Instead of embedding binaries inside the LUKS2 header, keep `pivsetup`,
`dm-piv.ko` (for the installed kernel versions), and optional key files on an
external encrypted USB drive (or a live/initramfs USB stick):

1. The internal disk contains **only** the stock LUKS2 + `dm-integrity` volume
   and an ordinary decoy installation (or no bootloader at all if booting from
   USB). Neither `/boot`, the initramfs, nor the unallocated LUKS2 keyslots area
   on the internal disk is modified after `luksFormat`.
2. When opening the hidden volume (either at `break=premount` in the stock
   initramfs or after booting a live/decoy environment), unlock the USB stick,
   load `dm-piv.ko` and run `pivsetup open-blocks` from RAM, then unmount and
   unplug the USB stick.

---

## 6. Operational considerations and residual tells

1. **Forgetting to add `break=premount` at boot**:
   On a system where the LUKS2 volume is listed in `/etc/crypttab` (e.g., as the
   root filesystem), a normal un-intercepted boot runs `scripts/local-top/cryptroot`
   and halts synchronously at the `Please unlock disk ...:` passphrase prompt.
   **No writes occur to the LUKS2 header or data area before or during that
   prompt** (`cryptsetup` only opens the device `O_RDONLY` to parse the header).
   If the user sees the stock prompt and realizes they forgot `break=premount`,
   rebooting (`Ctrl-Alt-Del`) or powering off at the prompt leaves the hidden
   volume completely untouched. Damage only occurs if the user enters the LUKS
   passphrase into the stock prompt, which opens the volume through stock
   `dm-crypt` and mounts the decoy filesystem read-write.
   (`break=premount` runs in `initramfs-tools` *before* `scripts/local-top/cryptroot`;
   if `unlock.sh` creates `/dev/mapper/<cryptroot-target>` via `dm-piv` before
   exiting the `break=premount` shell, `cryptroot` sees the target already
   active and skips `cryptsetup open`.)
2. **Initial build and kernel upgrades (`vermagic` lockstep)**:
   The kernel loads `dm-piv.ko` only if its `vermagic` and `Module.symvers` CRCs
   match `uname -r` exactly.
   - **Initial setup**: Perform the initial `dm-piv.ko` build, `pivsetup`
     initialization, and `[14 MiB, 16 MiB)` stash write from an ephemeral live
     environment in RAM (such as Tails or Debian Live) so no `dm-piv` sources or
     build artifacts ever touch the decoy filesystem.
   - **Kernel upgrades**: Keep the `dm-piv` module sources, signing key (if
     any), and stash-update script **inside the hidden volume**, and only
     rebuild `dm-piv.ko` while `dm-piv.ko` is already loaded and the hidden
     volume is mounted. When the decoy OS installs a new `linux-image-X.Y.Z`
     and `linux-headers-X.Y.Z` (ordinary packages on a Linux workstation),
     build `dm-piv.ko` against `/lib/modules/X.Y.Z/build` from the hidden
     mount (`M=/mnt/hidden/dm-piv/kernel`) and re-embed the stash before
     rebooting into the new kernel. Because each stripped `.ko.xz` is only
     `~40 KiB`, the 2 MiB stash can carry `dm-piv-$(uname -r).ko` for both the
     current and new kernels simultaneously so the previous kernel remains
     bootable.
3. **UEFI Secure Boot and MOK enrollment**:
   A stock Debian/Ubuntu/Fedora Secure Boot chain does **not** use a user-enrolled
   MOK in UEFI NVRAM: the UEFI firmware's factory Microsoft 3rd-Party CA verifies
   `shimx64.efi`, `shim` embeds the distro's CA certificate inside its own binary
   to verify `grubx64.efi` and `vmlinuz`, and `vmlinuz` embeds the distro kernel
   key to verify in-tree modules. Thus, on a stock install with no out-of-tree
   (DKMS) modules, `mokutil --list-enrolled` is empty.
   - Enrolling a MOK dedicated to `dm-piv` (or having a MOK enrolled when the
     decoy OS has no out-of-tree modules) is visible via `mokutil --list-enrolled`.
   - To avoid that tell, either disable Secure Boot, or (if the decoy OS
     already installs an ordinary DKMS package such as `nvidia-driver` or
     `v4l2loopback-dkms`) sign `dm-piv.ko` with that existing
     `/var/lib/dkms/mok.key` so `MokList` contains only the standard DKMS key
     expected for the decoy OS.

---

## 7. Recommendation

1. **Recommend removable media (Candidate B) first** in user-facing
   documentation for high-deniability deployments: keeping `pivsetup`,
   `dm-piv.ko`, and keys off the internal disk avoids modifying the LUKS2
   header after `luksFormat`, avoids any KDF/initramfs compromise, and makes
   kernel-module updates trivial on a separate machine.
2. **If a self-contained single-disk stash is desired, use Candidate A
   (unallocated keyslot tail `[14 MiB, 16 MiB)` with `cryptsetup --type plain`),
   not active-keyslot AF stripes**:
   - The upper 4.22 MiB of a default 16 MiB LUKS2 header (`[12,353,536, 16,777,216)`)
     is filled with CSPRNG bytes by `luksFormat`, is unreachable by all 32
     stock LUKS2 keyslots (`luksAddKey`, `luksChangeKey`, `luksConvertKey`), is
     automatically preserved by `luksHeaderBackup`/`luksHeaderRestore`, fits the
     unmodified static `pivsetup` + stripped `dm-piv.ko` (`664` KiB `.tar.xz`)
     with >3× headroom in a 2 MiB slice at `[14 MiB, 16 MiB)`, and can be
     unlocked using only binaries already in a stock `cryptsetup-initramfs`
     image (`cryptsetup`, `xz`, `tar`, `insmod`).
   - Do **not** implement the active-keyslot AF-stripe trick: while proven
     feasible (`383,904` B in a 96-byte-key keyslot), it is too small for the
     static `pivsetup` binary without spanning multiple visible keyslots or
     maintaining a second minimal C unlock binary, and it is wiped whenever
     `luksChangeKey` or `luksConvertKey` is run on that keyslot.
   - No code changes to `dm-piv` or `pivsetup` are required to use Candidate A
     today (it uses stock `cryptsetup --type plain`, `dd`, `tar`, and `xz`).
     Do not add wrapper subcommands to `pivsetup` unless requested by the user.
