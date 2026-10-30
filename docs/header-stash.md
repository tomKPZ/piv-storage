# Storing tooling and keys inside the LUKS2 header

Design note and disposable-guest measurements (`scripts/probe-luks2-header.sh`,
run `artifacts/header-stash-probe-003` on Debian 13 kernel `6.12.113+deb13-amd64`
with `cryptsetup` `2:2.7.5-2`). **Reference note only: header-stash helpers,
boot hooks, and full-system hiding are out of scope for `piv-storage` (user
decision 2026-10-30), which provides only the block-layer module `dm-piv.ko`,
`pivsetup`, and read-only diagnostics.**

## Problem statement

Format v5 keeps all hidden-volume data and metadata inside the 16-byte random
IVs of a stock LUKS2 + `dm-integrity` carrier. However, installing
`/usr/local/sbin/pivsetup`, `/lib/modules/.../dm-piv.ko`, or key files on a
persistent host filesystem (see [packaging/README.md](../packaging/README.md))
reveals that the machine has hidden-volume software installed—and once a
deniable-storage repository is public, the presence of its tooling shows
capability even when absence of a hidden volume cannot be proven.

For users who prioritize deniability over convenience, this note examines:
1. Where `dm-piv.ko`, `pivsetup`, an unlock script, and optional key files can
   live off the decoy filesystem—either on removable RAM-booted live media or
   inside the LUKS2 header itself as ciphertext indistinguishable from bytes
   that stock `cryptsetup` already writes.
2. Why `piv-storage` carriers should be secondary or external data volumes
   opened from a clean RAM-only OS rather than root/boot filesystems.

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

- **96-byte volume key** (`385,024` B/slot, sector `24,128` max): $32{,}768 + 32 \times 385{,}024 = 12{,}353{,}536$ B (`11.78` MiB), leaving **`4,423,680` B (`4.22` MiB)** at `[12353536, 16777216)` permanently unreachable.
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
| `cryptsetup luksConvertKey` (slot 0) | `[0, 8192)`, `[16384, 802816)` | **Slot 0: `417792` / `385024`** | Yes | Calls `crypt_keyslot_change_by_passphrase`; same area ping-pong and wipe as `luksChangeKey` |
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

| Property | Active keyslot AF stripes (`0..3998`) | Unallocated keyslot tail (`[12.35 MiB, 16 MiB)`) |
| --- | --- | --- |
| Usable capacity (96 B / 64 B / 16 B VK) | `383,904` B / `255,936` B / `63,984` B per active slot | Up to `4,423,680` B (`4.22` MiB) on any profile |
| Fits unmodified static `pivsetup` + `dm-piv.ko` (`679,740` B `.tar.xz`)? | **No** (needs 2 active slots on 96 B VK, 3 on 64 B VK, or a separate custom binary) | **Yes** (~15% of the 4.22 MiB unreachable tail) |
| Survives `luksChangeKey` / `luksConvertKey` on slot 0? | **No** — `cryptsetup` swaps slot 0 to `417,792` and random-wipes `[32768, 417792)` | **Yes** — `LUKS2_find_area_gap` never reaches above `11.78` MiB (sector `24,128`) |
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
| `pivsetup` (`strip --strip-all`) | `1,693,048` | `786,012` | **`640,692`** | Static runtime-independent Rust binary |
| **Combined bundle** (`pivsetup` + `dm-piv.ko` + `luks.key` + `hidden.key` + `unlock.sh`) | `1,873,920` (`.tar`) | — | **`679,740`** (`.tar.xz`) | `679,936` B (`664` KiB) padded to 512 B sectors |

---

## 5. Whole-OS boundary vs root-filesystem carriers

A core lesson from whole-OS deniable systems is **strict OS-boundary
separation**: hidden data must never be mounted inside a persistent decoy OS,
because decoy `journald`, `dmesg`, file indexers (`plocate`/`updatedb`), desktop
`recently-used.xbel` and thumbnail caches, shell history, and swap inevitably
record traces of hidden files onto the decoy disk.

Using `piv-storage` on a **root/boot filesystem** creates a structural catch-22:

1. **Routine decoy boots require the hidden key**: `dm-piv` has no decoy-only
   mode, because preserving a 687-IV hidden record across decoy writes requires
   the hidden key. Putting a decoy root filesystem on `piv-storage` means every
   routine decoy boot would have to stop at `break=premount`, load `dm-piv.ko`
   (leaving `dm_piv` visible in `/proc/modules` and `*-hidden` visible to
   `udev`/`lsblk`), and prompt for *both* decoy and hidden credentials.
2. **Coercion vs contamination**: Booting a root decoy OS normally under
   coercion (through stock `dm-crypt`) mounts the decoy read-write and corrupts
   whichever hidden records decoy boot logs and journals overwrite. Conversely,
   mounting `*-hidden` inside the running decoy OS leaks traces into decoy logs
   and caches, while booting a full hidden OS *inside* `*-hidden` runs into
   `piv-storage`'s 0.58%–1.16% capacity ratio and ~86×–172× write amplification
   (687 sectors rewritten per 4 KiB hidden block).

By contrast, `piv-storage` fits **secondary data partitions and external
encrypted drives unlocked from a RAM-only live environment** (such as Tails or
Debian Live):

- Every sector on the carrier has a valid `dm-integrity` tag under the decoy
  key, and hidden ciphertext lives inside IVs that stock Linux defines as fresh
  CSPRNG output—no unauthenticated "pre-randomized free space" alibi and no
  copy-on-write pool metadata residue.
- Neither decoy OS logs nor host kernel upgrades touch the volume when hidden
  data is accessed only from a clean RAM-only live OS.

---

## 6. Manual unlock recipes

### Candidate A: Removable media + RAM-only live OS (preferred)

Keep `pivsetup`, `dm-piv.ko` (built for the pinned live ISO kernel), and
optional key files on an encrypted USB drive, or build/load them inside a
RAM-only live session:

1. The carrier disk contains **only** the stock LUKS2 + `dm-integrity` volume;
   even the unallocated LUKS2 keyslots tail remains untouched after `luksFormat`.
2. Boot a RAM-only live environment (with `init_on_free=1` on the kernel command
   line so freed RAM pages are zeroed), load `dm-piv.ko`, run `pivsetup
   open-blocks`, do work on the hidden view, unmount and `close-blocks`, and
   power off.

### Candidate B: Single-disk stash in the unreachable LUKS2 keyslot tail

When a self-contained single drive is wanted (for example, an external drive
carrying `pivsetup` + `dm-piv.ko` built against a pinned Debian Live or Tails
kernel, so any stock copy of that live ISO can open it from memory):

#### Memorable round offset

Because anyone who knows LUKS2 geometry knows the unreachable `[11.78 MiB, 16 MiB)`
tail (512-byte sectors `24,128..32,768`), the stash offset is **not a secret**.
Writing the offset down is a physical tell, so pick a round sector offset easy
to type from memory, such as **`--offset 30000 --size 2000`** (`[14.65 MiB, 15.63 MiB)`,
`1,024,000` bytes — ~1.5× the `664 KiB` bundle; the guest probe measured
`--offset 28672 --size 4096`, `[14 MiB, 16 MiB)`, with `7.999909` bits/byte
entropy and $\chi^2 = 265.26$).

#### Argon2id key derivation with stock OpenSSL $\ge$ 3.2 (no extra binaries)

Stock live ISOs (Debian Live 13, Tails 7, Fedora, Ubuntu 25.04+) ship OpenSSL
$\ge$ 3.2, whose built-in `kdf ... ARGON2ID` derives a 64-byte raw XTS key
without installing `/usr/bin/argon2`. Using `cryptsetup luksUUID` (or the
32-byte header salt at bytes `[236, 268)`) supplies a per-volume random salt
with nothing extra to store or memorize, and `iter:1, memcost:1048576, lanes:4`
maximizes memory-hardness (1 GiB) per guess:

> [!IMPORTANT]
> In `cryptsetup --type plain`, `--key-file=-` (stdin) treats the input as a
> passphrase and **hashes it** unless `--hash plain` is also passed, whereas
> `--key-file=/proc/self/fd/N` (`<(...)` process substitution in `bash`) or a
> file path in `/run` uses the raw 64 bytes directly without hashing.

Embedding `bundle.tar.xz` from a throwaway RAM-only environment:

```sh
DEV=/dev/disk/by-partuuid/XXXX
read -rs P; echo
cryptsetup open --type plain --offset 30000 --size 2000 \
  --cipher aes-xts-plain64 --key-size 512 \
  --key-file <(openssl kdf -binary -keylen 64 \
    -kdfopt "pass:$P" -kdfopt "salt:$(cryptsetup luksUUID "$DEV")" \
    -kdfopt iter:1 -kdfopt memcost:1048576 -kdfopt lanes:4 ARGON2ID) \
  "$DEV" piv-stash
unset P
dd if=bundle.tar.xz of=/dev/mapper/piv-stash bs=4096 conv=fsync
cryptsetup close piv-stash
```

Unlocking from a stock live ISO (always open `piv-stash` `--readonly` and close
it before `pivsetup open-blocks`, which refuses devices with active DM holders):

```sh
DEV=/dev/disk/by-partuuid/XXXX
mkdir -p /run/piv-stash && chmod 700 /run/piv-stash
read -rs P; echo
cryptsetup open --readonly --type plain --offset 30000 --size 2000 \
  --cipher aes-xts-plain64 --key-size 512 \
  --key-file <(openssl kdf -binary -keylen 64 \
    -kdfopt "pass:$P" -kdfopt "salt:$(cryptsetup luksUUID "$DEV")" \
    -kdfopt iter:1 -kdfopt memcost:1048576 -kdfopt lanes:4 ARGON2ID) \
  "$DEV" piv-stash
unset P
xz --single-stream -dc /dev/mapper/piv-stash | tar -xf - -C /run/piv-stash
cryptsetup close piv-stash

/run/piv-stash/unlock.sh "$DEV"
shred -u /run/piv-stash/* 2>/dev/null || true
rm -rf /run/piv-stash
```

### Operational notes and edge cases

1. **Read-only block mappings and dirty-log replay**:
   Mounting `ext4` or `btrfs` with `-o ro` on a writable block device still
   replays a dirty journal/log and writes to disk (and `ext4` updates
   `s_last_mounted` when writable). If a filesystem image is used inside
   `piv-stash` instead of `.tar.xz`, format it without a journal (`mkfs.ext4 -O
   ^has_journal -b 1024 -m 0`, measured at `7.999906` bits/byte, $\chi^2 = 274.03$)
   and always open `piv-stash` with `cryptsetup open --readonly` (`mount -o ro,noload`).
2. **Stock `initramfs` (`break=premount`) limitations**:
   - A stock Debian `cryptsetup-initramfs` image includes `/sbin/cryptsetup` and
     `busybox` (`dd`, `tar`, `xz`, `insmod`), **not** `/usr/bin/openssl` or
     `/usr/bin/argon2`; unlocking inside an unmodified `break=premount` shell
     therefore falls back to `--hash sha512` and requires a high-entropy
     passphrase (e.g. 6+ random Diceware words, $\ge 77$ bits).
   - If a system has the LUKS2 volume in `/etc/crypttab` and boots without
     `break=premount`, `scripts/local-top/cryptroot` halts synchronously at the
     passphrase prompt after opening the header `O_RDONLY` (**no writes occur
     before or during that prompt**; rebooting at the prompt leaves hidden
     records untouched). Entering the passphrase into the stock prompt, however,
     mounts the decoy read-write through stock `dm-crypt` and destroys hidden
     records—one of the reasons root-filesystem carriers are discouraged (§5).
3. **Initial build, kernel `vermagic` lockstep, and UEFI NVRAM**:
   - Perform initial setup and module builds only from an ephemeral RAM-only
     environment so no `dm-piv` sources, compiler artifacts, or mounted UUID
     logs ever touch a persistent decoy OS. Check `efibootmgr` if UEFI firmware
     records a `Boot####` NVRAM entry for a boot USB.
   - `dm-piv.ko` loads only when its `vermagic` and `Module.symvers` CRCs match
     `uname -r`. Pinning to a known live ISO kernel avoids host-kernel churn;
     if rebuilding for a newer kernel, keep the module sources inside the
     hidden volume and rebuild only while `dm-piv` is active in a clean
     environment. Each stripped `.ko.xz` is `~40 KiB`, so multiple kernel builds
     fit easily in a 1–2 MiB stash.
4. **UEFI Secure Boot and MOK enrollment**:
   Stock Debian/Ubuntu/Fedora Secure Boot chains verify `shimx64.efi` via the
   firmware's Microsoft 3rd-Party CA and verify `grubx64.efi`, `vmlinuz`, and
   in-tree modules via distro keys embedded in `shim`/`vmlinuz`, leaving
   `mokutil --list-enrolled` empty unless out-of-tree DKMS modules are
   installed. Enrolling a custom MOK solely for `dm-piv` is visible in UEFI
   NVRAM; boot the unlock environment with Secure Boot off or reuse an existing
   host DKMS key only when the host already runs ordinary DKMS packages.

---

## 7. Scope decision

1. **Out of scope for `piv-storage` code**: `piv-storage` implements only the
   paired block-layer views (`dm-piv.ko`), `pivsetup`, and read-only
   diagnostics. Boot/initramfs hooks, full-system hiding, and `pivsetup`
   header-stash wrappers are intentionally omitted: Candidate B already works
   with stock `cryptsetup`, `openssl`, `tar`, and `xz`, while custom wrapper
   subcommands or boot hooks add maintenance surface and recognizable tool
   artifacts.
2. **Recommended deployment pattern**: Keep the LUKS2 + `dm-integrity` carrier
   on a secondary partition or external drive, open it from a clean RAM-only
   live environment (`init_on_free=1`), and keep `pivsetup` + `dm-piv.ko` either
   on removable media (Candidate A) or in the unreachable LUKS2 keyslot tail
   `--offset 30000 --size 2000` (Candidate B), never in active keyslot AF
   stripes.
