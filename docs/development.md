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
`--second-blank-mib N` (16–16384) adds a sparse /dev/vdc of any size
(migration, arbitrary-device and large-volume tests), `--power-cut-script`
reboots the same disks after a simulated power cut (also used for the deploy
suite's boot test), and `--code` exports the package source read-only. vm.py
freezes scripts/guest-common.sh (harness guards, package setup, module
build/load, provenance) into every run; reuse it rather than duplicating
guards.

pivsetup itself no longer confines activation to this guest (the activation
guards were removed 2026-10-22; [packaging/README.md](../packaging/README.md)
covers real installations). The harness guards in guest-common.sh and
guest-control.sh (pinned guest kernels, a 9p work share, a 128/512 MiB
/dev/vdb) remain: they protect the host and keep agent testing confined to
disposable guests and synthetic disks.

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
- `--suites routine` (default): faults, profile (including the decoy
  write-batching counts of kernel/guest-batch-test.py, formerly the `batch`
  suite), cancel, lifecycle, stress (concurrent I/O oracles and a fault under
  load), early, power, powerab (the power cut with `--ab`), v5. `early` (Python-free RAM-root initramfs from the
  native run) overlaps `deploy` (stock initramfs-tools boot) in proving
  initramfs activation; it stays routine because it is cheap and needs no
  package installation. `--suites all` adds controls, migrate (second 512 MiB disk),
  devices (activation on a 300 MiB second disk, a loop device, a dm-linear
  offset and a GPT partition, plus the remaining safety refusals and the
  absence of a luksFormat journal-size option; the loop and
  partition images are host-verified), deploy (packaging/install.sh: DKMS
  build and signature check, installed activation, initramfs-tools hook
  validation and a reboot whose initramfs opens the views),
  fuzz (seeded control-ioctl fuzzing with `PIV_FUZZ_STEPS`/`PIV_FUZZ_SEED`,
  plus dm table/constructor fuzzing; best on the sanitizer image) and
  ext4power (ext4 on a single-slot and an A/B hidden view, 512-byte sectors,
  two 2 GiB volumes on a 4 GiB second disk, across a power cut;
  [native-faults.md](native-faults.md#ext4-on-the-hidden-view-ext4power-suite)).
  Two suites are never in a set and must be requested explicitly: `bench`
  (the [configuration.md](configuration.md) measurements, on the pristine
  fixture; run it with `--jobs 1`) and `large` (a fresh 512 MiB volume of the
  profile, or an N MiB second disk with `PIV_LARGE_MIB=N` in the host
  environment; [large-volumes.md](large-volumes.md#large-geometry-guest-test)).
  An explicit comma list also works; `--suites-for PROFILE=LIST`
  narrows per profile.
- `--reuse-native PREFIX` skips the native step and starts from a previous
  passed, host-verified native run with the same module input and base image.
- `--base-image` selects a derived guest image (sanitizer or port, below);
  `--memory-mib`, `--jobs`, `--fresh` (no provisioned image) and `--accel`
  (default kvm when usable, else tcg). Guest RAM defaults to 1 GiB; the v5
  and bench suites raise it to 3 and 3.5 GiB (Argon2id tiers 3 and 4 need 1
  and 2 GiB); `--memory-mib` can only raise these floors.
  `--smp N` sets every guest's vCPUs (vm.py default 2; the early VM keeps
  its own); the Argon2id lanes run on four threads, so KDF timings depend on
  it (bench was measured at 2 and 4).
- The v5 suite also compiles `kernel/piv-rs.inc` unchanged into the
  freestanding harness `kernel/piv-rs-test.c` (guest gcc, loaded with ctypes;
  the guest has no libc headers) and compares RS parity and corrections with
  `pivstore/rs.py`.

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

### `profile` suite

scripts/guest-profile.sh loads the matched module and runs
kernel/guest-profile-test.py on the closed native fixture, with stock dm-crypt
loaded and an unrelated stock volume mounted. It pins the read and write paths
of [native-blocks.md](native-blocks.md#bounded-authenticated-reads).

**Timings (uninstrumented).** Three stock opens, then three native opens
without initialization; pivsetup's `PIVSETUP_TEST_GATE` hook reports the SETUP
ioctl time separately. Native opening includes cryptsetup/keyslot work, private
target conversion, the keyslot-area scan, directory load and view creation;
`--verify` would instead authenticate every primary sector. Close is not timed.
Stock primary plaintext is authenticated, hashed and kept in guest RAM as the
read oracle. Sequential O_DIRECT reads use 512/4096/16384/65536-byte
application requests (at least the stock logical block size), three samples
each, over 1 MiB of primary or 64 KiB of hidden data, plus 32 reproducible
random reads per role. All bytes are compared; timings include Python loops,
system calls and comparisons. Reading must spend zero primary encryptions.

**Call counts (separate pass).** Entry kprobes on module-qualified symbols
(`piv_read_range`, the private `piv_aead` helper, `pn_write`,
`piv_checkpoint`, `piv_batch_read`, `piv_batch_submit`) resolve the unique
non-cold compiler specialization in `[dm_piv]`, never the stock copy.
`tracing_on=0` keeps no event data; only `kprobe_profile` hit counters are
used, and any missed hit fails. The SETUP ioctl is bracketed by pivsetup's
gate/hold hooks, reads are counted after udev settles, and assertions use exact
per-operation deltas. Each range read is one batch submission:

| Operation | range reads | primary authentications | other |
| --- | ---: | ---: | --- |
| SETUP (keyslot area, directory, checkpoint) | 3 | 112 + 1374 + 1 | 1 checkpoint (one-sector read and rewrite: 2 submissions), 5 submissions, 0 `pn_write` |
| 512-byte decoy read | 1 | 1 | 1 submission |
| 16 KiB decoy read | 1 | 16384 / S | 1 submission |
| 128 KiB decoy read | 1 | 131072 / S | 1 submission |
| 4 KiB hidden read | 1 | 687 | 1 submission |
| 16 KiB hidden read | 4 | 2748 | 4 submissions |
| 16 KiB and 128 KiB decoy write (same bytes) | 0 | 2n (n checks + n encryptions, n = bytes / S) | 1 pn_write, 1 batch read, 2 submissions (read, write) |
| 4 KiB hidden write (same bytes) | 0 | 2m (m checks + m encryptions; m = 687 at 4096-byte sectors, 696 at 512: block 0's record shaped to 4 KiB edges) | 1 pn_write, 1 batch read, 2 submissions |

S is the primary sector size. The write rows pin the
[write path](native-blocks.md#write-path): one authenticated read of every
touched sector, one encryption each, no per-sector loads, re-reads or
self-decryption (the previous path made about five AEAD calls per sector); the
encryption counter must rise by exactly the sector count. The write descriptor
stays open across the counted window so udev's re-probe after closing a written
device is not counted. Probe counts establish calls, not time spent. No probe
is enabled during timings.

Afterwards both complete views are checked, the stack closes, the module
unloads, stock Linux authenticates and hashes the full primary, and suite.py
verifies `profile-final.img` on the host. `profile-results.json` keeps all
timing samples and counts; `profile-kprobe-counts.txt` the raw counters.

**Write shaping.** Before closing, hidden writes of blocks 0, 1, 2, the middle
and last block and a two-block write (3, 4) run one at a time while
`block:block_bio_queue` events are traced on the owner's lower dm-integrity
device; `kernel/shape_trace.py` requires the union of their write bios to be
exactly the record's shaped extent (`pivstore.records.shaped_extent`), on
4 KiB edges (`shaped_hidden_writes` in the results). The v5 suite does the
same for an A/B write and a keyslot add (both replicas and the directory).

Limits: these are warm-cache diagnostics under QEMU: O_DIRECT bypasses only the
public page cache, and the stock pass plus repeated opens warm lower, host and
device caches. Medians of three samples are not confidence intervals. There is
no claim about cold start, physical media, production throughput or a
controlled cipher comparison (profiles differ in cipher, tag size and
geometry). Current results live in each run's `profile-results.json`; the
sequential `bench` suite's user-facing write/read/activation numbers are in
[configuration.md](configuration.md).

```sh
python3 scripts/suite.py --prefix artifacts/profile-next --profile aegis-4096 \
  --profile aegis-512 --scaffold artifacts/stage-next/scaffold.tar --suites profile
```

Run timing comparisons sequentially (`--jobs 1`) to avoid competing VMs.
Original AEGIS-128 host verification needs the optional reference library
([below](#original-aegis-128-diagnostics)); native activation does not.

## Guest kernels

- Default: pinned Debian 6.12.113 (module built against the guest headers).
- Sanitizer: KASAN/UBSAN/lockdep/kmemleak kernel from
  scripts/build_debug_kernel.py; see [Sanitizer kernel](#sanitizer-kernel).
- Port: Debian trixie-backports 7.2.9 image from scripts/build_port_image.py;
  see [Newer-kernel port](#newer-kernel-port).

The harness guard (guest-common.sh) accepts the derived images only with
their marker files. Everything runs inside disposable guests; nothing touches
the host kernel.

### Sanitizer kernel

The guest suites can run on a debug build (KASAN, UBSAN, lockdep, kmemleak)
of the pinned kernel, inside disposable guests only (user-approved
2026-10-21). The current image is
`downloads/debug-kernel-6812e5047fb54014.qcow2`.

```sh
python3 scripts/build_debug_kernel.py --prefix artifacts/debug-image-next
```

1. **build** (scripts/guest-debug-kernel.sh, 32 vCPU / 32 GiB guest, tmpfs):
   Debian `linux-source-6.12` 6.12.113-1 with the pinned guest's boot config,
   reduced by `localmodconfig` to the modules the suites load. The list must
   include every module a suite needs, e.g. the AF_ALG modules (without them
   in-guest `cryptsetup luksFormat` reports aegis128-random unavailable) and the
   authenc/xts modules (plus `hmac`, `sha256` and `aesni_intel`) for the AES-XTS +
   HMAC-SHA256 profiles.
   Then KASAN (generic, inline, vmalloc), UBSAN (bounds, shift, bool, enum),
   PROVE_LOCKING, DEBUG_ATOMIC_SLEEP, DEBUG_LIST, DEBUG_SG and kmemleak; no
   debug info. `make bindeb-pkg` with `LOCALVERSION=+deb13-amd64-pivdbg`.
   About 3 minutes under KVM.
2. **install** (scripts/guest-debug-install.sh): installs both packages in a
   provisioned guest, makes the debug kernel the GRUB default and writes the
   marker `/etc/piv-debug-kernel`.
3. The install run's overlay becomes `downloads/debug-kernel-<hash>.qcow2`
   (read-only, qcow2 backing chain onto the provisioned image) with a `.json`
   provenance record (package hashes, enabled options).
4. **verify** (scripts/guest-debug-verify.sh): boots it and requires the KASAN
   and lockdep initialization messages.

The harness guard accepts the release `6.12.113+deb13-amd64-pivdbg` only when
the marker exists (pivsetup has no kernel check since the activation guards
were removed, 2026-10-22). On that image the module build checks vermagic
against the running kernel instead of the Debian header-config comparison
(bindeb-pkg headers ship no .config).

```sh
python3 scripts/suite.py --prefix artifacts/sanitizer-next \
  --base-image downloads/debug-kernel-6812e5047fb54014.qcow2 --memory-mib 2048 \
  --profile aegis-4096 --profile aegis-512 --scaffold artifacts/stage-next/scaffold.tar \
  --suites routine --suites-for aegis-512=faults
```

The 512-byte profiles dominate sanitizer time but share every kernel code path
with 4096, so routine sanitizer runs keep only their native and faults runs;
run them fully at milestones. Add `fuzz` when the ioctl or table code changes.
suite.py fails any run (stock or debug kernel) whose console or dmesg contains a
kernel self-report: KASAN/UBSAN, lockdep, sleeping-in-atomic, BUG/Oops/GPF,
WARNING or a kmemleak suspect. guest_record forces a final kmemleak scan and
saves the report; vm.py keeps logging for 10 seconds after a kernel fault so the
trace is preserved. After the task reports completion, vm.py allows QEMU 600 s
to power off on a sanitizer image (120 s otherwise) before treating the guest as
hung, and keeps reading the console into `shutdown-console.log` (also scanned
for kernel reports). Three sanitizer runs completed their task but QEMU never
exited (suite-078 v5 within 60 s, suite-084 and suite-091 cancel within 600 s).
suite-091's shutdown log showed the cause: `poweroff` was refused because
unattended-upgrades (started by the guest's apt timers) held a systemd
shutdown inhibitor while installing packages, which the slower sanitizer
guests hit more often. The task now ends with `systemctl poweroff -i`
(ignoring inhibitors in the disposable guest), falling back to `poweroff -f`.

Findings and known noise:

- **Scatterlist over stack memory (fixed 2026-10-21).** pn_v4_stream built a
  scatterlist over caller memory and keyslot unlock passed a stack buffer. With
  VMAP_STACK that is invalid; CONFIG_DEBUG_SG hit
  `BUG_ON(!virt_addr_valid(buf))` on the first v4 open. Stock x86-64 results
  were correct, but the usage was wrong (other architectures, DMA crypto, debug
  kernels). Every call now bounces through a kmalloc buffer.
- **kmemleak boot-time false positive.** The longest runs reported six
  suspected leaks at kmemleak's automatic scan. All are 4 KiB execmem
  allocations made by swapper/0 in start_kernel (apply_retpolines) before
  dm-piv loads, with no dm_piv frame. suite.py therefore ignores boot-time
  swapper/start_kernel objects in the saved report; any other suspect (or any
  dm_piv frame) fails the run.

Limits: sanitizers find only the faults the exercised paths trigger; there is no
sanitizer build of the 7.2 port kernel. Executed sanitizer runs are recorded in
commit messages.

### Newer-kernel port

dm-piv builds warning-free from one source tree for the pinned 6.12.113 kernel
and Debian's trixie-backports kernel `7.2.9+deb13-amd64` (package
7.2.9-1~bpo13+1), and the guest suites pass on both. The current image is
`downloads/port-kernel-3a70cfae7df48a4b.qcow2`.

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
The harness guard accepts `7.2.9+deb13-amd64` only with that marker. Module
builds on it use the normal boot/header config comparison;
kernel/check-config.py takes the release for the `CONFIG_BUILD_SALT` entry.
Run suites with
`suite.py --base-image downloads/port-kernel-3a70cfae7df48a4b.qcow2 ...`.

API differences handled:

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

Coverage and limits: the full suite set (`--suites all`) passed on the port
image for the AEGIS-128 4096 and 512 profiles, including the early-boot suite,
with no kernel reports; runs are recorded in commit messages. The AES-XTS +
HMAC-SHA256 profiles were added after the port; on 7.2.9 only aes-sha256-4096
has run (the routine suites, passing); aes-sha256-512 has not run there. Format
v5 (2026-10-22) ran the routine suites on the port image for aegis-4096 and
aes-sha256-4096, all passing; the 512-byte profiles and the opt-in suites have
not run v5 on 7.2. The batched write path (suite-085) passed the same routine
suites there. Not covered: sanitizer builds of 7.2, other distributions, and
kernels between 6.12 and 7.2.

## Stock fixtures

scripts/guest-control.sh formats /dev/vdb (or `PIV_CONTROL_DEVICE=/dev/vdc`)
with stock cryptsetup, selected by
`PIV_PRIMARY_CIPHER` (default `aes-xts-random` with `PIV_INTEGRITY` default
`hmac-sha256`, or `aegis128-random`) and `PIV_SECTOR_SIZE` (512 default, or
4096; the recommended configuration), with the default journaled integrity
mode, or with `PIV_NO_JOURNAL=1` (the `*-nojournal` suite profiles) after
persisting stock `--integrity-no-journal` on the first open. It writes
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
