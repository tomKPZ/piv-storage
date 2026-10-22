# Sanitizer guest kernel (KASAN, UBSAN, lockdep, kmemleak)

The guest suites can run on a debug build of the pinned kernel, inside
disposable guests only (user-approved 2026-10-21). Nothing touches the host
kernel. The current image is `downloads/debug-kernel-6812e5047fb54014.qcow2`.

## Building the image

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

The test harness guard (guest-common.sh) accepts the release
`6.12.113+deb13-amd64-pivdbg` only when the marker exists (pivsetup has no
kernel check since the activation guards were removed, 2026-10-22). On that image the
module build checks vermagic against the running kernel instead of the Debian
header-config comparison (bindeb-pkg headers ship no .config).

## Running suites

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

## Findings and known noise

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
sanitizer build of the 7.2 port kernel ([kernel-port.md](kernel-port.md)).
Executed sanitizer runs are recorded in commit messages.
