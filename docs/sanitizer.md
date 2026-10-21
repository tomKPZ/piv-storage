# Sanitizer guest kernel (KASAN, UBSAN, lockdep, kmemleak)

User-approved 2026-10-21: run the existing guest suites on a debug build of the
pinned kernel, inside disposable guests only. Nothing touches the host kernel.

## Building the image

```sh
python3 scripts/build_debug_kernel.py --prefix artifacts/debug-image-next
```

1. **build** (scripts/guest-debug-kernel.sh, 32 vCPU / 32 GiB guest, tmpfs):
   Debian `linux-source-6.12` 6.12.113-1, the pinned guest's boot config,
   `localmodconfig` from the modules the suites load, then KASAN (generic,
   inline, stack, vmalloc), UBSAN (bounds strict, shift, bool, enum),
   PROVE_LOCKING, DEBUG_ATOMIC_SLEEP, DEBUG_LIST, DEBUG_SG and kmemleak; no
   debug info. `make bindeb-pkg` with `LOCALVERSION=+deb13-amd64-pivdbg`.
   About 3 minutes under KVM.
2. **install** (scripts/guest-debug-install.sh): install both packages in a
   provisioned guest, select the debug kernel as the GRUB default and write the
   explicit marker `/etc/piv-debug-kernel`.
3. The install run's overlay becomes `downloads/debug-kernel-<hash>.qcow2`
   (read-only, qcow2 backing chain onto the provisioned image) with a `.json`
   provenance record (package hashes, enabled options).
4. **verify** (scripts/guest-debug-verify.sh): boots it and requires the
   KASAN and lockdep initialization messages.

Guards accept the release `6.12.113+deb13-amd64-pivdbg` only when the marker
exists (guest-common.sh, pivstore.kernel_owner, pivsetup). On that image the
module build checks vermagic against the running kernel instead of the Debian
header-config comparison (bindeb-pkg headers ship no .config). The early-boot
initramfs copies the marker.

## Running suites

```sh
python3 scripts/suite.py --prefix artifacts/sanitizer-next \
  --base-image downloads/debug-kernel-<hash>.qcow2 --memory-mib 2048 \
  --control ... --scaffold ... --suites faults,profile,cancel,lifecycle,batch,early,power,controls,v4
```

The sector suite asserts the stock release and is not run here. suite.py fails
any run (stock or debug) whose console or dmesg contains a kernel self-report:
KASAN/UBSAN, lockdep, sleeping-in-atomic, BUG/Oops/GPF, WARNING or kmemleak.
guest_record forces a final kmemleak scan and saves the report. vm.py now keeps
logging for 10 seconds after a kernel fault so the trace is preserved.

## Findings

- **pn_v4_stream used a scatterlist over caller memory (fixed 2026-10-21).**
  Keyslot unlock passed a stack buffer (`pn_siv_open` output). With VMAP_STACK
  a scatterlist must not reference stack memory: `sg_init_one` hit the
  CONFIG_DEBUG_SG `BUG_ON(!virt_addr_valid(buf))` on the first v4 open. On the
  stock x86-64 kernel the software ChaCha20 path round-trips the address and
  every stock test decrypted correctly, so no corruption was observed, but the
  usage is invalid (other architectures, DMA crypto, debug kernels). Fixed by
  bouncing every call through a kmalloc buffer.
- Before the fix, AES-GCM and ChaCha20-Poly1305 profiles already passed every
  suite on the sanitizer kernel without reports (suite-018).
- kmemleak reported "6 new suspected memory leaks" in the three longest
  (512-byte-sector) native runs, at its automatic 600-second scan. Triage
  (forced scans in artifacts/dbg-repro-003, short and long runs alike): all six
  objects are 4 KiB execmem allocations made by swapper/0 in start_kernel
  (apply_retpolines), before dm-piv is loaded; no backtrace contains a dm_piv
  frame. This is a kernel-internal false positive. suite.py therefore judges
  kmemleak by the saved report: boot-time swapper/start_kernel objects are
  ignored, any other suspected leak (or any dm_piv frame) fails the run.
