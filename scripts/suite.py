#!/usr/bin/env python3
"""Run the guest test matrix in parallel disposable VMs and verify outputs on the host.

Phases per profile (profiles run concurrently):
  0. control: create a stock fixture with vm.py (unless --control supplies one)
  1. native:  build (or reuse) dm-piv.ko and run the dual-view/early-build test
  2. suites:  run the selected suites concurrently against the closed native image
Each VM uses its own fresh run directory; nothing is overwritten. With
--reuse-native, phase 1 is skipped and the suites start from a previous
matrix's passed, host-verified native run (same module input and base image).
Suite sets: --suites routine (the default), all, or an explicit list;
--suites-for narrows the list per profile (e.g. on the sanitizer image).
Host checks use scripts/check_stateless.py (independent primary authentication
and hidden decoding). Original AEGIS-128 images need PIV_AEGIS_REFERENCE.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import re
import os
from pathlib import Path
import subprocess
import sys
import threading
import time

ROOT = Path(__file__).resolve().parents[1]

# Fixture profiles: environment for scripts/guest-control.sh (stock luksFormat).
PROFILES = {
    'aegis-4096': dict(PIV_PRIMARY_CIPHER='aegis128-random', PIV_SECTOR_SIZE='4096'),
    'aegis-512': dict(PIV_PRIMARY_CIPHER='aegis128-random', PIV_SECTOR_SIZE='512'),
    # AES-XTS + HMAC-SHA256 authenc (user decision 2026-10-22).
    'aes-sha256-4096': dict(PIV_PRIMARY_CIPHER='aes-xts-random', PIV_INTEGRITY='hmac-sha256', PIV_SECTOR_SIZE='4096'),
    'aes-sha256-512': dict(PIV_PRIMARY_CIPHER='aes-xts-random', PIV_INTEGRITY='hmac-sha256', PIV_SECTOR_SIZE='512'),
}
SUITES = ('faults', 'profile', 'cancel', 'lifecycle', 'batch', 'stress', 'early', 'power', 'controls', 'v5', 'migrate',
          'fuzz', 'bench')
# Routine tier: run after kernel or pivsetup changes. The opt-in remainder is for
# changes in its own area: controls (descriptive write-pattern statistics),
# migrate (pivsetup migrate) and
# fuzz (control ioctls and table constructors; most useful on the sanitizer).
# bench (docs/configuration.md numbers) is explicit only and should run with
# --jobs 1; 'all' excludes it.
DEFAULT_SUITES = ('faults', 'profile', 'cancel', 'lifecycle', 'batch', 'stress', 'early', 'power', 'v5')
# Guest RAM floors (MiB): Argon2id tier 3 (1 GiB, the default --kdf-cost) runs
# in pivsetup and in the Python cross-check; bench also measures tier 4 (2 GiB).
SUITE_MEMORY_MIB = {'v5': 3072, 'bench': 3584}
SUITE_SETS = {'routine': DEFAULT_SUITES, 'all': tuple(s for s in SUITES if s != 'bench')}
lock = threading.Lock()


# Kernel self-reports that fail any run (stock or sanitizer kernel alike).
KERNEL_REPORT = re.compile(r'BUG: KASAN|UBSAN:|possible circular locking|possible recursive locking|'
                           r'inconsistent lock state|BUG: sleeping function|BUG: unable to handle|'
                           r'WARNING: CPU|kernel BUG at|Oops|general protection fault')


def kernel_reports(run_dir):
    found = []
    for path in (run_dir / 'console.log', run_dir / 'shutdown-console.log', run_dir / 'share/dmesg.txt', run_dir / 'share/reboot-dmesg.txt'):
        if path.exists():
            for line in path.read_text(errors='replace').splitlines():
                if KERNEL_REPORT.search(line):
                    found.append(f'{path.name}: {line.strip()[:200]}')
    found += kmemleak_objects(run_dir / 'share/kmemleak.txt')
    return found[:20]


def kmemleak_objects(path):
    """Suspected leaks from guest_record's forced kmemleak scan. Boot-time objects
    (swapper/0 in start_kernel, e.g. 6.12's execmem retpoline thunks) predate our
    module and are a known kernel-internal false positive (docs/sanitizer.md)."""
    if not path.exists():
        return []
    found = []
    for block in path.read_text(errors='replace').split('unreferenced object ')[1:]:
        if 'comm "swapper/0"' in block and ' start_kernel+' in block and 'dm_piv' not in block:
            continue
        found.append('kmemleak: ' + ' '.join(block.split())[:200])
    return found


def log(message):
    with lock:
        print(time.strftime('%H:%M:%S'), message, flush=True)


class Matrix:
    def __init__(self, args):
        self.args = args
        self.results = {}
        self.slots = threading.Semaphore(args.jobs)

    def vm(self, name, script, run_dir, *, data=None, shares=(), timeout=3600, extra=(), memory_mib=None):
        command = [sys.executable, str(ROOT / 'scripts/vm.py'), 'run', '--script', str(script),
                   '--run-dir', str(run_dir), '--timeout', str(timeout), '--accel', self.args.accel, *extra]
        if self.args.base_image:
            command += ['--base-image', str(self.args.base_image)]
        elif self.args.provisioned:
            command.append('--provisioned')
        memory = max(self.args.memory_mib or 0, memory_mib or 0)
        if memory:
            command += ['--memory-mib', str(memory)]
        if data:
            command += ['--data-image', str(data)]
        for path in (*shares, self.args.pivsetup):
            command += ['--share-file', str(path)]
        with self.slots:
            log(f'start {name}: {run_dir}')
            started = time.monotonic()
            run_dir.parent.mkdir(parents=True, exist_ok=True)
            with open(str(run_dir) + '.log', 'wb') as output:
                code = subprocess.run(command, cwd=ROOT, stdout=output, stderr=subprocess.STDOUT).returncode
        elapsed = round(time.monotonic() - started, 1)
        reports = kernel_reports(run_dir)
        passed = code == 0 and not reports
        log(f'{"PASS" if passed else "FAIL"} {name} ({elapsed} s)' + (' KERNEL REPORTS' if reports else ''))
        self.record(name, dict(run_dir=str(run_dir), passed=passed, seconds=elapsed, kernel_reports=reports))
        return passed

    def record(self, name, value):
        with lock:
            self.results.setdefault(name, {}).update(value)

    def host_check(self, name, image, control, oracle_primary, oracle_hidden):
        command = [sys.executable, str(ROOT / 'scripts/check_stateless.py'), str(image),
                   '--volume-key-file', str(control / 'share/volume.key'),
                   '--hidden-key-file', str(control / 'hidden.key'),
                   '--expected-primary', str(oracle_primary), '--expected-hidden', str(oracle_hidden)]
        result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
        ok = result.returncode == 0
        self.record(name, dict(host_verified=ok, host_output=(result.stdout if ok else result.stderr)[-2000:]))
        log(f'{"VERIFIED" if ok else "VERIFY-FAIL"} {name}: {image.name}')
        return ok

    def control(self, profile):
        run_dir = self.args.prefix / f'{profile}-control'
        task = self.args.prefix / f'{profile}-control-task.sh'
        env = ' '.join(f'{k}={v}' for k, v in PROFILES[profile].items())
        task.write_text(f'#!/bin/bash\nset -euo pipefail\n{env} bash /mnt/piv-work/guest-control.sh\n')
        if not self.vm(f'{profile}/control', task, run_dir, shares=[ROOT / 'scripts/guest-control.sh'],
                       timeout=1800, extra=['--blank-mib', '128']):
            return None
        subprocess.run([str(self.args.pivsetup), 'keygen', '--output', str(run_dir / 'hidden.key')],
                       cwd=ROOT, check=True, capture_output=True)
        return run_dir

    def profile(self, profile, control):
        if control is None:
            control = self.control(profile)
            if control is None:
                return
        keys = [control / 'share/passphrase.key', control / 'hidden.key']
        suites = self.suites_for(profile)
        native = self.args.prefix / f'{profile}-native'
        script = ROOT / 'scripts/guest-stateless.sh'
        shares = [Path(self.args.scaffold), ROOT / 'scripts/guest-dual.sh', ROOT / 'scripts/guest-early-build.sh',
                  ROOT / 'kernel/guest-early-test.sh', ROOT / 'kernel/guest-dual-test.py',
                  ROOT / 'kernel/check-config.py', *keys]
        if self.args.reuse_native:
            native = self.reused_native(profile)
            if native is None:
                return
        elif not self.vm(f'{profile}/native', script, native, data=control / 'control.img',
                         shares=shares, extra=['--code']):
            return
        share = native / 'share'
        ko, final = share / 'experimental-dm-piv.ko', share / 'dual-final.img'
        primary, hidden = share / 'expected-primary.sha256', share / 'expected-hidden-volume'
        if not self.args.reuse_native:
            self.host_check(f'{profile}/native', final, control, primary, hidden)
        oracles = [hidden, primary]
        plans = {
            'faults': (ROOT / 'scripts/guest-faults.sh', final,
                       [ko, ROOT / 'kernel/guest-fault-test.py', *keys, *oracles], 'fault-final.img'),
            'profile': (ROOT / 'scripts/guest-profile.sh', final,
                        [ko, ROOT / 'kernel/guest-profile-test.py', *keys, *oracles], 'profile-final.img'),
            'cancel': (ROOT / 'scripts/guest-cancel.sh', final,
                       [ko, ROOT / 'kernel/check-config.py', ROOT / 'kernel/guest-cancel-test.py', *keys, *oracles],
                       'cancel-final.img'),
            'lifecycle': (ROOT / 'scripts/guest-lifecycle.sh', final,
                          [ko, ROOT / 'kernel/piv-io-test.c', ROOT / 'kernel/guest-lifecycle-test.py',
                           ROOT / 'kernel/lifecycle_trace.py', *keys, *oracles], 'lifecycle-final.img'),
            'batch': (ROOT / 'scripts/guest-batch.sh', final,
                      [ko, ROOT / 'kernel/check-config.py', ROOT / 'kernel/guest-batch-test.py', *keys, *oracles],
                      'batch-final.img'),
            'stress': (ROOT / 'scripts/guest-stress.sh', final,
                       [ko, ROOT / 'kernel/guest-stress-test.py', *keys, *oracles], 'stress-final.img'),
            'power': (ROOT / 'scripts/guest-stateless-power.sh', control / 'control.img',
                      [ko, ROOT / 'kernel/guest-stateless-power.py', *keys], None),
            'migrate': (ROOT / 'scripts/guest-migrate.sh', final,
                        [ko, ROOT / 'kernel/guest-migrate-test.py', *keys, *oracles], None),
            'fuzz': (ROOT / 'scripts/guest-fuzz.sh', final,
                     [ko, ROOT / 'kernel/guest-table-fuzz.py', ROOT / 'kernel/guest-ioctl-fuzz.py', *keys, *oracles], None),
            'v5': (ROOT / 'scripts/guest-v5.sh', control / 'control.img',
                   [ko, ROOT / 'kernel/guest-v5-test.py', ROOT / 'kernel/piv-rs-test.c',
                    ROOT / 'kernel/piv-rs.inc', *keys], 'v5-final.img'),
            'bench': (ROOT / 'scripts/guest-bench.sh', control / 'control.img',
                      [ko, ROOT / 'kernel/guest-bench-test.py', *keys], None),
            'controls': (ROOT / 'scripts/guest-controls.sh', control / 'control.img',
                         [ko, ROOT / 'kernel/guest-controls-test.py', ROOT / 'scripts/control_metrics.py', *keys],
                         None),
        }

        def suite(name):
            key = f'{profile}/{name}'
            if name == 'early':
                run_dir = self.args.prefix / f'{profile}-early'
                with self.slots:
                    log(f'start {key}: {run_dir}')
                    started = time.monotonic()
                    with open(str(run_dir) + '.log', 'wb') as output:
                        code = subprocess.run([sys.executable, str(ROOT / 'scripts/early_vm.py'),
                                               '--kernel', str(share / 'early-test.vmlinuz'),
                                               '--initrd', str(share / 'early-test.initrd'),
                                               '--data-image', str(final), '--run-dir', str(run_dir),
                                               '--accel', self.args.accel,
                                               '--memory-mib', str(self.args.memory_mib or 1024)],
                                              cwd=ROOT, stdout=output, stderr=subprocess.STDOUT).returncode
                reports = kernel_reports(run_dir)
                log(f'{"PASS" if code == 0 and not reports else "FAIL"} {key}')
                self.record(key, dict(run_dir=str(run_dir), passed=code == 0 and not reports,
                                      seconds=round(time.monotonic() - started, 1), kernel_reports=reports))
                return
            script, data, files, output = plans[name]
            run_dir = self.args.prefix / f'{profile}-{name}'
            extra = ['--code']
            if name == 'power':
                extra += ['--power-cut-script', str(ROOT / 'scripts/guest-stateless-recover.sh')]
            if name == 'migrate':
                extra += ['--second-blank-mib', '512']
            if not self.vm(key, script, run_dir, data=data, shares=files, extra=extra,
                           memory_mib=SUITE_MEMORY_MIB.get(name)):
                return
            out = run_dir / 'share'
            if name == 'cancel':
                self.host_check(key, out / output, control, primary, out / 'expected-cancel-hidden')
            elif name == 'controls':
                result = subprocess.run([sys.executable, str(ROOT / 'scripts/analyze_controls.py'), str(out),
                                         '--volume-key-file', str(control / 'share/volume.key'),
                                         '--hidden-key-file', str(control / 'hidden.key')],
                                        cwd=ROOT, capture_output=True, text=True)
                (run_dir / 'analysis.json').write_text(result.stdout)
                self.record(key, dict(host_verified=result.returncode == 0))
            elif name in ('v5', 'stress'):
                self.host_check(key, out / output, control, out / 'expected-primary.sha256',
                                out / 'expected-hidden-volume')
            elif output:
                self.host_check(key, out / output, control, primary, hidden)

        if suites:
            with ThreadPoolExecutor(max_workers=len(suites)) as pool:
                list(pool.map(suite, suites))

    def suites_for(self, profile):
        for prefix, names in self.args.suites_for:
            if profile.startswith(prefix):
                return [s for s in self.args.suites if s in names]
        return list(self.args.suites)

    def reused_native(self, profile):
        """A previous passed, host-verified native run built from the same module
        input on the same base image; recorded as reused, never re-verified."""
        key = f'{profile}/native'
        old = self.args.reuse_native_summary
        result = old['results'].get(key, {})
        reasons = []
        if old.get('module_input_sha256') != self.args.module_input_sha256:
            reasons.append('different (or unrecorded) module input')
        if old.get('base_image') != (str(self.args.base_image) if self.args.base_image else None):
            reasons.append('different base image')
        if not (result.get('passed') and result.get('host_verified')):
            reasons.append('native run did not pass host verification')
        if reasons:
            self.record(key, dict(passed=False, note='cannot reuse native: ' + '; '.join(reasons)))
            log(f'FAIL {key}: cannot reuse native ({"; ".join(reasons)})')
            return None
        self.record(key, dict(passed=True, host_verified=True, reused=result['run_dir']))
        log(f'REUSE {key}: {result["run_dir"]}')
        return Path(result['run_dir'])


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--prefix', type=Path, required=True, help='New directory for all runs, e.g. artifacts/suite-001')
    parser.add_argument('--profile', action='append', default=[], choices=sorted(PROFILES),
                        help='Create a fresh stock fixture for this profile (repeatable)')
    parser.add_argument('--control', action='append', default=[], type=Path,
                        help='Existing control run directory (with share/ and hidden.key); repeatable')
    parser.add_argument('--scaffold', type=Path, required=True,
                        help='Staged module scaffold.tar (scripts/fetch_kernel.py) to build in each native run')
    parser.add_argument('--suites', default='routine',
                        help=f'routine ({",".join(DEFAULT_SUITES)}), all, or a comma-separated '
                             f'subset of {",".join(SUITES)}')
    parser.add_argument('--suites-for', action='append', default=[], metavar='PROFILE=LIST',
                        help='Restrict profiles whose name starts with PROFILE to LIST (comma-separated, '
                             'may be empty); e.g. aegis-512=faults on the sanitizer image')
    parser.add_argument('--reuse-native', type=Path, metavar='PREFIX',
                        help='Skip native runs: reuse PREFIX/summary.json native results built from the '
                             'same --scaffold and base image')
    parser.add_argument('--jobs', type=int, default=max(1, min(16, (os.cpu_count() or 2) // 4)),
                        help='Maximum concurrent VMs')
    parser.add_argument('--fresh', dest='provisioned', action='store_false',
                        help='Use per-run first boot and apt instead of the provisioned image')
    parser.add_argument('--base-image', type=Path,
                        help='Read-only derived guest image, e.g. the sanitizer kernel (build_debug_kernel.py)')
    parser.add_argument('--memory-mib', type=int, help='Guest RAM (sanitizer kernels need more than 1024)')
    kvm = os.access('/dev/kvm', os.R_OK | os.W_OK)
    parser.add_argument('--accel', choices=('tcg', 'kvm'), default='kvm' if kvm else 'tcg',
                        help='QEMU accelerator for every VM (default: kvm when /dev/kvm is usable)')
    args = parser.parse_args()
    args.suites = list(SUITE_SETS.get(args.suites, [s for s in args.suites.split(',') if s]))
    if not set(args.suites) <= set(SUITES):
        parser.error('Unknown suite')
    limits = []
    for item in args.suites_for:
        prefix, sep, names = item.partition('=')
        names = [n for n in names.split(',') if n]
        if not sep or not prefix or not set(names) <= set(SUITES):
            parser.error(f'Invalid --suites-for {item}')
        limits.append((prefix, names))
    args.suites_for = limits
    args.module_input_sha256 = hashlib.sha256(args.scaffold.read_bytes()).hexdigest()
    args.reuse_native_summary = None
    if args.reuse_native:
        args.reuse_native_summary = json.loads((args.reuse_native / 'summary.json').read_text())
    if not args.profile and not args.control:
        parser.error('Give --profile and/or --control')
    args.prefix = args.prefix.resolve()
    args.prefix.mkdir(parents=True, exist_ok=False)
    if args.provisioned:
        subprocess.run([sys.executable, str(ROOT / 'scripts/vm.py'), 'provision', '--accel', args.accel],
                       cwd=ROOT, check=True)
    # Static Rust setup frontend shared into every guest (scripts/build_pivsetup.py).
    sys.path.insert(0, str(ROOT / 'scripts'))
    from build_pivsetup import build
    args.pivsetup = build(quiet=True)
    pivsetup_sha256 = hashlib.sha256(args.pivsetup.read_bytes()).hexdigest()
    log(f'pivsetup {pivsetup_sha256}')
    matrix = Matrix(args)
    work = [(p, None) for p in args.profile] + [(c.name, c.resolve()) for c in args.control]
    with ThreadPoolExecutor(max_workers=len(work)) as pool:
        list(pool.map(lambda item: matrix.profile(*item), work))
    summary = dict(provisioned=args.provisioned, accel=args.accel, pivsetup_sha256=pivsetup_sha256,
                   module_input_sha256=args.module_input_sha256,
                   reuse_native=str(args.reuse_native.resolve()) if args.reuse_native else None,
                   base_image=str(args.base_image) if args.base_image else None,
                   suites=args.suites, results=matrix.results)
    (args.prefix / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    failed = [k for k, v in matrix.results.items() if not v.get('passed') or v.get('host_verified') is False]
    expected = sum(1 + len(matrix.suites_for(name)) for name, _ in work) + len(args.profile)
    missing = expected - len(matrix.results)
    log(f'{len(matrix.results) - len(failed)} passed, {len(failed)} failed, {missing} not run; '
        f'summary: {args.prefix / "summary.json"}')
    return 1 if failed or missing else 0


if __name__ == '__main__':
    raise SystemExit(main())
