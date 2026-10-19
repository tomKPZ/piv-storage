#!/usr/bin/env python3
"""Download a pinned guest or run a script in a new disposable QEMU overlay."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import selectors
import shutil
import subprocess
import stat
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
PIN = json.loads((ROOT / "environment/guest.json").read_text())


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha512").hexdigest()


def prepare():
    image = ROOT / "downloads" / PIN["filename"]
    image.parent.mkdir(exist_ok=True)
    if not image.exists():
        temporary = image.with_suffix(".partial")
        print("Downloading pinned guest", flush=True)
        with urllib.request.urlopen(PIN["url"], timeout=60) as response:
            with temporary.open("wb") as out:
                shutil.copyfileobj(response, out)
        if digest(temporary) != PIN["sha512"]:
            raise RuntimeError("Guest download checksum mismatch")
        temporary.replace(image)
    if digest(image) != PIN["sha512"]:
        raise RuntimeError("Guest image checksum mismatch")
    return image


class Console:
    def __init__(self, process, deadline):
        self.process = process
        self.deadline = deadline
        self.buffer = b""
        self.selector = selectors.DefaultSelector()
        self.selector.register(process.stdout, selectors.EVENT_READ)
        self.log = None

    def send(self, value):
        self.process.stdin.write(value.encode())
        self.process.stdin.flush()

    def expect(self, pattern):
        regex = re.compile(pattern, re.I)
        while True:
            if re.search(rb"kernel BUG at|Oops:|Kernel panic", self.buffer):
                raise RuntimeError("Guest kernel fault; inspect console.log and discard run")
            match = regex.search(self.buffer)
            if match:
                self.buffer = self.buffer[match.end():]
                return match
            if time.monotonic() >= self.deadline:
                # Never include the bootstrap buffer: firstboot may echo its
                # ephemeral root credential. Post-login output is in the log.
                raise TimeoutError("Guest console timeout; inspect post-login console.log if present")
            if self.selector.select(timeout=1):
                chunk = os.read(self.process.stdout.fileno(), 65536)
                if not chunk:
                    raise RuntimeError("Guest exited before expected console response")
                if self.log:
                    self.log.write(chunk)
                    self.log.flush()
                self.buffer = (self.buffer + chunk)[-262144:]

    def close(self):
        self.selector.close()


def run(args):
    image = prepare()
    run_dir = args.run_dir.resolve()
    # Never reuse/overwrite an experiment or attach arbitrary host devices.
    run_dir.mkdir(parents=True, exist_ok=False)
    os.chmod(run_dir, 0o700)
    share = run_dir / "share"
    share.mkdir(mode=0o700)
    # Freeze shared guest scaffolding alongside the selected task, including reboot.
    shutil.copyfile(ROOT / 'scripts/guest-common.sh', share / 'guest-common.sh')
    shutil.copyfile(args.script, share / "task.sh")
    if args.power_cut_script:
        shutil.copyfile(args.power_cut_script, share / 'reboot-task.sh')
        os.chmod(share / 'reboot-task.sh', 0o600)
    for path in args.share_file:
        destination = share / path.name
        if destination.exists():
            raise ValueError('Duplicate shared filename')
        shutil.copyfile(path, destination)
        os.chmod(destination, 0o600)
    overlay = run_dir / "guest.qcow2"
    subprocess.run(["qemu-img", "create", "-f", "qcow2", "-F", "qcow2",
                    "-b", str(image), str(overlay)], check=True)
    # Back the test block device directly with a host regular file. Do not run
    # guest loop devices over 9p: that path faulted in the pinned guest kernel.
    with (run_dir / "control.img").open("xb") as disk:
        if args.data_image:
            if not args.data_image.is_file():
                raise ValueError('Input image must be a regular file')
            with args.data_image.open('rb') as source:
                info = os.fstat(source.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_size not in (128 * 1024 * 1024, 512 * 1024 * 1024):
                    raise ValueError('Expected a regular 128 or 512 MiB image')
                shutil.copyfileobj(source, disk)
        else:
            disk.truncate(args.blank_mib * 1024 * 1024)
    os.chmod(run_dir / "control.img", 0o600)
    command = ["qemu-system-x86_64", "-machine", "q35,accel=" + args.accel,
               "-cpu", "max", "-smp", "2", "-m", "1024",
               "-drive", f"file={overlay},format=qcow2,if=virtio",
               "-drive", f"file={run_dir / 'control.img'},format=raw,if=virtio",
               "-nic", "user,model=virtio-net-pci",
               "-virtfs", f"local,path={share},mount_tag=pivwork,security_model=none",
               "-display", "none", "-serial", "stdio", "-monitor", "none",
               "-no-reboot"]
    if args.code:
        frozen_code = run_dir / 'code' / 'pivstore'
        shutil.copytree(ROOT / 'pivstore', frozen_code,
                        ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
        command.extend(['-virtfs', f'local,path={frozen_code},mount_tag=pivcode,security_model=none,readonly=on'])
    # QEMU option strings use commas as separators.
    if "," in str(run_dir):
        raise ValueError("Run directory cannot contain a comma")
    process = subprocess.Popen(command, stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    console = Console(process, time.monotonic() + args.timeout)
    try:
        print("Booting guest and completing first-boot setup", flush=True)
        console.expect(rb"Press any key to proceed")
        console.send("\n")
        console.expect(rb"timezone name or number[^:]*:")
        console.send("UTC\n")
        console.expect(rb"new root password[^:]*:")
        # Ephemeral guest login credential only; never logged or persisted by host.
        password = secrets.token_urlsafe(24)
        console.send("\t" + password + "\n")
        result = console.expect(rb"(again|repeat|reenter|re-enter|login:)")
        if result.group(1).lower() != b"login:":
            console.send(password + "\n")
            console.expect(rb"login:")
        console.send("root\n")
        console.expect(rb"Password:")
        console.send(password + "\n")
        console.expect(rb"root@[^\r\n]*[#$] ")
        console.buffer = b""
        # First-boot prompts can echo credentials. Log only after login completes.
        with (run_dir / "console.log").open("wb") as log:
            console.log = log
            print("Guest login ready; executing task", flush=True)
            console.send("stty -echo; mkdir -p /mnt/piv-work; "
                         "mount -t 9p -o trans=virtio,version=9p2000.L pivwork /mnt/piv-work "
                         "&& bash /mnt/piv-work/task.sh; "
                         "rc=$?; printf '\\nPIV_TASK_DONE=%s\\n' \"$rc\"; sync; poweroff\n")
            match = console.expect(rb"\n(?:PIV_TASK_DONE=(\d+)[\r\n]|PIV_POWER_CUT[\r\n])")
            console.log = None
        if match.group(1) is None:
            if not args.power_cut_script:
                raise RuntimeError('Unexpected guest power-cut request')
            deadline = console.deadline
            process.kill()
            process.wait(timeout=20)
            console.close()
            process.stdin.close()
            process.stdout.close()
            (run_dir / 'power-cut.json').write_text(json.dumps({
                'mechanism': 'SIGKILL QEMU with delayed guest write in flight',
                'host_page_cache_survives': True, 'host_power_loss_tested': False}) + '\n')
            print('QEMU killed at requested device-I/O boundary; rebooting same disks', flush=True)
            process = subprocess.Popen(command, stdin=subprocess.PIPE,
                                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            console = Console(process, deadline)
            console.expect(rb'login:')
            console.send('root\n')
            console.expect(rb'Password:')
            console.send(password + '\n')
            console.expect(rb'root@[^\r\n]*[#$] ')
            console.buffer = b''
            with (run_dir / 'reboot-console.log').open('wb') as log:
                console.log = log
                console.send("stty -echo; mkdir -p /mnt/piv-work; "
                             "mount -t 9p -o trans=virtio,version=9p2000.L pivwork /mnt/piv-work "
                             "&& bash /mnt/piv-work/reboot-task.sh; "
                             "rc=$?; printf '\\nPIV_TASK_DONE=%s\\n' \"$rc\"; sync; poweroff\n")
                match = console.expect(rb'\nPIV_TASK_DONE=(\d+)[\r\n]')
                console.log = None
        password = None
        code = int(match.group(1))
        process.wait(timeout=60)
        if args.power_cut_script and not (run_dir / 'power-cut.json').exists() and code == 0:
            raise RuntimeError('Expected power cut was not requested')
        if process.returncode != 0 or code != 0:
            raise RuntimeError(f"Guest task failed: task={code}, QEMU={process.returncode}; see {run_dir}")
        print(f"Guest task passed; artifacts: {share}", flush=True)
    finally:
        console.close()
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        process.stdin.close()
        process.stdout.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    sub.add_parser("prepare")
    task = sub.add_parser("run")
    task.add_argument("--script", type=Path, required=True)
    task.add_argument("--run-dir", type=Path, required=True)
    task.add_argument('--power-cut-script', type=Path,
                      help='Reboot same disks after PIV_POWER_CUT and execute this follow-up')
    disks = task.add_mutually_exclusive_group()
    disks.add_argument("--blank-mib", type=int, choices=(128, 512), default=128,
                       help="Size of a new disposable blank disk (default: 128 MiB)")
    disks.add_argument("--data-image", type=Path,
                      help="Copy this image into the guest data disk; never attach it directly")
    task.add_argument("--share-file", type=Path, action='append', default=[])
    task.add_argument("--code", action='store_true', help='Export package source read-only to the guest')
    task.add_argument("--accel", choices=("tcg", "kvm"), default="tcg")
    task.add_argument("--timeout", type=int, default=1200)
    args = parser.parse_args()
    if args.action == "prepare":
        print(prepare())
    else:
        run(args)


if __name__ == "__main__":
    main()
