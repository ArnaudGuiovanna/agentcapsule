#!/usr/bin/env python3
"""Disposable Firecracker/KVM lab. Kill only VMMs started by this process.

Requires non-root access to /dev/kvm, mkfs.ext4, a kernel, Firecracker and a
statically linked internal/verification/guest binary. No TAP, host mount or
production data is used. This runner does not claim production jailer isolation.
"""
import argparse
import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import pwd
import grp
import shutil
import socket
import stat
import subprocess
import tempfile
import time


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def initrd(binary, destination):
    # Reproducible uncompressed SVR4 newc archive, including the early console.
    out = bytearray()
    entries = [("dev", stat.S_IFDIR | 0o755, b"", 0, 0),
               ("dev/console", stat.S_IFCHR | 0o600, b"", 5, 1),
               ("init", stat.S_IFREG | 0o755, binary.read_bytes(), 0, 0),
               ("TRAILER!!!", 0, b"", 0, 0)]
    for ino, (name, mode, data, major, minor) in enumerate(entries, 1):
        fields = [ino, mode, 0, 0, 1, 0, len(data), 0, 0, major, minor, len(name)+1, 0]
        out.extend(b"070701" + "".join(f"{x:08x}" for x in fields).encode())
        out.extend(name.encode() + b"\0")
        out.extend(b"\0" * (-len(out) % 4))
        out.extend(data)
        out.extend(b"\0" * (-len(out) % 4))
    destination.write_bytes(out)


class VM:
    def __init__(self, args, out, name, volume, cid):
        self.name, self.out = name, out
        self.socket_dir = Path(tempfile.mkdtemp(prefix="acp-vm-"))
        if os.geteuid() == 0:
            os.chown(self.socket_dir, args.vm_uid, args.vm_gid)
        self.uds = self.socket_dir / "vsock"
        self.started = time.monotonic()
        config = {"boot-source": {"kernel_image_path": str(args.kernel),
                  "initrd_path": str(out / "initrd"),
                  "boot_args": "console=ttyS0 reboot=k panic=1 pci=off"},
                  "drives": [{"drive_id": "data", "path_on_host": str(volume),
                              "is_root_device": False, "is_read_only": False,
                              "cache_type": "Writeback", "io_engine": "Sync"}],
                  "machine-config": {"vcpu_count": 1, "mem_size_mib": 256},
                  "vsock": {"guest_cid": cid, "uds_path": str(self.uds)}}
        config_path = out / f"{name}.config.json"
        config_path.write_text(json.dumps(config, indent=2) + "\n")
        self.log = (out / f"{name}.console.log").open("wb")
        self.process = subprocess.Popen([str(args.firecracker), "--no-api", "--config-file", str(config_path)],
                                        stdin=subprocess.DEVNULL, stdout=self.log, stderr=subprocess.STDOUT,
                                        **args.credentials)

    def ready(self):
        deadline = time.monotonic() + 40
        last = None
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise RuntimeError(f"{self.name} exited {self.process.returncode}; inspect console log")
            try:
                result = self.call({"op": "info"}, timeout=1)
                assert result["ok"], result
                self.boot_seconds = time.monotonic() - self.started
                return result
            except (OSError, TimeoutError, EOFError) as exc:
                last = str(exc)
                time.sleep(.1)
        raise TimeoutError(f"{self.name} boot timeout: {last}")

    def call(self, command, timeout=15):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect(str(self.uds))
            stream = sock.makefile("rwb", buffering=0)
            stream.write(b"CONNECT 5000\n")
            greeting = stream.readline(128)
            if not greeting.startswith(b"OK "):
                raise EOFError(f"vsock handshake: {greeting!r}")
            stream.write(json.dumps(command).encode() + b"\n")
            line = stream.readline(65536)
            if not line:
                raise EOFError("empty guest response")
            return json.loads(line)

    def kill(self):
        if self.process.poll() is None:
            self.process.kill()  # abrupt loss of ALL guest memory, no sync/unmount
            self.process.wait(timeout=10)
        self.log.close()
        shutil.rmtree(self.socket_dir)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--firecracker", type=Path, required=True)
    p.add_argument("--kernel", type=Path, required=True)
    p.add_argument("--guest", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--vmm-user", help="Required when orchestrating as root; VMM always runs as a non-root user")
    p.add_argument("--inject-io-errors", action="store_true", help="Use an owned loop/dm-error device; requires root")
    args = p.parse_args()
    args.credentials = {}
    args.vm_uid, args.vm_gid = os.getuid(), os.getgid()
    if os.geteuid() == 0:
        if not args.vmm_user:
            p.error("root orchestration requires --vmm-user (VMM must be unprivileged)")
        user = pwd.getpwnam(args.vmm_user)
        if user.pw_uid == 0:
            p.error("VMM user must not be root")
        args.vm_uid, args.vm_gid = user.pw_uid, user.pw_gid
        args.credentials = {"user": user.pw_uid, "group": user.pw_gid,
                            "extra_groups": [grp.getgrnam("kvm").gr_gid]}
    elif args.inject_io_errors:
        p.error("--inject-io-errors requires root orchestration, with an unprivileged --vmm-user")
    for field in ("firecracker", "kernel", "guest", "output"):
        setattr(args, field, getattr(args, field).resolve())
    if args.output.exists():
        p.error("output must be a new directory")
    out = args.output
    out.mkdir(parents=True, mode=0o700)
    if os.geteuid() == 0:
        os.chown(out, args.vm_uid, args.vm_gid)
    initrd(args.guest, out / "initrd")
    root = Path(__file__).resolve().parents[1]
    sources = [Path(__file__).resolve(), root / "internal/verification/guest/main.go",
               root / "internal/harnessstore/store.go", root / "go.mod", root / "go.sum"]
    hashes = {}
    for source in sources:
        rel = source.relative_to(root)
        dest = out / "sources" / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, dest)
        hashes[str(rel)] = digest(source)
    environment = {"started": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                   "platform": platform.platform(), "orchestrator_uid": os.getuid(), "groups": os.getgroups(),
                   "vmm_uid": args.vm_uid, "inject_io_errors": args.inject_io_errors,
                   "source_sha256": hashes,
                   "artifacts": {name: {"path": str(getattr(args, name)), "sha256": digest(getattr(args, name))}
                                 for name in ("firecracker", "kernel", "guest")},
                   "limitations": ["VMM SIGKILL; host/Windows caches remain alive",
                                   "No physical host power cut; EIO injection only when explicitly enabled",
                                   "Test-only guest endpoint, no authenticated production transport or jailer",
                                   "Separate guest device attachments do not prove absence of hypervisor vulnerabilities"]}
    (out / "environment.json").write_text(json.dumps(environment, indent=2) + "\n")
    records, live = [], []

    def record(name, actual, predicate):
        passed = bool(predicate(actual))
        records.append({"check": name, "passed": passed, "observation": actual})
        (out / "checks.json").write_text(json.dumps(records, indent=2) + "\n")
        print(json.dumps(records[-1]), flush=True)
        if not passed:
            raise AssertionError(name)

    def volume(name):
        path = out / (name + ".ext4")
        with path.open("xb") as f:
            f.truncate(128 << 20)
        path.chmod(0o600)
        if os.geteuid() == 0:
            os.chown(path, args.vm_uid, args.vm_gid)
        with (out / (name + ".mkfs.log")).open("wb") as log:
            subprocess.run(["/usr/sbin/mkfs.ext4", "-F", "-b", "4096", str(path)],
                           stdout=log, stderr=subprocess.STDOUT, check=True)
        return path

    def io_errors():
        # All device names are fresh, all backing files belong to this new run.
        # Never operate on a preexisting mapper or detach an unrelated loop.
        backing = volume("io-errors")
        loop_fd = None
        mapped = False
        name = "acp-lab-" + out.name[:16] + "-" + os.urandom(4).hex()
        sectors = backing.stat().st_size // 512
        log = (out / "device-mapper.jsonl").open("w")

        def dm(*argv):
            result = subprocess.run(["/usr/sbin/dmsetup", *argv], text=True, capture_output=True, timeout=30)
            log.write(json.dumps({"argv": argv, "returncode": result.returncode,
                                  "stdout": result.stdout, "stderr": result.stderr}) + "\n")
            log.flush()
            result.check_returncode()
            return result.stdout

        try:
            ctl = os.open("/dev/loop-control", os.O_RDWR)
            try:
                number = fcntl.ioctl(ctl, 0x4C82)  # LOOP_CTL_GET_FREE
            finally:
                os.close(ctl)
            loop = Path(f"/dev/loop{number}")
            if not loop.exists():
                os.mknod(loop, stat.S_IFBLK | 0o600, os.makedev(7, number))
            fd = os.open(loop, os.O_RDWR)
            image = os.open(backing, os.O_RDWR)
            try:
                fcntl.ioctl(fd, 0x4C00, image)  # LOOP_SET_FD fails if raced by another owner
                loop_fd = fd
            finally:
                os.close(image)
                if loop_fd is None:
                    os.close(fd)
            linear = f"0 {sectors} linear {loop} 0"
            dm("create", name, "--table", linear)
            mapped = True
            device = Path("/dev/mapper") / name
            os.chown(device, args.vm_uid, args.vm_gid)
            os.chmod(device, 0o600)
            vm = boot("io-before", device, 5)
            record("io-baseline-commit", vm.call({"op": "apply", "id": "durable", "bytes": 1 << 20}), lambda r: r["ok"])
            dm("suspend", "--noflush", "--nolockfs", name)
            dm("load", name, "--table", f"0 {sectors} error")
            dm("resume", name)
            record("io-error-table-active", dm("table", name).strip(), lambda r: r == f"0 {sectors} error")
            record("io-error-never-acknowledged", vm.call({"op": "apply", "id": "io-failed", "bytes": 16 << 20}),
                   lambda r: not r["ok"] and r.get("sqlite_code") == 10)
            kill(vm)
            dm("suspend", "--noflush", "--nolockfs", name)
            dm("load", name, "--table", linear)
            dm("resume", name)
            vm = boot("io-recovered", device, 5)
            inspect(vm, "io-recovery-preserves-only-prior-commit", 1)
            record("io-retry-after-recovery", vm.call({"op": "apply", "id": "io-failed", "bytes": 16 << 20}),
                   lambda r: r["ok"] and not r.get("replayed", False))
            inspect(vm, "io-retry-committed-once", 2)
            kill(vm)
        finally:
            # Close any VMM before tearing down its block device, even on failure.
            for vm in list(live):
                kill(vm)
            if mapped:
                dm("remove", name)
            if loop_fd is not None:
                try:
                    fcntl.ioctl(loop_fd, 0x4C01)  # LOOP_CLR_FD, owned attachment only
                finally:
                    os.close(loop_fd)
            log.close()

    def boot(name, disk, cid=3):
        vm = VM(args, out, name, disk, cid)
        live.append(vm)
        info = vm.ready()
        record(name + "/boot", {**info, "seconds": vm.boot_seconds},
               lambda r: r["ok"] and r["data"]["pid"] == 1 and r["data"]["block_devices"] == ["vda"])
        return vm

    def kill(vm):
        vm.kill()
        live.remove(vm)

    def inspect(vm, name, effects, fences=0):
        record(name, vm.call({"op": "inspect"}),
               lambda r: r["ok"] and r["data"] == {"effects": effects, "markers": effects,
                                                    "fences": fences, "integrity": ["ok"]})

    success = False
    try:
        disk_a, disk_b = volume("a"), volume("b")
        a = boot("a-before", disk_a)
        inspect(a, "initial-empty", 0)
        record("pause-before-commit", a.call({"op": "apply", "id": "pre", "bytes": 1 << 20, "pause": "before_commit"}),
               lambda r: r["ok"] and r["phase"] == "before_commit")
        kill(a)
        a = boot("a-recover-before", disk_a)
        inspect(a, "uncommitted-effect-and-marker-absent", 0)
        record("retry-uncommitted", a.call({"op": "apply", "id": "pre", "bytes": 1 << 20}),
               lambda r: r["ok"] and not r.get("replayed", False))
        record("pause-after-commit-before-ack", a.call({"op": "apply", "id": "post", "bytes": 1 << 20, "pause": "after_commit"}),
               lambda r: r["ok"] and r["phase"] == "after_commit")
        kill(a)
        a = boot("a-recover-after", disk_a)
        inspect(a, "committed-effect-and-marker-survive", 2)
        record("lost-ack-replays-result", a.call({"op": "apply", "id": "post", "bytes": 1 << 20}),
               lambda r: r["ok"] and r.get("replayed") and r["data"]["result"] == "committed:post")
        record("fence-commits", a.call({"op": "fence", "subject": "agent/a"}), lambda r: r["ok"])
        kill(a)
        a = boot("a-recover-fence", disk_a)
        inspect(a, "fence-survives-vm-cut", 2, 1)
        for event in ("post", "late"):
            record("fence-rejects-" + event, a.call({"op": "apply", "id": event, "bytes": 1 << 20}),
                   lambda r: not r["ok"] and r.get("fenced"))
        b = boot("b-concurrent", disk_b, 4)
        inspect(b, "separate-vm-has-no-a-state", 0)
        record("b-independent-write", b.call({"op": "apply", "id": "b-only", "bytes": 1 << 20}), lambda r: r["ok"])
        inspect(a, "a-unchanged-by-b", 2, 1)
        record("disk-filled", b.call({"op": "fill"}), lambda r: r["ok"] and r["data"]["errno"] == "ENOSPC")
        record("full-disk-never-acknowledged", b.call({"op": "apply", "id": "full", "bytes": 16 << 20}),
               lambda r: not r["ok"] and r.get("sqlite_code") == 13)
        record("free-test-filler", b.call({"op": "unfill"}), lambda r: r["ok"])
        inspect(b, "failed-write-left-no-effect-or-marker", 1)
        kill(b)
        b = boot("b-recover-full", disk_b, 4)
        inspect(b, "full-disk-recovery-integrity", 1)
        record("retry-after-storage-recovery", b.call({"op": "apply", "id": "full", "bytes": 16 << 20}),
               lambda r: r["ok"] and not r.get("replayed", False))
        inspect(b, "retry-committed-once", 2)
        kill(a)
        kill(b)
        broken = volume("broken")
        v = boot("broken-before", broken, 6)
        record("negative-split-commit-point", v.call({"op": "broken_split", "id": "split"}),
               lambda r: r["ok"] and r["phase"] == "broken_effect_committed_without_marker")
        kill(v)
        v = boot("broken-recovered", broken, 6)
        record("negative-split-atomicity-detected", v.call({"op": "inspect"}),
               lambda r: r["ok"] and r["data"] == {"effects": 1, "markers": 0, "fences": 0, "integrity": ["ok"]})
        kill(v)
        if args.inject_io_errors:
            io_errors()
        success = True
    finally:
        for vm in live:
            vm.kill()
        (out / "summary.json").write_text(json.dumps({"passed": success, "checks": len(records),
                                                     "failed_checks": [r["check"] for r in records if not r["passed"]]}, indent=2) + "\n")


if __name__ == "__main__":
    main()
