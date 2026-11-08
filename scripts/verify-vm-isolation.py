#!/usr/bin/env python3
"""Root-orchestrated, disposable jailer isolation tests on the selected WSL.

Only fresh directories, cgroups, network namespaces and unused numeric UIDs are
used. No host network configuration is changed. This is a lab, not a runtime API.
"""
import argparse
import ctypes
import errno
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pwd
import select
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time

spec = importlib.util.spec_from_file_location("storage_lab", Path(__file__).with_name("verify-vm-storage.py"))
storage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(storage)


def new_netns():
    libc = ctypes.CDLL(None, use_errno=True)
    original = os.open("/proc/self/ns/net", os.O_RDONLY)
    try:
        if libc.unshare(0x40000000):
            raise OSError(ctypes.get_errno(), "unshare network namespace")
        new = os.open("/proc/self/ns/net", os.O_RDONLY)
    finally:
        if libc.setns(original, 0):
            raise OSError(ctypes.get_errno(), "restore orchestrator network namespace")
        os.close(original)
    return new


class JailedVM:
    call = storage.VM.call

    def __init__(self, args, out, name, uid, volume, cgroup_parent, jails):
        self.name, self.uid, self.out = name, uid, out
        self.pidfd = None
        self.process = None
        self.netns = new_netns()
        self.root = jails / args.firecracker.name / name / "root"
        self.root.mkdir(parents=True, mode=0o700)
        self.uds = self.root / "vsock"
        for src, dest in [(args.kernel, "kernel"), (out / "initrd", "initrd")]:
            shutil.copyfile(src, self.root / dest)
            (self.root / dest).chmod(0o444)
        os.link(volume, self.root / "data.ext4")
        os.chown(self.root / "data.ext4", uid, uid)
        config = {"boot-source": {"kernel_image_path": "/kernel", "initrd_path": "/initrd",
                                   "boot_args": "console=ttyS0 reboot=k panic=1 pci=off"},
                  "drives": [{"drive_id": "data", "path_on_host": "/data.ext4", "is_root_device": False,
                              "is_read_only": False, "cache_type": "Writeback", "io_engine": "Sync"}],
                  "machine-config": {"vcpu_count": 1, "mem_size_mib": 256},
                  "vsock": {"guest_cid": 3, "uds_path": "/vsock"}}
        (self.root / "config.json").write_text(json.dumps(config, indent=2) + "\n")
        shutil.copy2(self.root / "config.json", out / f"{name}.config.json")
        self.log = (out / f"{name}.console.log").open("wb")
        self.cgroup = Path("/sys/fs/cgroup") / cgroup_parent / name
        argv = [str(args.jailer), "--id", name, "--exec-file", str(args.firecracker),
                "--uid", str(uid), "--gid", str(uid), "--chroot-base-dir", str(jails),
                "--new-pid-ns", "--netns", f"/proc/{os.getpid()}/fd/{self.netns}",
                "--cgroup-version", "2", "--parent-cgroup", cgroup_parent,
                "--cgroup", "memory.max=536870912", "--cgroup", "pids.max=32",
                "--cgroup", "cpu.max=100000 100000", "--resource-limit", "no-file=256",
                "--", "--no-api", "--config-file", "/config.json"]
        (out / f"{name}.command.json").write_text(json.dumps(argv, indent=2) + "\n")
        self.started = time.monotonic()
        self.process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=self.log, stderr=subprocess.STDOUT)

    def ready(self):
        pidfile = self.root / (self.args_name + ".pid")
        deadline = time.monotonic() + 40
        last = ""
        while time.monotonic() < deadline:
            if self.pidfd is None and pidfile.exists():
                self.pid = int(pidfile.read_text())
                self.pidfd = os.pidfd_open(self.pid)
            if self.process.poll() not in (None, 0):
                raise RuntimeError(f"jailer failed: {self.name}; inspect console log")
            if self.pidfd is not None and select.select([self.pidfd], [], [], 0)[0]:
                raise RuntimeError(f"jailed VM exited: {self.name}; inspect console log")
            try:
                result = self.call({"op": "info"}, timeout=1)
                if result["ok"]:
                    return {**result, "boot_seconds": time.monotonic() - self.started}
            except (OSError, EOFError) as exc:
                last = str(exc)
            time.sleep(.1)
        raise TimeoutError(last)

    @property
    def args_name(self):
        return self.root.parent.parent.name

    def stop(self):
        if self.pidfd is not None:
            if not select.select([self.pidfd], [], [], 0)[0]:
                signal.pidfd_send_signal(self.pidfd, signal.SIGKILL)
                if not select.select([self.pidfd], [], [], 10)[0]:
                    raise TimeoutError("VMM did not exit")
            os.close(self.pidfd)
            self.pidfd = None
        elif self.process and self.process.poll() is None:
            self.process.kill()
        if self.process:
            self.process.wait(timeout=10)
        self.log.close()
        os.close(self.netns)
        if self.cgroup.exists():
            self.cgroup.rmdir()

    def security(self):
        proc = Path(f"/proc/{self.pid}")
        fields = dict(line.split(":", 1) for line in (proc / "status").read_text().splitlines())
        actual_root, expected_root = (proc / "root").stat(), self.root.stat()
        return {"host_pid": self.pid,
                "uids": [int(x) for x in fields["Uid"].split()],
                "gids": [int(x) for x in fields["Gid"].split()],
                "supplementary_groups": fields["Groups"].split(),
                "cap_eff": fields["CapEff"].strip(), "seccomp": int(fields["Seccomp"]),
                "nspid": [int(x) for x in fields["NSpid"].split()],
                "root": os.readlink(proc / "root"),
                "root_identity": [actual_root.st_dev, actual_root.st_ino],
                "expected_root_identity": [expected_root.st_dev, expected_root.st_ino],
                "namespaces": {n: os.readlink(proc / "ns" / n) for n in ("mnt", "pid", "net")},
                "cgroup": (proc / "cgroup").read_text().strip(),
                "limits": {n: (self.cgroup / n).read_text().strip() for n in ("memory.max", "pids.max", "cpu.max")}}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ("firecracker", "jailer", "kernel", "guest", "output"):
        p.add_argument("--" + name, type=Path, required=True)
    args = p.parse_args()
    if os.geteuid() != 0:
        p.error("root required for jailer namespaces/cgroups; each VMM drops to its own UID")
    for name in vars(args):
        setattr(args, name, getattr(args, name).resolve())
    if args.output.exists():
        p.error("output must be new")
    out = args.output
    out.mkdir(parents=True, mode=0o700)
    storage.initrd(args.guest, out / "initrd")
    # No accounts are created; fail rather than reuse a named account.
    uids = [61001, 61002, 61003]
    for uid in uids:
        try:
            pwd.getpwuid(uid)
        except KeyError:
            continue
        raise RuntimeError(f"lab UID {uid} is already assigned")
    for status in Path("/proc").glob("[0-9]*/status"):
        try:
            used = next(line.split()[1:] for line in status.read_text().splitlines() if line.startswith("Uid:"))
        except (FileNotFoundError, PermissionError):
            continue
        if any(int(x) in uids for x in used):
            raise RuntimeError("a selected lab UID is already running a process")
    # /tmp is tmpfs on this WSL; the jail and volume must share a filesystem
    # for hard links, and the vsock Unix path must stay below 108 bytes.
    jails = Path(tempfile.mkdtemp(prefix="acp-jail-", dir="/var/tmp"))
    if jails.stat().st_dev != out.stat().st_dev:
        jails.rmdir()
        raise RuntimeError("/var/tmp and output must share a filesystem for jailed volumes")
    jails.chmod(0o711)  # traversal allows meaningful cross-UID file/socket checks
    cgroup_parent = "acp-lab-" + os.urandom(6).hex()
    root = Path(__file__).resolve().parents[1]
    sources = [Path(__file__).resolve(), Path(storage.__file__), root / "internal/verification/guest/main.go",
               root / "internal/harnessstore/store.go", root / "go.mod", root / "go.sum"]
    hashes = {}
    for source in sources:
        rel = source.relative_to(root)
        dest = out / "sources" / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, dest)
        hashes[str(rel)] = storage.digest(source)
    environment = {"source_sha256": hashes, "uids": uids, "orchestrator_uid": os.getuid(),
                   "artifacts": {n: {"path": str(getattr(args, n)), "sha256": storage.digest(getattr(args, n))}
                                 for n in ("firecracker", "jailer", "kernel", "guest")}}
    (out / "environment.json").write_text(json.dumps(environment, indent=2) + "\n")
    live, checks = [], []
    success = False

    def check(name, observation, predicate):
        passed = bool(predicate(observation))
        row = {"check": name, "passed": passed, "observation": observation}
        checks.append(row)
        (out / "checks.json").write_text(json.dumps(checks, indent=2) + "\n")
        print(json.dumps(row), flush=True)
        if not passed:
            raise AssertionError(name)

    def volume(name):
        disk = out / (name + ".ext4")
        with disk.open("xb") as f:
            f.truncate(128 << 20)
        disk.chmod(0o600)
        result = subprocess.run(["/usr/sbin/mkfs.ext4", "-F", "-b", "4096", str(disk)], capture_output=True, check=True)
        (out / (name + ".mkfs.log")).write_bytes(result.stdout + result.stderr)
        return disk

    def boot(name, uid, disk):
        v = JailedVM(args, out, name, uid, disk, cgroup_parent, jails)
        live.append(v)
        check(name + "/boot", v.ready(), lambda r: r["ok"] and r["data"]["block_devices"] == ["vda"])
        return v

    def stop(vm):
        vm.stop()
        live.remove(vm)

    def access(uid, op, target):
        # Probe permissions as the VMM UID, outside its chroot, with no groups.
        # Running outside is a stronger filesystem access attempt than the VMM
        # can make; a positive own-file control prevents false passes from setup.
        code = """import os,socket,sys,json
try:
 op,target=sys.argv[1:]
 if op=='file':
  f=os.open(target,os.O_RDONLY);os.close(f)
 elif op=='socket':
  s=socket.socket(socket.AF_UNIX);s.connect(target);s.close()
 else:os.kill(int(target),0)
 print(json.dumps({'allowed':True}))
except OSError as e:print(json.dumps({'allowed':False,'errno':e.errno}))
"""
        r = subprocess.run([sys.executable, "-c", code, op, str(target)], user=uid, group=uid,
                           extra_groups=[], capture_output=True, text=True, check=True)
        return json.loads(r.stdout)

    try:
        disk_a, disk_b = volume("a"), volume("b")
        a, b = boot("agent-a", uids[0], disk_a), boot("agent-b", uids[1], disk_b)
        sa, sb = a.security(), b.security()
        host_ns = {n: os.readlink("/proc/self/ns/" + n) for n in ("mnt", "pid", "net")}
        for v, security in [(a, sa), (b, sb)]:
            check(v.name + "/security", security,
                  lambda s: s["uids"] == [v.uid]*4 and s["gids"] == [v.uid]*4 and not s["supplementary_groups"]
                  and int(s["cap_eff"], 16) == 0 and s["seccomp"] == 2 and s["nspid"] == [v.pid, 1]
                  # pivot_root may render the proc symlink as '/'. Compare the
                  # actual filesystem object, not the namespace-relative text.
                  and s["root_identity"] == s["expected_root_identity"]
                  and s["limits"] == {"memory.max": "536870912", "pids.max": "32", "cpu.max": "100000 100000"})
        check("separate-mount-pid-network-namespaces", {"a": sa["namespaces"], "b": sb["namespaces"], "host": host_ns},
              lambda r: all(len({r[x][ns] for x in ("a", "b", "host")}) == 3 for ns in host_ns))
        for own, other in [(a, b), (b, a)]:
            check(own.name + "/own-volume-positive-control", access(own.uid, "file", own.root / "data.ext4"), lambda r: r["allowed"])
            check(own.name + "/other-volume-denied", access(own.uid, "file", other.root / "data.ext4"), lambda r: not r["allowed"] and r["errno"] == errno.EACCES)
            check(own.name + "/other-vsock-denied", access(own.uid, "socket", other.uds), lambda r: not r["allowed"] and r["errno"] == errno.EACCES)
            check(own.name + "/other-process-denied", access(own.uid, "signal", other.pid), lambda r: not r["allowed"] and r["errno"] == errno.EPERM)
            check(own.name + "/private-write", own.call({"op": "apply", "id": own.name, "bytes": 1 << 20}), lambda r: r["ok"])
            check(own.name + "/private-state", own.call({"op": "inspect"}), lambda r: r["ok"] and r["data"] == {"effects": 1, "markers": 1, "fences": 0, "integrity": ["ok"]})
        check("fence-before-cold-backup", a.call({"op": "fence", "subject": "agent/a"}), lambda r: r["ok"])
        stop(a)
        backup = out / "a-backup.ext4"
        shutil.copyfile(disk_a, backup)
        backup.chmod(0o600)
        with backup.open("rb") as f:
            os.fsync(f.fileno())
        check("cold-copy-matches-source", {"source": storage.digest(disk_a), "backup": storage.digest(backup)}, lambda r: r["source"] == r["backup"])
        restored = boot("agent-a-restored", uids[2], backup)
        check("cold-restore-state", restored.call({"op": "inspect"}), lambda r: r["ok"] and r["data"] == {"effects": 1, "markers": 1, "fences": 1, "integrity": ["ok"]})
        check("cold-restore-keeps-fence", restored.call({"op": "apply", "id": "late"}), lambda r: not r["ok"] and r.get("fenced"))
        success = True
    finally:
        for v in live:
            v.stop()
        parent = Path("/sys/fs/cgroup") / cgroup_parent
        if parent.exists():
            parent.rmdir()
        shutil.rmtree(jails)
        (out / "summary.json").write_text(json.dumps({"passed": success, "checks": len(checks),
                                                     "failed_checks": [x["check"] for x in checks if not x["passed"]]}, indent=2) + "\n")


if __name__ == "__main__":
    main()
