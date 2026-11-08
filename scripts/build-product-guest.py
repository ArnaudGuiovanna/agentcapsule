#!/usr/bin/env python3
"""Build capsule-init and the independent echo harness into a pinned initramfs.

No mount, block-device operation, kernel change, credential or volume key is
performed/embedded. Native binaries come from trusted operator-supplied/system
paths. Their complete ldd dependency closure and configuration are frozen with
hashes; this records provenance, not a security assessment of those versions.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def archive(entries):
    out = bytearray()
    dirs = {"dev", "proc", "sys", "run", "tmp", "mnt", "var", "var/lib"}
    for name in entries:
        p = Path(name).parent
        while str(p) != ".":
            dirs.add(str(p))
            p = p.parent
    rows = [(x, stat.S_IFDIR | 0o755, b"", 0, 0) for x in sorted(dirs, key=lambda x: (x.count("/"), x))]
    rows += [("dev/console", stat.S_IFCHR | 0o600, b"", 5, 1)]
    rows += [(name, stat.S_IFREG | mode, data, 0, 0) for name, (mode, data) in sorted(entries.items())]
    rows.append(("TRAILER!!!", 0, b"", 0, 0))
    for ino, (name, mode, data, major, minor) in enumerate(rows, 1):
        fields = [ino, mode, 0, 0, 1, 0, len(data), 0, 0, major, minor, len(name.encode()) + 1, 0]
        out.extend(b"070701" + "".join(f"{x:08x}" for x in fields).encode())
        out.extend(name.encode() + b"\0")
        out.extend(b"\0" * (-len(out) % 4))
        out.extend(data)
        out.extend(b"\0" * (-len(out) % 4))
    return out


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--go", type=Path, required=True)
    p.add_argument("--cryptsetup", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    out = a.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    src = out / "sources"
    src.mkdir()
    for name in ["go.mod", "go.sum"]:
        shutil.copy2(ROOT / name, src / name)
    for name in ["internal/capsuleprotocol", "internal/harnessstore", "internal/guestinit", "internal/referenceharness", "cmd/capsule-init", "cmd/capsule-echo"]:
        shutil.copytree(ROOT / name, src / name)
    (src / "scripts").mkdir()
    shutil.copy2(Path(__file__), src / "scripts" / Path(__file__).name)
    sources = {str(f.relative_to(src)): sha(f) for f in src.rglob("*") if f.is_file()}
    records = []

    def run(label, cmd, timeout=180):
        start = time.monotonic()
        record = {"phase": label, "command": [str(x) for x in cmd], "status": "running"}
        records.append(record)
        (out / "summary.json").write_text(json.dumps(records, indent=2) + "\n")
        print("RUN", label, flush=True)
        with (out / (label + ".log")).open("w") as log:
            proc = subprocess.Popen(record["command"], cwd=src, env=dict(os.environ, CGO_ENABLED="1"),
                                    stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
            try:
                rc = proc.wait(timeout=timeout)
            except BaseException:
                os.killpg(proc.pid, signal.SIGTERM)
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    os.killpg(proc.pid, signal.SIGKILL)
                    proc.wait()
                record.update(status="interrupted_or_timed_out", seconds=round(time.monotonic()-start, 3))
                (out / "summary.json").write_text(json.dumps(records, indent=2) + "\n")
                raise
        record.update(status="passed" if rc == 0 else "failed", returncode=rc, seconds=round(time.monotonic()-start, 3))
        (out / "summary.json").write_text(json.dumps(records, indent=2) + "\n")
        print(record["status"].upper(), label, flush=True)
        if rc:
            raise RuntimeError(f"{label} failed; inspect log")

    for name in ["capsule-init", "capsule-echo"]:
        run(name, [a.go.resolve(), "build", "-buildvcs=false", "-trimpath", "-tags=netgo,osusergo,sqlite_omit_load_extension",
                   "-ldflags=-linkmode external -extldflags '-static'", "-o", out / name, "./cmd/" + name])
    entries = {"init": (0o500, (out / "capsule-init").read_bytes()),
               "harness/capsule-echo": (0o555, (out / "capsule-echo").read_bytes()),
               "etc/capsule/runtime.json": (0o400, b'{"entrypoint":["/harness/capsule-echo"]}\n')}
    native = {}

    def add(source, destination, mode):
        destination = destination.lstrip("/")
        data = source.read_bytes()
        if destination in entries and entries[destination] != (mode, data):
            raise RuntimeError("conflicting native dependency: " + destination)
        entries[destination] = (mode, data)
        frozen = out / "native" / destination
        frozen.parent.mkdir(parents=True, exist_ok=True)
        frozen.write_bytes(data)
        native[destination] = {"source": str(source.resolve()), "sha256": sha(source)}

    for source, dest in [(a.cryptsetup.resolve(), "sbin/cryptsetup"), (Path("/usr/sbin/mkfs.ext4"), "sbin/mkfs.ext4"),
                         (Path("/usr/sbin/e2fsck"), "sbin/e2fsck"), (Path("/usr/sbin/blkid"), "sbin/blkid")]:
        add(source, dest, 0o500)
        result = subprocess.run(["ldd", str(source)], capture_output=True, text=True, check=True, timeout=30)
        if "not found" in result.stdout:
            raise RuntimeError("unresolved native dependency")
        for line in result.stdout.splitlines():
            match = re.search(r"(?:=>\s+|^\s*)(/\S+)\s+\(", line)
            if match:
                path = Path(match.group(1))
                add(path, str(path), 0o555)
    for name in ["mke2fs.conf", "e2fsck.conf"]:
        path = Path("/etc") / name
        if path.is_file():
            add(path, "etc/" + name, 0o444)
    image = archive(entries)
    assert archive(entries) == image, "non-deterministic archive encoding"
    (out / "product.initrd").write_bytes(image)
    metadata = {"source_sha256": sources, "go": subprocess.check_output([str(a.go.resolve()), "version"], text=True).strip(),
                "native_files": native, "archive_files": {k: {"mode": oct(mode), "sha256": hashlib.sha256(data).hexdigest()} for k, (mode, data) in entries.items()},
                "artifacts": {name: sha(out / name) for name in ["capsule-init", "capsule-echo", "product.initrd"]},
                "scope": "Reusable guest supervisor and independently executed reference echo harness compiled and packaged with LUKS/ext4 tools. No VM boot, filesystem mount or product path validated by this build."}
    (out / "artifacts.json").write_text(json.dumps(metadata, indent=2) + "\n")
    print("Built", out / "product.initrd", len(image), "bytes", flush=True)


if __name__ == "__main__":
    main()
