#!/usr/bin/env python3
"""Build the python-echo reference harness package.

docker build (pinned base image) -> docker export -> extracted filesystem ->
agentcapsule-harness pack -> <output>/package (harness.yaml, checksums.json,
harness.ext4), ready for agentcapsule-harness push. Runs on a developer machine
or in CI, never on the platform host. The output directory must be new.
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "examples/python-echo"
SDK = ROOT / "sdk/python/agentcapsule_harness.py"
SKIP = ("dev/", "proc/", "sys/")


def run(cmd, **kw):
    print("+", " ".join(str(c) for c in cmd), flush=True)
    return subprocess.run([str(c) for c in cmd], check=True, **kw)


def extract(tar_path: Path, dest: Path) -> int:
    """Extracts a docker export without device nodes, FIFOs or the contents of
    dev/, proc/ and sys/ (the guest mounts its own)."""
    count = 0
    with tarfile.open(tar_path) as tar:
        members = []
        for m in tar.getmembers():
            name = m.name.lstrip("./")
            if m.isdev() or m.isfifo() or name == ".dockerenv" or any(name.startswith(p) for p in SKIP):
                continue
            members.append(m)
        kwargs = {"filter": "tar"} if hasattr(tarfile, "tar_filter") else {}
        tar.extractall(dest, members=members, **kwargs)
        count = len(members)
    return count


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--go", default="go", help="Go toolchain used to build agentcapsule-harness")
    p.add_argument("--docker", default="docker")
    p.add_argument("--output", required=True, type=Path, help="new output directory")
    p.add_argument("--size-mib", type=int, default=160, help="harness.ext4 size")
    a = p.parse_args()
    out = a.output.resolve()
    if out.exists():
        print("output directory must be new", file=sys.stderr)
        return 2
    out.mkdir(parents=True)
    context = out / "context"
    context.mkdir()
    for src in (EXAMPLE / "Dockerfile", EXAMPLE / "harness.py", SDK):
        shutil.copy2(src, context / src.name)
    iid = out / "image.id"
    run([a.docker, "build", "--platform", "linux/amd64", "--iidfile", iid, "-t", "agentcapsule/python-echo:build", context])
    image = iid.read_text().strip()
    container = subprocess.run([a.docker, "create", "--platform", "linux/amd64", image], check=True,
                               capture_output=True, text=True).stdout.strip()
    try:
        run([a.docker, "export", "-o", out / "rootfs.tar", container])
    finally:
        subprocess.run([a.docker, "rm", container], capture_output=True)
    rootfs = out / "rootfs"
    rootfs.mkdir()
    files = extract(out / "rootfs.tar", rootfs)
    tool = out / "agentcapsule-harness"
    run([a.go, "build", "-trimpath", "-o", tool, "./cmd/agentcapsule-harness"], cwd=ROOT,
        env=dict(os.environ, CGO_ENABLED="0", GOFLAGS="-mod=readonly"))
    run([tool, "pack", "--manifest", EXAMPLE / "harness.yaml", "--rootfs", rootfs, "--size-mib", a.size_mib, "--out", out / "package"])
    checksums = json.loads((out / "package/checksums.json").read_text())
    base = next(line.split()[1] for line in (EXAMPLE / "Dockerfile").read_text().splitlines() if line.startswith("FROM "))
    (out / "build.json").write_text(json.dumps({"harness": "python-echo", "base_image": base, "image_id": image,
                                                "files": files, "checksums": checksums["files"]}, indent=2) + "\n")
    shutil.rmtree(rootfs, ignore_errors=True)
    (out / "rootfs.tar").unlink()
    print("package:", out / "package")
    return 0


if __name__ == "__main__":
    sys.exit(main())
