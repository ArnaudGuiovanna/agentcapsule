#!/usr/bin/env python3
"""Build an adapted harness package: an ordinary agent image plus capsule-adapter.

docker build of the agent's image (examples/adapted-agent by default) ->
docker export -> extracted filesystem -> + /agentcapsule/capsule-adapter (a
static binary built here) and /agentcapsule/adapter.json -> agentcapsule-harness
pack -> <output>/package, ready for agentcapsule-harness push. The agent itself
is not changed. Runs on a developer machine or in CI, never on the platform
host. The output directory must be new. Building capsule-adapter needs cgo
(SQLite) and static C libraries, as for capsule-echo (set CPATH if needed).
"""

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "examples/adapted-agent"
SKIP = ("dev/", "proc/", "sys/")


def run(cmd, **kw):
    print("+", " ".join(str(c) for c in cmd), flush=True)
    return subprocess.run([str(c) for c in cmd], check=True, **kw)


def sha(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def extract(tar_path: Path, dest: Path) -> int:
    """Extracts a docker export without device nodes, FIFOs or the contents of
    dev/, proc/ and sys/ (the guest mounts its own)."""
    with tarfile.open(tar_path) as tar:
        members = []
        for m in tar.getmembers():
            name = m.name.lstrip("./")
            if m.isdev() or m.isfifo() or name == ".dockerenv" or any(name.startswith(p) for p in SKIP):
                continue
            members.append(m)
        kwargs = {"filter": "tar"} if hasattr(tarfile, "tar_filter") else {}
        tar.extractall(dest, members=members, **kwargs)
        return len(members)


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--go", default="go", help="Go toolchain")
    p.add_argument("--docker", default="docker")
    p.add_argument("--context", type=Path, default=EXAMPLE, help="agent image build context with a Dockerfile")
    p.add_argument("--adapter-config", type=Path, default=EXAMPLE / "adapter.json")
    p.add_argument("--manifest", type=Path, default=EXAMPLE / "harness.yaml")
    p.add_argument("--output", required=True, type=Path, help="new output directory")
    p.add_argument("--size-mib", type=int, default=256, help="harness.ext4 size")
    a = p.parse_args()
    out = a.output.resolve()
    if out.exists():
        print("output directory must be new", file=sys.stderr)
        return 2
    out.mkdir(parents=True)
    iid = out / "image.id"
    run([a.docker, "build", "--platform", "linux/amd64", "--iidfile", iid, a.context.resolve()])
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
    (out / "rootfs.tar").unlink()
    go_env = dict(os.environ, GOFLAGS="-mod=readonly")
    adapter = out / "capsule-adapter"
    run([a.go, "build", "-buildvcs=false", "-trimpath", "-tags=netgo,osusergo,sqlite_omit_load_extension",
         "-ldflags=-linkmode external -extldflags '-static'", "-o", adapter, "./cmd/capsule-adapter"],
        cwd=ROOT, env=dict(go_env, CGO_ENABLED="1"))
    target = rootfs / "agentcapsule"
    if target.exists():
        print("the agent image already has /agentcapsule", file=sys.stderr)
        return 2
    target.mkdir(mode=0o755)
    shutil.copy2(adapter, target / "capsule-adapter")
    (target / "capsule-adapter").chmod(0o755)
    shutil.copy2(a.adapter_config, target / "adapter.json")
    (target / "adapter.json").chmod(0o644)
    tool = out / "agentcapsule-harness"
    run([a.go, "build", "-trimpath", "-o", tool, "./cmd/agentcapsule-harness"], cwd=ROOT, env=dict(go_env, CGO_ENABLED="0"))
    run([tool, "pack", "--manifest", a.manifest, "--rootfs", rootfs, "--size-mib", a.size_mib, "--out", out / "package"])
    shutil.rmtree(rootfs)
    base = next(line.split()[1] for line in (a.context / "Dockerfile").read_text().splitlines() if line.startswith("FROM "))
    (out / "build.json").write_text(json.dumps({
        "context": str(a.context.resolve()), "base_image": base, "image_id": image, "extracted_entries": files,
        "capsule_adapter_sha256": sha(adapter), "adapter_config_sha256": sha(a.adapter_config),
        "package": json.loads((out / "package/checksums.json").read_text()),
    }, indent=2) + "\n")
    print(out / "package")
    return 0


if __name__ == "__main__":
    sys.exit(main())
