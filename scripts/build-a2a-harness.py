#!/usr/bin/env python3
"""Build the a2a-agent harness package: an A2A server agent run by capsule-adapter.

examples/a2a-agent is a Go program written against the official A2A Go SDK; it
knows nothing of Agent Capsule. This script builds it (static, without cgo) and
capsule-adapter (static, cgo for SQLite), lays out a root filesystem holding
only /opt/agent/a2a-agent, /agentcapsule/capsule-adapter and
/agentcapsule/adapter.json, and packs it with agentcapsule-harness into
<output>/package, ready for agentcapsule-harness push. No Docker: the agent
needs no base image. Runs on a developer machine or in CI, never on the platform
host. The output directory must be new. Building capsule-adapter needs cgo and
static C libraries, as for build-adapted-harness.py (set CPATH if needed).
"""

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "examples/a2a-agent"


def run(cmd, **kw):
    print("+", " ".join(str(c) for c in cmd), flush=True)
    return subprocess.run([str(c) for c in cmd], check=True, **kw)


def sha(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--go", default="go", help="Go toolchain")
    p.add_argument("--output", required=True, type=Path, help="new output directory")
    p.add_argument("--size-mib", type=int, default=64, help="harness.ext4 size")
    a = p.parse_args()
    out = a.output.resolve()
    if out.exists():
        print("output directory must be new", file=sys.stderr)
        return 2
    out.mkdir(parents=True)
    go_env = dict(os.environ, GOFLAGS="-mod=readonly")
    agent, adapter, tool = out / "a2a-agent", out / "capsule-adapter", out / "agentcapsule-harness"
    run([a.go, "build", "-buildvcs=false", "-trimpath", "-ldflags=-s -w", "-o", agent, "./examples/a2a-agent"],
        cwd=ROOT, env=dict(go_env, CGO_ENABLED="0"))
    run([a.go, "build", "-buildvcs=false", "-trimpath", "-tags=netgo,osusergo,sqlite_omit_load_extension",
         "-ldflags=-linkmode external -extldflags '-static'", "-o", adapter, "./cmd/capsule-adapter"],
        cwd=ROOT, env=dict(go_env, CGO_ENABLED="1"))
    run([a.go, "build", "-trimpath", "-o", tool, "./cmd/agentcapsule-harness"], cwd=ROOT, env=dict(go_env, CGO_ENABLED="0"))
    rootfs = out / "rootfs"
    for path, source, mode in [("opt/agent/a2a-agent", agent, 0o755), ("agentcapsule/capsule-adapter", adapter, 0o755),
                               ("agentcapsule/adapter.json", EXAMPLE / "adapter.json", 0o644)]:
        target = rootfs / path
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
        shutil.copy2(source, target)
        target.chmod(mode)
    run([tool, "pack", "--manifest", EXAMPLE / "harness.yaml", "--rootfs", rootfs, "--size-mib", a.size_mib, "--out", out / "package"])
    shutil.rmtree(rootfs)
    (out / "build.json").write_text(json.dumps({
        "a2a_agent_sha256": sha(agent), "capsule_adapter_sha256": sha(adapter),
        "adapter_config_sha256": sha(EXAMPLE / "adapter.json"),
        "package": json.loads((out / "package/checksums.json").read_text()),
    }, indent=2) + "\n")
    print(out / "package")
    return 0


if __name__ == "__main__":
    sys.exit(main())
