#!/usr/bin/env python3
"""Build the pi-agent harness package from an existing Pi installation.

Copies the installed Pi release (its node_modules, nothing else: no credential,
session or setting) and the Node.js binary it runs on into the build context of
examples/pi-agent, adds the one library that binary needs beyond Debian
(libatomic), then runs scripts/build-adapted-harness.py: Docker image, plus
capsule-adapter, packed into <output>/adapted/package. Pi itself is not changed.

The result depends on the local installation, so it is a test build, not a
reproducible one. Runs on a developer machine, never on the platform host. The
output directory must be new.
"""

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "examples/pi-agent"


def sha(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--pi-release", type=Path, required=True,
                   help="installed Pi release directory holding node_modules/.bin/pi (e.g. ~/.pi/agent/install/releases/<version>)")
    p.add_argument("--node", type=Path, required=True, help="the Node.js binary Pi runs on (glibc build, x86_64)")
    p.add_argument("--output", type=Path, required=True, help="new output directory")
    p.add_argument("--go", default="go")
    p.add_argument("--docker", default="docker")
    p.add_argument("--size-mib", type=int, default=640, help="harness.ext4 size")
    a = p.parse_args()
    release, node = a.pi_release.expanduser().resolve(), a.node.expanduser().resolve()
    if not (release / "node_modules/.bin/pi").exists():
        p.error("--pi-release must hold node_modules/.bin/pi")
    out = a.output.resolve()
    if out.exists():
        print("output directory must be new", file=sys.stderr)
        return 2
    out.mkdir(parents=True)
    context = out / "context"
    context.mkdir()
    for name in ("Dockerfile", "start", "models.json"):
        shutil.copy2(EXAMPLE / name, context / name)
    shutil.copytree(release / "node_modules", context / "pi" / "node_modules", symlinks=True)
    shutil.copy2(node, context / "node")
    linked = subprocess.run(["ldd", str(node)], check=True, capture_output=True, text=True).stdout
    match = re.search(r"libatomic\.so\.1 => (\S+)", linked)
    if not match:
        p.error("the node binary does not link libatomic; adapt examples/pi-agent/Dockerfile")
    shutil.copy2(Path(match.group(1)).resolve(), context / "libatomic.so.1")
    version = subprocess.run([str(node), str(release / "node_modules/.bin/pi"), "--version"], check=True, capture_output=True, text=True,
                             env={"PATH": str(node.parent) + ":/usr/bin:/bin", "HOME": str(out), "PI_OFFLINE": "1",
                                  "PI_SKIP_VERSION_CHECK": "1", "PI_TELEMETRY": "0", "PI_CODING_AGENT_DIR": str(out / "pi-version")}).stdout.strip()
    node_version = subprocess.run([str(node), "--version"], check=True, capture_output=True, text=True).stdout.strip()
    subprocess.run([sys.executable, str(ROOT / "scripts/build-adapted-harness.py"), "--go", a.go, "--docker", a.docker,
                    "--context", str(context), "--adapter-config", str(EXAMPLE / "adapter.json"), "--manifest", str(EXAMPLE / "harness.yaml"),
                    "--size-mib", str(a.size_mib), "--output", str(out / "adapted")], check=True)
    shutil.rmtree(context)
    shutil.rmtree(out / "pi-version", ignore_errors=True)
    (out / "pi-build.json").write_text(json.dumps({
        "pi_version": version, "pi_release": str(release), "node_version": node_version, "node_sha256": sha(node),
        "libatomic": str(Path(match.group(1)).resolve()), "package": str(out / "adapted/package"),
        "scope": "Test build from a local Pi installation; not reproducible elsewhere.",
    }, indent=2) + "\n")
    print(out / "adapted/package")
    return 0


if __name__ == "__main__":
    sys.exit(main())
