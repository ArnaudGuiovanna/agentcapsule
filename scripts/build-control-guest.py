#!/usr/bin/env python3
"""Build the disposable authenticated SQL harness from frozen Go sources.

The resulting static /init uses the real capsuleprotocol and harnessstore. It is
a test fixture, not the complete capsule-init supervisor or a user harness.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--go", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    out = a.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    src = out / "sources"
    src.mkdir()
    for name in ("go.mod", "go.sum"):
        shutil.copy2(ROOT / name, src / name)
    for name in ("internal/capsuleprotocol", "internal/harnessstore", "internal/verification/controlguest"):
        shutil.copytree(ROOT / name, src / name)
    (src / "scripts").mkdir()
    shutil.copy2(Path(__file__), src / "scripts" / Path(__file__).name)
    hashes = {str(f.relative_to(src)): hashlib.sha256(f.read_bytes()).hexdigest()
              for f in src.rglob("*") if f.is_file()}
    go = a.go.resolve()
    command = [str(go), "build", "-trimpath", "-tags=netgo,osusergo,sqlite_omit_load_extension",
               "-ldflags=-linkmode external -extldflags '-static'", "-o", str(out / "init"), "./internal/verification/controlguest"]
    metadata = {"source_sha256": hashes,
                "go": subprocess.check_output([str(go), "version"], text=True).strip(),
                "command": command, "env": {"CGO_ENABLED": "1"},
                "scope": "Disposable SQL harness fixture; authenticated control protocol and real SQLite; not a production capsule-init supervisor."}
    (out / "environment.json").write_text(json.dumps(metadata, indent=2) + "\n")
    start = time.monotonic()
    with (out / "build.log").open("w") as log:
        result = subprocess.run(command, cwd=src, env=dict(os.environ, CGO_ENABLED="1"),
                                stdout=log, stderr=subprocess.STDOUT, timeout=300)
    summary = {"passed": result.returncode == 0, "returncode": result.returncode,
               "seconds": round(time.monotonic() - start, 3)}
    if result.returncode == 0:
        summary["sha256"] = hashlib.sha256((out / "init").read_bytes()).hexdigest()
        summary["go_build_info"] = subprocess.check_output([str(go), "version", "-m", str(out / "init")], text=True)
    (out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps({k: v for k, v in summary.items() if k != "go_build_info"}), flush=True)
    raise SystemExit(result.returncode)


if __name__ == "__main__":
    main()
