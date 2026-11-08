#!/usr/bin/env python3
"""Build the pinned AgentCapsule Firecracker variant with VMM-owned file locks.

Requires the pinned Rust toolchain, musl-gcc, cmake, pkg-config and patch. Source,
patch, Cargo.lock, release logs and artifact digests are retained. This is a
downstream build, never presented as the official upstream release binary.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import time
import urllib.request


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output", required=True, type=Path)
    p.add_argument("--cargo", default="cargo")
    p.add_argument("--source-archive", type=Path)
    p.add_argument("--target-dir", type=Path, help="Optional Cargo build cache shared by build attempts")
    args = p.parse_args()
    root = Path(__file__).resolve().parents[1]
    inputs = root / "runtime/firecracker"
    manifest = json.loads((inputs / "manifest.json").read_text())
    patch = inputs / manifest["patch"]
    assert sha(patch) == manifest["patch_sha256"], "patch checksum mismatch"
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    shutil.copy2(inputs / "manifest.json", out / "manifest.json")
    shutil.copy2(patch, out / patch.name)
    shutil.copy2(__file__, out / "build-firecracker.py")
    archive = out / "upstream.tgz"
    if args.source_archive:
        shutil.copyfile(args.source_archive, archive)
    else:
        urllib.request.urlretrieve(manifest["source_url"], archive)
    assert sha(archive) == manifest["source_sha256"], "upstream checksum mismatch"
    with tarfile.open(archive) as t:
        t.extractall(out, filter="data")
    source = out / ("firecracker-" + manifest["version"])
    target_dir = (args.target_dir or source / "build/cargo_target").resolve()
    # musl-gcc intentionally omits glibc's include directory. Add only Linux
    # UAPI headers, avoiding accidental mixing of musl and glibc headers.
    headers = out / "linux-uapi"
    headers.mkdir()
    for name, original in [("linux", "/usr/include/linux"), ("asm-generic", "/usr/include/asm-generic"),
                           ("asm", "/usr/include/x86_64-linux-gnu/asm")]:
        (headers / name).symlink_to(original)
    env = {**os.environ, "RUSTUP_TOOLCHAIN": manifest["rust_toolchain"], "CARGO_BUILD_JOBS": "2",
           "CARGO_TARGET_DIR": str(target_dir),
           "CFLAGS_x86_64_unknown_linux_musl": "-isystem " + str(headers)}
    records = []

    def run(label, command, timeout=1200):
        start = time.monotonic()
        print(label, flush=True)
        with (out / (label + ".log")).open("w") as log:
            try:
                r = subprocess.run(command, cwd=source, env=env, stdout=log, stderr=subprocess.STDOUT, timeout=timeout)
                rc = r.returncode
            except subprocess.TimeoutExpired:
                rc = 124
        records.append({"phase": label, "command": command, "returncode": rc,
                        "seconds": round(time.monotonic() - start, 3), "passed": rc == 0})
        (out / "summary.json").write_text(json.dumps(records, indent=2) + "\n")
        if rc:
            raise RuntimeError(f"{label} failed ({rc}); see {out / (label + '.log')}")

    run("patch", ["patch", "--batch", "--fuzz=0", "-p1", "-i", str(patch)], 60)
    shutil.copy2(source / "Cargo.lock", out / "Cargo.lock")
    run("cargo-version", [args.cargo, "--version"], 60)
    run("build", [args.cargo, "build", "--locked", "--release", "--target", manifest["target"],
                  "-p", "firecracker", "-p", "jailer", "--bin", "firecracker", "--bin", "jailer"])
    run("lock-unit-tests", [args.cargo, "test", "--locked", "--release", "--target", manifest["target"],
                           "-p", "vmm", "test_disk_backing_file_lock", "--", "--nocapture"])
    artifacts = {}
    for name in ("firecracker", "jailer"):
        src = target_dir / manifest["target"] / "release" / name
        shutil.copy2(src, out / name)
        artifacts[name] = sha(out / name)
    (out / "artifacts.json").write_text(json.dumps({"variant": "agentcapsule-volume-lock-v1",
                                                   "upstream": manifest, "sha256": artifacts,
                                                   "build_script_sha256": sha(Path(__file__))}, indent=2) + "\n")
    print(json.dumps(artifacts), flush=True)


if __name__ == "__main__":
    main()
