#!/usr/bin/env python3
"""Build the pinned guest kernel with encrypted-volume support, without root.

Only the new --output directory is written. This never installs a host kernel,
loads a module, mounts an image or alters the running WSL kernel.
"""
import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tarfile
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[1]


def sha(path):
    with path.open("rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--tools", type=Path, help="Optional privately extracted build tools (usr/bin, usr/include)")
    p.add_argument("--source-archive", type=Path, help="Reuse an existing source archive after checking its pinned hash")
    p.add_argument("--jobs", type=int, default=4)
    a = p.parse_args()
    if not 1 <= a.jobs <= 16:
        p.error("--jobs must be between 1 and 16")
    source_manifest = ROOT / "runtime/guest/kernel.json"
    spec = json.loads(source_manifest.read_text())
    config = source_manifest.parent / spec["base_config"]
    assert sha(config) == spec["base_config_sha256"], "base config checksum mismatch"
    out = a.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    shutil.copy2(source_manifest, out / "kernel.json")
    shutil.copy2(config, out / "base.config")
    shutil.copy2(Path(__file__), out / "build-guest-kernel.py")
    env = dict(os.environ, KBUILD_BUILD_TIMESTAMP="2026-11-07 00:00:00 UTC",
               KBUILD_BUILD_USER="agentcapsule", KBUILD_BUILD_HOST="guest-build", KBUILD_BUILD_VERSION="1")
    if a.tools:
        tools = a.tools.resolve()
        env["PATH"] = str(tools / "usr/bin") + os.pathsep + env.get("PATH", "")
        env["BISON_PKGDATADIR"] = str(tools / "usr/share/bison")
        env["M4"] = str(tools / "usr/bin/m4")
        env["CPATH"] = str(tools / "usr/include")
        env["LIBRARY_PATH"] = str(tools / "usr/lib/x86_64-linux-gnu")
        env["LD_LIBRARY_PATH"] = env["LIBRARY_PATH"]
        if (tools / "packages.json").is_file():
            shutil.copy2(tools / "packages.json", out / "build-tools.json")
    records = []

    def record():
        (out / "summary.json").write_text(json.dumps(records, indent=2) + "\n")

    def run(label, command, cwd, timeout=120):
        start = time.monotonic()
        item = {"phase": label, "command": [str(x) for x in command], "status": "running"}
        records.append(item)
        record()
        print("RUN", label, flush=True)
        with (out / (label + ".log")).open("w") as log:
            proc = subprocess.Popen(item["command"], cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                    stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
            try:
                rc = proc.wait(timeout=timeout)
            except BaseException:
                os.killpg(proc.pid, signal.SIGTERM)
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    os.killpg(proc.pid, signal.SIGKILL)
                    proc.wait()
                item.update(status="interrupted_or_timed_out", seconds=round(time.monotonic()-start, 3))
                record()
                raise
        item.update(status="passed" if rc == 0 else "failed", returncode=rc, seconds=round(time.monotonic()-start, 3))
        record()
        print(item["status"].upper(), label, item["seconds"], "s", flush=True)
        if rc:
            raise RuntimeError(f"{label} failed; inspect {out / (label + '.log')}")

    archive = out / "linux.tar.xz"
    if a.source_archive:
        assert sha(a.source_archive) == spec["source_sha256"], "cached Linux source checksum mismatch"
        shutil.copy2(a.source_archive, archive)
    else:
        print("DOWNLOAD", spec["source_url"], flush=True)
        with urllib.request.urlopen(spec["source_url"], timeout=90) as response, archive.open("wb") as f:
            shutil.copyfileobj(response, f)
    assert sha(archive) == spec["source_sha256"], "Linux source checksum mismatch"
    source_root = out / "source"
    source_root.mkdir()
    with tarfile.open(archive) as tar:
        tar.extractall(source_root, filter="data")
    source = source_root / ("linux-" + spec["version"])
    build = out / "build"
    build.mkdir()
    shutil.copy2(config, build / ".config")
    command = [source / "scripts/config", "--file", build / ".config"]
    for name in spec["required_builtins"]:
        command += ["--enable", name]
    command += ["--set-str", "LOCALVERSION", spec["localversion"], "--disable", "LOCALVERSION_AUTO"]
    run("config", command, source)
    make = ["make", "O=" + str(build)]
    run("olddefconfig", make + ["olddefconfig"], source)
    options = (build / ".config").read_text().splitlines()
    for name in spec["required_builtins"]:
        assert "CONFIG_" + name + "=y" in options, f"required built-in unavailable: {name}"
    run("kernel", make + ["-j" + str(a.jobs), "vmlinux"], source, timeout=3600)
    shutil.copy2(build / "vmlinux", out / "vmlinux")
    shutil.copy2(build / ".config", out / "config")
    artifact = {"built_at": dt.datetime.now(dt.timezone.utc).isoformat(), "source": spec,
                "script_sha256": sha(out / "build-guest-kernel.py"),
                "sha256": {name: sha(out / name) for name in ["vmlinux", "config"]},
                "compiler": subprocess.check_output(["gcc", "--version"], env=env, text=True).splitlines()[0],
                "scope": "Kernel compilation and built-in configuration checks only; boot and encrypted storage not yet exercised."}
    (out / "artifacts.json").write_text(json.dumps(artifact, indent=2) + "\n")
    print("ARTIFACT", out / "vmlinux", flush=True)


if __name__ == "__main__":
    main()
