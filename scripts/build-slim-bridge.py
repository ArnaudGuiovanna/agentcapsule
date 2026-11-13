#!/usr/bin/env python3
"""Build the platform's SLIM bridge (runtime/slimbridge) for the product KVM
campaign (verify-product-guest.py --slim-bridge-build).

The bridge links the pinned SLIM native library (runtime/interop/profile.json),
taken from the archive that scripts/verify-interop.py caches
(~/.cache/agentcapsule-interop) and checked by SHA256 at every step. Runs as an
ordinary user, never on the platform host. The output directory must be new:
it receives the binary and artifacts.json (the binary's, the native library's
and every source's digest), which the campaign checks before it runs anything.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
BRIDGE = ROOT / "runtime/slimbridge"
PROFILE = ROOT / "runtime/interop/profile.json"


def sha(path: Path) -> str:
    with path.open("rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()


def sources():
    """The files the binary is built from, relative to the repository."""
    files = [p for p in sorted(BRIDGE.rglob("*")) if p.is_file() and "__pycache__" not in p.parts]
    return [p.relative_to(ROOT) for p in files + [PROFILE]]


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--go", required=True, type=Path, help="Go executable of the pinned version")
    p.add_argument("--output", required=True, type=Path, help="new output directory")
    p.add_argument("--cache", type=Path, default=Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache")) / "agentcapsule-interop",
                   help="directory holding the native archive cached by verify-interop.py")
    a = p.parse_args()
    slim = json.loads(PROFILE.read_text())["slim"]
    archive = a.cache / (slim["native_sha256"] + ".zip")
    if not archive.is_file() or sha(archive) != slim["native_sha256"]:
        p.error(f"the pinned SLIM archive is not in {a.cache}: run scripts/verify-interop.py once to fetch it")
    out = a.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    before = {str(f): sha(ROOT / f) for f in sources()}
    with tempfile.TemporaryDirectory(prefix="slim-native-") as native:
        library = Path(native) / slim["native_library"]
        with zipfile.ZipFile(archive) as zipped:
            entries = [e for e in zipped.infolist() if Path(e.filename).name == slim["native_library"]]
            if len(entries) != 1:
                p.error("unexpected native archive contents")
            with zipped.open(entries[0]) as incoming, library.open("wb") as outgoing:
                shutil.copyfileobj(incoming, outgoing)
        if sha(library) != slim["native_library_sha256"]:
            p.error("native library SHA256 mismatch")
        env = {**os.environ, "CGO_ENABLED": "1", "CGO_LDFLAGS": "-L" + native, "GOWORK": "off", "GOFLAGS": "-mod=readonly", "GOTOOLCHAIN": "local"}
        version = subprocess.check_output([str(a.go), "version"], env=env, text=True).strip()
        if version != "go version " + json.loads(PROFILE.read_text())["go"] + " linux/amd64":
            p.error("Go version does not match the pinned profile: " + version)
        binary = out / "agentcapsule-slim-bridge"
        with (out / "build.log").open("w") as log:
            built = subprocess.run([str(a.go), "build", "-trimpath", "-buildvcs=false", "-o", str(binary), "."], cwd=BRIDGE, env=env,
                                   stdout=log, stderr=subprocess.STDOUT, check=False)
        if built.returncode:
            print("build failed; see", out / "build.log", file=sys.stderr)
            return 1
        native_sha = sha(library)
    if {str(f): sha(ROOT / f) for f in sources()} != before:
        print("sources changed during the build", file=sys.stderr)
        return 1
    artifacts = {"go": version, "native_library_sha256": native_sha, "binary": binary.name, "binary_sha256": sha(binary),
                 "source_sha256": before}
    (out / "artifacts.json").write_text(json.dumps(artifacts, indent=2) + "\n")
    print("built", binary)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
