#!/usr/bin/env python3
"""Reproducible, partial upstream qualification. No system installation or Docker."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile
import time
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_TESTS = {
    "TestA2AJSONRPCTaskRoundTrip",
    "TestOASFVersionedDecoding",
    "TestDirectoryClientBuildAndConfiguration",
    "TestSLIMNativeABI",
}


def sha256(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--go", default="go", help="Go 1.27.3 executable")
    parser.add_argument("--output", required=True, type=Path, help="new evidence directory")
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    report = {"status": "failed", "int01_complete": False, "gate_g2_complete": False}
    started = time.monotonic()
    try:
        profile_path = ROOT / "runtime/interop/profile.json"
        profile = json.loads(profile_path.read_text())
        report["profile"] = profile["profile"]
        report["unexecuted_services"] = profile["required_services_not_executed"]
        report["host"] = {"system": platform.system(), "machine": platform.machine(), "libc": platform.libc_ver()}
        if platform.system() != "Linux" or platform.machine() != "x86_64" or platform.libc_ver()[0] != "glibc":
            raise RuntimeError("this profile requires Linux amd64 glibc")
        go = shutil.which(args.go)
        if not go or not shutil.which("cc"):
            raise RuntimeError("Go and a C compiler must already be installed")
        with tempfile.TemporaryDirectory(prefix="agentcapsule-interop-") as temporary:
            work = Path(temporary)
            source = work / "probe"
            shutil.copytree(ROOT / "runtime/interop/probe", source)
            frozen = {p.name: sha256(p) for p in source.iterdir() if p.is_file()}
            sources = [Path(__file__).resolve(), profile_path, *sorted((ROOT / "runtime/interop/probe").glob("*"))]
            report["source_sha256"] = {str(p.relative_to(ROOT)): sha256(p) for p in sources if p.is_file()}
            shutil.copy2(profile_path, output / "profile.json")
            # Allow no inherited credentials, Go flags, or protocol endpoint settings.
            env = {"PATH": os.defpath, "HOME": str(work), "GOENV": "off", "GOWORK": "off", "GOTOOLCHAIN": "local", "CGO_ENABLED": "1", "GOMAXPROCS": "2", "GOFLAGS": "-p=2", "GOPROXY": "https://proxy.golang.org", "GOSUMDB": "sum.golang.org"}
            # Share only module/build caches; neither stores runtime credentials.
            cache = Path(os.environ.get("XDG_CACHE_HOME", str(Path.home() / ".cache"))) / "agentcapsule-interop"
            cache.mkdir(parents=True, exist_ok=True)
            env["GOPATH"] = str(Path.home() / "go")
            env["GOCACHE"] = str(cache / "go-build")

            def run(name, command, timeout=600):
                print(name, flush=True)
                with (output / (name + ".log")).open("w") as log:
                    result = subprocess.run(command, cwd=source, env=env, stdout=log, stderr=subprocess.STDOUT, timeout=timeout, check=False)
                if result.returncode:
                    raise RuntimeError(f"{name} failed ({result.returncode}); see {name}.log")

            version = subprocess.check_output([go, "version"], env=env, text=True).strip()
            report["go"] = version
            if version != "go version " + profile["go"] + " linux/amd64":
                raise RuntimeError("Go version does not match the pinned profile")
            slim = profile["slim"]
            archive = cache / (slim["native_sha256"] + ".zip")
            if not archive.exists() or sha256(archive) != slim["native_sha256"]:
                print("download pinned SLIM native archive (~90 MB)", flush=True)
                with urllib.request.urlopen(slim["native_url"], timeout=60) as remote, (work / "native.zip").open("wb") as target:
                    total = 0
                    while chunk := remote.read(1024 * 1024):
                        total += len(chunk)
                        if total > slim["native_archive_bytes"]:
                            raise RuntimeError("native archive exceeds pinned size")
                        target.write(chunk)
                if sha256(work / "native.zip") != slim["native_sha256"]:
                    raise RuntimeError("native SHA256 mismatch")
                # The build directory can live on a different filesystem.
                with tempfile.NamedTemporaryFile(dir=cache, delete=False) as cached:
                    pending = Path(cached.name)
                    with (work / "native.zip").open("rb") as downloaded:
                        shutil.copyfileobj(downloaded, cached)
                os.replace(pending, archive)
            report["native_archive_sha256"] = sha256(archive)
            library = work / "native"
            library.mkdir()
            with zipfile.ZipFile(archive) as zipped:
                matches = [entry for entry in zipped.infolist() if Path(entry.filename).name == slim["native_library"]]
                if len(matches) != 1 or matches[0].file_size > 1024 * 1024 * 1024:
                    raise RuntimeError("unexpected native archive contents")
                with zipped.open(matches[0]) as incoming, (library / slim["native_library"]).open("wb") as outgoing:
                    shutil.copyfileobj(incoming, outgoing)
            report["native_library_sha256"] = sha256(library / slim["native_library"])
            if report["native_library_sha256"] != slim["native_library_sha256"]:
                raise RuntimeError("native library SHA256 mismatch")
            env["CGO_LDFLAGS"] = "-L" + str(library)
            run("modules", [go, "mod", "download"], timeout=600)
            run("module-integrity", [go, "mod", "verify"])
            run("tests", [go, "test", "-mod=readonly", "-count=1", "-json", "-timeout=60s", "."], timeout=600)
            if {p.name: sha256(p) for p in source.iterdir() if p.is_file()} != frozen:
                raise RuntimeError("Go modified the frozen module; update committed dependencies first")
            events = []
            for line in (output / "tests.log").read_text().splitlines():
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    continue  # Compiler diagnostics are retained, and command status checked.
            passed = {e["Test"] for e in events if e.get("Action") == "pass" and "Test" in e}
            if passed != EXPECTED_TESTS or any(e.get("Action") in ("skip", "fail") for e in events):
                raise RuntimeError("expected test set was not fully executed without skips")
            if any(sha256(ROOT / name) != digest for name, digest in report["source_sha256"].items()):
                raise RuntimeError("sources changed during qualification")
            report["passed_tests"] = sorted(passed)
            report["status"] = "passed_partial_qualification"
    except Exception as error:
        report["error"] = str(error)
    finally:
        report["elapsed_seconds"] = round(time.monotonic() - started, 3)
        (output / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report, indent=2))
    return 0 if report["status"] == "passed_partial_qualification" else 1


if __name__ == "__main__":
    raise SystemExit(main())
