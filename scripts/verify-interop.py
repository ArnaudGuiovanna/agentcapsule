#!/usr/bin/env python3
"""Reproducible qualification of the pinned interoperability profile.

Without --services: the libraries only (A2A, OASF, Directory and SLIM Go
modules, the SLIM native library), no Docker. With --services: also the private
services of deploy/interop (OASF schema server, Directory behind its mutual-TLS
edge, SLIM node) started from pinned images with lab certificates, then driven
by Go tests: publish, search and validation in Directory, refused identities,
exchanges through the SLIM node, A2A over SLIM, and the platform's own
Directory publisher (internal/directory).
"""
import argparse
import contextlib
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
LIBRARY_TESTS = {
    "TestA2AJSONRPCTaskRoundTrip",
    "TestOASFVersionedDecoding",
    "TestDirectoryClientBuildAndConfiguration",
    "TestSLIMNativeABI",
}
SERVICE_TESTS = {
    "TestDirectoryPublishesSearchesAndDeletes",
    "TestDirectoryValidatesRecordsAgainstThePrivateSchema",
    "TestDirectoryEdgeAdmitsOnlyTheControlPlane",
    "TestSLIMExchangeThroughThePrivateNode",
    "TestSLIMNodeAdmitsOnlyTheSLIMAuthority",
    "TestSLIMKeepsNothingForAnAbsentRecipient",
}
A2A_SLIM_TESTS = {"TestA2AOverSLIMThroughThePrivateNode"}
# The platform's own Directory client and publisher (internal/directory).
PLATFORM_TESTS = {"TestPublisherAgainstThePrivateDirectory"}


def sha256(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def tree_digests(base):
    return {str(p.relative_to(base)): sha256(p) for p in sorted(base.rglob("*")) if p.is_file()}


def passed_tests(log, expected):
    events = []
    for line in log.read_text().splitlines():
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue  # Compiler diagnostics are retained, and command status checked.
    passed = {e["Test"] for e in events if e.get("Action") == "pass" and "Test" in e and "/" not in e["Test"]}
    if passed != expected or any(e.get("Action") in ("skip", "fail") for e in events):
        raise RuntimeError(f"expected test set was not fully executed without skips; see {log.name}")
    return sorted(passed)


def stop_services(compose, docker_env, output):
    with (output / "services.log").open("w") as log:
        subprocess.run([*compose, "logs", "--no-color", "--timestamps"], env=docker_env, stdout=log, stderr=subprocess.STDOUT, timeout=120, check=False)
    down = subprocess.run([*compose, "down", "-v", "--remove-orphans"], env=docker_env, capture_output=True, text=True, timeout=300, check=False)
    if down.returncode:
        raise RuntimeError("could not remove the services: " + down.stderr.strip()[-500:])


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--go", default="go", help="Go 1.27.3 executable")
    parser.add_argument("--output", required=True, type=Path, help="new evidence directory")
    parser.add_argument("--services", action="store_true", help="also start and test the private services (Docker Compose)")
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    report = {"status": "failed", "services_tested": args.services, "gate_g2_complete": False}
    started = time.monotonic()
    profile = {}
    try:
        profile_path = ROOT / "runtime/interop/profile.json"
        profile = json.loads(profile_path.read_text())
        report["profile"] = profile["profile"]
        report["host"] = {"system": platform.system(), "machine": platform.machine(), "libc": platform.libc_ver()}
        if platform.system() != "Linux" or platform.machine() != "x86_64" or platform.libc_ver()[0] != "glibc":
            raise RuntimeError("this profile requires Linux amd64 glibc")
        go = shutil.which(args.go)
        if not go or not shutil.which("cc"):
            raise RuntimeError("Go and a C compiler must already be installed")
        if args.services and not (shutil.which("docker") and shutil.which("openssl")):
            raise RuntimeError("--services needs Docker with Compose and openssl")
        with tempfile.TemporaryDirectory(prefix="agentcapsule-interop-") as temporary, contextlib.ExitStack() as cleanup:
            work = Path(temporary)
            modules = {"probe": work / "probe", "a2aslim": work / "a2aslim", "deploy": work / "deploy"}
            shutil.copytree(ROOT / "runtime/interop/probe", modules["probe"])
            shutil.copytree(ROOT / "runtime/interop/a2aslim", modules["a2aslim"])
            shutil.copytree(ROOT / "deploy/interop", modules["deploy"])
            frozen = {name: tree_digests(path) for name, path in modules.items()}
            sources = [Path(__file__).resolve(), profile_path, *sorted((ROOT / "runtime/interop").rglob("*")), *sorted((ROOT / "deploy/interop").rglob("*")),
                       ROOT / "go.mod", ROOT / "go.sum", *sorted((ROOT / "internal/directory").glob("*.go"))]
            report["source_sha256"] = {str(p.relative_to(ROOT)): sha256(p) for p in sources if p.is_file()}
            shutil.copy2(profile_path, output / "profile.json")
            # Allow no inherited credentials, Go flags, or protocol endpoint settings.
            env = {"PATH": os.defpath, "HOME": str(work), "GOENV": "off", "GOWORK": "off", "GOTOOLCHAIN": "local", "CGO_ENABLED": "1", "GOMAXPROCS": "2", "GOFLAGS": "-p=2", "GOPROXY": "https://proxy.golang.org", "GOSUMDB": "sum.golang.org"}
            # Share only module/build caches; neither stores runtime credentials.
            cache = Path(os.environ.get("XDG_CACHE_HOME", str(Path.home() / ".cache"))) / "agentcapsule-interop"
            cache.mkdir(parents=True, exist_ok=True)
            env["GOPATH"] = str(Path.home() / "go")
            env["GOCACHE"] = str(cache / "go-build")

            def run(name, command, cwd, timeout=600, extra=None, environment=None):
                print(name, flush=True)
                with (output / (name + ".log")).open("w") as log:
                    result = subprocess.run(command, cwd=cwd, env=environment or {**env, **(extra or {})}, stdout=log, stderr=subprocess.STDOUT, timeout=timeout, check=False)
                if result.returncode:
                    raise RuntimeError(f"{name} failed ({result.returncode}); see {name}.log")
                return output / (name + ".log")

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
            probe = modules["probe"]
            run("modules", [go, "mod", "download"], probe)
            run("module-integrity", [go, "mod", "verify"], probe)
            if not args.services:
                log = run("tests", [go, "test", "-mod=readonly", "-count=1", "-json", "-timeout=60s", "."], probe)
                report["passed_tests"] = passed_tests(log, LIBRARY_TESTS)
            else:
                a2aslim = modules["a2aslim"]
                run("a2aslim-modules", [go, "mod", "download"], a2aslim)
                run("a2aslim-module-integrity", [go, "mod", "verify"], a2aslim)
                certs = work / "certs"
                run("certificates", ["sh", str(modules["deploy"] / "make-certs.sh"), str(certs), "--test-identities"], work, timeout=120)
                # Docker keeps the caller's environment (context, socket); the
                # services get only the lab certificates and loopback ports.
                docker_env = {**os.environ, "INTEROP_CERTS": str(certs), "INTEROP_DIRECTORY_PORT": "0", "INTEROP_SLIM_PORT": "0"}
                compose = ["docker", "compose", "-p", f"agentcapsule-interop-{os.getpid()}", "-f", str(modules["deploy"] / "compose.yml")]
                report["compose"] = subprocess.check_output(["docker", "compose", "version", "--short"], text=True).strip()
                # Registered before start-up, run before the compose file is deleted.
                cleanup.callback(stop_services, compose, docker_env, output)
                run("services-up", [*compose, "up", "-d", "--wait", "--quiet-pull"], work, timeout=900, environment=docker_env)

                def compose_output(*command):
                    return subprocess.check_output([*compose, *command], env=docker_env, text=True, timeout=60).strip()

                containers = {}
                for cid in compose_output("ps", "-a", "-q").split():
                    service, image, state = subprocess.check_output(["docker", "inspect", "--format", '{{index .Config.Labels "com.docker.compose.service"}} {{.Config.Image}} {{.State.Status}}', cid], text=True).split()
                    containers[service] = {"image": image, "state": state}
                report["services"] = containers
                if {s: c["image"] for s, c in containers.items()} != profile["services"]:
                    raise RuntimeError("the running images are not the pinned ones")
                directory = compose_output("port", "directory-edge", "8443")
                slim_node = compose_output("port", "slim", "46357")
                if not directory.startswith("127.0.0.1:") or not slim_node.startswith("127.0.0.1:"):
                    raise RuntimeError("a service port is published beyond loopback")

                def stats(name):
                    ids = compose_output("ps", "-q").split()
                    lines = subprocess.check_output(["docker", "stats", "--no-stream", "--format", "{{json .}}", *ids], text=True, timeout=120).splitlines()
                    report.setdefault("footprint", {})[name] = {json.loads(l)["Name"]: {"memory": json.loads(l)["MemUsage"], "cpu": json.loads(l)["CPUPerc"]} for l in lines}

                stats("idle")
                extra = {"INTEROP_CERTS": str(certs), "INTEROP_DIRECTORY_ADDR": directory, "INTEROP_SLIM_ENDPOINT": "https://" + slim_node}
                log = run("tests", [go, "test", "-mod=readonly", "-tags=interop_services", "-count=1", "-json", "-timeout=300s", "."], probe, timeout=900, extra=extra)
                report["passed_tests"] = passed_tests(log, LIBRARY_TESTS | SERVICE_TESTS)
                log = run("a2aslim-tests", [go, "test", "-mod=readonly", "-tags=interop_services", "-count=1", "-json", "-timeout=300s", "."], a2aslim, timeout=900, extra=extra)
                report["passed_a2aslim_tests"] = passed_tests(log, A2A_SLIM_TESTS)
                # In place, read-only: only internal/directory and its imports
                # are built, without CGO.
                log = run("platform-tests", [go, "test", "-mod=readonly", "-tags=interop_services", "-count=1", "-json", "-timeout=300s",
                                             "-run", "AgainstThePrivateDirectory", "./internal/directory"], ROOT, timeout=900, extra={**extra, "CGO_ENABLED": "0"})
                report["passed_platform_tests"] = passed_tests(log, PLATFORM_TESTS)
                stats("after_tests")
            if {name: tree_digests(path) for name, path in modules.items()} != frozen:
                raise RuntimeError("Go modified a frozen module; update committed dependencies first")
            if any(sha256(ROOT / name) != digest for name, digest in report["source_sha256"].items()):
                raise RuntimeError("sources changed during qualification")
            report["status"] = "passed" if args.services else "passed_libraries_only"
    except Exception as error:
        report["status"] = "failed"  # also when only the services' removal failed
        report["error"] = str(error)
    finally:
        report["int01_complete"] = report["status"] == "passed" and profile.get("int01_complete", False)
        report["elapsed_seconds"] = round(time.monotonic() - started, 3)
        (output / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report, indent=2))
    return 0 if report["status"] in ("passed", "passed_libraries_only") else 1


if __name__ == "__main__":
    raise SystemExit(main())
