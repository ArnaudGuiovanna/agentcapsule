#!/usr/bin/env python3
"""Check the current Go packages without PostgreSQL or KVM.

Only cmd/, internal/, go.mod and go.sum are copied into a fresh source snapshot.
Expected PostgreSQL skips are reported as required work, never as validation.
Use verify-postgres.py and the KVM runners for the integration gates.
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
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
GO_VERSION = "go1.27.3"
PACKAGES = ("./cmd/...", "./internal/...")
PG_SKIP_MESSAGES = {
    "run scripts/verify-postgres.py",
    "run scripts/verify-postgres.py for real PostgreSQL integration checks",
}
PG_PACKAGES = ("internal/api", "internal/controlplane", "internal/worker")


def source_files(root):
    files = [root / "go.mod", root / "go.sum"]
    for name in ("cmd", "internal"):
        directory = root / name
        if not directory.is_dir() or directory.is_symlink():
            raise ValueError(f"missing or linked source directory: {name}")
        for path in sorted(directory.rglob("*")):
            if path.is_symlink():
                raise ValueError(f"linked source is not supported: {path.relative_to(root)}")
            if path.is_file():
                files.append(path)
    for path in files:
        if not path.is_file() or path.is_symlink():
            raise ValueError(f"missing or linked source: {path.relative_to(root)}")
    return files


def source_hashes(root):
    return {str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in source_files(root)}


def freeze_sources(root, target):
    before = source_hashes(root)
    target.mkdir()
    for name in before:
        destination = target / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(root / name, destination)
    if source_hashes(target) != before or source_hashes(root) != before:
        raise ValueError("sources changed during capture; use a new output directory and retry")
    return before


def local_environment(environ, go):
    # Never inherit a test database or a subprocess crash-helper invocation.
    env = {key: value for key, value in environ.items()
           if not key.startswith(("AGENTCAPSULE_", "AC_", "CAPSULE_CRASH_", "PG"))}
    env.update(GOTOOLCHAIN="local", GOENV="off", GOWORK="off", GOFLAGS="-mod=readonly",
               CGO_ENABLED="1", GOOS="linux", GOARCH="amd64", GOEXPERIMENT="")
    env["PATH"] = str(go.parent) + os.pathsep + env.get("PATH", os.defpath)
    return env


def analyze_events(events, module):
    outputs, passed, skipped, failures = {}, [], [], []
    empty_packages, packages, terminal = set(), set(), set()
    for event in events:
        if not isinstance(event, dict):
            raise ValueError("invalid go test JSON event")
        package, test = event.get("Package", ""), event.get("Test")
        if package:
            if not any(package.startswith(module + "/" + prefix + "/") or
                       package == module + "/" + prefix for prefix in ("cmd", "internal")):
                raise ValueError(f"unexpected package outside cmd/internal: {package}")
            packages.add(package)
        action = event.get("Action")
        if action == "output":
            output = event.get("Output", "")
            outputs.setdefault((package, test), []).append(output)
            if "[no test files]" in output and not test:
                empty_packages.add(package)
        elif action == "pass" and test:
            passed.append({"package": package, "test": test})
        elif action == "skip":
            skipped.append((package, test))
        elif action == "fail":
            failures.append({"package": package, "test": test})
        if not test and action in ("pass", "skip", "fail"):
            terminal.add(package)
    expected_skips, unexpected_skips = [], []
    for package, test in skipped:
        if not test and package in empty_packages:
            continue
        lines = "".join(outputs.get((package, test), [])).splitlines()
        reason = next((line.strip().split(": ", 1)[-1] for line in lines
                       if line.strip().split(": ", 1)[-1] in PG_SKIP_MESSAGES), None)
        item = {"package": package, "test": test, "reason": reason}
        if test and package in {module + "/" + name for name in PG_PACKAGES} and reason:
            expected_skips.append(item)
        else:
            unexpected_skips.append(item)
    return {
        "passed_tests": passed,
        "required_postgres_tests_not_run": expected_skips,
        "unexpected_skips": unexpected_skips,
        "failed_tests_or_packages": failures,
        "packages_without_tests": sorted(empty_packages),
        "packages_without_terminal_event": sorted(packages - terminal),
        "packages": sorted(packages),
    }


def run_tests(command, sources, env, output, timeout):
    with (output / "tests.jsonl").open("w") as stdout, (output / "tests.stderr.log").open("w") as stderr:
        proc = subprocess.Popen(command, cwd=sources, env=env, stdout=stdout, stderr=stderr,
                                stdin=subprocess.DEVNULL, start_new_session=True)
        try:
            return proc.wait(timeout=timeout)
        except BaseException:
            if proc.poll() is None:
                os.killpg(proc.pid, signal.SIGTERM)
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    os.killpg(proc.pid, signal.SIGKILL)
                    proc.wait()
            raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--go", default="go", help=f"Go executable; {GO_VERSION} is required")
    parser.add_argument("--native-tools", type=Path,
                        help="Root containing usr/include/libcryptsetup.h; omit for system headers")
    parser.add_argument("--output", type=Path, help="Fresh evidence directory, never overwritten")
    parser.add_argument("--timeout", type=int, default=300, help="Whole test process timeout in seconds")
    parser.add_argument("--fail-on-skip", action="store_true",
                        help="Return nonzero even for expected PostgreSQL skips; does not run PostgreSQL")
    args = parser.parse_args(argv)
    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    selected = shutil.which(args.go)
    if selected is None:
        parser.error("Go executable not found")
    go = Path(selected).resolve()
    output = (args.output or ROOT / "_evidence" /
              dt.datetime.now(dt.timezone.utc).strftime("go-local-%Y%m%dT%H%M%S%fZ")).resolve()
    if output == ROOT or any(output.is_relative_to(ROOT / name) for name in ("cmd", "internal")):
        parser.error("--output must be outside the current Go source directories")
    output.mkdir(parents=True, exist_ok=False)
    started = time.monotonic()
    summary = {"status": "running", "scope": "local Go/race only; no PostgreSQL, WAL recovery or KVM",
               "postgres_validation": "required_not_run", "kvm_validation": "required_not_run",
               "packages_requested": list(PACKAGES)}

    def save():
        summary["seconds"] = round(time.monotonic() - started, 3)
        (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")

    save()
    try:
        env = local_environment(os.environ, go)
        version = subprocess.check_output([str(go), "version"], env=env, text=True, timeout=15).strip()
        if version != f"go version {GO_VERSION} linux/amd64":
            raise ValueError(f"requires {GO_VERSION} linux/amd64; found {version}")
        summary["go"] = version
        summary["python"] = sys.version.split()[0]
        summary["runner_sha256"] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        if args.native_tools:
            header = args.native_tools.resolve() / "usr/include/libcryptsetup.h"
            native = output / "native"
            native.mkdir()
            shutil.copy2(header, native / header.name)
            env["CPATH"] = str(native)
            summary["native_header_sha256"] = hashlib.sha256(header.read_bytes()).hexdigest()
        sources = output / "sources"
        summary["source_sha256"] = freeze_sources(ROOT, sources)
        module = next(line.split()[1] for line in (sources / "go.mod").read_text().splitlines()
                      if line.startswith("module "))
        command = [str(go), "test", "-race", "-json", "-count=1", "-timeout=180s", *PACKAGES]
        summary["command"] = command
        save()
        print("RUN local Go/race (PostgreSQL and KVM remain required)", flush=True)
        summary["returncode"] = run_tests(command, sources, env, output, args.timeout)
        events = [json.loads(line) for line in (output / "tests.jsonl").read_text().splitlines()]
        summary.update(analyze_events(events, module))
        summary["frozen_sources_unchanged"] = source_hashes(sources) == summary["source_sha256"]
        failed = (summary["returncode"] != 0 or summary["unexpected_skips"] or
                  summary["failed_tests_or_packages"] or summary["packages_without_terminal_event"] or
                  not summary["passed_tests"] or not summary["frozen_sources_unchanged"] or
                  (args.fail_on_skip and summary["required_postgres_tests_not_run"]))
        summary["status"] = "failed" if failed else "passed_local_only"
    except (Exception, KeyboardInterrupt) as error:
        summary["status"] = "interrupted" if isinstance(error, KeyboardInterrupt) else "failed"
        summary["error"] = str(error) or type(error).__name__
    save()
    print(f"{summary['status']}: {len(summary.get('passed_tests', []))} passed test cases; "
          f"{len(summary.get('required_postgres_tests_not_run', []))} PostgreSQL cases NOT RUN", flush=True)
    print("Required integration gate: scripts/verify-postgres.py; KVM is a separate gate.", flush=True)
    print("Evidence:", output, flush=True)
    return 0 if summary["status"] == "passed_local_only" else 1


if __name__ == "__main__":
    def interrupt(_signum, _frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, interrupt)
    sys.exit(main())
