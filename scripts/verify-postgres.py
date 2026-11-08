#!/usr/bin/env python3
"""Run real PostgreSQL integration/crash checks in an owned, temporary cluster.

No existing database is connected to, stopped, or modified. PostgreSQL listens
only on a private Unix socket. The database files are under --output (not /tmp).
SIGQUIT/immediate shutdown exercises WAL recovery, not physical power failure.
"""
import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import signal
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pg-bin", type=Path, default=os.environ.get("PG_BIN"))
    parser.add_argument("--library-path", default=os.environ.get("PG_LIBRARY_PATH"))
    parser.add_argument("--native-tools", type=Path, help="Private native development headers, including libcryptsetup-dev")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--llm-base-url", help="Optional real OpenAI-compatible endpoint (e.g. a local Ollama, http://127.0.0.1:11434/v1) for the llmlive phase")
    parser.add_argument("--llm-model", help="Upstream model for the llmlive phase; required with --llm-base-url")
    args = parser.parse_args()
    if bool(args.llm_base_url) != bool(args.llm_model):
        parser.error("--llm-base-url and --llm-model go together")
    pg_bin = args.pg_bin
    if pg_bin is None:
        postgres = shutil.which("postgres")
        if not postgres:
            parser.error("set --pg-bin or PG_BIN to the PostgreSQL bin directory")
        pg_bin = Path(postgres).parent
    pg_bin = pg_bin.resolve()
    for name in ["postgres", "pg_ctl", "initdb", "psql"]:
        if not (pg_bin / name).is_file():
            parser.error(f"missing {pg_bin / name}")
    out = (args.output or ROOT / "_evidence" / (dt.datetime.now().strftime("%Y%m%d-%H%M%S") + "-postgres")).resolve()
    out.mkdir(parents=True, exist_ok=False)
    sources = out / "sources"
    sources.mkdir()
    for name in ["go.mod", "go.sum"]:
        shutil.copy2(ROOT / name, sources / name)
    shutil.copytree(ROOT / "internal", sources / "internal")
    shutil.copytree(ROOT / "cmd", sources / "cmd")
    (sources / "scripts").mkdir()
    for script in (ROOT / "scripts").glob("*.py"):
        shutil.copy2(script, sources / "scripts" / script.name)
    hashes = {str(p.relative_to(sources)): hashlib.sha256(p.read_bytes()).hexdigest()
              for p in sources.rglob("*") if p.is_file()}
    env = dict(os.environ, AGENTCAPSULE_REQUIRE_POSTGRES="1")
    native_headers = {}
    if args.native_tools:
        native = out / "native"
        native.mkdir()
        header = args.native_tools.resolve() / "usr/include/libcryptsetup.h"
        shutil.copy2(header, native / header.name)
        env["CPATH"] = str(native)
        native_headers[header.name] = hashlib.sha256(header.read_bytes()).hexdigest()
        packages = args.native_tools.resolve() / "packages.json"
        if packages.is_file():
            shutil.copy2(packages, native / "packages.json")
    for name in list(env):
        if name.startswith("AGENTCAPSULE_TEST_LLM_") and name != "AGENTCAPSULE_TEST_LLM_SECRET":
            env.pop(name)  # the live phase gets them explicitly, never by accident
        if name.startswith("PG") or name.startswith("AGENTCAPSULE_DELIVERY_") or name.startswith("AGENTCAPSULE_REPLY_"):
            env.pop(name)
    # Do not let a parent test-helper variable accidentally alter these runs.
    for name in ["AGENTCAPSULE_PG_CHILD", "AGENTCAPSULE_PG_CHILD_DSN", "AGENTCAPSULE_PG_RECOVERY",
                 "CAPSULE_CRASH_POINT", "CAPSULE_CRASH_DB", "AGENTCAPSULE_VOLUME_CHILD", "AGENTCAPSULE_KEY_CHILD"]:
        env.pop(name, None)
    if args.library_path:
        env["LD_LIBRARY_PATH"] = args.library_path
    results = []
    data = out / "data"
    started = False

    def run(label, command, timeout=60, extra_env=None, go_json=False):
        started_at = time.monotonic()
        record = {"label": label, "command": [str(x) for x in command], "timeout_seconds": timeout}
        results.append(record)
        (out / "summary.json").write_text(json.dumps(results, indent=2) + "\n")
        print("RUN", label, flush=True)
        stdout = out / (label + (".jsonl" if go_json else ".log"))
        with stdout.open("w") as output, (out / (label + ".stderr.log")).open("w") as errors:
            proc = subprocess.Popen(record["command"], cwd=sources,
                                    env=dict(env, **(extra_env or {})), stdout=output,
                                    stderr=errors, stdin=subprocess.DEVNULL, start_new_session=True)
            try:
                proc.wait(timeout=timeout)
            except BaseException as error:
                os.killpg(proc.pid, signal.SIGTERM)
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    os.killpg(proc.pid, signal.SIGKILL)
                    proc.wait()
                record["status"] = "timeout" if isinstance(error, subprocess.TimeoutExpired) else "interrupted"
                record["seconds"] = round(time.monotonic() - started_at, 3)
                (out / "summary.json").write_text(json.dumps(results, indent=2) + "\n")
                raise
        record.update(returncode=proc.returncode, seconds=round(time.monotonic() - started_at, 3))
        record["status"] = "passed" if proc.returncode == 0 else "failed"
        if go_json and proc.returncode == 0:
            events = [json.loads(line) for line in stdout.read_text().splitlines()]
            # Go emits a package-level "skip" for a library without its own
            # _test.go files, even when exercised by another package's tests.
            empty_packages = {event["Package"] for event in events
                              if "[no test files]" in event.get("Output", "")}
            skips = [event for event in events if event.get("Action") == "skip"
                     and (event.get("Test") or event.get("Package") not in empty_packages)]
            failures = [event for event in events if event.get("Action") == "fail"]
            passes = [event.get("Test") for event in events if event.get("Action") == "pass" and event.get("Test")]
            record["passed_tests"] = passes
            record["packages_without_test_files"] = sorted(empty_packages)
            if skips or failures or not passes:
                record["status"] = "failed"
                record["reason"] = "Skipped/failed tests or no executed test evidence"
        (out / "summary.json").write_text(json.dumps(results, indent=2) + "\n")
        print(record["status"].upper(), label, record["seconds"], "s", flush=True)
        if record["status"] != "passed":
            raise RuntimeError(f"{label} failed; see {stdout} and its stderr log")

    metadata = {"source_sha256": hashes, "go": subprocess.check_output(["go", "version"], text=True).strip(),
                "postgres": subprocess.check_output([str(pg_bin / "postgres"), "--version"], env=env, text=True).strip(),
                "scope": "Owned local PostgreSQL and SQLite instances; process crashes and PostgreSQL WAL recovery, not power-loss or production-VPS validation.",
                # The credential, if any, is never recorded.
                "llm_live": {"base_url": args.llm_base_url, "model": args.llm_model} if args.llm_base_url else "not_run"}
    if native_headers:
        metadata["native_headers_sha256"] = native_headers
    library = Path("/usr/lib/x86_64-linux-gnu/libcryptsetup.so.12")
    if library.is_file():
        metadata["libcryptsetup"] = {"path": str(library.resolve()), "sha256": hashlib.sha256(library.read_bytes()).hexdigest()}
    (out / "environment.json").write_text(json.dumps(metadata, indent=2) + "\n")
    # Short socket path avoids Unix's path-length limit, even for long worktrees.
    with tempfile.TemporaryDirectory(prefix="acp-pg-") as socket_dir:
        options = shlex.join(["-c", "listen_addresses=", "-k", socket_dir,
                             "-c", "unix_socket_permissions=0700", "-c", "fsync=on",
                             "-c", "full_page_writes=on", "-c", "synchronous_commit=on",
                             "-c", "shared_buffers=32MB", "-c", "max_connections=40"])
        env["AGENTCAPSULE_TEST_POSTGRES"] = f"host={socket_dir} user=agentcapsule_test dbname=postgres application_name=agentcapsule-tests"
        try:
            run("initdb", [pg_bin / "initdb", "-D", data, "--username=agentcapsule_test", "--no-locale", "--encoding=UTF8", "--auth-local=trust", "--auth-host=reject"])
            run("start", [pg_bin / "pg_ctl", "-D", data, "-l", out / "server.log", "-o", options, "-w", "start"])
            started = True
            run("settings", [pg_bin / "psql", "-h", socket_dir, "-U", "agentcapsule_test", "-d", "postgres", "-Atc",
                             "SELECT version(); SHOW fsync; SHOW full_page_writes; SHOW synchronous_commit; SHOW listen_addresses;"])
            command = ["go", "test", "-race", "-json", "-count=1", "-timeout=180s"]
            run("integration", [*command, "./..."], timeout=300, go_json=True)
            if args.llm_base_url:
                run("llm-live", [*command, "-tags=llmlive", "-run=^TestLive", "./internal/llmgateway", "./internal/controlplane"], timeout=300, go_json=True,
                    extra_env={"AGENTCAPSULE_TEST_LLM_BASE_URL": args.llm_base_url, "AGENTCAPSULE_TEST_LLM_MODEL": args.llm_model})
            run("recovery-prepare", [*command, "./internal/controlplane", "-run=^Test(DurableDatabaseRestart|StoreSealDatabaseRecovery|RenewalDatabaseRecovery|WorkDatabaseRecovery)$"],
                extra_env={"AGENTCAPSULE_PG_RECOVERY": "prepare"}, timeout=120, go_json=True)
            run("database-crash", [pg_bin / "pg_ctl", "-D", data, "-m", "immediate", "-w", "stop"])
            started = False
            run("restart", [pg_bin / "pg_ctl", "-D", data, "-l", out / "server.log", "-o", options, "-w", "start"])
            started = True
            run("recovery-verify", [*command, "./internal/controlplane", "-run=^Test(DurableDatabaseRestart|StoreSealDatabaseRecovery|RenewalDatabaseRecovery|WorkDatabaseRecovery)$"],
                extra_env={"AGENTCAPSULE_PG_RECOVERY": "verify"}, timeout=120, go_json=True)
            log = (out / "server.log").read_text()
            if "automatic recovery in progress" not in log:
                raise RuntimeError("PostgreSQL log did not confirm crash recovery")
        finally:
            if started or (data / "postmaster.pid").exists():
                # pg_ctl is always scoped to the PGDATA created by this invocation.
                run("stop", [pg_bin / "pg_ctl", "-D", data, "-m", "fast", "-w", "stop"])
            if data.exists():
                shutil.rmtree(data)
    print("Evidence:", out, flush=True)


if __name__ == "__main__":
    def terminate(_signal, _frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, terminate)
    main()
