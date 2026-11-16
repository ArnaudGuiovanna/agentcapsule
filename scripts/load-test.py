#!/usr/bin/env python3
"""Load test of the API and the worker against PostgreSQL (OPS-03).

Runs internal/worker's TestLoad (go test -tags loadtest): invocations sent over
HTTP to the real API at each rate in turn, for a fixed time per rate, and
dispatched by real worker passes. The VMs are the mock runtime of the
PostgreSQL tests: one SQLite store per agent, written by each delivery after
a set service time. No KVM, no root.

It reports, per rate: admission latency (the API's answer), the age of the
oldest due delivery (the worker's queue), completions and their latency,
refusals by HTTP status and problem code; then the dead letters and the limit
observed: the highest rate sustained without refusal, server error or a queue
that kept growing.

By default it starts its own PostgreSQL, as scripts/verify-postgres.py does,
on a private Unix socket, with its data under --output (never under /tmp).
With --dsn it uses an existing PostgreSQL instead: the test creates its own
schema there and drops it at the end (see docs/worker.md, "Load test").
"""
import argparse
import datetime as dt
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--pg-bin", type=Path, default=os.environ.get("PG_BIN"), help="PostgreSQL bin directory (not with --dsn)")
    p.add_argument("--library-path", default=os.environ.get("PG_LIBRARY_PATH"))
    p.add_argument("--native-tools", type=Path, help="private native development headers, including libcryptsetup-dev")
    p.add_argument("--dsn", help="an existing PostgreSQL to use instead of starting one")
    p.add_argument("--output", type=Path, help="evidence directory (default _evidence/<time>-load)")
    p.add_argument("--rates", default="5,10,20,40,80", help="invocations per second, one step each")
    p.add_argument("--step", default="30s", help="duration of each step")
    p.add_argument("--agents", type=int, default=8)
    p.add_argument("--workers", type=int, default=2, help="worker processes' dispatch loops")
    p.add_argument("--batch", type=int, default=16, help="the worker's dispatch_batch")
    p.add_argument("--service", default="20ms", help="time each delivery takes in the mock VM")
    p.add_argument("--fail-every", type=int, default=0, help="fail one delivery in N (dead letters); 0 never")
    p.add_argument("--drain", default="120s", help="time allowed to finish the accepted work")
    a = p.parse_args()
    out = (a.output or ROOT / "_evidence" / (dt.datetime.now().strftime("%Y%m%d-%H%M%S") + "-load")).resolve()
    out.mkdir(parents=True, exist_ok=False)
    env = {k: v for k, v in os.environ.items() if not k.startswith("PG") and not k.startswith("AGENTCAPSULE_")}
    env.update({"AGENTCAPSULE_LOAD_RATES": a.rates, "AGENTCAPSULE_LOAD_STEP": a.step, "AGENTCAPSULE_LOAD_AGENTS": str(a.agents),
                "AGENTCAPSULE_LOAD_WORKERS": str(a.workers), "AGENTCAPSULE_LOAD_BATCH": str(a.batch),
                "AGENTCAPSULE_LOAD_SERVICE": a.service, "AGENTCAPSULE_LOAD_FAIL_EVERY": str(a.fail_every),
                "AGENTCAPSULE_LOAD_DRAIN": a.drain, "AGENTCAPSULE_LOAD_REPORT": str(out / "report.json")})
    if a.native_tools:
        env["CPATH"] = str(a.native_tools.resolve() / "usr/include")
    if a.library_path:
        env["LD_LIBRARY_PATH"] = a.library_path
    test = ["go", "test", "-tags", "loadtest", "-count=1", "-run", "^TestLoad$", "-timeout", "3h", "-v", "./internal/worker"]
    if a.dsn:
        env["AGENTCAPSULE_TEST_POSTGRES"] = a.dsn
        code = run_test(test, env, out)
    else:
        if a.pg_bin is None:
            p.error("give --pg-bin (or PG_BIN), or --dsn")
        code = with_cluster(a.pg_bin.resolve(), env, out, test)
    report = out / "report.json"
    if report.is_file():
        summarize(json.loads(report.read_text()))
    print("Evidence:", out)
    return code


def run_test(test, env, out):
    with (out / "go-test.log").open("w") as log:
        return subprocess.run(test, cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT).returncode


def with_cluster(pg_bin, env, out, test):
    """A private cluster, its data under out, its socket in a short directory."""
    data = out / "data"
    pg_env = dict(env)
    with tempfile.TemporaryDirectory(prefix="acp-load-") as socket_dir:
        options = shlex.join(["-c", "listen_addresses=", "-k", socket_dir, "-c", "unix_socket_permissions=0700",
                              "-c", "fsync=on", "-c", "full_page_writes=on", "-c", "synchronous_commit=on",
                              "-c", "max_connections=100"])
        subprocess.run([pg_bin / "initdb", "-D", data, "--username=agentcapsule_test", "--no-locale", "--encoding=UTF8",
                        "--auth-local=trust", "--auth-host=reject"], env=pg_env, check=True, stdout=subprocess.DEVNULL)
        subprocess.run([pg_bin / "pg_ctl", "-D", data, "-l", out / "server.log", "-o", options, "-w", "start"],
                       env=pg_env, check=True, stdout=subprocess.DEVNULL)
        try:
            env["AGENTCAPSULE_TEST_POSTGRES"] = f"host={socket_dir} user=agentcapsule_test dbname=postgres application_name=agentcapsule-load"
            return run_test(test, env, out)
        finally:
            subprocess.run([pg_bin / "pg_ctl", "-D", data, "-m", "fast", "-w", "stop"], env=pg_env, stdout=subprocess.DEVNULL)
            shutil.rmtree(data, ignore_errors=True)


def summarize(r):
    c = r["config"]
    print(f"PostgreSQL {r['postgresql']}; {c['agents']} agents, {c['workers']} dispatch loops, batch {c['dispatch_batch']}, "
          f"{c['service_ms']:g} ms per delivery, {c['step']} per rate")
    print(f"{'rate/s':>7} {'accepted/s':>10} {'refused':>8} {'adm p50':>8} {'adm p99':>8} {'wait max':>9} {'job max':>8} {'backlog':>8} {'done p99':>9}  sustained")
    for s in r["steps"]:
        refused = sum(s["refusals"].values())
        adm, done = s["admission_latency_ms"], s["completion_latency_ms"]
        print(f"{s['offered_per_second']:>7g} {s['accepted_per_second']:>10.1f} {refused:>8} {adm.get('p50', 0):>6.0f}ms {adm.get('p99', 0):>6.0f}ms "
              f"{s['max_queue_age_seconds']:>8.1f}s {s['max_job_delay_seconds']:>7.1f}s {s['end_backlog']:>8} {done.get('p99', 0) / 1000:>8.1f}s  "
              f"{'yes' if s['sustained'] else 'no: ' + s['not_sustained_because']}")
    print(f"dead letters: {r['dead_letters']}; drained: {r['drained']}")
    print("limit observed:", r["limit"])


if __name__ == "__main__":
    sys.exit(main())
