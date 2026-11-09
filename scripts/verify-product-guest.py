#!/usr/bin/env python3
"""Run the reusable encrypted guest under jailed Firecracker, in owned fixtures.

Requires root for jailer/cgroups and access to /dev/kvm. Never mounts a guest
filesystem on the host. Two private volumes/VMs, temporary keys and a negative
unpatched-VMM control are exercised. No user database, network setting, existing
volume, or unrelated process is changed. Evidence excludes boot credentials and
private volumes/keys. Optional worker checks create a private PostgreSQL cluster
and require the complete two-owner API path: provisioning, consented private
exchange, sleep/wake persistence and deletion with a request queued for delivery.
The privileged P1 seal projection separately replays one frozen model scenario
using local mTLS/SQLite and the real host registry, without claiming a VM replay.
These checks do not replace the remaining model-to-Go scenarios.
"""
import argparse
import hashlib
import json
import os
import pwd
from pathlib import Path
import shlex
import shutil
import signal
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ["go", "firecracker-build", "upstream-firecracker", "kernel", "guest-build", "native-headers", "output"]:
        p.add_argument("--" + name, type=Path, required=True)
    p.add_argument("--python-harness", type=Path, required=True,
                   help="python-echo package directory written by scripts/build-python-harness.py (<output>/package)")
    p.add_argument("--pg-bin", type=Path)
    p.add_argument("--pg-library-path", type=Path)
    p.add_argument("--pg-user", help="Non-root owner of the temporary PostgreSQL cluster")
    a = p.parse_args()
    if os.geteuid() != 0:
        p.error("root is required for the private jailer/cgroup test")
    for name in vars(a):
        if isinstance(getattr(a, name), Path):
            setattr(a, name, getattr(a, name).resolve())
    if bool(a.pg_bin) != bool(a.pg_user):
        p.error("--pg-bin and --pg-user must be supplied together")
    if a.pg_user and pwd.getpwnam(a.pg_user).pw_uid == 0:
        p.error("PostgreSQL must run as a non-root user")
    fc = json.loads((a.firecracker_build / "artifacts.json").read_text())
    assert fc["variant"] == "agentcapsule-volume-lock-v1"
    assert all(r["passed"] for r in json.loads((a.firecracker_build / "summary.json").read_text()))
    for name, expected in fc["sha256"].items():
        assert sha(a.firecracker_build / name) == expected, name
    guest = json.loads((a.guest_build / "artifacts.json").read_text())
    for name, expected in guest["artifacts"].items():
        assert sha(a.guest_build / name) == expected, name
    for name, expected in guest["source_sha256"].items():
        assert sha(ROOT / name) == expected, "rebuild guest after source changes: " + name
    python_package = {name: sha(a.python_harness / name) for name in ["harness.yaml", "checksums.json", "harness.ext4"]}
    out = a.output
    out.mkdir(parents=True, exist_ok=False, mode=0o700)
    src = out / "sources"
    src.mkdir()
    for name in ["go.mod", "go.sum"]:
        shutil.copy2(ROOT / name, src / name)
    for name in ["internal", "cmd", "scripts", "runtime", "sdk", "examples"]:
        shutil.copytree(ROOT / name, src / name, ignore=shutil.ignore_patterns("__pycache__"))
    native = out / "native"
    native.mkdir()
    shutil.copy2(a.native_headers / "libcryptsetup.h", native / "libcryptsetup.h")
    parent = Path(tempfile.mkdtemp(prefix="acpg-", dir="/var/tmp"))
    config = {"Firecracker": str(a.firecracker_build / "firecracker"), "Jailer": str(a.firecracker_build / "jailer"),
              "Kernel": str(a.kernel), "Initrd": str(a.guest_build / "product.initrd"),
              "UpstreamFirecracker": str(a.upstream_firecracker), "Output": str(out / "observations"), "RootParent": str(parent)}
    (out / "config.json").write_text(json.dumps(config, indent=2) + "\n")
    environment = {"source_sha256": {str(f.relative_to(src)): sha(f) for f in src.rglob("*") if f.is_file()},
                   "firecracker_build": fc, "guest_build": guest, "kernel_sha256": sha(a.kernel),
                   "upstream_sha256": sha(a.upstream_firecracker), "native_header_sha256": sha(native / "libcryptsetup.h"),
                   "python_harness_sha256": python_package,
                   "scope": __doc__}
    library = Path("/usr/lib/x86_64-linux-gnu/libcryptsetup.so.12")
    environment["libcryptsetup_sha256"] = sha(library)
    (out / "environment.json").write_text(json.dumps(environment, indent=2) + "\n")
    env = {k: v for k, v in os.environ.items() if not k.startswith(("AGENTCAPSULE_", "AC_RUNTIME_CHILD_", "CAPSULE_CRASH_"))}
    env.update(AGENTCAPSULE_KVM_CONFIG=str(out / "config.json"), AGENTCAPSULE_KVM_PYTHON_HARNESS=str(a.python_harness), CPATH=str(native), CGO_ENABLED="1",
               GOPATH=str(out / "go-path"), GOCACHE=str(out / "go-cache"), TMPDIR=str(out / "tmp"))
    (out / "tmp").mkdir()
    records = []
    pgroot = None
    pgcommand = None

    def run(label, command, timeout, cwd=None):
        start = time.monotonic()
        record = {"phase": label, "command": [str(x) for x in command], "cwd": str(cwd or src), "status": "running"}
        records.append(record)
        (out / "summary.json").write_text(json.dumps(records, indent=2) + "\n")
        print("RUN", label, flush=True)
        with (out / (label + ".log")).open("w") as log:
            proc = subprocess.Popen(record["command"], cwd=cwd or src, env=env, stdin=subprocess.DEVNULL,
                                    stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
            try:
                rc = proc.wait(timeout=timeout)
            except BaseException:
                os.killpg(proc.pid, signal.SIGKILL)
                proc.wait()
                record.update(status="interrupted_or_timed_out", seconds=round(time.monotonic()-start, 3))
                (out / "summary.json").write_text(json.dumps(records, indent=2) + "\n")
                raise
        record.update(status="passed" if rc == 0 else "failed", returncode=rc, seconds=round(time.monotonic()-start, 3))
        (out / "summary.json").write_text(json.dumps(records, indent=2) + "\n")
        print(record["status"].upper(), label, flush=True)
        if rc:
            raise RuntimeError(f"{label} failed; inspect {out / (label + '.log')}")

    try:
        run("compile", [a.go, "test", "-c", "-buildvcs=false", "-race", "-tags=kvm_integration,kvm_product_integration",
                        "-o", out / "product-runtime.test", "./internal/runtime"], 300)
        run("integration", [a.go, "tool", "test2json", "-p", "github.com/ArnaudGuiovanna/agentcapsule/internal/runtime",
                            out / "product-runtime.test", "-test.v", "-test.run=^TestProductGuest", "-test.timeout=240s"], 270)
        events = [json.loads(line) for line in (out / "integration.log").read_text().splitlines()]
        assert not any(e["Action"] in ["skip", "fail"] for e in events)
        passed = {e["Test"] for e in events if e["Action"] == "pass" and "Test" in e}
        required = {"TestProductGuestEncryptedPersistenceAndIsolation", "TestProductGuestRejectsUnlockedVMMBeforeKeyDelivery"}
        assert required <= passed
        worker_passed = set()
        conformance_passed = set()
        if a.pg_bin:
            account = pwd.getpwnam(a.pg_user)
            pgroot = Path(tempfile.mkdtemp(prefix="acpg-db-", dir="/var/tmp"))
            os.chown(pgroot, account.pw_uid, account.pw_gid)
            prefix = ["/usr/sbin/runuser", "-u", a.pg_user, "--", "/usr/bin/env"]
            if a.pg_library_path:
                prefix.append("LD_LIBRARY_PATH=" + str(a.pg_library_path))
            pgdata = pgroot / "data"
            pgcommand = prefix + [a.pg_bin / "pg_ctl", "-D", pgdata]
            pgoptions = shlex.join(["-c", "listen_addresses=", "-k", str(pgroot),
                "-c", "unix_socket_permissions=0700", "-c", "fsync=on", "-c", "full_page_writes=on",
                "-c", "synchronous_commit=on", "-c", "shared_buffers=32MB", "-c", "max_connections=40"])
            run("pg-init", prefix + [a.pg_bin / "initdb", "-D", pgdata, "--username=agentcapsule_test",
                "--no-locale", "--encoding=UTF8", "--auth-local=trust", "--auth-host=reject"], 60)
            run("pg-start", pgcommand + ["-l", pgroot / "server.log", "-o", pgoptions, "-w", "start"], 60)
            env["AGENTCAPSULE_TEST_POSTGRES"] = f"host={pgroot} user=agentcapsule_test dbname=postgres application_name=agentcapsule-product-test"
            env["AGENTCAPSULE_REQUIRE_POSTGRES"] = "1"
            run("worker-compile", [a.go, "test", "-c", "-buildvcs=false", "-race", "-tags=kvm_integration,kvm_product_integration",
                "-o", out / "product-worker.test", "./internal/worker"], 300)
            run("worker-integration", [a.go, "tool", "test2json", "-p", "github.com/ArnaudGuiovanna/agentcapsule/internal/worker",
                out / "product-worker.test", "-test.v", "-test.run=^TestProductWorker", "-test.timeout=720s"], 780)
            events = [json.loads(line) for line in (out / "worker-integration.log").read_text().splitlines()]
            assert not any(e["Action"] in ["skip", "fail"] for e in events)
            worker_passed = {e["Test"] for e in events if e["Action"] == "pass" and "Test" in e}
            required_worker = {"TestProductWorkerProvisioningAndEncryptedWake", "TestProductWorkerTwoOwnersPrivateExchange",
                "TestProductWorkerContractOutagePreservesCensusAndMaintenance", "TestProductWorkerTenantAsyncInvocationWithFileAndModel",
                "TestProductWorkerTenantRunsAnImportedHarness", "TestProductWorkerTenantUpgradesAndRollsBackAnImportedHarness",
                "TestProductWorkerTenantRunsAPythonHarness"}
            assert required_worker <= worker_passed, "missing required product worker scenario"
            run("conformance-compile", [a.go, "test", "-c", "-buildvcs=false", "-race", "-tags=kvm_integration,kvm_product_integration",
                "-o", out / "product-conformance.test", "./internal/controlplane"], 300)
            run("conformance-integration", [a.go, "tool", "test2json", "-p", "github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane",
                out / "product-conformance.test", "-test.v", "-test.run=^TestPreimplementationP1HostSealITF$", "-test.timeout=120s"], 150,
                cwd=src / "internal/controlplane")
            events = [json.loads(line) for line in (out / "conformance-integration.log").read_text().splitlines()]
            assert not any(e["Action"] in ["skip", "fail"] for e in events)
            conformance_passed = {e["Test"] for e in events if e["Action"] == "pass" and "Test" in e}
            required_conformance = {"TestPreimplementationP1HostSealITF",
                "TestPreimplementationP1HostSealITF/sealed-store-satisfies-future-barrier"}
            assert required_conformance <= conformance_passed, "missing P1 host seal projection"
        (out / "verification.json").write_text(json.dumps({"status": "passed", "executed_tests": sorted(passed),
            "worker_tests": sorted(worker_passed),
            "conformance_tests": sorted(conformance_passed),
            "two_owner_api_path": "passed" if "TestProductWorkerTwoOwnersPrivateExchange" in worker_passed else "not_run",
            "contract_admission_and_maintenance": "passed" if "TestProductWorkerContractOutagePreservesCensusAndMaintenance" in worker_passed else "not_run",
            "tenant_async_file_and_model": "passed" if "TestProductWorkerTenantAsyncInvocationWithFileAndModel" in worker_passed else "not_run",
            "imported_harness": "passed" if "TestProductWorkerTenantRunsAnImportedHarness" in worker_passed else "not_run",
            "harness_upgrade_rollback": "passed" if "TestProductWorkerTenantUpgradesAndRollsBackAnImportedHarness" in worker_passed else "not_run",
            "python_harness": "passed" if "TestProductWorkerTenantRunsAPythonHarness" in worker_passed else "not_run",
            "scope": "Real jailed encrypted guests and separate unprivileged harness processes. When worker_tests is nonempty, all mandatory worker scenarios passed: contract outage/recovery while preserving the physical census, credential replacement and forced retirement after a blocked quiesce; provisioning and encrypted wake; two owners/agents created via HTTP, manual consent while recipient sleeps, private reply and owner inbox, distinct persistent guest stores across clean sleep/wake, stale control rejection, queued-request cancellation and physical deletion; a tenant agent (delegated identity) acknowledging an invocation as working, then reading its encrypted attachment and calling its model over the platform channel and posting the answer; two tenant agents running a harness imported from an OCI registry, sharing one read-only cached image attached as a second drive and run chrooted by capsule-init; a tenant agent upgraded to another imported release and rolled back across sleep/wake with its encrypted volume, each change applied at the next boot, then the unused deprecated package evicted from the cache while the running release stays; a harness written in Python (built off-host from a pinned base image) imported and run in the guest, answering from its own SQLite state kept across sleep/wake and posting a deferred model answer over the platform channel. Direct setup covers installation only. Nonempty conformance_tests separately establish the P1 permanent-seal projection on local mTLS/SQLite, PostgreSQL and a real host registry: same inode, future seal revalidation, missing-file/busy-lock/restart refusals. Its initial placements and VMM retirement are fixtures, not a physical replay of the trace. No concurrent in-flight writer crash, restore protocol or complete MVP validation is claimed."}, indent=2) + "\n")
    finally:
        cleanup_errors = []
        if pgroot is not None:
            try:
                if (pgroot / "data/postmaster.pid").exists():
                    run("pg-stop", pgcommand + ["-m", "fast", "-w", "stop"], 60)
            except BaseException as error:
                cleanup_errors.append(error)
            finally:
                if (pgroot / "server.log").exists():
                    shutil.copy2(pgroot / "server.log", out / "postgres-server.log")
                # Preserve any cluster whose physical stop is not established.
                if not (pgroot / "data/postmaster.pid").exists():
                    shutil.rmtree(pgroot)
        # Only this invocation's fresh runtime roots determine cleanup scope.
        for instance in parent.iterdir():
            if not instance.is_dir():
                continue
            group = Path("/sys/fs/cgroup") / ("acp-runtime-" + hashlib.sha256(str(instance).encode()).hexdigest()[:16])
            if group.exists():
                for child in group.iterdir():
                    if child.is_dir():
                        (child / "cgroup.kill").write_text("1")
                        deadline = time.monotonic() + 10
                        while "populated 1" in (child / "cgroup.events").read_text():
                            if time.monotonic() > deadline:
                                raise RuntimeError("owned VMM cgroup could not be drained: " + str(child))
                            time.sleep(.05)
                        child.rmdir()
                group.rmdir()
            logs = instance / "logs"
            if logs.exists():
                shutil.copytree(logs, out / "cleanup-logs" / instance.name, dirs_exist_ok=True)
        shutil.rmtree(parent)
        (out / "cleanup.json").write_text(json.dumps({"owned_root": str(parent), "removed": True}) + "\n")
        if cleanup_errors:
            raise RuntimeError("owned PostgreSQL cleanup failed; cluster preserved") from cleanup_errors[0]
        # Let the invoking user inspect this new evidence directory after sudo.
        # No credentials/disks from the private runtime roots are copied here.
        if os.environ.get("SUDO_UID", "").isdigit() and os.environ.get("SUDO_GID", "").isdigit():
            uid, gid = int(os.environ["SUDO_UID"]), int(os.environ["SUDO_GID"])
            if uid != 0:
                for path in out.rglob("*"):
                    os.chown(path, uid, gid, follow_symlinks=False)
                os.chown(out, uid, gid, follow_symlinks=False)
    print("Evidence:", out, flush=True)


if __name__ == "__main__":
    main()
