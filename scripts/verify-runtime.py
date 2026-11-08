#!/usr/bin/env python3
"""Run real Go host-driver/KVM tests from frozen sources as root orchestration.

All VMMs belong to this run's private directory/cgroups. No global process kill,
existing volume or host network configuration is used.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pwd
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
    for name in ("go", "firecracker-build", "upstream-firecracker", "kernel", "guest", "output"):
        p.add_argument("--" + name, type=Path, required=True)
    p.add_argument("--cache", type=Path, help="Optional reusable Go compiler/module cache directory")
    p.add_argument("--pg-bin", type=Path, help="Enable real PostgreSQL + KVM placement checks")
    p.add_argument("--pg-library-path", type=Path)
    p.add_argument("--pg-user", help="Unprivileged OS user for the owned PostgreSQL cluster")
    p.add_argument("--control-guest", type=Path, help="Authenticated SQL harness fixture for real control RPC checks")
    p.add_argument("--native-headers", type=Path, help="Directory holding libcryptsetup.h; the worker links libcryptsetup")
    a = p.parse_args()
    if os.geteuid() != 0:
        p.error("root orchestration required; jailer drops VMM privileges")
    for name in vars(a):
        if isinstance(getattr(a, name), Path):
            setattr(a, name, getattr(a, name).resolve())
    if bool(a.pg_bin) != bool(a.pg_user):
        p.error("--pg-bin and --pg-user must be supplied together")
    if a.control_guest and not a.pg_bin:
        p.error("--control-guest requires the PostgreSQL checks")
    if a.pg_bin and not a.native_headers:
        p.error("--native-headers is required with the PostgreSQL checks (worker builds use libcryptsetup)")
    if a.pg_user and pwd.getpwnam(a.pg_user).pw_uid == 0:
        p.error("PostgreSQL must run as a non-root user")
    manifest = json.loads((a.firecracker_build / "artifacts.json").read_text())
    assert manifest["variant"] == "agentcapsule-volume-lock-v1"
    assert all(r["passed"] for r in json.loads((a.firecracker_build / "summary.json").read_text()))
    for name, expected in manifest["sha256"].items():
        assert sha(a.firecracker_build / name) == expected, name
    out = a.output
    out.mkdir(parents=True, exist_ok=False, mode=0o700)
    sources = out / "sources"
    sources.mkdir()
    for name in ("go.mod", "go.sum"):
        shutil.copy2(ROOT / name, sources / name)
    for name in ("internal", "scripts", "runtime", "cmd"):
        shutil.copytree(ROOT / name, sources / name, ignore=shutil.ignore_patterns("__pycache__"))
    hashes = {str(f.relative_to(sources)): sha(f) for f in sources.rglob("*") if f.is_file()}
    spec = importlib.util.spec_from_file_location("storage", sources / "scripts/verify-vm-storage.py")
    storage = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(storage)
    storage.initrd(a.guest, out / "initrd")
    native = None
    if a.native_headers:
        native = out / "native"
        native.mkdir()
        shutil.copy2(a.native_headers / "libcryptsetup.h", native / "libcryptsetup.h")
    if a.control_guest:
        storage.initrd(a.control_guest, out / "control.initrd")
    parent = Path(tempfile.mkdtemp(prefix="acrt-", dir="/var/tmp"))
    config = {"Firecracker": str(a.firecracker_build / "firecracker"), "Jailer": str(a.firecracker_build / "jailer"),
              "Kernel": str(a.kernel), "Initrd": str(out / "initrd"), "UpstreamFirecracker": str(a.upstream_firecracker),
              "Output": str(out / "observations"), "RootParent": str(parent)}
    if a.control_guest:
        config["ControlInitrd"] = str(out / "control.initrd")
        config["WorkerExecutable"] = str(out / "agentcapsule-worker")
    (out / "config.json").write_text(json.dumps(config, indent=2) + "\n")
    metadata = {"source_sha256": hashes, "firecracker_build": manifest,
                "guest_sha256": sha(a.guest), "kernel_sha256": sha(a.kernel),
                "upstream_firecracker_sha256": sha(a.upstream_firecracker),
                "go": subprocess.check_output([str(a.go), "version"], text=True).strip(),
                "scope": "Real jailed VMMs, lifetime locks, controller SIGKILL, cgroup-at-fork recovery, generation checks and host fence. Placement callbacks use a test authority, not PostgreSQL."}
    if a.control_guest:
        metadata["control_guest_sha256"] = sha(a.control_guest)
    if native:
        metadata["native_header_sha256"] = sha(native / "libcryptsetup.h")
    (out / "environment.json").write_text(json.dumps(metadata, indent=2) + "\n")
    env = {k: v for k, v in os.environ.items() if not k.startswith(("AC_RUNTIME_CHILD_", "AC_PLACEMENT_CHILD_", "AC_SEAL_CHILD_", "AC_ADMISSION_CHILD_", "AC_CREDENTIAL_CHILD_"))}
    for name in list(env):
        if name.startswith("PG") or name.startswith("AGENTCAPSULE_VM_PG_"):
            env.pop(name)
    cache = a.cache or out
    env.update(AGENTCAPSULE_KVM_CONFIG=str(out / "config.json"), GOPATH=str(cache / "go-path"),
               GOCACHE=str(cache / "go-cache"), TMPDIR=str(out / "tmp"), CGO_ENABLED="1")
    if native:
        env["CPATH"] = str(native)
    (out / "tmp").mkdir()
    records = []
    pgroot = None
    pgstarted = False

    def run(label, command, timeout):
        print("RUN", label, flush=True)
        start = time.monotonic()
        with (out / (label + ".log")).open("w") as output, (out / (label + ".stderr.log")).open("w") as errors:
            proc = subprocess.Popen([str(x) for x in command], cwd=sources, env=env,
                                    stdout=output, stderr=errors, start_new_session=True)
            try:
                rc = proc.wait(timeout=timeout)
            except BaseException:
                os.killpg(proc.pid, signal.SIGKILL)
                proc.wait()
                records.append({"phase": label, "passed": False, "status": "interrupted_or_timed_out"})
                (out / "summary.json").write_text(json.dumps(records, indent=2) + "\n")
                raise
        record = {"phase": label, "command": [str(x) for x in command], "returncode": rc,
                  "seconds": round(time.monotonic() - start, 3), "passed": rc == 0}
        records.append(record)
        (out / "summary.json").write_text(json.dumps(records, indent=2) + "\n")
        print(json.dumps(record), flush=True)
        if rc:
            raise RuntimeError(f"{label} failed ({rc}); see logs")

    try:
        if a.pg_bin:
            if a.control_guest:
                # Frozen source hashes are the provenance record. Do not stamp
                # the parent checkout's unrelated Git status (root builds also
                # correctly reject that user-owned checkout as dubious).
                run("service-compile", [a.go, "build", "-buildvcs=false", "-race", "-o", out / "agentcapsule-worker", "./cmd/agentcapsule-worker"], 300)
            account = pwd.getpwnam(a.pg_user)
            pgroot = Path(tempfile.mkdtemp(prefix="acrt-pg-", dir="/var/tmp"))
            os.chown(pgroot, account.pw_uid, account.pw_gid)
            prefix = ["/usr/sbin/runuser", "-u", a.pg_user, "--", "/usr/bin/env"]
            if a.pg_library_path:
                prefix.append("LD_LIBRARY_PATH=" + str(a.pg_library_path))
            pgdata = pgroot / "data"
            pgcommand = prefix + [a.pg_bin / "pg_ctl", "-D", pgdata]
            pgoptions = shlex.join(["-c", "listen_addresses=", "-k", str(pgroot),
                "-c", "unix_socket_permissions=0700", "-c", "fsync=on", "-c", "full_page_writes=on",
                "-c", "synchronous_commit=on", "-c", "shared_buffers=32MB", "-c", "max_connections=40"])
            pgstart = pgcommand + ["-l", pgroot / "server.log", "-o", pgoptions, "-w", "start"]
            run("pg-init", prefix + [a.pg_bin / "initdb", "-D", pgdata, "--username=agentcapsule_test",
                "--no-locale", "--encoding=UTF8", "--auth-local=trust", "--auth-host=reject"], 60)
            run("pg-start", pgstart, 60)
            pgstarted = True
            env["AGENTCAPSULE_TEST_POSTGRES"] = f"host={pgroot} user=agentcapsule_test dbname=postgres application_name=agentcapsule-kvm-tests"
            metadata["scope"] = "Real jailed VMMs and lifetime locks, PostgreSQL placement leases/confirmation/adoption, stale workers, retired generations, SQL timeout, and VMM adoption after PostgreSQL WAL recovery. Test guest probe; no authenticated application transport."
            if a.control_guest:
                metadata["scope"] = "Real PostgreSQL/KVM placements and bidirectional mTLS/vsock: control effect/dedup/barrier ACKs; guest-initiated submission/reply/directory postcheck with transactional generation authorization; separate TLS authorities, VMM PID/UID binding and listener handover without VM restart. Disposable SQL harness; public user API, encrypted transit resolution and complete supervision remain unimplemented."
            metadata["postgres"] = subprocess.check_output([str(x) for x in prefix + [a.pg_bin / "postgres", "--version"]], text=True).strip()
            (out / "environment.json").write_text(json.dumps(metadata, indent=2) + "\n")
        run("compile", [a.go, "test", "-c", "-race", "-tags=kvm_integration", "-o", out / "runtime.test", "./internal/runtime"], 300)
        run("integration", [a.go, "tool", "test2json", "-p", "github.com/ArnaudGuiovanna/agentcapsule/internal/runtime",
                            out / "runtime.test", "-test.v", "-test.timeout=240s"], 270)
        events = [json.loads(line) for line in (out / "integration.log").read_text().splitlines()]
        assert not any(e["Action"] in ("skip", "fail") for e in events), "skipped or failed checks"
        passed = [e["Test"] for e in events if e["Action"] == "pass" and "Test" in e]
        assert len(passed) >= 9, "incomplete test evidence"
        (out / "tests.json").write_text(json.dumps(passed, indent=2) + "\n")
        if a.pg_bin:
            tags = "kvm_integration" + (",kvm_control_integration" if a.control_guest else "")
            run("worker-compile", [a.go, "test", "-c", "-race", "-tags=" + tags, "-o", out / "worker.test", "./internal/worker"], 300)
            worker = [a.go, "tool", "test2json", "-p", "github.com/ArnaudGuiovanna/agentcapsule/internal/worker",
                      out / "worker.test", "-test.v", "-test.timeout=360s"]
            run("worker-integration", worker, 390)
            env["AGENTCAPSULE_VM_PG_RECOVERY"] = "prepare"
            run("worker-recovery-prepare", worker + ["-test.run=^TestPostgresKVMDatabaseRecovery$"], 90)
            run("pg-crash", pgcommand + ["-m", "immediate", "-w", "stop"], 60)
            pgstarted = False
            # The VMM is alive while PostgreSQL is down; no restart may replace it.
            survivor = json.loads((out / "observations/vm-restart.json").read_text())
            os.kill(survivor["pid"], 0)
            run("pg-restart", pgstart, 60)
            pgstarted = True
            env["AGENTCAPSULE_VM_PG_RECOVERY"] = "verify"
            run("worker-recovery-verify", worker + ["-test.run=^TestPostgresKVMDatabaseRecovery$"], 90)
            env.pop("AGENTCAPSULE_VM_PG_RECOVERY")
            assert "automatic recovery in progress" in (pgroot / "server.log").read_text(), "no PostgreSQL crash recovery evidence"
            worker_passes = {}
            for label in ("worker-integration", "worker-recovery-prepare", "worker-recovery-verify"):
                events = [json.loads(line) for line in (out / (label + ".log")).read_text().splitlines()]
                assert not any(e["Action"] in ("skip", "fail") for e in events), "skipped or failed worker checks"
                worker_passes[label] = [e["Test"] for e in events if e["Action"] == "pass" and "Test" in e]
                minimum = (13 if a.control_guest else 6) if label == "worker-integration" else 1
                assert len(worker_passes[label]) >= minimum, "incomplete worker evidence"
                if a.control_guest and label == "worker-integration":
                    required = {"TestControlVMDeliveryAndRevocation", "TestControlVMStoppedDeletionUsesFenceOnlyBoot"}
                    required.add("TestPlatformVMIdentityMandatesRepliesAndWorkerHandover")
                    required.update({"TestSealedStoreAllowsLaterRevocationAndClosure", "TestStoreSealWorkerCrashBeforeDatabaseReceipt"})
                    required.add("TestBarrierCapacityOneSlotThreeStoresAndReplay")
                    required.update({"TestDispatchServiceRequestReplyAndNotification", "TestDispatchPreparationAndOneSlotCapacity",
                                     "TestDispatchServiceClosureExpirationAndDeletion", "TestDispatchWorkerCrashRecovery"})
                    assert required <= set(worker_passes[label]), "missing authenticated control checks"
            (out / "worker-tests.json").write_text(json.dumps(worker_passes, indent=2) + "\n")
    finally:
        if pgroot is not None:
            try:
                if pgstarted or (pgroot / "data/postmaster.pid").exists():
                    run("pg-stop", pgcommand + ["-m", "fast", "-w", "stop"], 60)
                if (pgroot / "server.log").exists():
                    shutil.copy2(pgroot / "server.log", out / "postgres-server.log")
            finally:
                # If stopping failed, preserve the directory: never unlink a
                # possibly running cluster or obscure the failure evidence.
                if not (pgroot / "data/postmaster.pid").exists():
                    shutil.rmtree(pgroot)
        # If the test binary timed out, clean only this run's roots/cgroups.
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
                                raise RuntimeError(f"owned VMMs remain in {child}")
                            time.sleep(.05)
                        child.rmdir()
                group.rmdir()
            logs = instance / "logs"
            if logs.exists():
                shutil.copytree(logs, out / "cleanup-logs" / instance.name, dirs_exist_ok=True)
        shutil.rmtree(parent)
        (out / "cleanup.json").write_text(json.dumps({"owned_root": str(parent), "removed": True}) + "\n")


if __name__ == "__main__":
    main()
