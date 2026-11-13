#!/usr/bin/env python3
"""The failover exercise of ADR 004 for the database and the API (REC-03).

On one machine, containers and local processes stand for the hosts. The
stores, the primary and the standby are those of scripts/verify-backups.py
(its Lab): pgBackRest pushes every WAL segment to S3 (SeaweedFS, standing for
the provider) and to the standby over SFTP (OpenSSH); the standby replays that
archive, as deploy/standby ships it. archive_timeout is scaled down to 30
seconds. The run:
1. builds agentcapsule-api and agentcapsule-admin once: the release installed
   on both hosts;
2. installs the primary: the schema, the receipt key and a platform token
   (bootstrap-platform), a transit key, a tenant with a delegated-identity
   trust, base backups, and the API. The operator keeps a copy of the API's
   keys and configuration off the host: a stand-in until D-05 is decided;
3. a client writes steadily through the API, with real authenticated
   requests: it creates an organization every 0.2 seconds and records each
   acknowledged ID with its time;
4. builds the standby from its own disk; it replays the archive;
5. the disaster, one and a half archive_timeout after a segment switch: the
   primary's PostgreSQL and API are killed with SIGKILL, with the pushes in
   progress; its data directory and the WAL it had not pushed are removed;
6. the failover, timed from the decision: fence the old primary's
   credentials (its S3 credential revoked at the provider, its key removed
   from the standby's SFTP account), promote the standby, give it a
   repository of its own, install the API's configuration and keys, start the
   API, then wait for readiness, a first authenticated read (with the
   platform token and with a delegated identity) and a first write;
7. measures the RTO (from the decision to the first write), the RPO (the
   acknowledged writes the standby lacks, and the age of the oldest), and the
   loss window to announce (from the last replayed commit to the disaster).
   Every acknowledged write older than the window must be there, and every
   missing one inside it;
8. then, outside the RTO: a full backup into the new repository; the fence
   (the old primary's credential and key are refused, the standby's
   credential still reads); what a client sees of a lost write;
9. searches the evidence for every secret of the run.

Runs as an ordinary user with Docker and Go; the images are those of
verify-backups.py, pinned by digest.
"""

import argparse
import base64
from datetime import datetime, timezone
import hashlib
import http.client
import importlib.util
import json
import os
from pathlib import Path
import secrets
import shutil
import signal
import subprocess
import sys
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("verify_backups", ROOT / "scripts/verify-backups.py")
BACKUPS = importlib.util.module_from_spec(SPEC)
sys.dont_write_bytecode = True
SPEC.loader.exec_module(BACKUPS)
Lab, free_port, kill = BACKUPS.Lab, BACKUPS.free_port, BACKUPS.kill
SEAWEED, SFTP, SFTP_HOME = BACKUPS.SEAWEED, BACKUPS.SFTP, BACKUPS.SFTP_HOME
ARCHIVE_TIMEOUT, PUSH_MARGIN = BACKUPS.ARCHIVE_TIMEOUT, BACKUPS.PUSH_MARGIN
PRODUCTION_ARCHIVE_TIMEOUT = 300  # deploy/backup/postgresql.conf
WRITE_INTERVAL = 0.2  # seconds between two writes of the client
DISASTER_AFTER_SWITCH = 1.5  # in archive_timeouts: the disaster comes halfway through a segment
BINARIES = ("agentcapsule-api", "agentcapsule-admin")
ISSUER, AUDIENCE = "https://client.example", "agentcapsule:organisation"
HOST_ID = "local"


def call(port, method, path, token=None, body=None, key=None, timeout=5):
    """One request to the API on this port. Returns (status, JSON); raises OSError or HTTPException when nothing answers."""
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    try:
        headers = {}
        if token:
            headers["Authorization"] = "Bearer " + token
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        if key:
            headers["Idempotency-Key"] = key
        connection.request(method, path, body=data, headers=headers)
        response = connection.getresponse()
        raw = response.read()
        return response.status, (json.loads(raw) if raw.strip() else None)
    finally:
        connection.close()


def organization(n):
    return {"name": f"failover write {n}", "initial_owner": {"issuer": ISSUER, "subject": f"writer-{n}", "display_name": f"Writer {n}"}}


class Writer(threading.Thread):
    """The client: creates an organization every WRITE_INTERVAL through the API and records each answer."""

    def __init__(self, port, token, prefix):
        super().__init__(daemon=True)
        self.port, self.token, self.prefix = port, token, prefix
        self.acknowledged = []  # (n, organization ID, acknowledged at), wall clock, in the order sent
        self.failed = []  # (n, sent at, what happened)
        self.halt = threading.Event()

    def run(self):
        n, start = 0, time.monotonic()
        while not self.halt.is_set():
            n += 1
            sent = time.time()
            try:
                status, body = call(self.port, "POST", "/v1/organizations", self.token, organization(n), f"{self.prefix}-{n}")
            except (OSError, http.client.HTTPException) as error:
                self.failed.append((n, sent, type(error).__name__))
            else:
                if status == 201 and body and body.get("id"):
                    self.acknowledged.append((n, body["id"], time.time()))
                else:
                    self.failed.append((n, sent, f"HTTP {status}"))
            self.halt.wait(max(0.0, start + n * WRITE_INTERVAL - time.monotonic()))


def assess_loss(acknowledged, present, window_start, disaster_at, bound):
    """The RPO as the client sees it, and the checks of the window to announce.

    acknowledged: (n, organization ID, acknowledged at) in the order sent;
    present: the IDs the promoted standby serves; window_start: the commit
    time of the last transaction the standby replayed; disaster_at: when the
    primary was gone; bound: archive_timeout plus the push. Times are on one
    clock. Returns the measures and the failed checks.
    """
    missing = [w for w in acknowledged if w[1] not in present]
    kept = [w for w in acknowledged if w[1] in present]
    failures = []
    if kept != acknowledged[:len(kept)]:
        failures.append("the writes on the standby are not a prefix of the acknowledged writes")
    older = [w for w in acknowledged if w[2] <= window_start]
    if any(w[1] not in present for w in older):
        failures.append("an acknowledged write older than the window is missing")
    if any(not window_start < w[2] <= disaster_at for w in missing):
        failures.append("a missing write is outside the window")
    if any(w[2] > disaster_at for w in acknowledged):
        failures.append("a write was acknowledged after the disaster")
    oldest = disaster_at - missing[0][2] if missing else 0.0
    if oldest > bound:
        failures.append("a write acknowledged more than archive_timeout plus the push before the disaster was lost")
    window = disaster_at - window_start
    if window > bound:
        failures.append("the standby was further behind than archive_timeout plus the push")
    measures = {
        "acknowledged": len(acknowledged), "present": len(kept), "missing": len(missing),
        "oldest_missing_age_seconds": round(oldest, 2),
        "newest_missing_age_seconds": round(disaster_at - missing[-1][2], 2) if missing else 0.0,
        "newest_present_age_seconds": round(disaster_at - kept[-1][2], 2) if kept else None,
        "window_seconds": round(window, 2),
        "acknowledged_older_than_window": len(older),
        "acknowledged_inside_window": len(acknowledged) - len(older),
    }
    return measures, failures


def b64url(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def instant(seconds):
    return datetime.fromtimestamp(seconds, timezone.utc).isoformat(timespec="milliseconds")


def process_tree(pid):
    """pid and every process below it."""
    children = {}
    for proc in Path("/proc").iterdir():
        if proc.name.isdigit():
            try:
                parent = int((proc / "stat").read_text().rsplit(")", 1)[1].split()[1])
            except (OSError, IndexError, ValueError):
                continue
            children.setdefault(parent, []).append(int(proc.name))
    tree, todo = [], [pid]
    while todo:
        p = todo.pop()
        tree.append(p)
        todo.extend(children.get(p, []))
    return tree


def alive(pid):
    try:
        return (Path("/proc") / str(pid) / "stat").read_text().rsplit(")", 1)[1].split()[0] != "Z"
    except (OSError, IndexError):
        return False


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--pg-bin", type=Path, required=True, help="PostgreSQL bin directory (initdb, pg_ctl, psql)")
    p.add_argument("--pg-library-path", type=Path, help="library directory for PostgreSQL and pgBackRest")
    p.add_argument("--pgbackrest", type=Path, required=True, help="pgbackrest executable")
    p.add_argument("--go", type=Path, required=True, help="Go executable, to build the API and the admin tool from the sources")
    p.add_argument("--output", type=Path, required=True, help="new evidence directory")
    a = p.parse_args()
    for tool in ("docker", "openssl", "ssh-keygen"):
        if not shutil.which(tool):
            p.error(tool + " is required")
    out = a.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    report = {"status": "failed", "images": {"s3": SEAWEED, "sftp": SFTP}, "settings": {
        "archive_timeout_seconds": ARCHIVE_TIMEOUT, "checkpoint_timeout_seconds": ARCHIVE_TIMEOUT,
        "production_archive_timeout_seconds": PRODUCTION_ARCHIVE_TIMEOUT, "write_interval_seconds": WRITE_INTERVAL,
        "disaster_after_segment_switch_seconds": ARCHIVE_TIMEOUT * DISASTER_AFTER_SWITCH,
        "loss_bound_seconds": ARCHIVE_TIMEOUT + PUSH_MARGIN}}
    lab = Lab(out, a.pg_bin, a.pgbackrest, a.pg_library_path, "acpfo")
    run, psql, wait, pg, work = lab.run, lab.psql, lab.wait, lab.pg, lab.work
    # The Go programs need none of PostgreSQL's or pgBackRest's libraries.
    go_env = {k: v for k, v in lab.env.items() if k != "LD_LIBRARY_PATH"}
    apis, logs, writer = {}, [], None

    def expect(condition, message):
        if not condition:
            raise RuntimeError(message)

    def admin(label, dsn, *args):
        """agentcapsule-admin, as the operator runs it on a host. Its output holds fixed codes and public metadata only."""
        command = [str(work / "bin/agentcapsule-admin"), *(str(x) for x in args)]
        r = subprocess.run(command, env={**go_env, "AGENTCAPSULE_DATABASE_URL": dsn}, capture_output=True, text=True, timeout=60, check=False)
        with (out / (label + ".log")).open("a") as log:
            log.write("$ " + " ".join(command) + "\n" + r.stdout + r.stderr)
        expect(r.returncode == 0, f"agentcapsule-admin {args[0]} failed; see {label}.log")
        return r.stdout

    def start_api(name, etc, dsn, port):
        """agentcapsule-api with the configuration and keys installed in etc, as its service would start it."""
        command = [work / "bin/agentcapsule-api", "-listen", f"127.0.0.1:{port}", "-host-id", HOST_ID,
                   "-receipt-key-file", etc / "receipt.key", "-transit-active-key", "v1", "-transit-key", f"v1={etc / 'transit-v1.key'}"]
        if (etc / "delegation.json").exists():
            command += ["-delegated-identity-file", etc / "delegation.json"]
        log = (out / f"api-{name}.log").open("a")
        logs.append(log)
        log.write("$ " + " ".join(str(c) for c in command) + "\n")
        log.flush()
        apis[name] = subprocess.Popen([str(c) for c in command], env={**go_env, "AGENTCAPSULE_DATABASE_URL": dsn},
                                      stdout=log, stderr=subprocess.STDOUT)
        return apis[name]

    def ready(name, port):
        def probe():
            expect(apis[name].poll() is None, f"the API of the {name} exited; see api-{name}.log")
            try:
                return call(port, "GET", "/v1/health/ready", timeout=1)[0] == 200
            except (OSError, http.client.HTTPException):
                return False
        return wait(probe, 60, f"the API of the {name} did not become ready", every=0.05)

    def stop_api(name):
        proc = apis.pop(name)
        proc.send_signal(signal.SIGTERM)
        expect(proc.wait(timeout=30) == 0, f"the API of the {name} did not stop cleanly")

    def jwt(key_pem, generation):
        """A delegated identity, signed by the client's own Ed25519 key, for GET /v1/organizations/current."""
        now = int(time.time())
        claims = {"iss": ISSUER, "aud": AUDIENCE, "sub": "failover-reader", "jti": secrets.token_hex(16), "iat": now, "exp": now + 120,
                  "scope": "org:read", "trust_generation": generation}
        signing = b64url(json.dumps({"alg": "EdDSA", "typ": "JWT", "kid": "primary"}, separators=(",", ":")).encode()) + "." + \
            b64url(json.dumps(claims, separators=(",", ":")).encode())
        message = work / "client/jwt-input"
        message.write_text(signing)
        signature = subprocess.run(["openssl", "pkeyutl", "-sign", "-inkey", str(key_pem), "-rawin", "-in", str(message)],
                                   capture_output=True, check=True, timeout=30).stdout
        token = signing + "." + b64url(signature)
        lab.credentials.append(token)
        return token

    def private_file(path, content):
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(content)

    def key_forms(raw):
        return [raw, raw.hex(), base64.b64encode(raw).decode(), base64.urlsafe_b64encode(raw).rstrip(b"=").decode()]

    try:
        # ---- The release, built once from a frozen copy of the sources.
        src = work / "src"
        src.mkdir()
        for name in ("go.mod", "go.sum"):
            shutil.copy2(ROOT / name, src / name)
        shutil.copytree(ROOT / "internal", src / "internal", ignore=shutil.ignore_patterns("*_test.go"))
        for name in BINARIES:
            shutil.copytree(ROOT / "cmd" / name, src / "cmd" / name, ignore=shutil.ignore_patterns("*_test.go"))
        (work / "bin").mkdir()
        run("build", [a.go.resolve(), "build", "-trimpath", "-o", str(work / "bin") + "/", *(f"./cmd/{n}" for n in BINARIES)], timeout=900,
            cwd=src, environment={**go_env, "CGO_ENABLED": "1", "GOTOOLCHAIN": "local", "GOFLAGS": "-mod=readonly"})
        report["release"] = {n: hashlib.sha256((work / "bin" / n).read_bytes()).hexdigest() for n in BINARIES}
        report["go"] = subprocess.check_output([str(a.go.resolve()), "version"], env=go_env, text=True).strip()

        # ---- The stores and the primary host.
        lab.stores()
        data, sock = work / "primary", work / "s"
        backrest = lab.primary(data, sock)
        psql(sock, "CREATE DATABASE agentcapsule")
        primary_dsn = f"host={sock} dbname=agentcapsule"
        primary_etc, client = work / "primary-etc", work / "client"  # the API's /etc/agentcapsule on the primary; the client's own files
        primary_etc.mkdir(mode=0o700)
        client.mkdir(mode=0o700)
        admin("primary-admin", primary_dsn, "bootstrap-platform", "-receipt-key-file", primary_etc / "receipt.key",
              "-token-file", client / "platform.token", "-platform-account", "failover-operator", "-token-lifetime", "2h")
        token = (client / "platform.token").read_text()
        private_file(primary_etc / "transit-v1.key", secrets.token_bytes(32))
        admin("primary-admin", primary_dsn, "activate-transit-keys", "-active-key", "v1", "-key", f"v1={primary_etc / 'transit-v1.key'}")
        lab.credentials += [token, *key_forms((primary_etc / "receipt.key").read_bytes()), *key_forms((primary_etc / "transit-v1.key").read_bytes())]

        # A tenant whose member signs in with a delegated identity: the
        # client's Ed25519 key signs, the API holds only the public trust.
        primary_port = free_port()
        start_api("primary", primary_etc, primary_dsn, primary_port)
        ready("primary", primary_port)
        status, tenant = call(primary_port, "POST", "/v1/organizations", token, {
            "name": "failover tenant", "initial_owner": {"issuer": ISSUER, "subject": "failover-reader", "display_name": "Reader"}}, "tenant")
        expect(status == 201, f"the tenant was not created ({status})")
        run("setup", ["openssl", "genpkey", "-algorithm", "ed25519", "-out", client / "identity.pem"])
        lab.credentials.append("".join((client / "identity.pem").read_text().splitlines()[1:-1]))
        public = subprocess.check_output(["openssl", "pkey", "-in", str(client / "identity.pem"), "-pubout", "-outform", "DER"])[-32:]
        (primary_etc / "delegation.json").write_text(json.dumps({"version": 1, "max_token_bytes": 8192, "trusts": [{
            "tenant_id": tenant["id"], "issuer": ISSUER, "audience": AUDIENCE, "allowed_scopes": ["org:read"], "max_ttl_seconds": 300,
            "keys": [{"kid": "primary", "public_key": base64.b64encode(public).decode()}]}]}))
        (primary_etc / "delegation.json").chmod(0o644)
        trust = json.loads(admin("primary-admin", primary_dsn, "configure-delegation", "-action", "install", "-operation-id", "failover-trust",
                                 "-tenant-id", tenant["id"], "-issuer", ISSUER, "-audience", AUDIENCE, "-trust-file", primary_etc / "delegation.json"))
        not_before = datetime.fromisoformat(trust["minimum_iat"].replace("Z", "+00:00")).timestamp()
        stop_api("primary")
        start_api("primary", primary_etc, primary_dsn, primary_port)
        report["primary"] = {"api_ready_seconds": ready("primary", primary_port)}
        time.sleep(max(0.0, not_before - time.time() + 1))
        status, current = call(primary_port, "GET", "/v1/organizations/current", jwt(client / "identity.pem", trust["generation"]))
        expect(status == 200 and current["organization"]["id"] == tenant["id"], f"the delegated identity does not read on the primary ({status})")

        # The operator's copy of the API's keys and configuration, made at
        # installation and kept off the host. A stand-in until D-05 decides
        # where these keys live and how a standby gets them.
        safe = work / "operator-safe"
        safe.mkdir(mode=0o700)
        for name in ("receipt.key", "transit-v1.key", "delegation.json"):
            shutil.copy2(primary_etc / name, safe / name)

        # Base backups into both repositories, as the installation does.
        run("backup", [*backrest, "stanza-create"])
        run("backup", [*backrest, "check"])
        for repo in ("1", "2"):
            run("backup", [*backrest, f"--repo={repo}", "--type=full", "backup"], timeout=600)

        # ---- The client writes, the standby replays.
        writer = Writer(primary_port, token, "failover-" + secrets.token_hex(4))
        writer.start()
        standby, ssock = work / "standby", work / "t"
        standby_started = time.time()
        on_standby = lab.standby(standby, ssock)
        s = report["standby"] = {}
        s["catch_up_seconds"] = wait(lambda: psql(ssock, "SELECT pg_last_xact_replay_timestamp() > to_timestamp("
                                                  f"{standby_started})", quiet=True) == "t", 300, "the standby did not replay the archive")
        expect(psql(ssock, "SELECT pg_is_in_recovery()") == "t", "the standby is not in recovery")
        s["poll"] = psql(ssock, "SHOW wal_retrieve_retry_interval")
        # The fence's control: before it, the old primary reaches both stores.
        for repo in ("1", "2"):
            run("fence-control", [*backrest, f"--repo={repo}", "repo-ls"])
        # Halfway through a segment: switch it now, then let the client write
        # one and a half archive_timeout. archive_timeout closes the next
        # segment after one; the disaster comes half a segment later. The
        # archiver counts a segment once pgBackRest has it in both stores.
        segment = psql(sock, "SELECT pg_walfile_name(pg_switch_wal())")
        switched = time.monotonic()
        s["switched_segment_archived_seconds"] = wait(
            lambda: psql(sock, f"SELECT last_archived_wal >= '{segment}' FROM pg_stat_archiver") == "t", ARCHIVE_TIMEOUT,
            "the switched segment did not reach both stores")
        time.sleep(max(0.0, switched + ARCHIVE_TIMEOUT * DISASTER_AFTER_SWITCH - time.monotonic()))
        expect(writer.is_alive() and not writer.failed, f"the client's writes failed before the disaster: {writer.failed[:3]}")

        # ---- The disaster: the primary host is lost at once.
        postmaster = int((data / "postmaster.pid").read_text().split()[0])
        victims = [apis["primary"].pid, *process_tree(postmaster)]
        for pid in victims:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        pushes = kill(f"--config={lab.conf}", "archive-push")
        deadline = time.monotonic() + 10
        while any(alive(pid) for pid in victims):
            expect(time.monotonic() < deadline, "the primary's processes did not die")
            time.sleep(0.01)
        disaster_at, decided = time.time(), time.monotonic()
        apis.pop("primary").wait()
        lab.clusters.remove(data)
        shutil.rmtree(data)  # its data directory, pg_wal included
        shutil.rmtree(work / "spool", ignore_errors=True)  # the WAL pgBackRest had queued and not pushed
        writer.halt.set()
        writer.join(timeout=30)
        report["disaster"] = {"at": instant(disaster_at), "processes_killed": len(victims), "pushes_cut": pushes,
                              "data_directory_removed": not data.exists(), "spool_removed": not (work / "spool").exists(),
                              "writes_acknowledged": len(writer.acknowledged), "writes_failed": len(writer.failed)}

        # ---- The failover, timed from the decision.
        steps = {}

        def step(name, action):
            started = time.monotonic()
            result = action()
            steps[name] = round(time.monotonic() - started, 2)
            return result

        def fence():
            # At the provider: the old primary's S3 credential is revoked.
            # SeaweedFS reads its identities again on SIGHUP.
            lab.write_s3_identities({k: v for k, v in lab.keys.items() if k != "primary"})
            run("failover", ["docker", "kill", "--signal=HUP", f"{lab.tag}-s3"])
            # On the standby: the old primary's key leaves the SFTP account.
            run("failover", ["docker", "exec", f"{lab.tag}-sftp", "rm", f"{SFTP_HOME}/.ssh/authorized_keys"])

        def promote():
            run("standby", [pg("pg_ctl"), "-D", standby, "-t", "300", "-w", "promote"])
            expect(psql(ssock, "SELECT pg_is_in_recovery()") == "f", "the promoted standby is still in recovery")

        standby_etc = work / "standby-etc"

        def install():
            # From the operator's copy: the same files, the same modes.
            standby_etc.mkdir(mode=0o700)
            for name in ("receipt.key", "transit-v1.key", "delegation.json"):
                shutil.copy2(safe / name, standby_etc / name)

        standby_port = free_port()
        standby_dsn = f"host={ssock} dbname=agentcapsule"

        def read():
            status, listing = call(standby_port, "GET", "/v1/organizations?limit=1", token)
            expect(status == 200 and listing["items"], f"the platform token does not read on the standby ({status})")
            status, current = call(standby_port, "GET", "/v1/organizations/current", jwt(client / "identity.pem", trust["generation"]))
            expect(status == 200 and current["organization"]["id"] == tenant["id"], f"the delegated identity does not read on the standby ({status})")

        def write():
            status, body = call(standby_port, "POST", "/v1/organizations", token, {
                "name": "first write on the standby", "initial_owner": {"issuer": ISSUER, "subject": "after", "display_name": "After"}}, "after-failover")
            expect(status == 201, f"the first write on the standby failed ({status})")
            return body["id"]

        step("fence_old_primary", fence)
        step("promote", promote)
        on_promoted = step("own_repository", lambda: lab.own_repository(standby, ssock))[0]
        step("install_api_configuration_and_keys", install)
        step("start_api", lambda: start_api("standby", standby_etc, standby_dsn, standby_port))
        step("api_ready", lambda: ready("standby", standby_port))
        step("first_authenticated_read", read)
        first_write = step("first_authenticated_write", write)
        rto = time.monotonic() - decided
        report["failover"] = {"steps_seconds": steps, "rto_seconds": round(rto, 2)}

        # ---- After the RTO. A full backup into the new repository: until it
        # ends, the new primary has no backup of its own. A checkpoint first:
        # until the one that follows the promotion ends, pg_control keeps the
        # old timeline and pgBackRest refuses a backup ("WAL timeline 2 does
        # not match pg_control timeline 1").
        started = time.monotonic()
        psql(ssock, "CHECKPOINT")
        run("promoted", [*on_promoted, "--repo=1", "--type=full", "backup"], timeout=600)
        report["failover"]["full_backup_seconds"] = round(time.monotonic() - started, 2)

        # The RPO, as the client sees it, through the standby's API.
        present, after = {}, ""
        while True:
            status, page = call(standby_port, "GET", f"/v1/organizations?limit=200&after={after}", token)
            expect(status == 200, f"the standby's API does not list the organizations ({status})")
            present.update((o["id"], o["name"]) for o in page["items"])
            if len(page["items"]) < 200:
                break
            after = page["items"][-1]["id"]
        expect(first_write in present and tenant["id"] in present, "the standby lacks the tenant or its first write")
        window_start = float(psql(ssock, "SELECT extract(epoch FROM pg_last_xact_replay_timestamp())"))
        measures, failures = assess_loss(writer.acknowledged, present, window_start, disaster_at, ARCHIVE_TIMEOUT + PUSH_MARGIN)
        acknowledged_n = {w[0] for w in writer.acknowledged}
        measures["present_without_acknowledgement"] = sum(1 for name in present.values() if name.startswith("failover write ")
                                                          and int(name.rsplit(" ", 1)[1]) not in acknowledged_n)
        measures["window"] = {"from": instant(window_start), "to": instant(disaster_at)}
        measures["window_in_archive_timeouts"] = round(measures["window_seconds"] / ARCHIVE_TIMEOUT, 2)
        report["rpo"] = measures
        (out / "writes.json").write_text(json.dumps({
            "acknowledged": [{"n": n, "id": i, "acknowledged_at": instant(t), "on_standby": i in present} for n, i, t in writer.acknowledged],
            "failed": [{"n": n, "sent_at": instant(t), "error": e} for n, t, e in writer.failed]}, indent=1) + "\n")
        expect(not failures, "; ".join(failures))
        expect(measures["missing"] > 0, "the disaster lost no acknowledged write: the exercise did not measure a loss")

        # What a client sees of a write lost in the window: the ID it was
        # given is unknown, and the same request with the same idempotency
        # key creates it again, under a new ID: its receipt was lost with it.
        n, lost_id, _ = next(w for w in writer.acknowledged if w[1] not in present)
        status, _ = call(standby_port, "GET", f"/v1/organizations/{lost_id}", token)
        again, body = call(standby_port, "POST", "/v1/organizations", token, organization(n), f"{writer.prefix}-{n}")
        report["lost_write_seen_by_client"] = {"read_status": status, "retry_status": again, "retry_same_id": bool(body) and body.get("id") == lost_id}
        expect(status == 404 and again == 201 and body["id"] != lost_id, "a lost write does not behave as announced")

        # The fence: the old primary's credential and key are refused, while
        # the standby's read-only credential still reads the same store.
        def refused(repo, reason):
            before = (out / "fence-check.log").read_text() if (out / "fence-check.log").exists() else ""
            code = run("fence-check", [*backrest, f"--repo={repo}", "repo-ls"], check=False)
            return code != 0 and reason in (out / "fence-check.log").read_text()[len(before):]

        report["fence"] = {"old_primary_s3_refused": refused(1, "HTTP request failed with 403 (Forbidden)"),
                           "old_primary_sftp_refused": refused(2, "public key authentication failed"),
                           "standby_s3_still_reads": run("fence-check", [*on_standby, "--repo=2", "repo-ls"], check=False) == 0}
        expect(all(report["fence"].values()), "the fence is not as expected; see fence-check.log")

        report["pgbackrest"] = lab.output([a.pgbackrest, "version"])
        report["postgresql"] = lab.output([pg("postgres"), "--version"])
        report["status"] = "passed"
    except Exception as error:
        report["error"] = str(error)
    finally:
        if writer:
            writer.halt.set()
            writer.join(timeout=30)
        for proc in apis.values():
            if proc.poll() is None:
                proc.send_signal(signal.SIGTERM)
                try:
                    proc.wait(timeout=20)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
        for log in logs:
            log.close()
        exit_code = lab.close(report)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
