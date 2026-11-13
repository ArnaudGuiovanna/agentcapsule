#!/usr/bin/env python3
"""Qualify the continuous archiving of PostgreSQL (REC-03, ADR 004).

pgBackRest pushes every WAL segment of a PostgreSQL cluster to two encrypted
repositories at once: S3-compatible object storage (SeaweedFS, standing for
the provider) and SFTP on the standby host (an OpenSSH server). The run:
1. creates the stanza and a full backup in each repository;
2. writes rows, among them a marker, then measures how long a commit takes to
   be archived without any manual switch: archive_timeout bounds the loss;
3. restores the cluster from each repository alone into a new data directory
   and finds every committed row there;
4. checks that neither store holds the marker in clear, while the cluster's own
   WAL does (the control that the search works).

Runs as an ordinary user with Docker; both images are pinned by digest. Every
credential is generated for the run and removed with it.
"""

import argparse
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
SEAWEED = "chrislusf/seaweedfs@sha256:ccad23e18639c8b98cee17e7100b95830a06077b56d8e5b006d6dcf8ec5e94a0"  # 4.53
SFTP = "atmoz/sftp@sha256:c5fb9e4beb8b7054a4c0b65c5e11df47cc20da95ad6002e88aecff62bab06372"  # alpine, 2026-11-06
STANZA = "agentcapsule"
ARCHIVE_TIMEOUT = 30  # seconds for the run; production uses at most 900 (RPO 15 minutes)


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--pg-bin", type=Path, required=True, help="PostgreSQL bin directory (initdb, pg_ctl, psql)")
    p.add_argument("--pg-library-path", type=Path, help="library directory for PostgreSQL and pgBackRest")
    p.add_argument("--pgbackrest", type=Path, required=True, help="pgbackrest executable")
    p.add_argument("--output", type=Path, required=True, help="new evidence directory")
    a = p.parse_args()
    for tool in ("docker", "openssl", "ssh-keygen"):
        if not shutil.which(tool):
            p.error(tool + " is required")
    out = a.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    report = {"status": "failed", "images": {"s3": SEAWEED, "sftp": SFTP}, "archive_timeout_seconds": ARCHIVE_TIMEOUT}
    libs = ":".join(str(x) for x in [a.pg_library_path, a.pgbackrest.resolve().parents[2] / "lib/x86_64-linux-gnu"] if x)
    env = {**os.environ, "LD_LIBRARY_PATH": libs}
    for k in list(env):
        if k.startswith(("PG", "PGBACKREST_")):
            env.pop(k)  # nothing inherited may redirect the run
    work = Path(tempfile.mkdtemp(prefix="acpbk-", dir="/tmp"))  # short: Unix socket paths
    containers, clusters = [], []
    tag = f"acpbk-{os.getpid()}"

    def run(label, command, timeout=300, check=True, **kw):
        with (out / (label + ".log")).open("a") as log:
            log.write("$ " + " ".join(str(c) for c in command) + "\n")
            log.flush()
            r = subprocess.run([str(c) for c in command], env=kw.pop("environment", env), stdout=log, stderr=subprocess.STDOUT,
                               timeout=timeout, check=False, **kw)
        if check and r.returncode:
            raise RuntimeError(f"{label} failed ({r.returncode}); see {label}.log")
        return r.returncode

    def output(command, **kw):
        return subprocess.check_output([str(c) for c in command], env=env, text=True, timeout=120, **kw).strip()

    pg = lambda name: a.pg_bin / name  # noqa: E731
    try:
        # Certificates and keys for the run only.
        certs = work / "certs"
        certs.mkdir()
        run("setup", ["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-days", "1",
                      "-subj", "/CN=backup lab CA", "-keyout", certs / "ca.key", "-out", certs / "ca.pem"])
        run("setup", ["openssl", "req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-subj", "/CN=127.0.0.1",
                      "-keyout", certs / "s3.key", "-out", certs / "s3.csr"])
        (certs / "san.ext").write_text("subjectAltName=IP:127.0.0.1\nextendedKeyUsage=serverAuth\n")
        run("setup", ["openssl", "x509", "-req", "-in", certs / "s3.csr", "-CA", certs / "ca.pem", "-CAkey", certs / "ca.key",
                      "-CAcreateserial", "-days", "1", "-extfile", certs / "san.ext", "-out", certs / "s3.crt"])
        access, secret = "backup" + secrets.token_hex(6), secrets.token_hex(24)
        (certs / "s3.json").write_text(json.dumps({"identities": [{"name": "backup", "credentials": [{"accessKey": access, "secretKey": secret}],
                                                                  "actions": ["Admin", "Read", "Write", "List", "Tagging"]}]}))
        for f in certs.iterdir():
            f.chmod(0o644)  # read by the container's user
        run("setup", ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", certs / "host_key"])
        run("setup", ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", certs / "client_key"])
        (certs / "client_key").chmod(0o600)

        # The object store, over TLS, and the standby's SFTP server.
        s3_port, sftp_port = free_port(), free_port()
        containers.append(f"{tag}-s3")
        run("services", ["docker", "run", "-d", "--name", f"{tag}-s3", "-p", f"127.0.0.1:{s3_port}:8333", "-v", f"{certs}:/etc/seaweed:ro",
                         SEAWEED, "server", "-dir=/data", "-s3", "-s3.port=8333", "-s3.config=/etc/seaweed/s3.json",
                         "-s3.cert.file=/etc/seaweed/s3.crt", "-s3.key.file=/etc/seaweed/s3.key"])
        containers.append(f"{tag}-sftp")
        run("services", ["docker", "run", "-d", "--name", f"{tag}-sftp", "-p", f"127.0.0.1:{sftp_port}:22",
                         "-v", f"{certs / 'host_key'}:/etc/ssh/ssh_host_ed25519_key:ro",
                         "-v", f"{certs / 'client_key.pub'}:/home/backup/.ssh/keys/client.pub:ro", SFTP, "backup::1001:1001:repo"])
        deadline = time.monotonic() + 120
        while True:
            if run("services", ["docker", "exec", f"{tag}-s3", "sh", "-c", "echo 's3.bucket.create -name agentcapsule-backups' | weed shell"],
                   timeout=60, check=False) == 0 and "agentcapsule-backups" in output(["docker", "exec", f"{tag}-s3", "sh", "-c", "echo s3.bucket.list | weed shell"]):
                break
            if time.monotonic() > deadline:
                raise RuntimeError("the object store did not start; see services.log")
            time.sleep(2)
        (certs / "known_hosts").write_text(f"[127.0.0.1]:{sftp_port} " + (certs / "host_key.pub").read_text().rsplit(" ", 1)[0] + "\n")

        # pgBackRest as deploy/backup ships it: the configuration, with only
        # this environment's addresses and paths replaced, and the secrets in
        # their own file under conf.d.
        conf, include = work / "pgbackrest.conf", work / "conf.d"
        data, sock = work / "primary", work / "s"
        sock.mkdir()
        include.mkdir()
        shipped = (ROOT / "deploy/backup/pgbackrest.conf").read_text()
        for old, new in {
            "repo1-s3-endpoint=s3.example.net": f"repo1-s3-endpoint=127.0.0.1\nrepo1-storage-port={s3_port}\nrepo1-storage-ca-file={certs / 'ca.pem'}",
            "repo1-s3-region=fr-par": "repo1-s3-region=us-east-1",
            "repo2-sftp-host=standby.example.net": f"repo2-sftp-host=127.0.0.1\nrepo2-sftp-host-port={sftp_port}",
            "/var/lib/postgresql/.ssh/backup_ed25519": str(certs / "client_key"),
            "/etc/pgbackrest/known_hosts": str(certs / "known_hosts"),
            "spool-path=/var/spool/pgbackrest": f"spool-path={work / 'spool'}\nlock-path={work / 'lock'}\nlog-level-console=info",
            "log-path=/var/log/pgbackrest": f"log-path={out / 'pgbackrest'}",
            "pg1-path=/var/lib/postgresql/18/main": f"pg1-path={data}\npg1-socket-path={sock}",
        }.items():
            if old not in shipped:
                raise RuntimeError("deploy/backup/pgbackrest.conf changed: " + old)
            shipped = shipped.replace(old, new)
        conf.write_text(shipped)
        (include / "secrets.conf").write_text("\n".join(["[global]", f"repo1-s3-key={access}", f"repo1-s3-key-secret={secret}",
                                                         f"repo1-cipher-pass={secrets.token_hex(32)}", f"repo2-cipher-pass={secrets.token_hex(32)}", ""]))
        (include / "secrets.conf").chmod(0o600)
        backrest = [a.pgbackrest, f"--config={conf}", f"--config-include-path={include}", f"--stanza={STANZA}"]
        archive = " ".join(["env", f"LD_LIBRARY_PATH={libs}", *(str(x) for x in backrest), "archive-push", "%p"])
        run("primary", [pg("initdb"), "-D", data, "--auth-local=trust", "--auth-host=reject", "--no-locale", "--encoding=UTF8"])
        settings = (ROOT / "deploy/backup/postgresql.conf").read_text()
        for old, new in {"archive_command = 'pgbackrest --stanza=agentcapsule archive-push %p'": f"archive_command = '{archive}'",
                         "archive_timeout = 300": f"archive_timeout = {ARCHIVE_TIMEOUT}"}.items():
            if old not in settings:
                raise RuntimeError("deploy/backup/postgresql.conf changed: " + old)
            settings = settings.replace(old, new)
        with (data / "postgresql.conf").open("a") as f:
            f.write(f"listen_addresses = ''\nunix_socket_directories = '{sock}'\n" + settings)
        run("primary", [pg("pg_ctl"), "-D", data, "-l", out / "primary-server.log", "-w", "start"])
        clusters.append(data)
        psql = lambda s, *sql: output([pg("psql"), "-h", s, "-d", "postgres", "-Atq", "-v", "ON_ERROR_STOP=1", *[x for q in sql for x in ("-c", q)]])  # noqa: E731

        run("backup", [*backrest, "stanza-create"])
        run("backup", [*backrest, "check"])
        for repo in ("1", "2"):
            run("backup", [*backrest, f"--repo={repo}", "--type=full", "backup"], timeout=600)
        marker = "acp-plaintext-marker-" + secrets.token_hex(8)
        psql(sock, "CREATE TABLE ledger(id int PRIMARY KEY, note text NOT NULL, at timestamptz NOT NULL DEFAULT clock_timestamp())",
             f"INSERT INTO ledger(id,note) SELECT g, '{marker} ' || g FROM generate_series(1,200) g")
        run("backup", [*backrest, "check"])  # switches the WAL and waits until every repository has it

        # The loss bound: a commit with no manual switch reaches both
        # repositories within archive_timeout, plus the push.
        before = int(psql(sock, "SELECT archived_count FROM pg_stat_archiver"))
        committed = time.monotonic()
        psql(sock, f"INSERT INTO ledger(id,note) VALUES (201, '{marker} last')")
        while int(psql(sock, "SELECT archived_count FROM pg_stat_archiver")) <= before:
            if time.monotonic() - committed > ARCHIVE_TIMEOUT * 4:
                raise RuntimeError("the last commit was not archived within four times archive_timeout")
            time.sleep(1)
        report["commit_to_archived_seconds"] = round(time.monotonic() - committed, 1)
        expected = int(psql(sock, "SELECT count(*) FROM ledger"))
        run("primary", [pg("pg_ctl"), "-D", data, "-m", "fast", "-w", "stop"])
        clusters.remove(data)

        # A restore from each repository alone: every committed row is there.
        report["restores"] = {}
        for repo in ("1", "2"):
            target, rsock = work / f"restore{repo}", work / f"r{repo}"
            rsock.mkdir()
            run("restore", [*backrest, f"--repo={repo}", f"--pg1-path={target}", "--archive-mode=off", "restore"], timeout=600)
            run("restore", [pg("pg_ctl"), "-D", target, "-l", out / f"restore{repo}-server.log", "-o",
                            f"-c listen_addresses='' -c unix_socket_directories={rsock} -c archive_mode=off", "-w", "start"])
            clusters.append(target)
            deadline = time.monotonic() + 120
            while psql(rsock, "SELECT pg_is_in_recovery()") == "t":
                if time.monotonic() > deadline:
                    raise RuntimeError("restore from repository " + repo + " did not finish recovery")
                time.sleep(1)
            found = int(psql(rsock, "SELECT count(*) FROM ledger"))
            report["restores"]["s3" if repo == "1" else "sftp"] = {"rows": found, "expected": expected}
            if found != expected:
                raise RuntimeError(f"restore from repository {repo}: {found} rows, {expected} committed")
            run("restore", [pg("pg_ctl"), "-D", target, "-m", "fast", "-w", "stop"])
            clusters.remove(target)

        # Neither store holds the marker in clear; the cluster's WAL does.
        def holds(root):
            needle = marker.encode()
            return [str(f.relative_to(root)) for f in root.rglob("*") if f.is_file() and needle in f.read_bytes()]

        copies = work / "copies"
        copies.mkdir()
        run("scan", ["docker", "cp", f"{tag}-s3:/data", copies / "s3"])
        run("scan", ["docker", "cp", f"{tag}-sftp:/home/backup/repo", copies / "sftp"])
        report["plaintext_in_stores"] = {"s3": holds(copies / "s3"), "sftp": holds(copies / "sftp")}
        report["plaintext_in_primary_wal"] = len(holds(data / "pg_wal")) > 0
        if not report["plaintext_in_primary_wal"]:
            raise RuntimeError("the control failed: the marker is not even in the primary's WAL")
        if report["plaintext_in_stores"]["s3"] or report["plaintext_in_stores"]["sftp"]:
            raise RuntimeError("a store holds the marker in clear")
        report["files_in_stores"] = {k: sum(1 for f in (copies / k).rglob("*") if f.is_file()) for k in ("s3", "sftp")}
        report["pgbackrest"] = output([a.pgbackrest, "version"])
        report["postgresql"] = output([pg("postgres"), "--version"])
        report["status"] = "passed"
    except Exception as error:
        report["error"] = str(error)
    finally:
        for c in clusters:
            subprocess.run([str(pg("pg_ctl")), "-D", str(c), "-m", "immediate", "-w", "stop"], env=env, capture_output=True, check=False)
        for c in containers:
            with (out / "services.log").open("a") as log:
                subprocess.run(["docker", "logs", c], stdout=log, stderr=subprocess.STDOUT, check=False)
            subprocess.run(["docker", "rm", "-f", "-v", c], capture_output=True, check=False)
        shutil.rmtree(work, ignore_errors=True)
        (out / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report, indent=2))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
