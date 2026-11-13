#!/usr/bin/env python3
"""Qualify the continuous archiving of PostgreSQL and the standby (REC-03, ADR 004).

pgBackRest pushes every WAL segment of a PostgreSQL cluster to two encrypted
repositories at once: S3-compatible object storage (SeaweedFS, standing for
the provider) and SFTP on the standby host (an OpenSSH server). The run:
1. creates the stanza and a full backup in each repository;
2. writes rows, among them a marker, then measures how long a commit takes to
   be archived without any manual switch: archive_timeout bounds the loss;
3. restores the cluster from each repository alone into a new data directory
   and finds every committed row there;
4. builds the standby as deploy/standby ships it: it reads the SFTP repository
   on its own disk (the very directory the SFTP server writes) and S3 with a
   read-only credential. It measures how long a commit takes to reach the
   standby, and again with the SFTP server down;
5. stops the primary at once, as a disaster would, promotes the standby, and
   measures the rows lost and the time until it accepts writes. Every row
   archived before the loss must be there, and no row after it;
6. gives the new primary a repository of its own, as the promotion procedure
   does: it archives there, and nothing reaches the old primary's;
7. checks that neither store holds the marker in clear, while the cluster's own
   WAL does (the control that the search works), and that no secret of the
   run appears in the evidence;
8. runs deploy/backup/agentcapsule-backup-metrics.py, as its timer does, after
   the full backups, after a differential one, and with the standby's store
   stopped: the times it reports are those of the backups, each repository's
   state is right, and the file holds no secret.

Runs as an ordinary user with Docker; both images are pinned by digest. Every
credential is generated for the run and removed with it. The stores, the
primary, the standby and the promoted standby's repository are built by Lab,
which scripts/verify-failover.py shares.
"""

import argparse
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
SEAWEED = "chrislusf/seaweedfs@sha256:ccad23e18639c8b98cee17e7100b95830a06077b56d8e5b006d6dcf8ec5e94a0"  # 4.53
SFTP = "atmoz/sftp@sha256:c5fb9e4beb8b7054a4c0b65c5e11df47cc20da95ad6002e88aecff62bab06372"  # alpine, 2026-11-06
SFTP_USER = "backup"
# atmoz/sftp gives each user its home under /home inside the container.
SFTP_HOME = "/home/" + SFTP_USER
STANZA = "agentcapsule"
ARCHIVE_TIMEOUT = 30  # seconds for the run; production uses at most 900 (RPO 15 minutes)
PUSH_MARGIN = 15  # seconds allowed, beyond archive_timeout, for a closed segment to reach the stores
# A whole WAL segment in a repository: timeline, log, segment, checksum and
# compression. Not a .partial, a .history, a .backup, nor a push left unfinished.
SEGMENT_FILE = re.compile(r"(?:^|/)([0-9A-F]{8})([0-9A-F]{8})([0-9A-F]{8})-[0-9a-f]{40}(?:\.[a-z0-9]+)?$")


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def shipped(relative, replacements):
    """A file of deploy/ as shipped, with only this environment's values replaced."""
    text = (ROOT / relative).read_text()
    for old, new in replacements.items():
        if old not in text:
            raise RuntimeError(f"{relative} changed: {old}")
        text = text.replace(old, new)
    return text


def lsn(text):
    high, low = text.split("/")
    return int(high, 16) << 32 | int(low, 16)


def kill(*needles):
    """SIGKILL every process whose command line holds all the needles."""
    killed = 0
    for proc in Path("/proc").iterdir():
        if not proc.name.isdigit() or int(proc.name) == os.getpid():
            continue
        try:
            command = (proc / "cmdline").read_bytes().replace(b"\0", b" ")
        except OSError:
            continue
        if all(n.encode() in command for n in needles):
            try:
                os.kill(int(proc.name), signal.SIGKILL)
                killed += 1
            except OSError:
                pass
    return killed


class Lab:
    """The two stores, the primary and the standby, as deploy/ ships them.

    verify-backups.py and verify-failover.py share it. Every credential is
    generated for the run and listed in credentials; close() removes what the
    run started, then searches the evidence for each of them.
    """

    def __init__(self, out, pg_bin, pgbackrest, pg_library_path, prefix):
        self.out, self.pg_bin, self.pgbackrest = out, pg_bin, pgbackrest
        for logs in ("pgbackrest", "pgbackrest-standby", "pgbackrest-promoted"):
            (out / logs).mkdir()  # pgBackRest does not create its log path
        # pgBackRest's own libraries, extracted beside it: <root>/usr/bin/pgbackrest, <root>/usr/lib/x86_64-linux-gnu.
        self.libs = ":".join(str(x) for x in [pg_library_path, pgbackrest.resolve().parents[1] / "lib/x86_64-linux-gnu"] if x)
        self.env = {**os.environ, "LD_LIBRARY_PATH": self.libs}
        for k in list(self.env):
            if k.startswith(("PG", "PGBACKREST_")):
                self.env.pop(k)  # nothing inherited may redirect the run
        self.work = Path(tempfile.mkdtemp(prefix=prefix + "-", dir="/tmp"))  # short: Unix socket paths
        self.tag = f"{prefix}-{os.getpid()}"
        self.containers, self.paused, self.clusters, self.credentials = [], [], [], []
        # Both timeouts scaled down together, as they are equal in production.
        self.timeouts = {"archive_timeout = 300": f"archive_timeout = {ARCHIVE_TIMEOUT}",
                         "checkpoint_timeout = 300": f"checkpoint_timeout = {ARCHIVE_TIMEOUT}"}

    def run(self, label, command, timeout=300, check=True, **kw):
        with (self.out / (label + ".log")).open("a") as log:
            log.write("$ " + " ".join(str(c) for c in command) + "\n")
            log.flush()
            r = subprocess.run([str(c) for c in command], env=kw.pop("environment", self.env), stdout=log, stderr=subprocess.STDOUT,
                               timeout=timeout, check=False, **kw)
        if check and r.returncode:
            raise RuntimeError(f"{label} failed ({r.returncode}); see {label}.log")
        return r.returncode

    def output(self, command, **kw):
        return subprocess.check_output([str(c) for c in command], env=self.env, text=True, timeout=120, **kw).strip()

    def pg(self, name):
        return self.pg_bin / name

    def psql(self, s, *sql, quiet=False):
        return self.output([self.pg("psql"), "-h", s, "-d", "postgres", "-Atq", "-v", "ON_ERROR_STOP=1", *[x for q in sql for x in ("-c", q)]],
                           stderr=subprocess.DEVNULL if quiet else None)

    @staticmethod
    def wait(probe, limit, failure, every=0.5):
        """Seconds until probe() holds; a query that fails counts as not yet."""
        start = time.monotonic()
        while True:
            try:
                if probe():
                    return round(time.monotonic() - start, 1)
            except subprocess.CalledProcessError:
                pass
            if time.monotonic() - start > limit:
                raise RuntimeError(failure)
            time.sleep(every)

    @staticmethod
    def secrets_file(directory, lines):
        directory.mkdir()
        (directory / "secrets.conf").write_text("\n".join(["[global]", *lines, ""]))
        (directory / "secrets.conf").chmod(0o600)

    def backrest(self, conf, include):
        return [self.pgbackrest, f"--config={conf}", f"--config-include-path={include}", f"--stanza={STANZA}"]

    def archive_command(self, backrest):
        return " ".join(["env", f"LD_LIBRARY_PATH={self.libs}", *(str(x) for x in backrest), "archive-push", "%p"])

    def stores(self):
        """Certificates and credentials for the run, then the object store and the standby's SFTP server."""
        run, certs = self.run, self.work / "certs"
        self.certs = certs
        certs.mkdir()
        run("setup", ["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-days", "1",
                      "-subj", "/CN=backup lab CA", "-keyout", certs / "ca.key", "-out", certs / "ca.pem"])
        run("setup", ["openssl", "req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-subj", "/CN=127.0.0.1",
                      "-keyout", certs / "s3.key", "-out", certs / "s3.csr"])
        (certs / "san.ext").write_text("subjectAltName=IP:127.0.0.1\nextendedKeyUsage=serverAuth\n")
        run("setup", ["openssl", "x509", "-req", "-in", certs / "s3.csr", "-CA", certs / "ca.pem", "-CAkey", certs / "ca.key",
                      "-CAcreateserial", "-days", "1", "-extfile", certs / "san.ext", "-out", certs / "s3.crt"])
        # One S3 credential for the primary, a read-only one for the standby,
        # and a new one for the standby once promoted.
        self.keys = {name: (name + secrets.token_hex(6), secrets.token_hex(24)) for name in ("primary", "standby", "promoted")}
        self.s3_actions = {"primary": ["Admin", "Read", "Write", "List", "Tagging"], "standby": ["Read", "List"],
                           "promoted": ["Admin", "Read", "Write", "List", "Tagging"]}
        self.write_s3_identities(self.keys)
        self.passes = {name: secrets.token_hex(32) for name in ("s3", "sftp", "promoted")}
        self.credentials += [s for _, s in self.keys.values()] + list(self.passes.values())
        for f in certs.iterdir():
            f.chmod(0o644)  # read by the container's user
        run("setup", ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", certs / "host_key"])
        run("setup", ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", certs / "client_key"])
        (certs / "client_key").chmod(0o600)

        # The object store, over TLS, and the standby's SFTP server. The SFTP
        # repository is a directory of this host, as it is on the standby's
        # disk; its user has this user's uid, so that the standby reads what
        # it writes, as postgres does on the standby through the backup group.
        self.s3_port, self.sftp_port = free_port(), free_port()
        self.sftp_repo = self.work / "sftp-repo"
        self.sftp_repo.mkdir()
        self.sftp_repo.chmod(0o750)
        tag = self.tag
        self.containers.append(f"{tag}-s3")
        run("services", ["docker", "run", "-d", "--name", f"{tag}-s3", "-p", f"127.0.0.1:{self.s3_port}:8333", "-v", f"{certs}:/etc/seaweed:ro",
                         SEAWEED, "server", "-dir=/data", "-s3", "-s3.port=8333", "-s3.config=/etc/seaweed/s3.json",
                         "-s3.cert.file=/etc/seaweed/s3.crt", "-s3.key.file=/etc/seaweed/s3.key"])
        self.containers.append(f"{tag}-sftp")
        run("services", ["docker", "run", "-d", "--name", f"{tag}-sftp", "-p", f"127.0.0.1:{self.sftp_port}:22",
                         "-v", f"{certs / 'host_key'}:/etc/ssh/ssh_host_ed25519_key:ro",
                         "-v", f"{certs / 'client_key.pub'}:{SFTP_HOME}/.ssh/keys/client.pub:ro",
                         "-v", f"{self.sftp_repo}:{SFTP_HOME}/repo", SFTP, f"{SFTP_USER}::{os.getuid()}:{os.getgid()}:repo"])
        deadline = time.monotonic() + 120
        while True:
            if run("services", ["docker", "exec", f"{tag}-s3", "sh", "-c", "echo 's3.bucket.create -name agentcapsule-backups' | weed shell"],
                   timeout=60, check=False) == 0 and "agentcapsule-backups" in self.output(["docker", "exec", f"{tag}-s3", "sh", "-c", "echo s3.bucket.list | weed shell"]):
                break
            if time.monotonic() > deadline:
                raise RuntimeError("the object store did not start; see services.log")
            time.sleep(2)
        (certs / "known_hosts").write_text(f"[127.0.0.1]:{self.sftp_port} " + (certs / "host_key.pub").read_text().rsplit(" ", 1)[0] + "\n")

    def write_s3_identities(self, keys):
        """The object store's credentials: SeaweedFS reads this file at start, and again on SIGHUP."""
        (self.certs / "s3.json").write_text(json.dumps({"identities": [
            {"name": n, "credentials": [{"accessKey": k, "secretKey": s}], "actions": self.s3_actions[n]} for n, (k, s) in keys.items()]}))
        (self.certs / "s3.json").chmod(0o644)

    def s3_here(self, n):
        return f"repo{n}-s3-endpoint=127.0.0.1\nrepo{n}-storage-port={self.s3_port}\nrepo{n}-storage-ca-file={self.certs / 'ca.pem'}"

    def primary(self, data, sock):
        """pgBackRest and PostgreSQL as deploy/backup ships them, then the cluster started. Returns pgBackRest's command."""
        # The configuration, with only this environment's addresses and paths
        # replaced, and the secrets in their own file under conf.d.
        self.conf, self.include = self.work / "pgbackrest.conf", self.work / "conf.d"
        sock.mkdir()
        self.conf.write_text(shipped("deploy/backup/pgbackrest.conf", {
            "repo1-s3-endpoint=s3.example.net": self.s3_here(1),
            "repo1-s3-region=fr-par": "repo1-s3-region=us-east-1",
            "repo2-sftp-host=standby.example.net": f"repo2-sftp-host=127.0.0.1\nrepo2-sftp-host-port={self.sftp_port}",
            "/var/lib/postgresql/.ssh/backup_ed25519": str(self.certs / "client_key"),
            "/etc/pgbackrest/known_hosts": str(self.certs / "known_hosts"),
            "spool-path=/var/spool/pgbackrest": f"spool-path={self.work / 'spool'}\nlock-path={self.work / 'lock'}\nlog-level-console=info",
            "log-path=/var/log/pgbackrest": f"log-path={self.out / 'pgbackrest'}",
            "pg1-path=/var/lib/postgresql/18/main": f"pg1-path={data}\npg1-socket-path={sock}",
        }))
        self.secrets_file(self.include, [f"repo1-s3-key={self.keys['primary'][0]}", f"repo1-s3-key-secret={self.keys['primary'][1]}",
                                         f"repo1-cipher-pass={self.passes['s3']}", f"repo2-cipher-pass={self.passes['sftp']}"])
        backrest = self.backrest(self.conf, self.include)
        self.run("primary", [self.pg("initdb"), "-D", data, "--auth-local=trust", "--auth-host=reject", "--no-locale", "--encoding=UTF8"])
        settings = shipped("deploy/backup/postgresql.conf", {
            "archive_command = 'pgbackrest --stanza=agentcapsule archive-push %p'": f"archive_command = '{self.archive_command(backrest)}'",
            **self.timeouts})
        with (data / "postgresql.conf").open("a") as f:
            f.write(f"listen_addresses = ''\nunix_socket_directories = '{sock}'\n" + settings)
        self.run("primary", [self.pg("pg_ctl"), "-D", data, "-l", self.out / "primary-server.log", "-w", "start"])
        self.clusters.append(data)
        return backrest

    def standby(self, standby, ssock):
        """The standby as deploy/standby ships it, built as docs/recovery.md gives it, then started. Returns its pgBackRest command.

        Repository 1 is the SFTP directory on its own disk, repository 2 is S3,
        read-only. The primary must have a backup in its repository 2.
        """
        sconf, sinclude = self.work / "standby.conf", self.work / "standby.d"
        ssock.mkdir()
        sconf.write_text(shipped("deploy/standby/pgbackrest.conf", {
            "repo1-path=/srv/backup/repo": f"repo1-path={self.sftp_repo}",
            "repo2-s3-endpoint=s3.example.net": self.s3_here(2),
            "repo2-s3-region=fr-par": "repo2-s3-region=us-east-1",
            "spool-path=/var/spool/pgbackrest": f"spool-path={self.work / 'standby-spool'}\nlock-path={self.work / 'standby-lock'}\nlog-level-console=info",
            "log-path=/var/log/pgbackrest": f"log-path={self.out / 'pgbackrest-standby'}",
            "pg1-path=/var/lib/postgresql/18/main": f"pg1-path={standby}\npg1-socket-path={ssock}",
        }))
        self.secrets_file(sinclude, [f"repo1-cipher-pass={self.passes['sftp']}", f"repo2-s3-key={self.keys['standby'][0]}",
                                     f"repo2-s3-key-secret={self.keys['standby'][1]}", f"repo2-cipher-pass={self.passes['s3']}"])
        on_standby = self.backrest(sconf, sinclude)
        # pg_createcluster's part, then the build as docs/recovery.md gives it.
        # The restored postgresql.conf is the primary's, archive_command
        # included: the standby's settings, appended, must override it.
        self.run("standby", [self.pg("initdb"), "-D", standby, "--auth-local=trust", "--auth-host=reject", "--no-locale", "--encoding=UTF8"])
        # No --repo: the backup comes from the first repository that has one,
        # the local directory, and restore_command searches both.
        self.run("standby", [*on_standby, "--type=standby", "--delta", "restore"], timeout=600)
        if "repo1: restore backup set" not in (self.out / "standby.log").read_text():
            raise RuntimeError("the standby was not built from its local repository")
        restore_command = re.search(r"^restore_command = '(.*)'$", (standby / "postgresql.auto.conf").read_text(), re.M)
        if not (standby / "standby.signal").exists() or not restore_command or "archive-get" not in restore_command[1]:
            raise RuntimeError("the restore did not prepare a standby")
        if "--repo" in restore_command[1]:
            raise RuntimeError("restore_command is limited to one repository: " + restore_command[1])
        with (standby / "postgresql.conf").open("a") as f:
            f.write(shipped("deploy/standby/postgresql.conf", self.timeouts) + f"listen_addresses = ''\nunix_socket_directories = '{ssock}'\n")
        self.run("standby", [self.pg("pg_ctl"), "-D", standby, "-l", self.out / "standby-server.log", "-t", "300", "-w", "start"])
        self.clusters.append(standby)
        return on_standby

    def own_repository(self, standby, ssock):
        """A promoted standby's repository, as the promotion procedure gives it. Returns its pgBackRest command, configuration and include path.

        A path the old primary never wrote, with a new credential and a new
        passphrase; repository 2 waits for a new standby. The WAL written since
        the promotion was kept and is archived there.
        """
        nconf, ninclude = self.work / "promoted.conf", self.work / "promoted.d"
        text = shipped("deploy/backup/pgbackrest.conf", {
            "repo1-path=/agentcapsule": "repo1-path=/agentcapsule-2",
            "repo1-s3-endpoint=s3.example.net": self.s3_here(1),
            "repo1-s3-region=fr-par": "repo1-s3-region=us-east-1",
            "spool-path=/var/spool/pgbackrest": f"spool-path={self.work / 'promoted-spool'}\nlock-path={self.work / 'promoted-lock'}\nlog-level-console=info",
            "log-path=/var/log/pgbackrest": f"log-path={self.out / 'pgbackrest-promoted'}",
            "pg1-path=/var/lib/postgresql/18/main": f"pg1-path={standby}\npg1-socket-path={ssock}",
        })
        nconf.write_text("".join(line for line in text.splitlines(keepends=True) if not line.startswith("repo2-")))
        self.secrets_file(ninclude, [f"repo1-s3-key={self.keys['promoted'][0]}", f"repo1-s3-key-secret={self.keys['promoted'][1]}",
                                     f"repo1-cipher-pass={self.passes['promoted']}"])
        on_promoted = self.backrest(nconf, ninclude)
        self.run("promoted", [*on_promoted, "stanza-create"])
        self.psql(ssock, f"ALTER SYSTEM SET archive_command = '{self.archive_command(on_promoted)}'", "SELECT pg_reload_conf()")
        self.run("promoted", [*on_promoted, "check"])
        return on_promoted, nconf, ninclude

    def close(self, report):
        """Removes what the run started and writes summary.json. Returns the exit code.

        No secret of the run may be in the evidence: pgBackRest redacts them,
        and the run searches every file of the evidence for each one.
        """
        for c in self.clusters:
            subprocess.run([str(self.pg("pg_ctl")), "-D", str(c), "-m", "immediate", "-w", "stop"], env=self.env, capture_output=True, check=False)
        kill(str(self.work))  # pgBackRest's asynchronous processes, and any other process of the run
        for c in self.paused:
            subprocess.run(["docker", "unpause", c], capture_output=True, check=False)
        for c in self.containers:
            with (self.out / "services.log").open("a") as log:
                subprocess.run(["docker", "logs", c], stdout=log, stderr=subprocess.STDOUT, check=False)
            subprocess.run(["docker", "rm", "-f", "-v", c], capture_output=True, check=False)
        shutil.rmtree(self.work, ignore_errors=True)
        needles = [c if isinstance(c, bytes) else c.encode() for c in self.credentials]
        leaks = []
        for f in sorted(self.out.rglob("*")):
            if f.is_file():
                content = f.read_bytes()
                if any(n in content for n in needles):
                    leaks.append(str(f.relative_to(self.out)))
        report["secrets_in_evidence"] = leaks
        if leaks and report["status"] == "passed":
            report["status"], report["error"] = "failed", "a secret of the run is in the evidence"
        (self.out / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report, indent=2))
        return 0 if report["status"] == "passed" else 1


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
    lab = Lab(out, a.pg_bin, a.pgbackrest, a.pg_library_path, "acpbk")
    run, output, psql, wait, pg = lab.run, lab.output, lab.psql, lab.wait, lab.pg
    work, tag = lab.work, lab.tag

    try:
        lab.stores()
        keys, sftp_repo = lab.keys, lab.sftp_repo
        data, sock = work / "primary", work / "s"
        backrest = lab.primary(data, sock)

        # Base-backup freshness, written for node_exporter as the timer does.
        textfile = out / "textfile"
        textfile.mkdir()
        never_written = [*(k for k, _ in keys.values()), *lab.credentials, str(work), "127.0.0.1"]

        def freshness(label, config=lab.conf, config_include=lab.include):
            code = run(label, [sys.executable, "-I", ROOT / "deploy/backup/agentcapsule-backup-metrics.py", f"--pgbackrest={a.pgbackrest}",
                               f"--config={config}", f"--config-include-path={config_include}", f"--textfile-directory={textfile}"], check=False)
            path = textfile / "agentcapsule-backup.prom"
            text = path.read_text()
            leaked = [i for i, s in enumerate(never_written) if s in text]
            if path.stat().st_mode & 0o777 != 0o644 or leaked or [f.name for f in textfile.iterdir()] != [path.name]:
                raise RuntimeError(f"{label}: the metrics file is not as written (mode, a leftover file, or secrets {leaked})")
            samples = {}
            for line in text.splitlines():
                if not line.startswith("#"):
                    series, value = line.rsplit(" ", 1)
                    samples[series.removeprefix("agentcapsule_backup_")] = int(value)
            report.setdefault("freshness", {})[label] = {"exit_code": code, "samples": samples}
            return code, samples

        def finished(samples, repo, kind):
            return samples.get(f'last_success_timestamp_seconds{{repo="{repo}",type="{kind}"}}')

        run("backup", [*backrest, "stanza-create"])
        run("backup", [*backrest, "check"])
        full_started = int(time.time())
        for repo in ("1", "2"):
            run("backup", [*backrest, f"--repo={repo}", "--type=full", "backup"], timeout=600)
        code, after_full = freshness("freshness-after-full")
        fulls = {repo: finished(after_full, repo, "full") for repo in ("s3", "standby")}
        if code or any(not full_started <= (t or 0) <= time.time() for t in fulls.values()) or \
                finished(after_full, "s3", "diff") != 0 or finished(after_full, "standby", "diff") != 0 or \
                after_full.get('repository_readable{repo="s3"}') != 1 or after_full.get('repository_readable{repo="standby"}') != 1 or \
                not full_started <= after_full.get("collected_timestamp_seconds", 0) <= time.time():
            raise RuntimeError("freshness after the full backups is wrong; see summary.json")
        diff_started = int(time.time())
        run("backup", [*backrest, "--repo=1", "--type=diff", "backup"], timeout=600)
        code, after_diff = freshness("freshness-after-diff")
        if code or not diff_started <= (finished(after_diff, "s3", "diff") or 0) <= time.time() or \
                finished(after_diff, "standby", "diff") != 0 or {repo: finished(after_diff, repo, "full") for repo in fulls} != fulls:
            raise RuntimeError("freshness after the differential backup is wrong; see summary.json")
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
        lab.clusters.remove(data)

        # A restore from each repository alone: every committed row is there.
        report["restores"] = {}
        for repo in ("1", "2"):
            target, rsock = work / f"restore{repo}", work / f"r{repo}"
            rsock.mkdir()
            run("restore", [*backrest, f"--repo={repo}", f"--pg1-path={target}", "--archive-mode=off", "restore"], timeout=600)
            run("restore", [pg("pg_ctl"), "-D", target, "-l", out / f"restore{repo}-server.log", "-o",
                            f"-c listen_addresses='' -c unix_socket_directories={rsock} -c archive_mode=off", "-w", "start"])
            lab.clusters.append(target)
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
            lab.clusters.remove(target)

        # The standby, as deploy/standby ships it, built from its own disk.
        run("primary", [pg("pg_ctl"), "-D", data, "-l", out / "primary-server.log", "-w", "start"])
        lab.clusters.append(data)
        standby, ssock = work / "standby", work / "t"
        on_standby = lab.standby(standby, ssock)
        s = report["standby"] = {}
        s["catch_up_seconds"] = wait(lambda: psql(ssock, "SELECT count(*) FROM ledger", quiet=True) == str(expected), 300,
                                     "the standby did not replay the archive")
        if psql(ssock, "SELECT pg_is_in_recovery()") != "t":
            raise RuntimeError("the standby is not in recovery")
        if psql(ssock, "SHOW archive_command") != "":
            raise RuntimeError("the standby inherited the primary's archive_command")

        # Replay through the archive: a commit right after a segment switch,
        # the worst case, reaches the standby within archive_timeout, plus the
        # push and the standby's next poll.
        run("backup", [*backrest, "check"])
        psql(sock, f"INSERT INTO ledger(id,note) VALUES (202, '{marker} replayed')")
        s["commit_to_standby_seconds"] = wait(lambda: psql(ssock, "SELECT count(*) FROM ledger WHERE id = 202") == "1",
                                              ARCHIVE_TIMEOUT * 4, "a commit did not reach the standby")
        # The same with the SFTP server down: the segment comes from S3.
        run("backup", [*backrest, "check"])
        run("services", ["docker", "pause", f"{tag}-sftp"])
        lab.paused.append(f"{tag}-sftp")
        segment = psql(sock, f"INSERT INTO ledger(id,note) VALUES (203, '{marker} through S3') RETURNING pg_walfile_name(pg_current_wal_insert_lsn())")
        s["commit_to_standby_sftp_down_seconds"] = wait(lambda: psql(ssock, "SELECT count(*) FROM ledger WHERE id = 203") == "1",
                                                        ARCHIVE_TIMEOUT * 4 + 60, "with SFTP down, a commit did not reach the standby from S3")
        if any(f.name.startswith(segment) for f in sftp_repo.rglob("*")):
            raise RuntimeError(f"{segment} reached the SFTP repository while its server was paused")
        s["segment_from_s3"] = segment
        run("services", ["docker", "unpause", f"{tag}-sftp"])
        lab.paused.remove(f"{tag}-sftp")

        # The disaster. Everything so far is in both repositories, and the
        # archive_timeout clock restarts. The primary commits a row a second
        # for one and a half archive_timeout, then disappears at once with
        # the pushes it had not finished.
        psql(sock, "CREATE TABLE disaster(id int PRIMARY KEY, note text NOT NULL)")
        s["sftp_recovered_seconds"] = wait(lambda: run("backup", [*backrest, "check"], check=False) == 0, 300,
                                           "the SFTP repository did not catch up", every=5)
        size = int(psql(sock, "SELECT setting FROM pg_settings WHERE name = 'wal_segment_size'"))
        commits = []  # (id, insert LSN before its commit record, insert LSN after it, acknowledged at)
        start = time.monotonic()
        while time.monotonic() - start < ARCHIVE_TIMEOUT * 1.5:
            n = len(commits) + 1
            before, after = psql(sock, f"INSERT INTO disaster VALUES ({n}, '{marker} disaster {n}') RETURNING pg_current_wal_insert_lsn()",
                                 "SELECT pg_current_wal_insert_lsn()").split()
            commits.append((n, lsn(before), lsn(after), time.monotonic()))
            time.sleep(max(0.0, start + n - time.monotonic()))
        lost_at = time.monotonic()
        run("disaster", [pg("pg_ctl"), "-D", data, "-m", "immediate", "-w", "stop"])
        lab.clusters.remove(data)
        cut = kill(f"--config={lab.conf}", "archive-push")

        # What the archive holds, as the standby sees it: the WAL segments of
        # timeline 1 in either repository, contiguous from the first row on.
        def segments(command, repo):
            listing = output([*command, f"--repo={repo}", "repo-ls", "--recurse", f"archive/{STANZA}"])
            found = set()
            for line in listing.splitlines():
                m = SEGMENT_FILE.search(line)
                if m:
                    found.add((int(m[1], 16), int(m[2], 16) * (0x100000000 // size) + int(m[3], 16)))
            return found, listing

        held = {n for t, n in segments(on_standby, 1)[0] | segments(on_standby, 2)[0] if t == 1}
        next_segment = commits[0][1] // size
        while next_segment in held:
            next_segment += 1
        archived_end = next_segment * size

        # The promotion, timed from the command to the first write accepted.
        promoted = time.monotonic()
        run("standby", [pg("pg_ctl"), "-D", standby, "-t", "300", "-w", "promote"])
        wait(lambda: psql(ssock, "INSERT INTO ledger(id,note) VALUES (204, 'written after the promotion')", quiet=True) == "", 300,
             "the promoted standby does not accept writes", every=0.1)
        s["promotion_seconds"] = round(time.monotonic() - promoted, 1)
        if psql(ssock, "SELECT pg_is_in_recovery()") != "f":
            raise RuntimeError("the promoted standby is still in recovery")
        s["timeline_after_promotion"] = int(psql(ssock, "SELECT substr(pg_walfile_name(pg_current_wal_lsn()), 1, 8)"), 16)
        if s["timeline_after_promotion"] != 2:
            raise RuntimeError("the promotion did not start timeline 2")
        if int(psql(ssock, "SELECT count(*) FROM ledger")) != expected + 3:
            raise RuntimeError("the promoted standby lacks rows committed before the disaster")

        # The loss: a prefix of the committed rows survives. Every row whose
        # commit record ends inside the archive is there; none that starts
        # after it is.
        present = [int(x) for x in psql(ssock, "SELECT id FROM disaster ORDER BY id").split()]
        if present != [c[0] for c in commits[:len(present)]]:
            raise RuntimeError("the promoted standby's rows are not a prefix of the committed rows")
        for n, before, after, _ in commits:
            if after <= archived_end and n not in present:
                raise RuntimeError(f"row {n} was archived but is not on the promoted standby")
            if before >= archived_end and n in present:
                raise RuntimeError(f"row {n} was never archived but is on the promoted standby")
        lost = commits[len(present):]
        s["disaster"] = {"rows_committed": len(commits), "rows_on_promoted_standby": len(present), "rows_lost": len(lost),
                         "oldest_lost_commit_age_seconds": round(lost_at - lost[0][3], 1) if lost else 0.0,
                         "archived_through_lsn": f"{archived_end >> 32:X}/{archived_end & 0xFFFFFFFF:X}", "pushes_cut": cut}
        if lost and lost_at - lost[0][3] > ARCHIVE_TIMEOUT + PUSH_MARGIN:
            raise RuntimeError("a row committed more than archive_timeout before the disaster was lost")

        # After the promotion: a repository of its own. The old primary's
        # repositories get nothing.
        on_promoted, nconf, ninclude = lab.own_repository(standby, ssock)
        # Until the checkpoint that follows the promotion ends, pg_control
        # keeps the old timeline and pgBackRest refuses a backup.
        psql(ssock, "CHECKPOINT")
        promoted_full_started = int(time.time())
        run("promoted", [*on_promoted, "--repo=1", "--type=full", "backup"], timeout=600)
        # Its freshness timer reports that backup in S3, and the standby's
        # repository unreadable, without backup times, until there is a new
        # standby: its alert stays on, as there is no second copy.
        code, on_new = freshness("freshness-promoted", nconf, ninclude)
        if code or on_new.get('repository_readable{repo="s3"}') != 1 or on_new.get('repository_readable{repo="standby"}') != 0 or \
                any("standby" in series for series in on_new if series.startswith("last_success")) or \
                not promoted_full_started <= (finished(on_new, "s3", "full") or 0) <= time.time():
            raise RuntimeError("freshness on the promoted standby is wrong; see summary.json")
        new, new_listing = segments(on_promoted, 1)
        old = segments(on_standby, 1)[0] | segments(on_standby, 2)[0]
        s["new_repository"] = {"timelines": sorted({t for t, _ in new}), "history_file": "00000002.history" in new_listing,
                               "timelines_in_old_repositories": sorted({t for t, _ in old})}
        if not s["new_repository"]["history_file"] or 2 not in s["new_repository"]["timelines"]:
            raise RuntimeError("the new primary did not archive timeline 2 into its own repository")
        if s["new_repository"]["timelines_in_old_repositories"] != [1]:
            raise RuntimeError("the new primary wrote into the old primary's repositories")

        # Neither store holds the marker in clear; the cluster's WAL does. The
        # files the SFTP server wrote are readable by its group, and by no one
        # else: on the standby, postgres reads them through that group.
        def holds(root):
            needle = marker.encode()
            return [str(f.relative_to(root)) for f in root.rglob("*") if f.is_file() and needle in f.read_bytes()]

        copies = work / "copies"
        copies.mkdir()
        run("scan", ["docker", "cp", f"{tag}-s3:/data", copies / "s3"])
        stores = {"s3": copies / "s3", "sftp": sftp_repo}
        report["plaintext_in_stores"] = {k: holds(v) for k, v in stores.items()}
        report["plaintext_in_primary_wal"] = len(holds(data / "pg_wal")) > 0
        if not report["plaintext_in_primary_wal"]:
            raise RuntimeError("the control failed: the marker is not even in the primary's WAL")
        if report["plaintext_in_stores"]["s3"] or report["plaintext_in_stores"]["sftp"]:
            raise RuntimeError("a store holds the marker in clear")
        report["files_in_stores"] = {k: sum(1 for f in v.rglob("*") if f.is_file()) for k, v in stores.items()}
        modes = {oct(f.stat().st_mode & 0o777) for f in sftp_repo.rglob("*")}
        report["sftp_repository_modes"] = sorted(modes)
        if modes - {"0o640", "0o750"}:
            raise RuntimeError("the SFTP repository holds a file its group cannot read, or others can")

        # The standby's store stopped: it is reported unreadable, without
        # backup times, while the object storage's stay as they were. The
        # new primary's backups went to another path, which it does not read.
        run("services", ["docker", "stop", f"{tag}-sftp"])
        code, stopped = freshness("freshness-standby-stopped")
        if stopped.get('repository_readable{repo="standby"}') != 0 or stopped.get('repository_readable{repo="s3"}') != 1 or \
                any("standby" in series for series in stopped if series.startswith("last_success")) or \
                [finished(stopped, "s3", kind) for kind in ("full", "diff")] != [finished(after_diff, "s3", kind) for kind in ("full", "diff")]:
            raise RuntimeError("freshness with the standby's store stopped is wrong; see summary.json")
        report["pgbackrest"] = output([a.pgbackrest, "version"])
        report["postgresql"] = output([pg("postgres"), "--version"])
        report["status"] = "passed"
    except Exception as error:
        report["error"] = str(error)
    finally:
        exit_code = lab.close(report)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
