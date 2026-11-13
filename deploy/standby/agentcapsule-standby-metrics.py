#!/usr/bin/python3 -I
"""Write how far the standby's replay is behind, for node_exporter (REC-03).

On the standby host, every minute, this script asks PostgreSQL, through
psql, and writes for node_exporter's textfile collector:
- whether PostgreSQL answered;
- whether it is in recovery: a standby that replays the WAL archive. 0 once
  promoted;
- the commit time of the last transaction it replayed
  (pg_last_xact_replay_timestamp()). When it has replayed none since it
  started, the time it started: a standby that was just restarted has the
  alert's whole delay to replay one;
- when this collection ran, so that an alert notices when it stops.

The age of the last replayed transaction measures the replay only if the
primary commits now and then. An idle platform may commit nothing for hours,
and its standby would look late. So the primary commits an empty transaction
every minute (deploy/backup/agentcapsule-pg-heartbeat.timer). A standby that
keeps up has then replayed a transaction from the last few minutes:
archive_timeout, plus the heartbeat's minute, plus the push and the standby's
poll. The commit time comes from the primary's clock: both hosts keep time
with NTP.

The file holds numbers only: no host, path or message. It is replaced
atomically and has mode 0644. agentcapsule-standby-metrics.service runs it as
root, so that it can write into node_exporter's directory; psql runs as
postgres, over the local socket.
"""

import argparse
import contextlib
import os
from pathlib import Path
import pwd
import subprocess
import sys
import tempfile
import time

QUERY = ("SELECT pg_is_in_recovery(), extract(epoch FROM pg_last_xact_replay_timestamp()), "
         "extract(epoch FROM pg_postmaster_start_time())")
LABELS = {}
# Every metric is a gauge: name -> (help, label names).
METRICS = {
    "agentcapsule_standby_postgres_up": (
        "1 when the standby's PostgreSQL answered the last collection.", ()),
    "agentcapsule_standby_in_recovery": (
        "1 when the standby's PostgreSQL is in recovery, replaying the WAL archive; 0 once promoted.", ()),
    "agentcapsule_standby_replay_timestamp_seconds": (
        "Unix time the last transaction the standby replayed was committed; the time it started, if it replayed none since.", ()),
    "agentcapsule_standby_collected_timestamp_seconds": (
        "Unix time of the last collection of the standby's replay.", ()),
}
FILE_NAME = "agentcapsule-standby.prom"


def parse(line):
    """(in recovery, replay time) from psql's unaligned row: "t,<epoch or empty>,<epoch>".

    A shape this does not expect raises ValueError.
    """
    fields = line.strip().split(",")
    if len(fields) != 3 or fields[0] not in ("t", "f") or not fields[2]:
        raise ValueError("unexpected answer from psql")
    started = float(fields[2])
    replayed = float(fields[1]) if fields[1] else started
    if not (0 < started < float("inf") and 0 < replayed < float("inf")):
        raise ValueError("unexpected time from psql")
    return fields[0] == "t", replayed


def render(state, collected):
    """The Prometheus text format; state is None when PostgreSQL did not answer."""
    samples = {"agentcapsule_standby_collected_timestamp_seconds": collected,
               "agentcapsule_standby_postgres_up": 0 if state is None else 1}
    if state is not None:
        samples["agentcapsule_standby_in_recovery"] = 1 if state[0] else 0
        samples["agentcapsule_standby_replay_timestamp_seconds"] = state[1]
    lines = []
    for name in sorted(samples):
        help_text, labels = METRICS[name]
        if labels:
            raise ValueError("these metrics have no label")
        lines.extend([f"# HELP {name} {help_text}", f"# TYPE {name} gauge", f"{name} {int(samples[name])}"])
    return "\n".join(lines) + "\n"


def write_atomically(path, text):
    """Replace path with text, mode 0644: node_exporter never reads a partial file.

    The temporary file ends in .tmp, which the textfile collector ignores.
    """
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as f:
            f.write(text)
            f.flush()
            os.fchmod(f.fileno(), 0o644)
            os.fsync(f.fileno())
        os.replace(temporary, path)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(temporary)
        raise
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def query(a):
    command = [a.psql, "-X", "-A", "-t", "-q", "-v", "ON_ERROR_STOP=1", "-F", ",", "-d", a.dbname, "-c", QUERY]
    if a.host:
        command[1:1] = ["-h", a.host]
    if a.port:
        command[1:1] = ["-p", str(a.port)]
    env = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8", "PGCONNECT_TIMEOUT": "10",
           "PGAPPNAME": "agentcapsule-standby-metrics", "HOME": os.environ.get("HOME", "/nonexistent")}
    options = {}
    if a.user:
        account = pwd.getpwnam(a.user)
        env["HOME"] = account.pw_dir
        options = {"user": account.pw_uid, "group": account.pw_gid, "extra_groups": os.getgrouplist(account.pw_name, account.pw_gid)}
    result = subprocess.run(command, capture_output=True, text=True, env=env, timeout=a.timeout, check=False, **options)
    if result.returncode:
        raise RuntimeError(f"psql exited with code {result.returncode}")
    return parse(result.stdout)


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--textfile-directory", type=Path, default=Path("/var/lib/prometheus/node-exporter"),
                   help="node_exporter's --collector.textfile.directory (default: %(default)s)")
    p.add_argument("--psql", default="/usr/bin/psql", help="psql executable (default: %(default)s)")
    p.add_argument("--host", help="PostgreSQL's socket directory, if not the default")
    p.add_argument("--port", type=int, help="PostgreSQL's port, if not the default")
    p.add_argument("--dbname", default="postgres", help="database to connect to (default: %(default)s)")
    p.add_argument("--user", help="run psql as this user (default: postgres when run as root)")
    p.add_argument("--timeout", type=int, default=30, help="seconds psql may take (default: %(default)s)")
    a = p.parse_args(argv)
    if os.geteuid() == 0:
        a.user = a.user or "postgres"
        if pwd.getpwnam(a.user).pw_uid == 0:
            p.error("psql must not run as root")
    elif a.user and pwd.getpwnam(a.user).pw_uid != os.geteuid():
        p.error("--user needs root")
    else:
        a.user = None
    try:
        state, status = query(a), 0
    except (OSError, RuntimeError, subprocess.TimeoutExpired, ValueError) as error:
        # A fixed message: the reason is in PostgreSQL's own log.
        print(f"the standby's replay is unknown ({type(error).__name__}); run psql as {a.user or 'this user'} to see why",
              file=sys.stderr)
        state, status = None, 1
    write_atomically(a.textfile_directory / FILE_NAME, render(state, time.time()))
    return status


if __name__ == "__main__":
    raise SystemExit(main())
