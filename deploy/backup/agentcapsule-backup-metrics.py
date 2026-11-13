#!/usr/bin/python3 -I
"""Write the freshness of PostgreSQL's base backups for node_exporter (REC-03).

pgBackRest's `info` lists the backups that each repository holds. This script
writes, in the Prometheus text format, for node_exporter's textfile collector:
- when the newest full and the newest differential backup of each repository
  finished (0: the repository holds none);
- whether each repository could be read. The backups of a repository that
  could not be read are left out, so that its own alert fires instead of an
  age that would be wrong;
- when this collection ran, so that an alert notices when it stops.

Labels take declared values only: repo is "s3" (repository 1) or "standby"
(repository 2), type is "full" or "diff". No text from pgBackRest is copied:
no backup label, path, host or message. The file is replaced atomically and
has mode 0644.

agentcapsule-backup-metrics.service runs it as root, so that it can write into
node_exporter's directory. pgBackRest itself runs as postgres, which owns its
configuration and secrets. The ages in the alerts come from these timestamps,
so they keep growing even if this script stops running.
"""

import argparse
import contextlib
import json
import os
from pathlib import Path
import pwd
import subprocess
import sys
import tempfile
import time

# deploy/backup/pgbackrest.conf: repository 1 is the object storage, 2 the standby.
REPOSITORIES = {1: "s3", 2: "standby"}
TYPES = ("full", "diff")
LABELS = {"repo": tuple(REPOSITORIES.values()), "type": TYPES}
# Every metric is a gauge: name -> (help, label names).
METRICS = {
    "agentcapsule_backup_last_success_timestamp_seconds": (
        "Unix time the newest backup of this type in this repository finished; 0 when it holds none.", ("repo", "type")),
    "agentcapsule_backup_repository_readable": (
        "1 when pgBackRest read this repository's list of backups at the last collection.", ("repo",)),
    "agentcapsule_backup_collected_timestamp_seconds": (
        "Unix time of the last collection of backup freshness.", ()),
}
# pgBackRest's repository status: 0 is ok, 2 is "no valid backups" (readable,
# and its timestamps say 0). Any other code (a missing stanza, a mismatch, an
# error reaching the store) means that the repository could not be read.
READABLE = {0, 2}
FILE_NAME = "agentcapsule-backup.prom"


def natural(value):
    """A non-negative integer from pgBackRest's JSON; anything else is a shape this does not know."""
    if type(value) is not int or value < 0:
        raise ValueError("unexpected value in pgBackRest's info")
    return value


def freshness(info, stanza):
    """From `pgbackrest info --output=json`: {repo: readable} and {(repo, type): finished}.

    The finish times are given for readable repositories only. A shape this
    does not expect raises ValueError, KeyError or TypeError.
    """
    entries = [entry for entry in info if entry["name"] == stanza]
    if len(entries) != 1:
        raise ValueError("the stanza is not listed once")
    readable = dict.fromkeys(REPOSITORIES.values(), False)
    for repo in entries[0]["repo"]:
        key = natural(repo["key"])
        if key in REPOSITORIES and natural(repo["status"]["code"]) in READABLE:
            readable[REPOSITORIES[key]] = True
    finished = {(repo, kind): 0 for repo, ok in readable.items() if ok for kind in TYPES}
    for backup in entries[0]["backup"]:
        key = (REPOSITORIES.get(natural(backup["database"]["repo-key"])), backup["type"])
        stop = natural(backup["timestamp"]["stop"])
        if key in finished:
            finished[key] = max(finished[key], stop)
    return readable, finished


def render(readable, finished, collected):
    """The Prometheus text format. A label value outside its vocabulary raises ValueError."""
    lines = []

    def family(name, samples):
        help_text, names = METRICS[name]
        lines.extend([f"# HELP {name} {help_text}", f"# TYPE {name} gauge"])
        for values, value in sorted(samples):
            if len(values) != len(names) or any(v not in LABELS[n] for n, v in zip(names, values)):
                raise ValueError("a label value outside its vocabulary")
            labels = ",".join(f'{n}="{v}"' for n, v in zip(names, values))
            lines.append(f"{name}{{{labels}}} {int(value)}" if labels else f"{name} {int(value)}")

    family("agentcapsule_backup_collected_timestamp_seconds", [((), collected)])
    family("agentcapsule_backup_last_success_timestamp_seconds", list(finished.items()))
    family("agentcapsule_backup_repository_readable", [((repo,), ok) for repo, ok in readable.items()])
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


def read_info(a):
    command = [a.pgbackrest, f"--stanza={a.stanza}", "--output=json"]
    if a.config:
        command.append(f"--config={a.config}")
    if a.config_include_path:
        command.append(f"--config-include-path={a.config_include_path}")
    options = {}
    if a.user:
        account = pwd.getpwnam(a.user)
        options = {"user": account.pw_uid, "group": account.pw_gid,
                   "extra_groups": os.getgrouplist(account.pw_name, account.pw_gid),
                   "env": {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "HOME": account.pw_dir, "LANG": "C.UTF-8"}}
    result = subprocess.run([*command, "info"], capture_output=True, timeout=a.timeout, check=False, **options)
    if result.returncode:
        raise RuntimeError(f"pgbackrest info exited with code {result.returncode}")
    return json.loads(result.stdout)


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--textfile-directory", type=Path, default=Path("/var/lib/prometheus/node-exporter"),
                   help="node_exporter's --collector.textfile.directory (default: %(default)s)")
    p.add_argument("--pgbackrest", default="/usr/bin/pgbackrest", help="pgbackrest executable (default: %(default)s)")
    p.add_argument("--stanza", default="agentcapsule", help="pgBackRest stanza (default: %(default)s)")
    p.add_argument("--config", help="pgBackRest configuration file, if not the default")
    p.add_argument("--config-include-path", help="pgBackRest configuration include directory, if not the default")
    p.add_argument("--user", help="run pgBackRest as this user (default: postgres when run as root)")
    p.add_argument("--timeout", type=int, default=300, help="seconds pgbackrest info may take (default: %(default)s)")
    a = p.parse_args(argv)
    if os.geteuid() == 0:
        a.user = a.user or "postgres"
        if pwd.getpwnam(a.user).pw_uid == 0:
            p.error("pgBackRest must not run as root")
    elif a.user and pwd.getpwnam(a.user).pw_uid != os.geteuid():
        p.error("--user needs root")
    else:
        a.user = None
    try:
        readable, finished = freshness(read_info(a), a.stanza)
        status = 0
    except (OSError, RuntimeError, subprocess.TimeoutExpired, ValueError, KeyError, TypeError) as error:
        # A fixed message: the reason is in pgBackRest's own log.
        print(f"backup freshness unknown ({type(error).__name__}); run pgbackrest info as {a.user or 'this user'} to see why",
              file=sys.stderr)
        readable, finished, status = dict.fromkeys(REPOSITORIES.values(), False), {}, 1
    write_atomically(a.textfile_directory / FILE_NAME, render(readable, finished, time.time()))
    return status


if __name__ == "__main__":
    raise SystemExit(main())
