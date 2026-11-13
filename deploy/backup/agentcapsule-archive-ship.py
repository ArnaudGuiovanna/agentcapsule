#!/usr/bin/python3 -I
"""Ship the host's volume archives off the host, and fetch them back (REC-02, ADR 004).

`ship` copies every complete archive of the worker's archive root to two
stores, each an rclone crypt remote with its own passphrase: "s3" (the object
store) and "standby" (the standby host, over SFTP). The stores see neither the
archive IDs, nor the manifests (which name the agent), nor the containers'
bytes in clear. Then it writes, for node_exporter's textfile collector, per
store: the time of the last successful ship, the archives not yet there, the
archives that changed since they were shipped, and whether the store could be
listed.

An archive is a directory arc_<32 hex> holding volume.luks and manifest.json
(internal/volumearchive). Directories named .pending-* (a capture in progress)
or .removed-* (a removal in progress) are never archives.

- **Complete on a store.** An archive is complete on a store when its
  manifest is there, reads as the manifest of that archive, and its data has
  the size the manifest gives. The data goes first and the manifest last, so a
  partial upload never looks complete: on S3 an unfinished upload is not an
  object at all; over SFTP, rclone 1.60 writes in place, and a partial file
  has a size or a manifest that gives it away.
- **Never rewritten.** Nothing is written into an archive that is complete on
  a store. A local archive whose size differs from that copy, or that was
  written after the upload, is reported as changed, and the store keeps the
  copy it received. An archive that is not complete on a store (an interrupted
  upload) is uploaded again, over its partial files.
- **Retention by age only.** An archive is removed from a store once its copy
  there is older than that store's --keep, whatever the host still holds: a
  host that deletes its archives, by retention or by mistake, deletes no
  copy. An archive older than --keep on the host is not shipped to that store.

Privileges: run as root (agentcapsule-archive-ship.service), it opens the
archive root's files read-only and hands each one to rclone on its standard
input. rclone runs as --user (agentcapsule-ship by default): it reads its own
configuration and can open no file of the archive root. `fetch` works the other
way: rclone writes each file to its standard output, into a file root created
in a hidden directory of the archive root, renamed into place once checked.

Metric labels take declared values only: store is "s3" or "standby". The file
holds counts and times: no archive ID, path, host or message. It is replaced
atomically and has mode 0644.
"""

import argparse
import contextlib
import datetime
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import time

STORES = ("s3", "standby")  # rclone remotes of these names, each a crypt remote
DATA, MANIFEST = "volume.luks", "manifest.json"
FILES = (DATA, MANIFEST)  # in upload order: the manifest marks a complete copy
ARCHIVE_ID = re.compile(r"arc_[0-9a-f]{32}")
MANIFEST_LIMIT = 8192  # bytes, as internal/volumearchive reads it
SIZE_LIMIT = 32 << 30  # the largest volume an archive holds
# A local file written more than this after its upload changed after it was
# shipped. The stores' times may be whole seconds, and on another clock.
CLOCK_MARGIN = 2.0
DEFAULT_KEEP = {"s3": "30d", "standby": "7d"}
LABELS = {"store": STORES}
# Every metric is a gauge: name -> (help, label names).
METRICS = {
    "agentcapsule_archive_ship_last_success_timestamp_seconds": (
        "Unix time of the last run that left every complete local archive within this store's retention complete on it; 0 when none did.",
        ("store",)),
    "agentcapsule_archive_ship_pending_archives": (
        "Complete local archives within this store's retention that were not complete on it at the end of the last run.", ("store",)),
    "agentcapsule_archive_ship_changed_archives": (
        "Archives complete on this store whose local copy changed after the upload; the store keeps the copy it received.", ("store",)),
    "agentcapsule_archive_ship_store_readable": (
        "1 when the last run could list this store.", ("store",)),
    "agentcapsule_archive_ship_collected_timestamp_seconds": (
        "Unix time the shipper last wrote these metrics.", ()),
}
FILE_NAME = "agentcapsule-archive-ship.prom"
STATE_NAME = "state.json"
DURATION = re.compile(r"([1-9][0-9]*)([smhd])")
UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400}
TIME = re.compile(r"(\d{4})-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d)(?:\.(\d+))?(Z|[+-]\d\d:\d\d)")


class StoreUnreadable(Exception):
    """The store could not be listed."""


class RcloneFailed(Exception):
    def __init__(self, action, code, detail):
        super().__init__(f"rclone {action} exited with code {code}")
        self.code, self.detail = code, detail


def log(message):
    print(message, file=sys.stderr, flush=True)


def duration(text):
    """Seconds from 30d, 12h, 45m or 90s."""
    m = DURATION.fullmatch(text)
    if not m:
        raise ValueError(f"not a duration: {text!r} (30d, 12h, 45m or 90s)")
    return int(m[1]) * UNITS[m[2]]


def unix_time(text):
    """Seconds since the epoch from rclone's RFC 3339 times, nanoseconds included."""
    m = TIME.fullmatch(text)
    if not m:
        raise ValueError(f"not an rclone time: {text!r}")
    zone = datetime.timezone.utc
    if m[8] != "Z":
        sign = 1 if m[8][0] == "+" else -1
        zone = datetime.timezone(sign * datetime.timedelta(hours=int(m[8][1:3]), minutes=int(m[8][4:6])))
    whole = datetime.datetime(*(int(m[i]) for i in range(1, 7)), tzinfo=zone).timestamp()
    return whole + (int(m[7]) / 10 ** len(m[7]) if m[7] else 0.0)


def manifest_size(data, archive_id):
    """The data size a manifest gives, when data is the manifest of archive_id; None otherwise."""
    try:
        m = json.loads(data)
    except (ValueError, UnicodeDecodeError):
        return None
    if not isinstance(m, dict) or m.get("id") != archive_id:
        return None
    size = m.get("size")
    return size if type(size) is int and 0 < size <= SIZE_LIMIT else None


def manifest_digest(data):
    """The SHA-256 digest a manifest gives, as bytes; None if it has none."""
    digest = json.loads(data).get("digest")
    if not isinstance(digest, list) or len(digest) != 32 or any(type(b) is not int or not 0 <= b <= 255 for b in digest):
        return None
    return bytes(digest)


def local_archives(root):
    """({archive ID: {file: (size, mtime)}}, number of archive directories skipped) for root.

    Only arc_<32 hex> directories count: never .pending-* or .removed-*, nor a
    symbolic link. One without exactly its two regular files is skipped and
    reported. Their content is not checked here: the restore authority does
    it when the archive is opened, and a fetch checks the size and digest.
    """
    found, skipped = {}, 0
    with os.scandir(root) as entries:
        for entry in entries:
            if not ARCHIVE_ID.fullmatch(entry.name) or not entry.is_dir(follow_symlinks=False):
                continue
            files = {}
            with os.scandir(entry.path) as inside:
                for f in inside:
                    if f.name in FILES and f.is_file(follow_symlinks=False):
                        st = f.stat(follow_symlinks=False)
                        files[f.name] = (st.st_size, st.st_mtime)
                    else:
                        files = None
                        break
            if files and set(files) == set(FILES) and files[MANIFEST][0] <= MANIFEST_LIMIT:
                found[entry.name] = files
            else:
                skipped += 1
                log(f"{entry.name} is not a complete archive on this host: not shipped")
    return found, skipped


def no_follow(path, flags):
    return os.open(path, flags | os.O_NOFOLLOW)


def remote_archives(listing):
    """{archive ID: {file: (size, modification time)}} from `rclone lsjson -R --files-only`.

    Anything but <archive ID>/<file of an archive> is ignored: a crypt remote
    already hides what it cannot decrypt.
    """
    found = {}
    for item in listing:
        parts = item["Path"].split("/")
        if len(parts) == 2 and ARCHIVE_ID.fullmatch(parts[0]) and parts[1] in FILES and not item.get("IsDir"):
            size = item["Size"]
            if type(size) is not int:
                raise ValueError("unexpected size in rclone's listing")
            found.setdefault(parts[0], {})[parts[1]] = (size, unix_time(item["ModTime"]))
    return found


def classify(archive_id, local, remote, read_manifest):
    """Where a local archive stands on a store: "complete", "changed" or "incomplete".

    local and remote are {file: (size, time)}; remote may be None.
    read_manifest() returns the store's manifest bytes, or None if it cannot.
    """
    if not remote or MANIFEST not in remote:
        return "incomplete"
    if all(remote.get(name, (None,))[0] == local[name][0] for name in FILES):
        # Written after its upload: changed since it was shipped.
        later = any(local[name][1] > remote[name][1] + CLOCK_MARGIN for name in FILES)
        return "changed" if later else "complete"
    # The sizes differ: a partial upload, or an archive complete on the store
    # that differs from the host's. The store's own manifest tells.
    data = read_manifest()
    if data is not None and complete_on_store(remote, data, archive_id):
        return "changed"
    return "incomplete"


def complete_on_store(files, manifest, archive_id):
    """The rule a restore applies to a store's copy: its manifest, then the size of its data."""
    size = manifest_size(manifest, archive_id)
    return size is not None and files.get(DATA, (None,))[0] == size


def age_on_store(files):
    """When an archive's copy became complete on a store, or, unfinished, was last written."""
    return files[MANIFEST][1] if MANIFEST in files else max(t for _, t in files.values())


class Rclone:
    """rclone as an unprivileged account, with no environment of ours."""

    def __init__(self, binary, config, flags, account, timeout):
        self.base = [binary, f"--config={config}", "--ask-password=false", "--stats=0", "--use-server-modtime",
                     "--contimeout=30s", "--timeout=5m", *flags]
        self.options = {}
        home = account.pw_dir if account else (os.environ.get("HOME") or "/nonexistent")
        self.env = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "HOME": home, "LANG": "C.UTF-8"}
        if account:
            self.options = {"user": account.pw_uid, "group": account.pw_gid,
                            "extra_groups": os.getgrouplist(account.pw_name, account.pw_gid), "umask": 0o077}
        self.timeout = timeout

    def run(self, action, *args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, timeout=None):
        result = subprocess.run([*self.base, action, *args], stdin=stdin, stdout=stdout, stderr=subprocess.PIPE,
                                env=self.env, timeout=timeout or self.timeout, check=False, **self.options)
        if result.returncode:
            detail = result.stderr.decode(errors="replace").strip().splitlines()[-3:]
            raise RcloneFailed(action, result.returncode, detail)
        return result.stdout

    def list(self, store, path=""):
        """The files of a store, or of one archive there. A missing root is unreadable."""
        try:
            return json.loads(self.run("lsjson", "-R", "--files-only", "--no-mimetype", f"{store}:{path}", timeout=1800))
        except (RcloneFailed, subprocess.TimeoutExpired, ValueError) as error:
            raise StoreUnreadable(str(error)) from error

    def manifest(self, store, archive_id):
        try:
            data = self.run("cat", "--count", str(MANIFEST_LIMIT + 1), f"{store}:{archive_id}/{MANIFEST}", timeout=600)
        except (RcloneFailed, subprocess.TimeoutExpired):
            return None
        return data if len(data) <= MANIFEST_LIMIT else None


def upload(rc, store, root, archive_id, local, remote):
    """Upload what a store lacks of an archive, data first, then the manifest; check each by listing."""
    # A partial file is shorter than the host's: data of the same size is
    # whole there, and only the manifest is missing or partial.
    data_whole = bool(remote) and remote.get(DATA, (None,))[0] == local[DATA][0]
    for name in FILES:
        if name == DATA and data_whole:
            continue
        with open(os.path.join(root, archive_id, name), "rb", opener=no_follow) as f:
            st = os.fstat(f.fileno())
            if (st.st_size, st.st_mtime) != local[name]:
                raise RuntimeError(f"{archive_id}/{name} changed during the run")
            rc.run("rcat", f"--size={st.st_size}", f"{store}:{archive_id}/{name}", stdin=f)
        there = remote_archives([{**item, "Path": f"{archive_id}/{item['Path']}"} for item in rc.list(store, archive_id)])
        if there.get(archive_id, {}).get(name, (None,))[0] != local[name][0]:
            raise RuntimeError(f"{archive_id}/{name} does not have its size on {store} after the upload")


def ship_store(rc, store, root, local, keep, now):
    """Ship one store, then prune it. Returns its result; raises StoreUnreadable."""
    result = {"readable": False, "uploaded": 0, "pending": None, "changed": None, "pruned": 0, "errors": 0}
    remote = remote_archives(rc.list(store))
    window = {i: files for i, files in local.items() if now - files[MANIFEST][1] < keep}
    # The newest archives first: each agent's newest archive is its RPO.
    for archive_id in sorted(window, key=lambda i: window[i][MANIFEST][1], reverse=True):
        state = classify(archive_id, window[archive_id], remote.get(archive_id), lambda: rc.manifest(store, archive_id))
        if state != "incomplete":
            continue
        try:
            upload(rc, store, root, archive_id, window[archive_id], remote.get(archive_id))
            result["uploaded"] += 1
        except (RcloneFailed, StoreUnreadable, OSError, RuntimeError, subprocess.TimeoutExpired) as error:
            result["errors"] += 1
            log(f"{store}: {archive_id} not shipped: {error}; {' / '.join(getattr(error, 'detail', []))}")
    # The end state, from a new listing: what is pending or changed now.
    remote = remote_archives(rc.list(store))
    result["readable"] = True
    states = {i: classify(i, window[i], remote.get(i), lambda i=i: rc.manifest(store, i)) for i in window}
    result["pending"] = sum(1 for s in states.values() if s == "incomplete")
    result["changed"] = sum(1 for s in states.values() if s == "changed")
    for archive_id, state in sorted(states.items()):
        if state == "changed":
            log(f"{store}: {archive_id} changed on this host after it was shipped; the store keeps its copy")
    # Retention by age, on the store's own times; never what is still to ship.
    for archive_id, files in sorted(remote.items()):
        if archive_id in window or now - age_on_store(files) < keep:
            continue
        try:
            if MANIFEST in files:
                rc.run("deletefile", f"{store}:{archive_id}/{MANIFEST}")  # no longer complete, then gone
            rc.run("purge", f"{store}:{archive_id}")
            result["pruned"] += 1
        except (RcloneFailed, subprocess.TimeoutExpired) as error:
            result["errors"] += 1
            log(f"{store}: {archive_id} not pruned: {error}; {' / '.join(getattr(error, 'detail', []))}")
    return result


def render(results, last_success, collected):
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

    family("agentcapsule_archive_ship_changed_archives",
           [((s,), r["changed"]) for s, r in results.items() if r.get("changed") is not None])
    family("agentcapsule_archive_ship_collected_timestamp_seconds", [((), collected)])
    family("agentcapsule_archive_ship_last_success_timestamp_seconds", [((s,), last_success.get(s, 0)) for s in STORES])
    family("agentcapsule_archive_ship_pending_archives",
           [((s,), r["pending"]) for s, r in results.items() if r.get("pending") is not None])
    family("agentcapsule_archive_ship_store_readable", [((s,), r["readable"]) for s, r in results.items()])
    return "\n".join(lines) + "\n"


def write_atomically(path, text, mode=0o644):
    """Replace path with text: a reader never sees a partial file.

    The temporary file ends in .tmp, which the textfile collector ignores.
    """
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as f:
            f.write(text)
            f.flush()
            os.fchmod(f.fileno(), mode)
            os.fsync(f.fileno())
        os.replace(temporary, path)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(temporary)
        raise
    fsync_directory(path.parent)


def fsync_directory(path):
    directory = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def read_state(path):
    try:
        state = json.loads(path.read_text())
        return {s: int(t) for s, t in state.get("last_success", {}).items() if s in STORES and type(t) is int and t >= 0}
    except FileNotFoundError:
        return {}
    except (ValueError, AttributeError, OSError):
        log("the state file is unreadable: the last successful ships are forgotten")
        return {}


def ship(a, rc):
    a.state_directory.mkdir(mode=0o700, exist_ok=True)
    with open(a.state_directory / "lock", "a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            log("another run holds the lock: nothing done")
            return 1
        return ship_locked(a, rc)


def ship_locked(a, rc):
    last_success = read_state(a.state_directory / STATE_NAME)
    results = {}

    def publish():
        write_atomically(a.textfile_directory / FILE_NAME, render(results, last_success, time.time()))
        write_atomically(a.state_directory / STATE_NAME, json.dumps({"last_success": last_success}) + "\n", 0o600)

    # A success means: each store holds every archive the host had at this time.
    scanned = time.time()
    try:
        local, skipped = local_archives(a.archive_root)
    except OSError as error:
        log(f"the archive root cannot be read ({error.strerror}): nothing shipped")
        publish()
        return 1
    status = 1 if skipped else 0
    for store in STORES:
        try:
            r = ship_store(rc, store, a.archive_root, local, a.keep[store], scanned)
        except StoreUnreadable as error:
            r = {"readable": False}
            log(f"{store}: the store cannot be listed: {error}; {' / '.join(getattr(error.__cause__, 'detail', []))}")
        results[store] = r
        if r["readable"] and r["pending"] == 0:
            last_success[store] = int(scanned)
        if not r["readable"] or r["pending"] or r["changed"] or r["errors"]:
            status = 1
        publish()  # after each store: a long upload to one does not hide the other
    print(json.dumps({"stores": results}, sort_keys=True), flush=True)
    return status


def fetch(a, rc):
    """Copy one archive from a store into the archive root, checked, then renamed into place."""
    if not ARCHIVE_ID.fullmatch(a.archive):
        raise SystemExit("not an archive ID: arc_ and 32 lowercase hexadecimal digits")
    try:
        a.archive_root.mkdir(mode=0o700, exist_ok=True)
        st = a.archive_root.lstat()
    except OSError as error:
        raise SystemExit(f"the archive root cannot be used: {error.strerror}") from error
    if not a.archive_root.is_dir() or a.archive_root.is_symlink() or st.st_uid != os.geteuid() or st.st_mode & 0o777 != 0o700:
        raise SystemExit("the archive root must be a directory of this user, mode 0700")
    final = a.archive_root / a.archive
    if os.path.lexists(final):
        raise SystemExit(f"{a.archive} is already in the archive root")
    try:
        listing = rc.list(a.store, a.archive)
    except StoreUnreadable as error:
        raise SystemExit(f"{a.store} has no copy of {a.archive}, or cannot be listed: {error}") from error
    files = remote_archives([{**item, "Path": f"{a.archive}/{item['Path']}"} for item in listing]).get(a.archive, {})
    manifest = rc.manifest(a.store, a.archive) if MANIFEST in files else None
    if manifest is None or not complete_on_store(files, manifest, a.archive):
        raise SystemExit(f"{a.store} holds no complete copy of {a.archive}")
    # A hidden staging directory, as the worker's own captures use: a crash
    # leaves no archive, and the worker sweeps what is left.
    stage = a.archive_root / (".pending-" + secrets.token_hex(16))
    stage.mkdir(mode=0o700)
    try:
        fd = os.open(stage / MANIFEST, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(manifest)
            f.flush()
            os.fsync(f.fileno())
        fd = os.open(stage / DATA, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as f:
            rc.run("cat", f"{a.store}:{a.archive}/{DATA}", stdout=f)
            f.flush()
            os.fsync(f.fileno())
        digest, h, size = manifest_digest(manifest), hashlib.sha256(), 0
        with open(stage / DATA, "rb") as f:
            for block in iter(lambda: f.read(1 << 20), b""):
                h.update(block)
                size += len(block)
        if size != manifest_size(manifest, a.archive) or digest is None or h.digest() != digest:
            raise SystemExit(f"the copy of {a.archive} on {a.store} does not match its manifest (size or digest)")
        for name in FILES:
            # The store's times: a fetched archive is not "written after its
            # upload" if this host ships it to the same store.
            os.utime(stage / name, (files[name][1], files[name][1]))
        fsync_directory(stage)
        try:
            os.rename(stage, final)  # cannot replace a complete (nonempty) archive directory
        except OSError as error:
            if error.errno in (errno.EEXIST, errno.ENOTEMPTY):
                raise SystemExit(f"{a.archive} appeared in the archive root meanwhile") from error
            raise
        fsync_directory(a.archive_root)
    except BaseException:
        shutil.rmtree(stage, ignore_errors=True)
        raise
    print(json.dumps({"archive": a.archive, "store": a.store, "bytes": size}), flush=True)
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--archive-root", type=Path, default=Path("/var/lib/agentcapsule-archives"),
                   help="the worker's archive root (default: %(default)s)")
    p.add_argument("--rclone", default="/usr/bin/rclone", help="rclone executable (default: %(default)s)")
    p.add_argument("--rclone-config", default="/etc/agentcapsule-archive-ship/rclone.conf",
                   help="rclone configuration with the remotes s3 and standby (default: %(default)s)")
    p.add_argument("--rclone-flag", action="append", default=[], help="an extra rclone flag, as --flag=value (repeatable)")
    p.add_argument("--user", help="run rclone as this user (default: agentcapsule-ship when run as root)")
    p.add_argument("--timeout", type=int, default=6 * 3600, help="seconds one rclone transfer may take (default: %(default)s)")
    sub = p.add_subparsers(dest="command", required=True)
    s = sub.add_parser("ship", help="ship every complete archive to both stores, prune them, write the metrics")
    s.add_argument("--keep", action="append", default=[], metavar="STORE=AGE",
                   help="how long a store keeps an archive: s3=30d, standby=7d (the defaults)")
    s.add_argument("--textfile-directory", type=Path, default=Path("/var/lib/prometheus/node-exporter"),
                   help="node_exporter's --collector.textfile.directory (default: %(default)s)")
    s.add_argument("--state-directory", type=Path, default=Path("/var/lib/agentcapsule-archive-ship"),
                   help="where the last successful ships are kept (default: %(default)s)")
    f = sub.add_parser("fetch", help="copy one archive from one store into the archive root")
    f.add_argument("--store", choices=STORES, required=True)
    f.add_argument("--archive", required=True, help="archive ID (arc_...)")
    a = p.parse_args(argv)
    if a.command == "ship":
        keep = dict(DEFAULT_KEEP)
        for item in a.keep:
            store, _, age = item.partition("=")
            if store not in STORES:
                p.error(f"--keep: unknown store {store!r}")
            keep[store] = age
        try:
            a.keep = {store: duration(age) for store, age in keep.items()}
        except ValueError as error:
            p.error(str(error))
    account = None
    if os.geteuid() == 0:
        account = pwd.getpwnam(a.user or "agentcapsule-ship")
        if account.pw_uid == 0:
            p.error("rclone must not run as root")
    elif a.user and pwd.getpwnam(a.user).pw_uid != os.geteuid():
        p.error("--user needs root")
    rc = Rclone(a.rclone, a.rclone_config, a.rclone_flag, account, a.timeout)
    os.umask(0o077)
    return ship(a, rc) if a.command == "ship" else fetch(a, rc)


if __name__ == "__main__":
    raise SystemExit(main())
