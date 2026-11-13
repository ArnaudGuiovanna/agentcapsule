#!/usr/bin/env python3
"""Fetch the pinned pgBackRest and rclone of the backup qualifications.

scripts/verify-backups.py qualifies pgBackRest 2.58, and
scripts/verify-archive-shipping.py rclone 1.60.1: the packages of Ubuntu 26.04.
Ubuntu 24.04, the CI runner's system, ships older versions. This script
downloads those exact .deb files from a fixed snapshot of the Ubuntu archive,
with the two libraries pgBackRest needs that Ubuntu 24.04 lacks or ships
older. It checks each file against the SHA-256 written below, which is the one
of Ubuntu's signed package index. It extracts them with dpkg-deb -x, without
root and without apt, then runs each tool once. The binaries need glibc 2.38
at most, so they run on Ubuntu 24.04 (glibc 2.39).

pgBackRest also needs libpq.so.5: install libpq5 (it comes with PostgreSQL's
client), or pass the directory that holds it with --library-path.

The new --output directory holds:
  pgbackrest/usr/bin/pgbackrest   its libraries in pgbackrest/usr/lib/x86_64-linux-gnu
  rclone/usr/bin/rclone
  debs/                           the checked .deb files
  packages.json                   each package, its URL and its SHA-256
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import urllib.request

# The Ubuntu archive as it was at this instant. The snapshot keeps every file
# of that day, also once a newer version replaces it in the archive's pool.
SNAPSHOT = "https://snapshot.ubuntu.com/ubuntu/20261113T000000Z"
LIBRARIES = "usr/lib/x86_64-linux-gnu"

# (tool, package, version, path in the pool, SHA-256)
PACKAGES = (
    ("pgbackrest", "pgbackrest", "2.58.0-1", "pool/universe/p/pgbackrest/pgbackrest_2.58.0-1_amd64.deb",
     "5b9999e7f4cb445662d2100ffc614162eb8ebc98f410bcb20718d2e42721b56d"),
    # Ubuntu 24.04 has libssh2 1.11.0; this is the build pgBackRest was qualified with.
    ("pgbackrest", "libssh2-1t64", "1.11.1-1ubuntu0.26.04.4", "pool/main/libs/libssh2/libssh2-1t64_1.11.1-1ubuntu0.26.04.4_amd64.deb",
     "bb3e334dc885d124d38cd4350f1cb4606c03ce58e9f53dc51a84c2c8d11c84e1"),
    # Ubuntu 24.04 has only libxml2.so.2.
    ("pgbackrest", "libxml2-16", "2.15.2+dfsg-0.1ubuntu0.3", "pool/main/libx/libxml2/libxml2-16_2.15.2+dfsg-0.1ubuntu0.3_amd64.deb",
     "e82ce35fd61483c1febf83232e76e54a296a6a78391983a24a904ff640b75c09"),
    ("rclone", "rclone", "1.60.1+dfsg-4ubuntu3.2", "pool/universe/r/rclone/rclone_1.60.1+dfsg-4ubuntu3.2_amd64.deb",
     "37124f897112c536e4057cc3e4c68b7bcb8dadb88e415c959d900c7ff0378bee"),
)

# tool: (executable in its directory, arguments, start of the first line it prints)
TOOLS = {
    "pgbackrest": ("usr/bin/pgbackrest", ["version"], "pgBackRest 2.58.0"),
    "rclone": ("usr/bin/rclone", ["version"], "rclone v1.60.1"),
}


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def download(url, target, digest, attempts=3):
    """Download url into target, which then holds exactly the file of that SHA-256."""
    partial = target.with_name(target.name + ".part")
    for attempt in range(1, attempts + 1):
        try:
            with urllib.request.urlopen(url, timeout=60) as response, open(partial, "wb") as f:
                shutil.copyfileobj(response, f)
            break
        except OSError as error:
            partial.unlink(missing_ok=True)
            if attempt == attempts:
                raise RuntimeError(f"cannot download {url}: {error}") from error
            time.sleep(2 * attempt)
    got = sha256(partial)
    if got != digest:
        partial.unlink()
        raise RuntimeError(f"{url}: SHA-256 {got}, expected {digest}")
    os.replace(partial, target)


def obtain(entry, debs, cache):
    """The checked .deb of entry in debs: from the cache when it holds the same file, else downloaded."""
    _, package, version, pool, digest = entry
    name = Path(pool).name
    target = debs / name
    cached = cache / name if cache else None
    if cached and cached.is_file() and sha256(cached) == digest:
        shutil.copyfile(cached, target)
        return target, "cache"
    download(f"{SNAPSHOT}/{pool}", target, digest)
    if cache:
        cache.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(target, cached)
    return target, "downloaded"


def run_tool(root, tool, library_path):
    executable, arguments, expected = TOOLS[tool]
    path = root / executable
    env = {k: v for k, v in os.environ.items() if not k.startswith(("PGBACKREST_", "RCLONE_"))}
    env["LD_LIBRARY_PATH"] = ":".join(str(p) for p in [root / LIBRARIES, *library_path])
    r = subprocess.run([str(path), *arguments], env=env, capture_output=True, text=True, timeout=60, check=False)
    first = r.stdout.splitlines()[0] if r.stdout.strip() else ""
    if r.returncode or not first.startswith(expected):
        hint = " (pgBackRest needs libpq.so.5: install libpq5, or pass --library-path)" if "libpq" in r.stderr else ""
        raise RuntimeError(f"{path} {' '.join(arguments)}: exit {r.returncode}, printed {first!r}, "
                           f"expected {expected!r}{hint}\n{r.stderr.strip()}")
    return path, first


def fetch(output, packages=PACKAGES, cache=None, library_path=()):
    """Download, check and extract every package into the new directory output; run each tool."""
    if not shutil.which("dpkg-deb"):
        raise RuntimeError("dpkg-deb is required")
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    try:
        debs = output / "debs"
        debs.mkdir()
        report = {"snapshot": SNAPSHOT, "packages": [], "tools": {}}
        for entry in packages:
            tool, package, version, pool, digest = entry
            deb, source = obtain(entry, debs, cache)
            subprocess.run(["dpkg-deb", "-x", str(deb), str(output / tool)], check=True)
            report["packages"].append({"tool": tool, "package": package, "version": version, "url": f"{SNAPSHOT}/{pool}",
                                       "sha256": digest, "source": source})
            print(f"{package} {version}: SHA-256 matches ({source})", file=sys.stderr)
        for tool in sorted({entry[0] for entry in packages}):
            path, printed = run_tool(output / tool, tool, [Path(p).resolve() for p in library_path])
            report["tools"][tool] = {"path": str(path), "version": printed}
            if (output / tool / LIBRARIES).is_dir():
                report["tools"][tool]["library_path"] = str(output / tool / LIBRARIES)
        (output / "packages.json").write_text(json.dumps(report, indent=2) + "\n")
    except BaseException:
        # Never leave a directory that looks usable but holds unchecked or partial tools.
        shutil.rmtree(output, ignore_errors=True)
        raise
    return report


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--output", type=Path, required=True, help="new directory for the tools")
    p.add_argument("--cache", type=Path, help="directory of .deb files kept between runs; each is checked again")
    p.add_argument("--library-path", type=Path, action="append", default=[],
                   help="extra library directory for running the tools once, such as one that holds libpq.so.5")
    a = p.parse_args()
    try:
        report = fetch(a.output, cache=a.cache.resolve() if a.cache else None, library_path=a.library_path)
    except (RuntimeError, OSError, subprocess.CalledProcessError) as error:
        print(f"fetch-backup-tools: {error}", file=sys.stderr)
        return 1
    print(json.dumps(report["tools"], indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
