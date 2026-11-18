#!/usr/bin/env python3
"""Fetch the pinned tools of the release audit, each checked by SHA-256.

scripts/release-tools.json names the release file of syft, grype, cosign and
actionlint and its SHA-256. A tool is downloaded once into the cache
(~/.cache/agentcapsule-release-tools by default, or --cache), checked against
that SHA-256 before it is unpacked and every time it is used, then run once to
check its version. Any other file stops the script; nothing unchecked is ever
executed.

govulncheck is built from scripts/tools/go.mod, whose go.sum pins it and every
module it needs: the Go command refuses a module whose hash differs.

The release scripts (audit-dependencies.py, build-release.py, release-sbom.py,
scan-artifacts.py) import this module. Run it alone to fetch every tool ahead,
for example before going offline:

  python3 scripts/release_tools.py [--cache DIR] [--go GO] [TOOL ...]
"""

import argparse
import datetime
import fnmatch
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import urllib.request

SCRIPTS = Path(__file__).resolve().parent
ROOT = SCRIPTS.parent
PINS = SCRIPTS / "release-tools.json"
TOOLS_MODULE = SCRIPTS / "tools"
ALLOWLIST = SCRIPTS / "vulnerability-allowlist.json"
# An exception is reviewed again at least this often.
MAX_ALLOWLIST_DAYS = 90
ALLOWLIST_FIELDS = ("ids", "package", "reason", "expires")


def load_allowlist(path=ALLOWLIST, today=None):
    """Return (entries in force, problems). An expired or malformed entry is a problem.

    An entry names its vulnerabilities with "ids" (a list) or "id" (one), one package, the targets
    it covers (patterns, default all), the reason and the expiry date.
    """
    today = today or datetime.date.today()
    data = json.loads(Path(path).read_text())
    entries, problems = [], []
    for index, entry in enumerate(data.get("entries", [])):
        entry = dict(entry)
        ids = entry.get("ids", [entry["id"]] if entry.get("id") else [])
        entry["ids"] = [i for i in ids if isinstance(i, str) and i.strip()] if isinstance(ids, list) else []
        label = f"allowlist entry {index} ({', '.join(entry['ids'][:3]) or '?'}, {entry.get('package', '?')})"
        missing = [field for field in ALLOWLIST_FIELDS if not entry.get(field) or not str(entry[field]).strip()]
        if missing:
            problems.append(f"{label}: missing {', '.join(missing)}")
            continue
        try:
            expires = datetime.date.fromisoformat(entry["expires"])
        except ValueError:
            problems.append(f"{label}: expires is not a date (YYYY-MM-DD)")
            continue
        if expires < today:
            problems.append(f"{label}: expired on {expires}; review it again or fix the finding")
            continue
        if (expires - today).days > MAX_ALLOWLIST_DAYS:
            problems.append(f"{label}: expires more than {MAX_ALLOWLIST_DAYS} days ahead")
            continue
        targets = entry.get("targets") or ["*"]
        if not isinstance(targets, list) or not all(isinstance(t, str) and t for t in targets):
            problems.append(f"{label}: targets must be a list of patterns")
            continue
        entries.append(dict(entry, targets=targets))
    return entries, problems


def allowlist_entry(finding, entries):
    """The entry in force that covers a finding: same ID or alias, same package, matching target."""
    ids = {finding["id"], *finding.get("aliases", ())}
    for entry in entries:
        if ids & set(entry["ids"]) and entry["package"] == finding["package"] and \
                any(fnmatch.fnmatchcase(finding["target"], pattern) for pattern in entry["targets"]):
            return entry
    return None


def apply_allowlist(findings, entries, blocking):
    """Split findings into (blocking, allowlisted, other); mark which entries were used."""
    blocked, allowed, other = [], [], []
    for finding in findings:
        if not blocking(finding):
            other.append(finding)
            continue
        entry = allowlist_entry(finding, entries)
        if entry is None:
            blocked.append(finding)
        else:
            entry["used"] = True
            allowed.append(dict(finding, allowlisted_until=entry["expires"], allowlist_reason=entry["reason"]))
    return blocked, allowed, other


def unused_entries(entries):
    return [{"ids": e["ids"], "package": e["package"], "targets": e["targets"]} for e in entries if not e.get("used")]


def default_cache():
    return Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache")) / "agentcapsule-release-tools"


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def pins():
    data = json.loads(PINS.read_text())
    return {name: pin for name, pin in data.items() if isinstance(pin, dict)}


def quiet_env(cache):
    """Environment for the Anchore tools: no update check, caches in ours."""
    env = dict(os.environ)
    env.update({
        "SYFT_CHECK_FOR_APP_UPDATE": "false",
        "GRYPE_CHECK_FOR_APP_UPDATE": "false",
        "GRYPE_DB_CACHE_DIR": str(Path(cache) / "grype-db"),
    })
    return env


def download(url, target):
    partial = target.with_name(target.name + ".part")
    try:
        with urllib.request.urlopen(url, timeout=120) as response, open(partial, "wb") as f:
            shutil.copyfileobj(response, f)
        partial.replace(target)
    finally:
        partial.unlink(missing_ok=True)


def extract_member(archive, member, target):
    """Write the single regular file named member of a .tar.gz to target."""
    with tarfile.open(archive, "r:gz") as tar:
        entries = [m for m in tar.getmembers() if m.name.lstrip("./") == member]
        if len(entries) != 1 or not entries[0].isfile():
            raise RuntimeError(f"{archive.name}: expected one regular file named {member}")
        source = tar.extractfile(entries[0])
        partial = target.with_name(target.name + ".part")
        with open(partial, "wb") as out:
            shutil.copyfileobj(source, out)
        partial.chmod(0o755)
        partial.replace(target)


def fetch(name, cache=None, opener=download):
    """Return the path of the pinned tool, downloading and checking it if needed."""
    pin = pins()[name]
    cache = Path(cache or default_cache())
    files = cache / "files"
    files.mkdir(parents=True, exist_ok=True)
    release = files / f"{pin['sha256']}-{Path(pin['url']).name}"
    if not release.is_file() or sha256(release) != pin["sha256"]:
        release.unlink(missing_ok=True)
        opener(pin["url"], release)
        actual = sha256(release)
        if actual != pin["sha256"]:
            release.unlink()
            raise RuntimeError(f"{name}: {pin['url']} has SHA-256 {actual}, pinned {pin['sha256']}")
    if "member" not in pin:
        release.chmod(0o755)
        return release
    executable = cache / "bin" / f"{name}-{pin['version']}-{pin['sha256'][:12]}"
    executable.parent.mkdir(parents=True, exist_ok=True)
    # Unpack again on every use: the executable is only as good as the archive
    # just checked, never a file that may have changed in the cache.
    extract_member(release, pin["member"], executable)
    return executable


def check_version(name, executable, cache=None):
    pin = pins()[name]
    out = subprocess.run([str(executable), *pin["version_command"]], capture_output=True, text=True,
                         env=quiet_env(cache or default_cache()), timeout=60, check=False)
    text = out.stdout + out.stderr
    if out.returncode or pin["version_output"] not in text:
        raise RuntimeError(f"{name}: unexpected version output: {text.strip()[:300]}")
    return text


def tool(name, cache=None):
    """Fetch, check and return the pinned tool's executable."""
    executable = fetch(name, cache)
    check_version(name, executable, cache)
    return executable


def govulncheck_version():
    text = (TOOLS_MODULE / "go.mod").read_text()
    match = re.search(r"^\s*golang\.org/x/vuln (v\S+)", text, re.M)
    if not match:
        raise RuntimeError("scripts/tools/go.mod does not require golang.org/x/vuln")
    return match.group(1)


def govulncheck(go, cache=None):
    """Build govulncheck from scripts/tools (go.sum-pinned) and return it."""
    cache = Path(cache or default_cache())
    target = cache / "bin" / f"govulncheck-{govulncheck_version()}"
    target.parent.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, GOFLAGS="-mod=readonly", GOWORK="off", GOTOOLCHAIN="local", CGO_ENABLED="0")
    subprocess.run([str(go), "build", "-trimpath", "-o", str(target), "golang.org/x/vuln/cmd/govulncheck"],
                   cwd=TOOLS_MODULE, env=env, check=True, timeout=600)
    return target


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--cache", type=Path, default=default_cache(), help="tool cache (default: %(default)s)")
    p.add_argument("--go", type=Path, help="Go toolchain, to build govulncheck too")
    p.add_argument("tools", nargs="*", help="tools to fetch (default: all)")
    a = p.parse_args()
    for name in a.tools or sorted(pins()):
        path = tool(name, a.cache)
        print(f"{name} {pins()[name]['version']} {path}")
    if a.go:
        print(f"govulncheck {govulncheck_version()} {govulncheck(a.go, a.cache)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
