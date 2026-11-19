"""Retain digest-checked upstream sources for the server and OCI release archives."""
from concurrent.futures import ThreadPoolExecutor
import hashlib
from http.client import IncompleteRead
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time
import tomllib
from urllib.error import HTTPError, URLError
from urllib.request import urlopen

from release_tools import sha256


def git_source(repository, revision, work, git_cache=None):
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository) or not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise ValueError("invalid upstream Git repository or revision")
    dest = work / f"{repository.replace('/', '-')}-{revision}.tar.gz"
    if git_cache:
        for repo in sorted(git_cache.glob(repository.split("/")[-1] + "-*")):
            git = ["git", "--no-replace-objects", "--git-dir", str(repo)]
            resolved = subprocess.run([*git, "rev-parse", "--verify", revision + "^{commit}"],
                                      capture_output=True, text=True, check=False)
            if resolved.returncode == 0 and resolved.stdout.strip() == revision:
                subprocess.run([*git, "archive", "--format=tar.gz", "--output", dest, revision], check=True)
                return dest
    with tempfile.TemporaryDirectory(dir=work) as temp:
        git = ["git", "-C", temp]
        subprocess.run([*git, "init", "--quiet", "--bare"], check=True)
        subprocess.run([*git, "fetch", "--quiet", "--depth=1", "https://github.com/" + repository + ".git", revision], check=True)
        actual = subprocess.check_output([*git, "rev-parse", "FETCH_HEAD^{commit}"], text=True).strip()
        if actual != revision:
            raise ValueError("upstream checkout differs from the pinned commit")
        subprocess.run([*git, "archive", "--format=tar.gz", "--output", dest, revision], check=True)
    return dest


def checked_download(url, dest, expected, cache=None):
    cached = cache / hashlib.sha256(url.encode()).hexdigest() if cache else None
    if cached and cached.is_file() and sha256(cached) == expected:
        shutil.copyfile(cached, dest)
        return dest
    for attempt in range(3):
        try:
            with urlopen(url, timeout=120) as source, dest.open("wb") as dst:
                shutil.copyfileobj(source, dst)
            break
        except (HTTPError, URLError, TimeoutError, IncompleteRead, ConnectionError) as err:
            if attempt == 2 or isinstance(err, HTTPError) and err.code < 500 and err.code != 429:
                raise
            time.sleep(2 ** attempt)
    if sha256(dest) != expected:
        raise ValueError("upstream source checksum mismatch for " + dest.name)
    if cached:
        cache.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=cache, delete=False) as entry:
            temporary = Path(entry.name)
        try:
            shutil.copyfile(dest, temporary)
            temporary.replace(cached)
        finally:
            temporary.unlink(missing_ok=True)
    return dest


def locked_crates(lock, work, *, source_cache=None, cargo_home=None, git_projects=()):
    """Materialize the external entries of a Cargo.lock, retaining original crate bytes."""
    packages = tomllib.loads(lock.decode())["package"]

    def collect(pkg):
        source = pkg["source"]
        if source.startswith("git+"):
            url, _, rev = source.partition("#")
            for project in git_projects:
                if url == "git+https://github.com/" + project:
                    return git_source(project, rev, work, cargo_home / "git/db" if cargo_home else None)
            raise ValueError("review the Cargo Git dependency for " + pkg["name"])
        if source != "registry+https://github.com/rust-lang/crates.io-index":
            raise ValueError("review the Cargo source registry for " + pkg["name"])
        name, version, checksum = pkg["name"], pkg["version"], pkg.get("checksum", "")
        if (not re.fullmatch(r"[a-zA-Z0-9_-]+", name) or not re.fullmatch(r"[a-zA-Z0-9.+_-]+", version)
                or not re.fullmatch("[a-f0-9]{64}", checksum)):
            raise ValueError("invalid locked crate identifier or checksum")
        filename = f"{name}-{version}.crate"
        dest = work / filename
        if cargo_home:
            candidates = sorted((cargo_home / "registry/cache").glob("*/" + filename))
            for cached in candidates:
                shutil.copyfile(cached, dest)
                if sha256(dest) == checksum:
                    return dest
            if candidates:
                raise ValueError("Cargo cache checksum mismatch for " + filename)
        return checked_download(f"https://static.crates.io/crates/{name}/{filename}", dest, checksum, source_cache)

    inputs = []
    git_sources = set()
    for pkg in packages:
        source = pkg.get("source")
        if not source or source in git_sources:
            continue
        if source.startswith("git+"):
            git_sources.add(source)
        inputs.append(pkg)
    with ThreadPoolExecutor(max_workers=8) as pool:
        return {"cargo/" + path.name: path for path in pool.map(collect, inputs)}
