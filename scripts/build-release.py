#!/usr/bin/env python3
"""Build the release binaries of one commit, reproducibly, and check it.

The commit (HEAD, or the tag given with --version) is cloned into a fresh
directory; nothing of the working tree but its git objects is used. Each
binary is built with the pinned Go toolchain, -trimpath, an empty build ID,
no symbol table and no DWARF, and with the commit stamped by Go (its version,
revision and time: `go version -m` shows them). SOURCE_DATE_EPOCH is the
commit's time unless the environment sets it; Go itself embeds no time, so it
only fixes what the later steps date.

With --twice (the release workflow and CI use it), the build runs again in a
second clone at another path, with another home, temporary directory, build
cache, umask, time zone and locale, and every digest must match. The module
cache is shared and checked by `go mod verify`, unless --fresh-module-cache
gives each round its own (it then downloads every module).

With --linux-dev-version, build the Linux/amd64 host programs and CLI at HEAD
for local installation tests. The development version uses the form vX.Y.Z-dev.N.

With --guest-cryptsetup, the guest image (product.initrd) is built too, by
the commit's scripts/build-product-guest.py, twice when --twice is given. Its
native files (cryptsetup, e2fsprogs, glibc and their libraries) are this
host's: the image is reproducible only on a host with the same packages.

The C toolchain and libraries are this host's (gcc, glibc, libcryptsetup
headers, the SLIM native library pinned by runtime/interop/profile.json): a
digest is reproducible with the same Go and the same packages. build.json
records them.

The new --output directory receives dist/ (the binaries, and the guest
image with its build record), build.json and the logs.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]
GO_VERSION = "go1.27.4"
# internal/volumestore links "-l:libcryptsetup.so.12", which Go refuses in a
# #cgo directive unless this pattern allows it.
CGO_LDFLAGS_ALLOW = r"-l:libcryptsetup\.so\.12"
STATIC_TAGS = "netgo,osusergo,sqlite_omit_load_extension"
# (name, module directory, package, cgo, static)
BINARIES = (
    ("agentcapsule-api", ".", "./cmd/agentcapsule-api", True, False),
    ("agentcapsule-worker", ".", "./cmd/agentcapsule-worker", True, False),
    ("agentcapsule-admin", ".", "./cmd/agentcapsule-admin", True, False),
    ("agentcapsule-authority", ".", "./cmd/agentcapsule-authority", True, False),
    ("agentcapsule-harness", ".", "./cmd/agentcapsule-harness", False, True),
    ("capsule-adapter", ".", "./cmd/capsule-adapter", True, True),
    ("agentcapsule-slim-bridge", "runtime/slimbridge", ".", True, False),
)
CLI_TARGETS = {f"agentcapsule-{system}-{arch}" + (".exe" if system == "windows" else ""): (system, arch)
               for system in ("linux", "darwin", "windows") for arch in ("amd64", "arm64")}
GUEST_FILES = ("product.initrd",)
# The host packages whose files a build uses, recorded when dpkg is present.
HOST_PACKAGES = ("gcc", "libc6-dev", "libcryptsetup-dev", "cryptsetup-bin", "e2fsprogs", "libc6")
VERSION_PATTERN = re.compile(r"v\d+\.\d+\.\d+(-[0-9A-Za-z.]+)?")


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def git(*args, cwd=ROOT):
    return subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True).stdout.strip()


def build_flags(static):
    ldflags = "-s -w -buildid="
    flags = ["-trimpath", "-buildvcs=true"]
    if static:
        flags.append("-tags=" + STATIC_TAGS)
    return flags, ldflags


def round_environment(base, round_dir, variant, go, module_cache, epoch, native_tools):
    """A minimal environment for one build round; variant b changes what must not matter."""
    home = round_dir / "home"
    tmp = round_dir / "tmp"
    for d in (home, tmp):
        d.mkdir(parents=True, exist_ok=True)
    env = {
        "PATH": f"{Path(go).parent}:/usr/local/bin:/usr/bin:/bin",
        "HOME": str(home),
        "TMPDIR": str(tmp),
        "GOCACHE": str(round_dir / "gocache"),
        "GOPATH": str(round_dir / "gopath"),
        "GOMODCACHE": str(module_cache),
        "GOTOOLCHAIN": "local",
        "GOENV": "off",
        "GOWORK": "off",
        "GOFLAGS": "-mod=readonly",
        "CGO_LDFLAGS_ALLOW": CGO_LDFLAGS_ALLOW,
        "GOOS": "linux",
        "GOARCH": "amd64",
        "GOAMD64": "v1",
        "SOURCE_DATE_EPOCH": str(epoch),
        "TZ": "UTC" if variant == "a" else "Pacific/Kiritimati",
        "LC_ALL": "C.UTF-8" if variant == "a" else "C",
    }
    for name in ("GOPROXY", "GONOSUMDB", "GONOSUMCHECK", "GOSUMDB", "GOPRIVATE", "CC", "SSL_CERT_FILE"):
        if base.get(name):
            env[name] = base[name]
    if native_tools:
        env["CGO_CFLAGS"] = f"-I{Path(native_tools).resolve() / 'usr/include'}"
    return env


def run(cmd, log, env, cwd, timeout=1800, umask=None):
    with open(log, "a") as out:
        out.write("+ " + " ".join(str(c) for c in cmd) + "\n")
        out.flush()
        preexec = (lambda: os.umask(umask)) if umask is not None else None
        result = subprocess.run([str(c) for c in cmd], cwd=cwd, env=env, stdout=out, stderr=subprocess.STDOUT,
                                stdin=subprocess.DEVNULL, timeout=timeout, preexec_fn=preexec, check=False)
    if result.returncode:
        raise RuntimeError(f"{' '.join(str(c) for c in cmd[:3])} failed; see {log}")


def slim_library(cache, work):
    """Extract the pinned SLIM native library (runtime/interop/profile.json) into work."""
    slim = json.loads((ROOT / "runtime/interop/profile.json").read_text())["slim"]
    archive = Path(cache) / (slim["native_sha256"] + ".zip")
    if not archive.is_file() or sha256(archive) != slim["native_sha256"]:
        archive.parent.mkdir(parents=True, exist_ok=True)
        partial = archive.with_name(archive.name + ".part")
        with urllib.request.urlopen(slim["native_url"], timeout=120) as remote, open(partial, "wb") as out:
            shutil.copyfileobj(remote, out)
        if sha256(partial) != slim["native_sha256"]:
            partial.unlink()
            raise RuntimeError("the SLIM native archive does not have its pinned SHA-256")
        partial.replace(archive)
    library = Path(work) / slim["native_library"]
    with zipfile.ZipFile(archive) as zipped:
        entries = [e for e in zipped.infolist() if Path(e.filename).name == slim["native_library"]]
        if len(entries) != 1:
            raise RuntimeError("unexpected SLIM native archive contents")
        with zipped.open(entries[0]) as incoming, open(library, "wb") as outgoing:
            shutil.copyfileobj(incoming, outgoing)
    if sha256(library) != slim["native_library_sha256"]:
        raise RuntimeError("the SLIM native library does not have its pinned SHA-256")
    return library, slim


def build_round(variant, round_dir, commit, go, base_env, module_cache, epoch, native_tools, slim_cache,
                guest_cryptsetup, log, version, cli_targets):
    """Clone the commit and build every binary (and the guest image) in round_dir."""
    # Variant b nests the clone deeper, so that no path of the first round can match.
    src = round_dir / ("src" if variant == "a" else "elsewhere/at/another/depth/src")
    src.parent.mkdir(parents=True, exist_ok=True)
    umask = 0o022 if variant == "a" else 0o077
    env = round_environment(base_env, round_dir, variant, go, module_cache, epoch, native_tools)
    run(["git", "clone", "--quiet", "--no-local", "--no-hardlinks", "--no-checkout", ROOT, src], log, env, round_dir)
    # A detached HEAD (a pull request's merge commit, a tag) may be on no branch the clone copied.
    run(["git", "fetch", "--quiet", "--no-tags", ROOT, "HEAD"], log, env, src)
    run(["git", "-c", "advice.detachedHead=false", "checkout", "--quiet", "--detach", commit], log, env, src)
    status = git("status", "--porcelain", "--untracked-files=all", cwd=src)
    if status:
        raise RuntimeError("the clone is not clean: " + status[:200])
    dist = round_dir / "dist"
    dist.mkdir()
    native = Path(tempfile.mkdtemp(prefix="slim-native-", dir=round_dir / "tmp"))
    library, _ = slim_library(slim_cache, native)
    for name, module, package, cgo, static in BINARIES:
        flags, ldflags = build_flags(static)
        if static and cgo:
            ldflags += " -linkmode external -extldflags '-static'"
        build_env = dict(env, CGO_ENABLED="1" if cgo else "0")
        if module == "runtime/slimbridge":
            build_env["CGO_LDFLAGS"] = f"-L{library.parent}"
        run([go, "build", *flags, "-ldflags=" + ldflags, "-o", dist / name, package], log, build_env, src / module,
            umask=umask)
    for name, (system, arch) in cli_targets.items():
        flags, ldflags = build_flags(True)
        ldflags += " -X github.com/ArnaudGuiovanna/agentcapsule/internal/hostops.Version=" + version
        run([go, "build", *flags, "-ldflags=" + ldflags, "-o", dist / name, "./cmd/agentcapsule"],
            log, dict(env, CGO_ENABLED="0", GOOS=system, GOARCH=arch), src, umask=umask)
    if guest_cryptsetup:
        guest = round_dir / "guest"
        run(["python3", src / "scripts/build-product-guest.py", "--go", go, "--cryptsetup", guest_cryptsetup,
             "--output", guest], log, env, src, umask=umask)
        for name in GUEST_FILES:
            shutil.copy2(guest / name, dist / name)
        shutil.copy2(guest / "artifacts.json", dist / "product-guest.json")
    shutil.rmtree(native)
    return dist


def host_packages():
    if not shutil.which("dpkg-query"):
        return {}
    out = subprocess.run(["dpkg-query", "-W", "-f", "${Package}\t${Version}\t${Status}\n", *HOST_PACKAGES],
                         capture_output=True, text=True, check=False).stdout
    return {line.split("\t")[0]: line.split("\t")[1] for line in out.splitlines()
            if line.count("\t") == 2 and line.endswith("\tinstall ok installed")}


def first_line(cmd):
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=30, check=False)
        return (out.stdout or out.stderr).splitlines()[0].strip()
    except (OSError, IndexError):
        return "unavailable"


def build_info(go, path, env):
    out = subprocess.run([str(go), "version", "-m", str(path)], capture_output=True, text=True, env=env, check=False)
    return [line.strip() for line in out.stdout.splitlines()[1:]]


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--go", required=True, type=Path, help=f"Go executable ({GO_VERSION})")
    p.add_argument("--output", required=True, type=Path, help="new output directory")
    versions = p.add_mutually_exclusive_group()
    versions.add_argument("--version", help="release tag (vMAJOR.MINOR.PATCH[-PRE]); it must point at HEAD. Default: HEAD, untagged")
    versions.add_argument("--linux-dev-version", help="local Linux/amd64 development build at HEAD, e.g. v0.1.0-dev.1")
    p.add_argument("--twice", action="store_true", help="build in a second clean environment and compare every digest")
    p.add_argument("--fresh-module-cache", action="store_true", help="give each round an empty module cache")
    p.add_argument("--native-tools", type=Path, help="directory whose usr/include holds the libcryptsetup headers")
    p.add_argument("--guest-cryptsetup", type=Path, help="cryptsetup executable: also build the guest image with it")
    p.add_argument("--slim-cache", type=Path,
                   default=Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache")) / "agentcapsule-interop",
                   help="cache of the SLIM native archive, shared with verify-interop.py (default: %(default)s)")
    p.add_argument("--keep-rounds", action="store_true", help="keep the clones and build caches of each round")
    a = p.parse_args(argv)

    cli_targets = CLI_TARGETS
    if a.linux_dev_version:
        if not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+-dev\.[0-9]+", a.linux_dev_version):
            p.error("--linux-dev-version must look like v0.1.0-dev.1")
        if sys.platform != "linux" or os.uname().machine != "x86_64":
            p.error("--linux-dev-version requires a Linux/amd64 builder")
        cli_targets = {"agentcapsule-linux-amd64": CLI_TARGETS["agentcapsule-linux-amd64"]}
    build_version = a.version or a.linux_dev_version
    go = a.go.resolve()
    version = subprocess.run([str(go), "env", "GOVERSION"], capture_output=True, text=True,
                             env=dict(os.environ, GOTOOLCHAIN="local"), check=True).stdout.strip()
    if version != GO_VERSION:
        p.error(f"Go is {version}, the release needs {GO_VERSION}")
    commit = git("rev-parse", "HEAD")
    if a.version:
        if not VERSION_PATTERN.fullmatch(a.version):
            p.error("--version must look like v1.2.3 or v1.2.3-rc.1")
        tagged = subprocess.run(["git", "rev-parse", "--verify", "--quiet", a.version + "^{commit}"], cwd=ROOT,
                                capture_output=True, text=True, check=False).stdout.strip()
        if tagged != commit:
            p.error(f"tag {a.version} does not point at HEAD ({commit})")
    epoch = int(os.environ.get("SOURCE_DATE_EPOCH") or git("show", "-s", "--format=%ct", commit))
    out = a.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    log = out / "build.log"
    base_env = dict(os.environ)
    shared_cache = subprocess.run([str(go), "env", "GOMODCACHE"], capture_output=True, text=True, check=True,
                                  env=dict(os.environ, GOTOOLCHAIN="local")).stdout.strip()

    record = {"commit": commit, "version": build_version or "untagged", "source_date_epoch": epoch, "go": version,
              "cc": first_line([os.environ.get("CC", "cc"), "--version"]), "host_packages": host_packages(),
              "flags": {"all": "-trimpath -buildvcs=true -ldflags='-s -w -buildid='",
                        "static": f"-tags={STATIC_TAGS} -ldflags='-linkmode external -extldflags -static'"},
              "binaries": {name: {"module": module, "package": package, "cgo": cgo, "static": static}
                           for name, module, package, cgo, static in BINARIES},
              "rounds": {}, "reproducible": None, "status": "running"}

    for name, (system, arch) in cli_targets.items():
        record["binaries"][name] = {"module": ".", "package": "./cmd/agentcapsule", "cgo": False, "static": True,
                                    "goos": system, "goarch": arch}

    def save():
        (out / "build.json").write_text(json.dumps(record, indent=2) + "\n")

    save()
    try:
        rounds = ["a", "b"] if a.twice else ["a"]
        dists = {}
        for variant in rounds:
            started = time.monotonic()
            round_dir = out / "rounds" / variant
            round_dir.mkdir(parents=True)
            module_cache = round_dir / "gomodcache" if a.fresh_module_cache else Path(shared_cache)
            if not a.fresh_module_cache:
                run([go, "mod", "verify"], log, dict(os.environ, GOTOOLCHAIN="local", GOWORK="off",
                                                     GOFLAGS="-mod=readonly"), ROOT)
            print(f"round {variant}: building {commit[:12]} in {round_dir}", flush=True)
            dists[variant] = build_round(variant, round_dir, commit, go, base_env, module_cache, epoch,
                                         a.native_tools, a.slim_cache, a.guest_cryptsetup, log,
                                         build_version or "development", cli_targets)
            record["rounds"][variant] = {
                "seconds": round(time.monotonic() - started, 1),
                "sha256": {f.name: sha256(f) for f in sorted(dists[variant].iterdir()) if f.name in
                           record["binaries"].keys() | set(GUEST_FILES)}}
            save()
        digests = [record["rounds"][v]["sha256"] for v in rounds]
        if a.twice:
            differing = sorted(n for n in digests[0] if digests[0][n] != digests[1].get(n))
            record["reproducible"] = not differing
            record["differing"] = differing
        dist = out / "dist"
        shutil.copytree(dists["a"], dist)
        env = round_environment(base_env, out / "rounds" / "a", "a", go, shared_cache, epoch, a.native_tools)
        for name in record["binaries"]:
            record["binaries"][name].update(sha256=sha256(dist / name), size=(dist / name).stat().st_size,
                                            build_info=build_info(go, dist / name, env))
        if a.guest_cryptsetup:
            record["guest"] = {"sha256": sha256(dist / "product.initrd"),
                               "native_files": json.loads((dist / "product-guest.json").read_text())["native_files"]}
        record["status"] = "failed" if record["reproducible"] is False else "passed"
        save()
    except BaseException as error:
        record["status"] = "failed"
        record["error"] = str(error)
        save()
        raise
    finally:
        if not a.keep_rounds and (out / "rounds").exists():
            subprocess.run(["chmod", "-R", "u+rwX", str(out / "rounds")], check=False)
            shutil.rmtree(out / "rounds", ignore_errors=True)
    if record["reproducible"] is False:
        print("NOT REPRODUCIBLE: " + ", ".join(record["differing"]), file=sys.stderr)
        return 1
    print(("reproducible: " if a.twice else "built: ") + ", ".join(sorted(record["rounds"]["a"]["sha256"])))
    print(out / "dist")
    return 0


if __name__ == "__main__":
    sys.exit(main())
