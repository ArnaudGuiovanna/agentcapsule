# Linux host controller. The portable CLI embeds setup.py followed by this file.
import argparse
import base64
import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request
import uuid

REPO = "ArnaudGuiovanna/agentcapsule"
VERSION = r"v[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.]+)?"
STATE = Path("/var/lib/agentcapsule-install")
OPERATIONS = STATE / "operations"
RELEASES = Path("/opt/agentcapsule-releases")
ACTIVE = Path("/opt/agentcapsule")
UNIT_DIR = Path("/etc/systemd/system")
ETC = Path("/etc/agentcapsule")
SERVER = "agentcapsule-server-linux-amd64.tar.gz"
DEBS = "agentcapsule-packages-linux-amd64.tar"
IMAGES = "agentcapsule-images-linux-amd64.tar.gz"
COSIGN_HASH = "424e2c97d0b45fd7a6b608a87f090f35633f4c23ece5f092d48bba11aaf4bbfa"
COSIGN_URL = "https://github.com/sigstore/cosign/releases/download/v3.1.4/cosign-linux-amd64"
OP_ID = r"host_[a-f0-9]{32}"
SCHEMA = "agentcapsule.host/v1"


def write_file(path, data, mode=0o600):
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as tmp:
        try:
            tmp.write(data)
            os.fchmod(tmp.fileno(), mode)
            tmp.flush()
            os.fsync(tmp.fileno())
            os.replace(tmp.name, path)
            fd = os.open(path.parent, os.O_DIRECTORY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        finally:
            Path(tmp.name).unlink(missing_ok=True)


def save(path, obj):
    write_file(path, (json.dumps(obj, sort_keys=True, indent=2) + "\n").encode())


def read(path):
    return json.loads(path.read_bytes())


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def sha(path):
    with path.open("rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()


def current():
    path = ACTIVE / "bundle.json"
    return read(path)["version"] if path.is_file() else None


def version_order(tag):
    match = re.fullmatch(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*))?", tag)
    if not match:
        raise ValueError("invalid semantic version")
    prerelease = match[4].split(".") if match[4] else []
    if any(part.isdigit() and len(part) > 1 and part.startswith("0") for part in prerelease):
        raise ValueError("invalid numeric prerelease identifier")
    labels = tuple((0, int(part)) if part.isdigit() else (1, part) for part in prerelease)
    return (*map(int, match.groups()[:3]), not prerelease, labels)


def validate_release_direction(request):
    action = request["action"]
    if action not in ("update", "rollback"):
        return
    older = version_order(request["version"]) < version_order(request["from"])
    if action == "update" and older:
        raise ValueError("use rollback plan for an older signed release")
    if action == "rollback" and not older:
        raise ValueError("rollback requires a strictly older signed release")


def activation_generation():
    receipt = STATE / "active-release.json"
    if receipt.is_file():
        return read(receipt)["operation_id"]
    if ACTIVE.is_symlink():
        info = ACTIVE.lstat()
        return f"legacy-{info.st_ino}-{info.st_ctime_ns}"
    return None


class MigrationHistoryMismatch(ValueError):
    pass


class RollbackIncompatible(ValueError):
    pass


def rollback_requires_restore(reason):
    return RollbackIncompatible("binary rollback requires coordinated restoration: " + reason +
                      ". Select a matching PostgreSQL and volume recovery point with the current independent "
                      "authorities. Writes after that point may be lost. See docs/recovery.md")


def check_binary_rollback(request, candidate, origin):
    version = request["from"]
    source = RELEASES / version / "bundle.json"
    receipt = STATE / "downloads" / version / "activated-origin.json"
    if not source.is_file() or not receipt.is_file():
        raise rollback_requires_restore("installed build lacks a verified activation receipt")
    if current() == version and (not ACTIVE.is_symlink() or ACTIVE.resolve() != source.parent.resolve()):
        raise ValueError("active link differs from the authenticated release directory")
    evidence = read(receipt)
    if sha(source) != evidence["manifest_sha256"] or evidence["version"] != version:
        raise ValueError("installed manifest differs from its authenticated activation receipt")
    if evidence["signer"] != origin["signer"]:
        raise ValueError("rollback signing authority differs from the installed release")
    installed = read(source)
    if (not installed.get("binary_rollback_epoch") or installed["binary_rollback_epoch"] != candidate.get("binary_rollback_epoch") or
            any(bundle.get("protocol") != "v1" or bundle.get("migration_mode") != "offline-exact-history"
                for bundle in (installed, candidate))):
        raise rollback_requires_restore("formats, protocols or authority semantics differ or are undeclared")
    if (not installed.get("migration_ledger") or installed["migration_ledger"] != candidate.get("migration_ledger") or
            installed.get("migrations") != candidate.get("migrations")):
        raise rollback_requires_restore("signed PostgreSQL histories differ or are undeclared")
    required = {"offline-images.json", "host-packages.json", "vmlinux", "firecracker", "jailer", "product.initrd"}
    def environment(bundle):
        files = bundle.get("sha256", {})
        return {name: digest for name, digest in files.items() if name in required or
                name == "agentcapsule-archive-ship.py" or
                name.startswith(("systemd/", "config/", "oidc/", "interop/", "backup/"))}
    installed_environment = environment(installed)
    if (not required <= installed_environment.keys() or
            installed_environment != environment(candidate)):
        raise rollback_requires_restore("host or guest dependencies, service definitions or OCI configurations differ")
    try:
        return check_migration_plan(installed, candidate)
    except MigrationHistoryMismatch as error:
        raise rollback_requires_restore(str(error)) from error


def run(*argv, **kwargs):
    return subprocess.run([str(arg) for arg in argv], check=True, **kwargs)


def output(*argv, **kwargs):
    return run(*argv, stdout=subprocess.PIPE, text=True, **kwargs).stdout.strip()


def download(url, dest, digest=None, limit=2 << 30):
    with urllib.request.urlopen(url, timeout=90) as reply, tempfile.NamedTemporaryFile(dir=dest.parent, delete=False) as out:
        try:
            if not reply.geturl().startswith("https://"):
                raise ValueError("insecure download redirect")
            total = 0
            h = hashlib.sha256()
            while chunk := reply.read(1 << 20):
                total += len(chunk)
                if total > limit:
                    raise ValueError("asset exceeds limit")
                h.update(chunk)
                out.write(chunk)
            if digest and h.hexdigest() != digest:
                raise ValueError("downloaded digest differs from signed manifest")
            out.flush()
            os.fsync(out.fileno())
            os.replace(out.name, dest)
        finally:
            Path(out.name).unlink(missing_ok=True)


def checksums(path, pinned_digest=None):
    contents = path.read_bytes()
    if pinned_digest is not None and hashlib.sha256(contents).hexdigest() != pinned_digest:
        raise ValueError("release checksums differ from the verified manifest")
    sums = {}
    for line in contents.decode("utf-8").splitlines():
        m = re.fullmatch(r"([a-f0-9]{64})  ([\w.+-]+)", line, re.ASCII)
        if not m or m[2] in sums:
            raise ValueError("invalid or duplicate release manifest entry")
        sums[m[2]] = m[1]
    return sums


def stage(request, manifest_only=False):
    version = request["version"]
    uri = f"https://github.com/{REPO}/releases/download/{version}/"
    dest = STATE / "downloads" / version
    dest.mkdir(parents=True, exist_ok=True)
    with (dest/"verify.lock").open("a+b") as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        return verify_assets(request,manifest_only,version,uri,dest)


def check_migration_plan(installed, candidate):
    for bundle in (installed, candidate):
        if (bundle.get("protocol", "v1") != "v1" or
                bundle.get("migration_mode", "offline-exact-history") != "offline-exact-history"):
            raise ValueError("incompatible server protocol or migration mode")
    before = installed.get("migrations", [])
    if candidate["migrations"][:len(before)] != before:
        raise ValueError("schema history requires restore; binary rollback cannot reverse these migrations")
    if "migration_ledger" not in candidate:
        return "migration_filenames"
    ledger = candidate["migration_ledger"]
    if (not isinstance(ledger, list) or len(ledger) != len(candidate["migrations"]) + 1 or
            any(not isinstance(row, dict) or row.get("version") != i or not row.get("name") or
                not re.fullmatch("[a-f0-9]{64}", row.get("sha256", "")) for i, row in enumerate(ledger, 1))):
        raise ValueError("invalid migration ledger in signed bundle")
    if not installed:
        return "initial_install"
    expected = ledger[:len(before) + 1]
    query = """SELECT coalesce(json_agg(json_build_object('version',version,'name',name,
               'sha256',encode(checksum,'hex')) ORDER BY version),'[]'::json) FROM schema_migrations"""
    actual = json.loads(postgres_scalar(read(STATE / "profile.json"), query))
    if actual != expected or installed.get("migration_ledger", actual) != actual:
        raise MigrationHistoryMismatch("database migration history differs from the signed build; review the restore plan")
    return "database_ledger_verified"


def verify_assets(request,manifest_only,version,uri,dest):
    offline = Path(request["offline"]) if request.get("offline") else None
    def fetch(name, digest=None, maxsize=2 << 30):
        target = dest / name
        if digest and target.is_file() and sha(target) == digest:
            return target
        if offline:
            # Copy into root-only storage before verification and use.
            with (offline / name).open("rb") as src, tempfile.NamedTemporaryFile(dir=dest, delete=False) as tmp:
                try:
                    if os.fstat(src.fileno()).st_size > maxsize:
                        raise ValueError("asset exceeds limit")
                    shutil.copyfileobj(src, tmp)
                    tmp.flush()
                    if digest and sha(Path(tmp.name)) != digest:
                        raise ValueError("offline asset digest mismatch")
                    os.replace(tmp.name, target)
                finally:
                    Path(tmp.name).unlink(missing_ok=True)
        else:
            download(uri + name, target, digest, maxsize)
        return target
    sums = fetch("SHA256SUMS", maxsize=8 << 20)
    if request.get("development_key"):
        # A private build can never claim a published release tag. The
        # operator supplies the public key independently of the bundle.
        if not offline or not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+-dev\.[0-9]+",version):
            raise ValueError("local build trust requires an offline -dev.N version")
        pub = dest / "development-key.pub"
        key = Path(request["development_key"]).read_bytes()
        write_file(pub, key)
        key_digest = hashlib.sha256(key).hexdigest()
        trusted = STATE / "development-key.sha256"
        sig = fetch("SHA256SUMS.dev.sig", maxsize=1024)
        with (STATE / "development-key.lock").open("a+b") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            if trusted.exists() and trusted.read_text() != key_digest or current() and not trusted.exists():
                raise ValueError("local development signing key differs from installed trust")
            run("openssl","pkeyutl","-verify","-pubin","-inkey",pub,"-rawin","-in",sums,"-sigfile",sig,stdout=sys.stderr)
            write_file(trusted, key_digest.encode())
        signer = {"mode":"development-ed25519", "key_sha256":key_digest}
    else:
        cosign = STATE / "cosign"
        if not cosign.exists() or sha(cosign) != COSIGN_HASH:
            if offline:
                verify = fetch("cosign-linux-amd64", COSIGN_HASH)
                write_file(cosign, verify.read_bytes(), 0o700)
            else:
                download(COSIGN_URL, cosign, COSIGN_HASH, 240 << 20)
                cosign.chmod(0o700)
        bundle = fetch("SHA256SUMS.sigstore.json", maxsize=8 << 20)
        verify = [cosign, "verify-blob", "--bundle", bundle, "--certificate-identity",
                  f"https://github.com/{REPO}/.github/workflows/release.yml@refs/tags/{version}",
                  "--certificate-oidc-issuer", "https://token.actions.githubusercontent.com"]
        custom_root = None
        if offline:
            root_contents = Path(request["trusted_root"]).read_bytes() if request.get("trusted_root") else TRUSTED_ROOT
            root = dest / "trusted-root.json"
            write_file(root, root_contents)
            if root_contents != TRUSTED_ROOT:
                custom_root = hashlib.sha256(root_contents).hexdigest()
            verify.extend(["--offline", "--trusted-root", root])
        run(*verify, sums,stdout=sys.stderr)
        signer = {"mode":"sigstore", "workflow":f"{REPO}/.github/workflows/release.yml",
                  "issuer":"https://token.actions.githubusercontent.com", "custom_root_sha256":custom_root}
    fingerprint=sha(sums)
    pinned=dest/"verified-manifest.sha256"
    if pinned.exists() and pinned.read_text()!=fingerprint:
        raise ValueError("release tag changed since its first signed plan")
    digests = checksums(sums)
    manifest = read(fetch("agentcapsule-bundle.json", digests["agentcapsule-bundle.json"], 8 << 20))
    if manifest["schema"]!="agentcapsule.bundle/v1" or manifest["version"]!=version or manifest["platform"]!="ubuntu-24.04-amd64":
        raise ValueError("incompatible server distribution")
    installed = read(ACTIVE / "bundle.json") if current() else {}
    before = installed.get("migrations", [])
    origin = {"version":version, "signer":signer, "manifest_sha256":digests["agentcapsule-bundle.json"]}
    activated = dest / "activated-origin.json"
    if activated.is_file() and read(activated) != origin:
        raise ValueError("release signing identity or manifest changed since activation")
    rollback = request.get("action") == "rollback"
    migration_check = check_binary_rollback(request, manifest, origin) if rollback else check_migration_plan(installed, manifest)
    save(dest / "verified-origin.json", origin)
    write_file(pinned,fingerprint.encode())
    if manifest_only:
        return {"added_migrations":manifest["migrations"][len(before):],"server_sha256":digests[SERVER],
                "backup_required":bool(installed),"maintenance_window":bool(installed),"commit":manifest["commit"],
                "migration_check":migration_check, **({"binary_rollback_compatible":True} if rollback else {})}
    for name in ((SERVER,) if rollback else (SERVER, DEBS, IMAGES)):
        fetch(name, digests[name])
    return dest


def unpack(archive, destination):
    destination.mkdir(mode=0o755)
    destination.chmod(0o755)
    with tarfile.open(archive) as tar:
        seen = set()
        for member in tar:
            path = Path(member.name)
            if (not member.isfile() or path.is_absolute() or ".." in path.parts or not path.parts
                    or path.as_posix() in seen or member.size > 2 << 30):
                raise ValueError("unexpected archive entry")
            seen.add(path.as_posix())
            target = destination / path
            target.parent.mkdir(parents=True, exist_ok=True)
            parent=target.parent
            while parent != destination:
                parent.chmod(0o755)
                parent=parent.parent
            with target.open("xb") as f:
                shutil.copyfileobj(tar.extractfile(member), f)
            target.chmod(0o755 if member.mode & 0o111 else 0o644)


def preflight():
    if os.geteuid() != 0:
        raise ValueError("run locally as root or use --ssh with sudo")
    if platform.freedesktop_os_release().get("VERSION_ID") != "24.04" or platform.freedesktop_os_release().get("ID") != "ubuntu":
        raise ValueError("requires Ubuntu 24.04")
    if platform.machine() != "x86_64" or not Path("/run/systemd/system").is_dir():
        raise ValueError("requires amd64 and systemd")
    with open("/dev/kvm", "rb+", buffering=0) as kvm:
        if not stat.S_ISCHR(os.fstat(kvm.fileno()).st_mode) or fcntl.ioctl(kvm.fileno(), 0xae00, 0) != 12:
            raise ValueError("requires KVM API version 12")
    controllers = Path("/sys/fs/cgroup/cgroup.controllers").read_text().split()
    if not {"cpu", "pids", "memory"}.issubset(controllers):
        raise ValueError("requires cgroup v2 cpu, memory and pids")


def opdir(operation_id):
    if not re.fullmatch(OP_ID, operation_id):
        raise ValueError("invalid host operation id")
    return OPERATIONS / operation_id


def state(directory, **fields):
    path = directory / "status.json"
    obj = read(path) if path.exists() else {"operation_id":directory.name, "schema":SCHEMA, "completed":[]}
    obj.update(updated_at=now(), **fields)
    save(path, obj)
    return obj


def activate(link, destination):
    new = link.with_name(".agentcapsule-" + uuid.uuid4().hex)
    try:
        new.symlink_to(destination)
        os.replace(new, link)
        parent = os.open(link.parent, os.O_DIRECTORY)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    finally:
        new.unlink(missing_ok=True)


def activate_verified(directory, request, release, dist):
    verified = dist / "verified-origin.json"
    if verified.is_file() and sha(release / "bundle.json") != read(verified)["manifest_sha256"]:
        raise ValueError("prepared manifest differs from the signed release")
    if request["action"] == "rollback":
        # Always check the live history with admissions closed, also on retry.
        check_binary_rollback(request, read(dist / "agentcapsule-bundle.json"), read(dist / "verified-origin.json"))
    activate(ACTIVE, release)
    if verified.is_file():
        save(dist / "activated-origin.json", read(verified))
        save(STATE / "active-release.json", {"operation_id":directory.name, "version":request["version"]})


def execute(directory):
    # An operation retried after an interrupted boot uses its original helper,
    # target digest, profile, and completed phases.
    if read(directory / "status.json")["state"] == "succeeded":
        return
    with (STATE / "operation.lock").open("a+b") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        status = read(directory / "status.json")
        if status["state"] == "succeeded":
            return
        request = read(directory / "request.json")
        fields = status["completed"]
        phase = "preflight"
        try:
            preflight()
            def step(name, fn):
                nonlocal phase
                phase = name
                if name in fields:
                    return
                state(directory, state="running", phase=name, reason=None)
                details = fn()
                fields.append(name)
                state(directory, completed=fields, **(details or {}))
            transition = STATE / "transition.json"
            owner = read(transition)["operation_id"] if transition.is_file() else None
            if owner and read(opdir(owner) / "status.json")["state"] == "succeeded":
                clear_gate("transition.json")
                owner = None
            if owner and owner != directory.name:
                raise ValueError("another host transition must be resumed: " + owner)
            if request["action"] in ("archive", "restore-test", "restore-apply"):
                if request.get("verify_starter"):
                    if read(STATE / "smoke.json").get("agent") != request["agent"]:
                        raise ValueError("--verify-starter requires the original installation probe agent")
                step(request["action"], lambda: run_storage(request, directory))
                if request.get("verify_starter"):
                    step("invocation", lambda: smoke(read(STATE / "profile.json"), directory))
            else:
                validate_release_direction(request)
                if "source_activation" in request and not owner:
                    if current() != request["from"] or activation_generation() != request["source_activation"]:
                        raise ValueError("installed activation changed after plan")
                if current() != request["from"] and "activate" not in fields and current() != request["version"]:
                    raise ValueError("installed release changed after plan")
                if request["action"] == "install" and ACTIVE.exists() and not ACTIVE.is_symlink():
                    raise ValueError("existing installation must be migrated explicitly")
                version = request["version"]
                dist = STATE / "downloads" / version
                release = RELEASES / version
                profile = request["profile"]
                step("verify-release", lambda: (stage(request), None)[1])
                if "prepare-release" in fields and ("activate" not in fields or request["action"] == "rollback"):
                    # A restart can leave an extracted candidate on disk for
                    # days before its package index and service units are used.
                    verify_release_files(release, dist, version)
                step("prepare-release", lambda: prepare_release(release, dist, version))
                if request["action"] in ("rollback", "update"):
                    step("backup", lambda: backup(profile, mandatory=True, directory=directory))
                    if "source_activation" in request and not owner:
                        save(transition, {"operation_id":directory.name})
                    if "drain" in fields and "services" not in fields and "configure" not in fields:
                        # A helper upgraded in place may resume an older drain
                        # whose units were enabled without suspension guards.
                        install_maintenance_gates()
                        pause_admissions()
                        suspend_services()
                    step("drain", lambda: drain(profile))
                if request["action"] != "rollback":
                    step("dependencies", lambda: install_dependencies(dist, release))
                try:
                    step("activate", lambda: activate_verified(directory, request, release, dist))
                except RollbackIncompatible:
                    # No switch took place. Reopen the verified source on a
                    # late compatibility refusal; a retry must drain again.
                    if current() == request["from"]:
                        start_services(profile)
                        fields.remove("drain")
                        state(directory, completed=fields)
                        clear_gate("transition.json")
                    raise
                if request["action"] != "rollback":
                    step("configure", lambda: configure(profile, version, request["action"] == "install"))
                step("services", lambda: start_services(profile))
                step("invocation", lambda: smoke(profile, directory))
                if request["action"] == "install":
                    step("backup", lambda: backup(profile, mandatory=False, directory=directory))
                    step("enrollment", lambda: issue_enrollment(profile))
                save(STATE / "profile.json", profile)
            state(directory, state="succeeded", phase="complete")
            if transition.is_file() and read(transition)["operation_id"] == directory.name:
                clear_gate("transition.json")
        except Exception as e:
            state(directory, state="failed", phase=phase, reason=safe_error(e))
            raise


def safe_error(error):
    if isinstance(error, subprocess.CalledProcessError):
        return f"{Path(str(error.cmd[0])).name} exited {error.returncode} (see system journal)"
    return str(error)


def verify_release_files(release, dist, version):
    # The external manifest was authenticated when staging the signed plan.
    manifest = read(dist / "agentcapsule-bundle.json")
    if (release.is_symlink() or (release / "bundle.json").is_symlink() or
            manifest.get("schema") != "agentcapsule.bundle/v1" or manifest.get("version") != version or
            read(release / "bundle.json") != manifest):
        raise ValueError("extracted release differs from the verified bundle manifest")
    expected = manifest["sha256"]
    required = {"firecracker", "jailer", "vmlinux", "product.initrd", "agentcapsule-api", "agentcapsule-worker"}
    if not required.issubset(expected) or "bundle.json" in expected:
        raise ValueError("incomplete server bundle manifest")
    verified = set()
    for path in release.rglob("*"):
        name = path.relative_to(release).as_posix()
        if path.is_symlink():
            raise ValueError("unexpected link in server bundle: " + name)
        if path.is_dir() or name == "bundle.json":
            continue
        if not path.is_file() or name not in expected or sha(path) != expected[name]:
            raise ValueError("server bundle file differs from manifest: " + name)
        verified.add(name)
    if verified != expected.keys():
        raise ValueError("server bundle lacks files from its manifest")


def prepare_release(release, dist, version):
    if release.exists():
        verify_release_files(release, dist, version)
        return
    RELEASES.mkdir(mode=0o755, exist_ok=True)
    RELEASES.chmod(0o755)
    with tempfile.TemporaryDirectory(dir=RELEASES) as tmp:
        new = Path(tmp) / "release"
        unpack(dist / SERVER, new)
        verify_release_files(new, dist, version)
        new.rename(release)


def launch(directory):
    unit = "agentcapsule-host@" + directory.name + ".service"
    template = """[Unit]
Description=AgentCapsule host operation %i
After=local-fs.target network-online.target
Wants=network-online.target
[Service]
Type=oneshot
ExecStart=/usr/bin/python3 -I /var/lib/agentcapsule-install/operations/%i/helper.py --execute %i
UMask=0077
TimeoutStartSec=infinity
# The operation installs the signed packages, configures the host and runs
# the worker binary for archives and restores: it keeps root's capabilities,
# writable file systems, devices and cgroups. Left out: RestrictNamespaces
# (the worker starts the jailer with clone3), RestrictSUIDSGID (packages ship
# setuid programs), ProtectKernelTunables and ProtectKernelModules (package
# scripts), MemoryDenyWriteExecute (package scripts), ProtectHome (profile
# files may live there), PrivateTmp (package scripts and services share /tmp).
NoNewPrivileges=yes
ProtectKernelLogs=yes
ProtectClock=yes
ProtectHostname=yes
LockPersonality=yes
RestrictRealtime=yes
SystemCallArchitectures=native
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK AF_ALG
[Install]
WantedBy=multi-user.target
"""
    write_file(UNIT_DIR / "agentcapsule-host@.service", template.encode(), 0o644)
    run("systemctl", "daemon-reload")
    run("systemctl", "--quiet", "enable", "--now", "--no-block", unit)


def submit(directory):
    state(directory, state="queued",reason=None)
    try:
        launch(directory)
    except (OSError,subprocess.CalledProcessError) as error:
        state(directory,state="failed",phase="submit",reason=safe_error(error))
        raise


def latest():
    with urllib.request.urlopen(f"https://api.github.com/repos/{REPO}/releases/latest", timeout=20) as reply:
        tag = json.loads(reply.read(2 << 20))["tag_name"]
    if not re.fullmatch(VERSION, tag):
        raise ValueError("invalid release tag")
    return tag


def main(argv, cli_version):
    parser = argparse.ArgumentParser(prog="agentcapsule")
    groups = parser.add_subparsers(dest="command", required=True)
    install = groups.add_parser("install")
    install.add_argument("--plan-only", action="store_true")
    updates = groups.add_parser("update").add_subparsers(dest="sub", required=True)
    check = updates.add_parser("check")
    check.add_argument("--to")
    plan = updates.add_parser("plan")
    apply = updates.add_parser("apply")
    apply.add_argument("--plan", required=True)
    rollbacks = groups.add_parser("rollback").add_subparsers(dest="sub", required=True)
    rollback_plan = rollbacks.add_parser("plan")
    rollbacks.add_parser("apply").add_argument("--plan", required=True)
    for p in (install, plan, rollback_plan):
        p.add_argument("--profile", help="installation profile JSON on host")
        p.add_argument("--to", required=p is rollback_plan)
        p.add_argument("--development-key",help="independently trusted key for local offline -dev.N builds")
        p.add_argument("--offline", help="verified release assets on host")
        p.add_argument("--trusted-root", help="trusted Sigstore root on host")
    host = groups.add_parser("host").add_subparsers(dest="group", required=True)
    add_diagnostics(host)
    operations = host.add_parser("operation").add_subparsers(dest="sub", required=True)
    for action in ("show", "wait", "resume"):
        p = operations.add_parser(action)
        p.add_argument("id")
        if action=="resume":
            p.add_argument("--refresh-helper",action="store_true",help="retry the failed phase with this CLI’s host helper")
    for action in ("archive", "restore"):
        parent = groups.add_parser(action)
        parents = [parent] if action == "archive" else [parent.add_subparsers(dest="sub", required=True)]
        items = [parent] if action == "archive" else [parents[0].add_parser(it) for it in ("test","apply")]
        for item in items:
            item.add_argument("--agent", required=True)
            item.add_argument("--archive-id", required=True)
            if action == "restore" and item.prog.endswith("apply"):
                item.add_argument("--restore-id", required=True)
                item.add_argument("--verify-starter", action="store_true", help="invoke the original installation probe after restoring it")
    args = parser.parse_args(argv)
    if args.command == "update" and args.sub == "check":
        target = args.to or latest()
        if not re.fullmatch(VERSION, target):
            raise ValueError("invalid release tag")
        return {"schema": SCHEMA, "installed": current(), "available": target, "different": current() != target}
    if args.command == "host" and args.group == "diagnose":
        return diagnose(args)
    if args.command == "host":
        directory = opdir(args.id)
        if args.sub == "resume":
            validate_release_direction(read(directory / "request.json"))
            if read(directory / "status.json")["state"] != "failed":
                raise ValueError("only a failed host operation can be resumed")
            if args.refresh_helper:
                write_file(directory/"helper.py",HELPER_SOURCE)
            submit(directory)
        while args.sub == "wait":
            report = read(directory / "status.json")
            if report["state"] == "failed":
                print(json.dumps(report), flush=True)
                raise ValueError("host operation failed")
            if report["state"] == "succeeded":
                break
            time.sleep(2)
        return read(directory / "status.json")
    preflight()
    STATE.mkdir(mode=0o700, exist_ok=True)
    OPERATIONS.mkdir(mode=0o700, exist_ok=True)
    action = args.command
    if action in ("update", "rollback") and args.sub == "apply":
        directory = opdir(args.plan)
        planned = read(directory / "request.json")
        validate_release_direction(planned)
        if planned["action"] != action:
            raise ValueError("plan belongs to a different operation: expected " + action + " plan")
        if read(directory / "status.json")["state"] == "planned":
            submit(directory)
        return read(directory / "status.json")
    if action in ("archive","restore"):
        if not re.fullmatch(r"agt_[a-f0-9]{32}", args.agent) or not re.fullmatch(r"arc_[a-f0-9]{32}", args.archive_id):
            raise ValueError("invalid agent or archive identifier")
        request = dict(action=action if action == "archive" else action+"-"+args.sub, agent=args.agent, archive=args.archive_id)
        if request["action"] == "restore-apply":
            if not re.fullmatch(r"rst_[a-f0-9]{32}", args.restore_id):
                raise ValueError("invalid restore identifier")
            request["restore"] = args.restore_id
            if args.verify_starter:
                request["verify_starter"] = True
    else:
        installed = current()
        profile = read(Path(args.profile)) if args.profile else (read(STATE/"profile.json") if (STATE/"profile.json").is_file() else {})
        if args.offline and not args.to and not re.fullmatch(VERSION, cli_version):
            raise ValueError("--offline requires an explicit release tag")
        version = args.to or (cli_version if re.fullmatch(VERSION, cli_version) and (args.offline or action=="install") else latest())
        if not re.fullmatch(VERSION, version):
            raise ValueError("invalid release tag")
        if action == "install" and installed and installed != version or action in ("update", "rollback") and not installed:
            raise ValueError("install requires an empty host and update or rollback requires an installed release")
        profile = normalize_profile(profile)
        if action in ("update", "rollback"):
            validate_release_direction({"version":version, "from":installed, "action":action})
            installed_profile = read(STATE/"profile.json")
            if any(installed_profile.get(k) != v for k,v in profile.items()
                   if action == "rollback" or k not in ("pgbackrest_config","rclone_config")):
                raise ValueError("use the installed host profile")
        request = {"action": action, "version":version, "from":None if action=="install" else installed, "profile":profile,
                   "development_key":str(Path(args.development_key).resolve()) if args.development_key else None,
                   "offline": str(Path(args.offline).resolve()) if args.offline else None,
                   "trusted_root":str(Path(args.trusted_root).resolve()) if args.trusted_root else None}
        if action in ("update", "rollback"):
            request["source_activation"] = activation_generation()
    ident = "host_" + hashlib.sha256(json.dumps(request, sort_keys=True).encode()).hexdigest()[:32]
    directory = opdir(ident)
    with (STATE/"submit.lock").open("a+") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if action=="install" and current() and not (directory/"request.json").is_file():
            raise ValueError("this installation already exists with another profile")
        directory.mkdir(mode=0o700, exist_ok=True)
        if not (directory / "status.json").exists():
            save(directory / "request.json",request)
            write_file(directory / "helper.py", HELPER_SOURCE)
            details=stage(request, manifest_only=True) if action in ("update","install","rollback") else {}
            state(directory, state="planned", action=request["action"], target=request.get("version"), **details,
                  installed=current(), services_started=False, invocation_verified=False,
                  off_host_backup_verified=False, phases=phases(request["action"]) + (["invocation"] if request.get("verify_starter") else []))
        if action == "install" and not args.plan_only or action in ("archive","restore"):
            if read(directory/"status.json")["state"] == "planned":
                submit(directory)
        return read(directory / "status.json")


def phases(action):
    if action == "rollback":
        return ["verify-release","prepare-release","backup","drain","activate","services","invocation"]
    if action not in ("install","update"):
        return [action]
    steps = ["verify-release","prepare-release"]
    if action == "update":
        steps += ["backup","drain"]
    steps += ["dependencies","activate","configure","services","invocation"]
    return steps + (["backup","enrollment"] if action == "install" else [])


if __name__ == "__main__":
    os.umask(0o077)
    try:
        if sys.argv[1] == "--execute":
            execute(opdir(sys.argv[2]))
            run("systemctl","disable","agentcapsule-host@"+sys.argv[2]+".service")
        else:
            encoded = sys.argv[1]
            version, *args = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
            print(json.dumps(main(args, version)))
    except (ValueError, OSError, KeyError, RuntimeError, subprocess.CalledProcessError) as error:
        sys.exit(safe_error(error))
