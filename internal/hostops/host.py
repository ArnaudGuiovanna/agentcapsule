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


def checksums(path):
    sums = {}
    for line in path.read_text().splitlines():
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
        pub=Path(request["development_key"])
        trusted=STATE/"development-key.sha256"
        if trusted.exists() and trusted.read_text()!=sha(pub) or current() and not trusted.exists():
            raise ValueError("local development signing key differs from installed trust")
        sig=fetch("SHA256SUMS.dev.sig",maxsize=1024)
        run("openssl","pkeyutl","-verify","-pubin","-inkey",pub,"-rawin","-in",sums,"-sigfile",sig,stdout=sys.stderr)
        write_file(trusted,sha(pub).encode())
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
        if offline:
            root=request.get("trusted_root")
            if not root:
                root=dest/"trusted-root.json"
                write_file(root,TRUSTED_ROOT)
            verify.extend(["--offline", "--trusted-root", root])
        run(*verify, sums,stdout=sys.stderr)
    fingerprint=sha(sums)
    pinned=dest/"verified-manifest.sha256"
    if pinned.exists() and pinned.read_text()!=fingerprint:
        raise ValueError("release tag changed since its first signed plan")
    digests = checksums(sums)
    manifest = read(fetch("agentcapsule-bundle.json", digests["agentcapsule-bundle.json"], 8 << 20))
    if manifest["schema"]!="agentcapsule.bundle/v1" or manifest["version"]!=version or manifest["platform"]!="ubuntu-24.04-amd64":
        raise ValueError("incompatible server distribution")
    before=read(ACTIVE/"bundle.json")["migrations"] if current() else []
    if manifest["migrations"][:len(before)] != before:
        raise ValueError("schema history requires restore; binary rollback cannot reverse these migrations")
    write_file(pinned,fingerprint.encode())
    if manifest_only:
        return {"added_migrations":manifest["migrations"][len(before):],"server_sha256":digests[SERVER],
                "backup_required":bool(before),"maintenance_window":bool(before),"commit":manifest["commit"]}
    for name in (SERVER, DEBS, IMAGES):
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
    finally:
        new.unlink(missing_ok=True)


def execute(directory):
    # An operation retried after an interrupted boot uses its original helper,
    # target digest, profile, and completed phases.
    request = read(directory / "request.json")
    status = read(directory / "status.json")
    if status["state"] == "succeeded":
        return
    with (STATE / "operation.lock").open("a+b") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
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
            if request["action"] in ("archive", "restore-test", "restore-apply"):
                step(request["action"], lambda: run_storage(request, directory))
            else:
                if current() != request["from"] and "activate" not in fields and current() != request["version"]:
                    raise ValueError("installed release changed after plan")
                if request["action"] == "install" and ACTIVE.exists() and not ACTIVE.is_symlink():
                    raise ValueError("existing installation must be migrated explicitly")
                version = request["version"]
                dist = STATE / "downloads" / version
                release = RELEASES / version
                profile = request["profile"]
                step("verify-release", lambda: (stage(request), None)[1])
                step("prepare-release", lambda: prepare_release(release, dist, version))
                step("dependencies", lambda: install_dependencies(dist, release))
                if request["action"] == "update":
                    step("backup", lambda: backup(profile, mandatory=True))
                    step("drain", lambda: drain(profile))
                step("activate", lambda: activate(ACTIVE, release))
                step("configure", lambda: configure(profile, version, request["action"] == "install"))
                step("services", lambda: start_services(profile))
                step("invocation", lambda: smoke(profile, directory))
                if request["action"] == "install":
                    step("backup", lambda: backup(profile, mandatory=False))
                save(STATE / "profile.json", profile)
            state(directory, state="succeeded", phase="complete")
        except Exception as e:
            state(directory, state="failed", phase=phase, reason=safe_error(e))
            raise


def safe_error(error):
    if isinstance(error, subprocess.CalledProcessError):
        return f"{Path(str(error.cmd[0])).name} exited {error.returncode} (see system journal)"
    return str(error)


def prepare_release(release, dist, version):
    if release.exists():
        if read(release / "bundle.json")["version"] != version:
            raise ValueError("release directory version mismatch")
        return
    RELEASES.mkdir(mode=0o755, exist_ok=True)
    RELEASES.chmod(0o755)
    with tempfile.TemporaryDirectory(dir=RELEASES) as tmp:
        new = Path(tmp) / "release"
        unpack(dist / SERVER, new)
        manifest = read(new / "bundle.json")
        if manifest["schema"] != "agentcapsule.bundle/v1" or manifest["version"] != version:
            raise ValueError("incompatible bundle")
        for name in ("firecracker", "jailer", "vmlinux", "product.initrd", "agentcapsule-api", "agentcapsule-worker"):
            if sha(new / name) != manifest["sha256"][name]:
                raise ValueError("incomplete server bundle")
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
    for p in (install, plan):
        p.add_argument("--profile", help="installation profile JSON on host")
        p.add_argument("--to")
        p.add_argument("--development-key",help="independently trusted key for local offline -dev.N builds")
        p.add_argument("--offline", help="verified release assets on host")
        p.add_argument("--trusted-root", help="trusted Sigstore root on host")
    host = groups.add_parser("host").add_subparsers(dest="group", required=True)
    add_diagnostics(host)
    operations = host.add_parser("operation").add_subparsers(dest="sub", required=True)
    for action in ("show", "wait", "resume"):
        p = operations.add_parser(action)
        p.add_argument("id")
    for action in ("archive", "restore"):
        parent = groups.add_parser(action)
        parents = [parent] if action == "archive" else [parent.add_subparsers(dest="sub", required=True)]
        items = [parent] if action == "archive" else [parents[0].add_parser(it) for it in ("test","apply")]
        for item in items:
            item.add_argument("--agent", required=True)
            item.add_argument("--archive-id", required=True)
            if action == "restore" and item.prog.endswith("apply"):
                item.add_argument("--restore-id", required=True)
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
            if read(directory / "status.json")["state"] != "failed":
                raise ValueError("only a failed host operation can be resumed")
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
    if action == "update" and args.sub == "apply":
        directory = opdir(args.plan)
        if read(directory / "request.json")["action"] != "update":
            raise ValueError("expected an update plan")
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
    else:
        installed = current()
        profile = read(Path(args.profile)) if args.profile else (read(STATE/"profile.json") if (STATE/"profile.json").is_file() else {})
        if args.offline and not args.to and not re.fullmatch(VERSION, cli_version):
            raise ValueError("--offline requires an explicit release tag")
        version = args.to or (cli_version if re.fullmatch(VERSION, cli_version) and (args.offline or action=="install") else latest())
        if not re.fullmatch(VERSION, version):
            raise ValueError("invalid release tag")
        if action == "install" and installed and installed != version or action == "update" and not installed:
            raise ValueError("install requires an empty host and update requires an installed release")
        profile = normalize_profile(profile)
        if action == "update":
            installed_profile = read(STATE/"profile.json")
            if any(installed_profile.get(k) != v for k,v in profile.items() if k not in ("pgbackrest_config","rclone_config")):
                raise ValueError("update uses the installed host profile")
        request = {"action": action, "version":version, "from":None if action=="install" else installed, "profile":profile,
                   "development_key":str(Path(args.development_key).resolve()) if args.development_key else None,
                   "offline": str(Path(args.offline).resolve()) if args.offline else None,
                   "trusted_root":str(Path(args.trusted_root).resolve()) if args.trusted_root else None}
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
            details=stage(request, manifest_only=True) if action in ("update","install") else {}
            state(directory, state="planned", action=request["action"], target=request.get("version"), **details,
                  installed=current(), services_started=False, invocation_verified=False,
                  off_host_backup_verified=False, phases=phases(request["action"]))
        if action == "install" and not args.plan_only or action in ("archive","restore"):
            if read(directory/"status.json")["state"] == "planned":
                submit(directory)
        return read(directory / "status.json")


def phases(action):
    if action not in ("install","update"):
        return [action]
    steps = ["verify-release","prepare-release","dependencies"]
    if action == "update":
        steps += ["backup","drain"]
    steps += ["activate","configure","services","invocation"]
    return steps + (["backup"] if action == "install" else [])


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
