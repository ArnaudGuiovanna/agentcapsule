#!/usr/bin/env python3
"""Reproducible qualification of the pinned interoperability profile.

Without --services: the libraries only (A2A, OASF, Directory and SLIM Go
modules, the SLIM native library, the SLIM bridge's contract and
configuration), no Docker. With --services: also the private services of
deploy/interop (OASF schema server, Directory behind its mutual-TLS edge, SLIM
node) started from pinned images with lab certificates, then driven by Go
tests: publish, search and validation in Directory, refused identities,
exchanges through the SLIM node, A2A over SLIM, the platform's SLIM bridge
(runtime/slimbridge: deliveries between two bridges and on one host, refusals,
the end of a bridge whose node restarts), and the platform's own Directory
publisher (internal/directory). The bridge test restarts the SLIM node, so it
runs last.

With --systemd: also the shipped units of deploy/systemd. systemd-analyze
verifies them, inside a throwaway root, without a single warning; the bridge's
exposure is scored; the sysusers and tmpfiles entries are applied to that root.
"--systemd static" stops there (CI: it needs no user manager). With
--services and a plain --systemd, the real bridge runs under its unit in the caller's
systemd user manager, next to the services under theirs: a delivery round trip,
a node restart at the same address, the services stopped for longer than three
probes (the bridge ends with code 3 and systemd starts new ones until the node
is back), a clean stop, and an invalid configuration that is not retried. The
user manager cannot apply User=, Group=, capability sets or IP filters: those
lines are left to the system manager and recorded as not exercised.
"""
import argparse
import base64
import contextlib
import hashlib
import http.client
import http.server
import json
import os
from pathlib import Path
import platform
import re
import secrets
import shlex
import shutil
import socket
import socketserver
import subprocess
import tempfile
import threading
import time
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]
LIBRARY_TESTS = {
    "TestA2AJSONRPCTaskRoundTrip",
    "TestOASFVersionedDecoding",
    "TestDirectoryClientBuildAndConfiguration",
    "TestSLIMNativeABI",
}
SERVICE_TESTS = {
    "TestDirectoryPublishesSearchesAndDeletes",
    "TestDirectoryValidatesRecordsAgainstThePrivateSchema",
    "TestDirectoryEdgeAdmitsOnlyTheControlPlane",
    "TestSLIMExchangeThroughThePrivateNode",
    "TestSLIMNodeAdmitsOnlyTheSLIMAuthority",
    "TestSLIMKeepsNothingForAnAbsentRecipient",
}
A2A_SLIM_TESTS = {"TestA2AOverSLIMThroughThePrivateNode"}
# The platform's SLIM bridge (runtime/slimbridge, INT-04).
BRIDGE_LIBRARY_TESTS = {"TestTheWorkerContractIsTheSameOnBothSides", "TestConfigurationIsCheckedBeforeConnecting", "TestNames"}
BRIDGE_SERVICE_TESTS = {"TestBridgesCarryDeliveriesThroughTheNode", "TestABridgeEndsWhenTheNodeIsLostAndANewOneWorks"}
# The platform's own Directory client and publisher (internal/directory).
PLATFORM_TESTS = {"TestPublisherAgainstThePrivateDirectory"}
# deploy/systemd. The user manager applies neither users, capabilities nor IP
# filters; these lines are dropped from the copies it runs.
SYSTEMD_UNITS = ("agentcapsule-slim-bridge.service", "agentcapsule-interop.service")
SYSTEM_MANAGER_ONLY = ("User", "Group", "CapabilityBoundingSet", "AmbientCapabilities")
MAX_BRIDGE_EXPOSURE = 2.0


def sha256(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def tree_digests(base):
    return {str(p.relative_to(base)): sha256(p) for p in sorted(base.rglob("*")) if p.is_file()}


def passed_tests(log, expected):
    events = []
    for line in log.read_text().splitlines():
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue  # Compiler diagnostics are retained, and command status checked.
    passed = {e["Test"] for e in events if e.get("Action") == "pass" and "Test" in e and "/" not in e["Test"]}
    if passed != expected or any(e.get("Action") in ("skip", "fail") for e in events):
        raise RuntimeError(f"expected test set was not fully executed without skips; see {log.name}")
    return sorted(passed)


def stop_services(compose, docker_env, output):
    with (output / "services.log").open("w") as log:
        subprocess.run([*compose, "logs", "--no-color", "--timestamps"], env=docker_env, stdout=log, stderr=subprocess.STDOUT, timeout=120, check=False)
    down = subprocess.run([*compose, "down", "-v", "--remove-orphans"], env=docker_env, capture_output=True, text=True, timeout=300, check=False)
    if down.returncode:
        raise RuntimeError("could not remove the services: " + down.stderr.strip()[-500:])


def check_units(units, work, output):
    """Static checks of deploy/systemd, installed as root would install them but
    inside a throwaway root: base units copied from this host, stand-ins for the
    bridge, Docker and docker.service."""
    for tool in ("systemd-analyze", "systemd-sysusers", "systemd-tmpfiles"):
        if not shutil.which(tool):
            raise RuntimeError("--systemd needs " + tool)
    root = work / "systemd-root"
    shutil.copytree("/usr/lib/systemd/system", root / "usr/lib/systemd/system", symlinks=True)
    for stand_in in ("opt/agentcapsule/agentcapsule-slim-bridge", "usr/bin/docker"):
        path = root / stand_in
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("#!/bin/sh\n")
        path.chmod(0o755)
    system = root / "etc/systemd/system"
    system.mkdir(parents=True)
    (system / "docker.service").write_text("[Unit]\nDescription=stand-in\n[Service]\nExecStart=/usr/bin/docker\n")
    for name in SYSTEMD_UNITS:
        shutil.copy2(units / name, system / name)

    def tool(name, *command):
        print("systemd-" + name, flush=True)
        result = subprocess.run(command, cwd=root, capture_output=True, text=True, timeout=120, check=False)
        (output / f"systemd-{name}.log").write_text(result.stdout + result.stderr)
        return result

    verify = tool("verify", "systemd-analyze", "verify", "--man=no", f"--root={root}", *(f"/etc/systemd/system/{n}" for n in SYSTEMD_UNITS))
    # verify exits 0 on an unknown key or a value it cannot parse: any output fails.
    if verify.returncode or (verify.stdout + verify.stderr).strip():
        raise RuntimeError("systemd-analyze verify reported problems; see systemd-verify.log")
    security = tool("security", "systemd-analyze", "security", "--offline=yes", f"--root={root}", "--no-pager",
                    "/etc/systemd/system/agentcapsule-slim-bridge.service")
    score = re.search(r"Overall exposure level for \S+: ([0-9.]+)", security.stdout)
    if security.returncode or not score or float(score.group(1)) > MAX_BRIDGE_EXPOSURE:
        raise RuntimeError(f"the bridge's unit is exposed above {MAX_BRIDGE_EXPOSURE}; see systemd-security.log")
    for name in ("passwd", "group", "shadow", "gshadow"):
        (root / "etc" / name).touch()
    sysusers = tool("sysusers", "systemd-sysusers", f"--root={root}", str(units / "agentcapsule-slim.sysusers"))
    if sysusers.returncode or not (root / "etc/passwd").read_text().startswith("agentcapsule-slim:"):
        raise RuntimeError("the bridge's user was not created; see systemd-sysusers.log")
    tmpfiles = tool("tmpfiles", "systemd-tmpfiles", f"--root={root}", "--create", str(units / "agentcapsule-slim.tmpfiles"))
    # A line systemd cannot parse, or an unknown user, exits 65 and names the
    # line. Without root (CI), the directories are created but not given to
    # their owners: exit 73, one fchownat line for each.
    modes = {name: (root / "run" / name).stat().st_mode & 0o7777 if (root / "run" / name).is_dir() else None
             for name in ("agentcapsule-slim", "agentcapsule-worker")}
    lines = [line for line in (tmpfiles.stdout + tmpfiles.stderr).splitlines() if line.strip()]
    owners_applied = tmpfiles.returncode == 0 and not lines
    chown_refused = os.geteuid() != 0 and tmpfiles.returncode == 73 and len(lines) == 2 and all(
        re.fullmatch(r"fchownat\(\) of \S+/run/agentcapsule-(slim|worker) failed: Operation not permitted", line) for line in lines)
    if modes != {"agentcapsule-slim": 0o750, "agentcapsule-worker": 0o711} or not (owners_applied or chown_refused):
        raise RuntimeError("the socket directories were not created as written; see systemd-tmpfiles.log")
    version = subprocess.check_output(["systemd-analyze", "--version"], text=True).splitlines()[0]
    return {"systemd": version, "verified_units": list(SYSTEMD_UNITS), "warnings": 0, "bridge_exposure": float(score.group(1)),
            "tmpfiles_owners_applied": owners_applied}


class UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, path, timeout):
        super().__init__("localhost", timeout=timeout)
        self.socket_path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.socket_path)


def bridge_call(path, method, route, body=None, timeout=60):
    connection = UnixHTTPConnection(str(path), timeout)
    try:
        connection.request(method, route, body=None if body is None else json.dumps(body), headers={"Content-Type": "application/json"})
        response = connection.getresponse()
        return response.status, response.read()
    finally:
        connection.close()


class FakeWorker(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    """Stands for the worker on its socket: records each delivery the bridge
    calls back with and answers with a receipt derived from the event."""
    daemon_threads = True

    def __init__(self, path):
        self.calls = []
        worker = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))))
                if self.path != "/v1/deliver":
                    self.send_error(400)
                    return
                worker.calls.append(body)
                answer = json.dumps({"result": base64.b64encode(b"guest:" + body["event"]["id"].encode()).decode(), "replayed": False}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(answer)))
                self.end_headers()
                self.wfile.write(answer)

        old = os.umask(0o177)  # mode 0600, as the worker's own socket
        try:
            super().__init__(path, Handler)
        finally:
            os.umask(old)

    def get_request(self):
        connection, _ = self.socket.accept()
        return connection, ("bridge", 0)


def systemctl(*args, check=True):
    return subprocess.run(["systemctl", "--user", *args], capture_output=True, text=True, timeout=600, check=check)


def unit_state(unit):
    shown = systemctl("show", unit, "-p", "ActiveState", "-p", "SubState", "-p", "Result", "-p", "NRestarts", "-p", "ExecMainStatus").stdout
    return dict(line.split("=", 1) for line in shown.splitlines() if "=" in line)


def wait_for(what, condition, seconds):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if condition():
            return
        time.sleep(1)
    raise RuntimeError("timed out waiting for " + what)


def rewrite_unit(text, drop=(), replace=None, environment=()):
    lines = []
    for line in text.splitlines():
        if line.split("=", 1)[0] in drop:
            continue
        for old, new in (replace or {}).items():
            line = line.replace(old, new)
        lines.append(line)
        if line == "[Service]":
            lines.extend("Environment=" + shlex.quote(f"{k}={v}") for k, v in environment)
    return "\n".join(lines) + "\n"


def supervise_units(units, deploy, bridge_binary, example, certs, compose, docker_env, output, cleanup):
    """The real bridge under its shipped unit and the services under theirs, in
    the caller's systemd user manager (see the module's docstring)."""
    manager = systemctl("is-system-running", check=False).stdout.strip()
    if manager not in ("running", "degraded") or not os.environ.get("XDG_RUNTIME_DIR"):
        raise RuntimeError("--systemd with --services needs the caller's systemd user manager (systemctl --user)")
    # The Go tests ran with a node on a new port after each restart. On a host
    # the node keeps its address: the services' unit publishes it again on a
    # fixed loopback port, which recreates the node's container.
    with socket.socket() as free:
        free.bind(("127.0.0.1", 0))
        docker_env = {**docker_env, "INTEROP_SLIM_PORT": str(free.getsockname()[1])}
    slim_node = "127.0.0.1:" + docker_env["INTEROP_SLIM_PORT"]
    tag = f"q{os.getpid()}"
    bridge_unit, interop_unit = f"agentcapsule-slim-bridge-{tag}.service", f"agentcapsule-interop-{tag}.service"
    # The bridge's sandbox hides /home, /run/user and /tmp (ProtectHome,
    # PrivateTmp); /dev/shm stays visible to it and to this script.
    base = Path(tempfile.mkdtemp(prefix="agentcapsule-units-", dir="/dev/shm"))
    cleanup.callback(shutil.rmtree, base, True)
    binary, etc, run_slim, run_worker = base / "bin/agentcapsule-slim-bridge", base / "etc", base / "run-slim", base / "run-worker"
    for directory, mode in ((binary.parent, 0o755), (etc, 0o755), (run_slim, 0o750), (run_worker, 0o711)):
        directory.mkdir()
        directory.chmod(mode)  # as agentcapsule-slim.tmpfiles
    shutil.copy2(bridge_binary, binary)
    for name in ("slim-ca.pem", "client.crt"):
        shutil.copy2(certs / "slim-bridge" / name, etc / name)
    for name, content in (("client.key", (certs / "slim-bridge/client.key").read_bytes()), ("secret", secrets.token_hex(32).encode())):
        (etc / name).write_bytes(content)
        (etc / name).chmod(0o600)
    paths = {"/etc/agentcapsule/slim-bridge/": f"{etc}/", "/run/agentcapsule-slim/": f"{run_slim}/", "/run/agentcapsule-worker/": f"{run_worker}/"}
    config = json.loads(example.read_text())
    for key, value in config.items():
        for old, new in paths.items():
            if isinstance(value, str):
                value = value.replace(old, new)
        config[key] = value
    config["node"], config["worker_uid"] = "https://" + slim_node, os.getuid()
    config_path = etc / "slim-bridge.json"
    config_path.write_text(json.dumps(config, indent=2) + "\n")
    config_path.chmod(0o644)
    bridge_socket = run_slim / "bridge.sock"

    installed = Path(os.environ["XDG_RUNTIME_DIR"]) / "systemd/user"
    installed.mkdir(parents=True, exist_ok=True)
    (installed / bridge_unit).write_text(rewrite_unit((units / SYSTEMD_UNITS[0]).read_text(), drop=SYSTEM_MANAGER_ONLY, replace={
        "/opt/agentcapsule/agentcapsule-slim-bridge": str(binary), "/etc/agentcapsule/slim-bridge.json": str(config_path),
        "ReadWritePaths=/run/agentcapsule-slim": f"ReadWritePaths={run_slim}", "agentcapsule-interop.service": interop_unit}))
    kept = {k: v for k, v in docker_env.items() if k in ("PATH", "HOME", "XDG_CONFIG_HOME") or k.startswith(("DOCKER_", "INTEROP_"))}
    project = compose[compose.index("-p") + 1]
    (installed / interop_unit).write_text(rewrite_unit((units / SYSTEMD_UNITS[1]).read_text(), drop=("Requires",), replace={
        "After=docker.service ": "After=", "/opt/agentcapsule/interop": str(deploy), "/usr/bin/docker": shutil.which("docker"),
        "Environment=INTEROP_CERTS=/etc/agentcapsule/interop": "Environment=INTEROP_CERTS=" + shlex.quote(str(certs))},
        environment=sorted({**kept, "COMPOSE_PROJECT_NAME": project}.items())))

    def remove():
        systemctl("stop", bridge_unit, interop_unit, check=False)
        with (output / "systemd.log").open("w") as log:
            subprocess.run(["journalctl", "--user", "--no-pager", "-o", "short-iso", "-u", bridge_unit, "-u", interop_unit],
                           stdout=log, stderr=subprocess.STDOUT, timeout=120, check=False)
        for unit in (bridge_unit, interop_unit):
            (installed / unit).unlink(missing_ok=True)
        systemctl("daemon-reload", check=False)
        systemctl("reset-failed", bridge_unit, interop_unit, check=False)

    cleanup.callback(remove)
    systemctl("daemon-reload")
    worker = FakeWorker(str(run_worker / "slim.sock"))
    threading.Thread(target=worker.serve_forever, daemon=True).start()
    cleanup.callback(worker.server_close)
    cleanup.callback(worker.shutdown)

    def healthy():
        try:
            return bridge_call(bridge_socket, "GET", "/v1/health", timeout=5)[0] == 200
        except (OSError, http.client.HTTPException):
            return False

    target = "agentcapsule/org_units/agt-units"

    def round_trip(label):
        status, _ = bridge_call(bridge_socket, "POST", "/v1/serve", {"name": target})
        if status != 204:
            raise RuntimeError(f"{label}: the bridge refused to serve ({status})")
        event = {"id": "mbx_" + label, "subjects": ["agent/agt-sender", "agent/agt-units", "event/mbx_" + label],
                 "body": base64.b64encode(json.dumps({"text": label}).encode()).decode()}
        status, body = bridge_call(bridge_socket, "POST", "/v1/send", {"to": target, "nonce": secrets.token_hex(32), "event": event}, timeout=120)
        if status != 200 or base64.b64decode(json.loads(body)["result"]) != b"guest:" + event["id"].encode():
            raise RuntimeError(f"{label}: no receipt ({status} {body[:200]!r})")
        call = worker.calls[-1]
        if call["to"] != target or call["event"] != event or not call["caller"].startswith(config["name"] + "_"):
            raise RuntimeError(f"{label}: the worker was called back with another delivery or caller")

    def delivers(label):
        try:
            round_trip(label)
            return True
        except (RuntimeError, OSError, http.client.HTTPException, ValueError, KeyError):
            return False

    result = {"manager": "user", "not_exercised": ["User=, Group=, CapabilityBoundingSet=, AmbientCapabilities= (system manager only)",
                                                    "IPAddressDeny=/IPAddressAllow= (the user manager attaches no IP filter)",
                                                    "Requires=docker.service (a system unit)"]}
    print("systemd-supervision", flush=True)
    # The services are up; the unit's start publishes the node on its port.
    systemctl("start", interop_unit)
    published = subprocess.check_output([*compose, "port", "slim", "46357"], env=docker_env, text=True, timeout=60).strip()
    if unit_state(interop_unit)["ActiveState"] != "active" or published != slim_node:
        raise RuntimeError(f"the services' unit is not active, or the node is at {published}")
    systemctl("start", bridge_unit)
    wait_for("the bridge under its unit to reach the node", healthy, 90)
    round_trip("started")
    # A node that restarts at the same address: SLIM's client reconnects.
    subprocess.run([*compose, "restart", "slim"], env=docker_env, capture_output=True, timeout=300, check=True)
    wait_for("a delivery after the node restarted", lambda: delivers("node-restarted"), 120)
    result["bridge_restarts_after_node_restart"] = int(unit_state(bridge_unit)["NRestarts"])
    # The services stopped through their unit for longer than three probes:
    # the bridge ends with code 3, and systemd starts new ones until the node
    # is back.
    before = int(unit_state(bridge_unit)["NRestarts"])
    systemctl("stop", interop_unit)
    state = subprocess.check_output([*compose, "ps", "-a", "--format", "{{.State}}", "slim"], env=docker_env, text=True, timeout=60).strip()
    if state != "exited":
        raise RuntimeError("stopping the services' unit left the node " + state)
    wait_for("systemd to restart the bridge after the node was lost", lambda: int(unit_state(bridge_unit)["NRestarts"]) > before, 120)
    systemctl("start", interop_unit)
    wait_for("a delivery once the services' unit started again", lambda: delivers("node-back"), 180)
    journal = subprocess.run(["journalctl", "--user", "--no-pager", "-o", "cat", "-u", bridge_unit], capture_output=True, text=True, timeout=60).stdout
    if "slim_node_lost" not in journal or "status=3/" not in journal:
        raise RuntimeError("the bridge did not end with code 3 (slim_node_lost)")
    result["bridge_restarts_during_outage"] = int(unit_state(bridge_unit)["NRestarts"]) - before
    # A clean stop: code 0, no restart, the socket removed.
    systemctl("stop", bridge_unit)
    state = unit_state(bridge_unit)
    if state["ActiveState"] != "inactive" or state["Result"] != "success" or bridge_socket.exists():
        raise RuntimeError(f"the bridge did not stop cleanly: {state}")
    # An invalid configuration (writable by others) ends with code 2, which
    # systemd does not retry.
    restarts = int(state["NRestarts"])
    config_path.chmod(0o666)
    systemctl("start", bridge_unit, check=False)
    wait_for("the bridge to refuse its configuration", lambda: unit_state(bridge_unit)["ActiveState"] == "failed", 30)
    time.sleep(12)  # more than two RestartSec
    state = unit_state(bridge_unit)
    if state["ActiveState"] != "failed" or state["ExecMainStatus"] != "2" or int(state["NRestarts"]) > restarts:
        raise RuntimeError(f"an invalid configuration was retried: {state}")
    result["invalid_configuration"] = {"exit": 2, "retried": False}
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--go", default="go", help="Go 1.27.3 executable")
    parser.add_argument("--output", required=True, type=Path, help="new evidence directory")
    parser.add_argument("--services", action="store_true", help="also start and test the private services (Docker Compose)")
    parser.add_argument("--systemd", nargs="?", const="full", choices=["static", "full"],
                        help="also check deploy/systemd; with --services and without 'static', run the bridge and the services under them (systemctl --user)")
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    report = {"status": "failed", "services_tested": args.services, "systemd_units_tested": args.systemd, "gate_g2_complete": False}
    started = time.monotonic()
    profile = {}
    try:
        profile_path = ROOT / "runtime/interop/profile.json"
        profile = json.loads(profile_path.read_text())
        report["profile"] = profile["profile"]
        report["host"] = {"system": platform.system(), "machine": platform.machine(), "libc": platform.libc_ver()}
        if platform.system() != "Linux" or platform.machine() != "x86_64" or platform.libc_ver()[0] != "glibc":
            raise RuntimeError("this profile requires Linux amd64 glibc")
        go = shutil.which(args.go)
        if not go or not shutil.which("cc"):
            raise RuntimeError("Go and a C compiler must already be installed")
        if args.services and not (shutil.which("docker") and shutil.which("openssl")):
            raise RuntimeError("--services needs Docker with Compose and openssl")
        with tempfile.TemporaryDirectory(prefix="agentcapsule-interop-") as temporary, contextlib.ExitStack() as cleanup:
            work = Path(temporary)
            modules = {"probe": work / "probe", "a2aslim": work / "a2aslim", "slimbridge": work / "runtime/slimbridge",
                       "slimlink-contract": work / "internal/slimlink/testdata", "deploy": work / "deploy", "systemd": work / "deploy-systemd"}
            shutil.copytree(ROOT / "runtime/interop/probe", modules["probe"])
            shutil.copytree(ROOT / "runtime/interop/a2aslim", modules["a2aslim"])
            # The bridge reads the worker's contract examples at the same
            # relative path as in the repository.
            shutil.copytree(ROOT / "runtime/slimbridge", modules["slimbridge"])
            shutil.copytree(ROOT / "internal/slimlink/testdata", modules["slimlink-contract"])
            shutil.copytree(ROOT / "deploy/interop", modules["deploy"])
            shutil.copytree(ROOT / "deploy/systemd", modules["systemd"])
            frozen = {name: tree_digests(path) for name, path in modules.items()}
            sources = [Path(__file__).resolve(), profile_path, *sorted((ROOT / "runtime/interop").rglob("*")), *sorted((ROOT / "deploy/interop").rglob("*")), *sorted((ROOT / "deploy/systemd").rglob("*")),
                       *sorted((ROOT / "runtime/slimbridge").rglob("*")), *sorted((ROOT / "internal/slimlink/testdata").rglob("*")),
                       ROOT / "go.mod", ROOT / "go.sum", *sorted((ROOT / "internal/directory").glob("*.go"))]
            report["source_sha256"] = {str(p.relative_to(ROOT)): sha256(p) for p in sources if p.is_file()}
            shutil.copy2(profile_path, output / "profile.json")
            # Allow no inherited credentials, Go flags, or protocol endpoint settings.
            env = {"PATH": os.defpath, "HOME": str(work), "GOENV": "off", "GOWORK": "off", "GOTOOLCHAIN": "local", "CGO_ENABLED": "1", "GOMAXPROCS": "2", "GOFLAGS": "-p=2", "GOPROXY": "https://proxy.golang.org", "GOSUMDB": "sum.golang.org"}
            # Share only module/build caches; neither stores runtime credentials.
            cache = Path(os.environ.get("XDG_CACHE_HOME", str(Path.home() / ".cache"))) / "agentcapsule-interop"
            cache.mkdir(parents=True, exist_ok=True)
            env["GOPATH"] = str(Path.home() / "go")
            env["GOCACHE"] = str(cache / "go-build")

            def run(name, command, cwd, timeout=600, extra=None, environment=None):
                print(name, flush=True)
                with (output / (name + ".log")).open("w") as log:
                    result = subprocess.run(command, cwd=cwd, env=environment or {**env, **(extra or {})}, stdout=log, stderr=subprocess.STDOUT, timeout=timeout, check=False)
                if result.returncode:
                    raise RuntimeError(f"{name} failed ({result.returncode}); see {name}.log")
                return output / (name + ".log")

            version = subprocess.check_output([go, "version"], env=env, text=True).strip()
            report["go"] = version
            if version != "go version " + profile["go"] + " linux/amd64":
                raise RuntimeError("Go version does not match the pinned profile")
            slim = profile["slim"]
            archive = cache / (slim["native_sha256"] + ".zip")
            if not archive.exists() or sha256(archive) != slim["native_sha256"]:
                print("download pinned SLIM native archive (~90 MB)", flush=True)
                with urllib.request.urlopen(slim["native_url"], timeout=60) as remote, (work / "native.zip").open("wb") as target:
                    total = 0
                    while chunk := remote.read(1024 * 1024):
                        total += len(chunk)
                        if total > slim["native_archive_bytes"]:
                            raise RuntimeError("native archive exceeds pinned size")
                        target.write(chunk)
                if sha256(work / "native.zip") != slim["native_sha256"]:
                    raise RuntimeError("native SHA256 mismatch")
                # The build directory can live on a different filesystem.
                with tempfile.NamedTemporaryFile(dir=cache, delete=False) as cached:
                    pending = Path(cached.name)
                    with (work / "native.zip").open("rb") as downloaded:
                        shutil.copyfileobj(downloaded, cached)
                os.replace(pending, archive)
            report["native_archive_sha256"] = sha256(archive)
            library = work / "native"
            library.mkdir()
            with zipfile.ZipFile(archive) as zipped:
                matches = [entry for entry in zipped.infolist() if Path(entry.filename).name == slim["native_library"]]
                if len(matches) != 1 or matches[0].file_size > 1024 * 1024 * 1024:
                    raise RuntimeError("unexpected native archive contents")
                with zipped.open(matches[0]) as incoming, (library / slim["native_library"]).open("wb") as outgoing:
                    shutil.copyfileobj(incoming, outgoing)
            report["native_library_sha256"] = sha256(library / slim["native_library"])
            if report["native_library_sha256"] != slim["native_library_sha256"]:
                raise RuntimeError("native library SHA256 mismatch")
            env["CGO_LDFLAGS"] = "-L" + str(library)
            probe = modules["probe"]
            run("modules", [go, "mod", "download"], probe)
            run("module-integrity", [go, "mod", "verify"], probe)
            bridge = modules["slimbridge"]
            run("slimbridge-modules", [go, "mod", "download"], bridge)
            run("slimbridge-module-integrity", [go, "mod", "verify"], bridge)
            if args.systemd:
                report["systemd"] = {"static": check_units(modules["systemd"], work, output)}
            if not args.services:
                log = run("tests", [go, "test", "-mod=readonly", "-count=1", "-json", "-timeout=60s", "."], probe)
                report["passed_tests"] = passed_tests(log, LIBRARY_TESTS)
                log = run("slimbridge-tests", [go, "test", "-mod=readonly", "-count=1", "-json", "-timeout=120s", "."], bridge)
                report["passed_bridge_tests"] = passed_tests(log, BRIDGE_LIBRARY_TESTS)
            else:
                a2aslim = modules["a2aslim"]
                run("a2aslim-modules", [go, "mod", "download"], a2aslim)
                run("a2aslim-module-integrity", [go, "mod", "verify"], a2aslim)
                certs = work / "certs"
                run("certificates", ["sh", str(modules["deploy"] / "make-certs.sh"), str(certs), "--test-identities"], work, timeout=120)
                # Docker keeps the caller's environment (context, socket); the
                # services get only the lab certificates and loopback ports.
                docker_env = {**os.environ, "INTEROP_CERTS": str(certs), "INTEROP_DIRECTORY_PORT": "0", "INTEROP_SLIM_PORT": "0"}
                compose = ["docker", "compose", "-p", f"agentcapsule-interop-{os.getpid()}", "-f", str(modules["deploy"] / "compose.yml")]
                report["compose"] = subprocess.check_output(["docker", "compose", "version", "--short"], text=True).strip()
                # Registered before start-up, run before the compose file is deleted.
                cleanup.callback(stop_services, compose, docker_env, output)
                run("services-up", [*compose, "up", "-d", "--wait", "--quiet-pull"], work, timeout=900, environment=docker_env)

                def compose_output(*command):
                    return subprocess.check_output([*compose, *command], env=docker_env, text=True, timeout=60).strip()

                containers = {}
                for cid in compose_output("ps", "-a", "-q").split():
                    service, image, state = subprocess.check_output(["docker", "inspect", "--format", '{{index .Config.Labels "com.docker.compose.service"}} {{.Config.Image}} {{.State.Status}}', cid], text=True).split()
                    containers[service] = {"image": image, "state": state}
                report["services"] = containers
                if {s: c["image"] for s, c in containers.items()} != profile["services"]:
                    raise RuntimeError("the running images are not the pinned ones")
                directory = compose_output("port", "directory-edge", "8443")
                slim_node = compose_output("port", "slim", "46357")
                if not directory.startswith("127.0.0.1:") or not slim_node.startswith("127.0.0.1:"):
                    raise RuntimeError("a service port is published beyond loopback")

                def stats(name):
                    ids = compose_output("ps", "-q").split()
                    lines = subprocess.check_output(["docker", "stats", "--no-stream", "--format", "{{json .}}", *ids], text=True, timeout=120).splitlines()
                    report.setdefault("footprint", {})[name] = {json.loads(l)["Name"]: {"memory": json.loads(l)["MemUsage"], "cpu": json.loads(l)["CPUPerc"]} for l in lines}

                stats("idle")
                extra = {"INTEROP_CERTS": str(certs), "INTEROP_DIRECTORY_ADDR": directory, "INTEROP_SLIM_ENDPOINT": "https://" + slim_node}
                log = run("tests", [go, "test", "-mod=readonly", "-tags=interop_services", "-count=1", "-json", "-timeout=300s", "."], probe, timeout=900, extra=extra)
                report["passed_tests"] = passed_tests(log, LIBRARY_TESTS | SERVICE_TESTS)
                log = run("a2aslim-tests", [go, "test", "-mod=readonly", "-tags=interop_services", "-count=1", "-json", "-timeout=300s", "."], a2aslim, timeout=900, extra=extra)
                report["passed_a2aslim_tests"] = passed_tests(log, A2A_SLIM_TESTS)
                # The bridge test restarts the node: the script carries only
                # what Docker needs to find its daemon; the test gets its path.
                restart = work / "restart-slim"
                kept = {k: v for k, v in docker_env.items() if k in ("PATH", "HOME", "USER", "XDG_RUNTIME_DIR", "XDG_CONFIG_HOME") or k.startswith(("DOCKER_", "INTEROP_"))}
                restart.write_text("#!/bin/sh\nset -e\n" + " ".join(["exec", "env", "-i", *(shlex.quote(f"{k}={v}") for k, v in kept.items()),
                                   "sh", "-c", shlex.quote(" ".join(shlex.quote(c) for c in compose) + " restart slim >/dev/null && " +
                                                           " ".join(shlex.quote(c) for c in compose) + " port slim 46357")]) + "\n")
                restart.chmod(0o700)
                log = run("slimbridge-tests", [go, "test", "-mod=readonly", "-tags=interop_services", "-count=1", "-json", "-timeout=600s", "."], bridge,
                          timeout=900, extra={**extra, "INTEROP_SLIM_RESTART": str(restart)})
                report["passed_bridge_tests"] = passed_tests(log, BRIDGE_LIBRARY_TESTS | BRIDGE_SERVICE_TESTS)
                # In place, read-only: only internal/directory and its imports
                # are built, without CGO.
                log = run("platform-tests", [go, "test", "-mod=readonly", "-tags=interop_services", "-count=1", "-json", "-timeout=300s",
                                             "-run", "AgainstThePrivateDirectory", "./internal/directory"], ROOT, timeout=900, extra={**extra, "CGO_ENABLED": "0"})
                report["passed_platform_tests"] = passed_tests(log, PLATFORM_TESTS)
                stats("after_tests")
                if args.systemd == "full":
                    # Last: it stops and starts the services.
                    run("slimbridge-build", [go, "build", "-mod=readonly", "-trimpath", "-o", str(work / "agentcapsule-slim-bridge"), "."], bridge, timeout=900)
                    report["systemd"]["supervision"] = supervise_units(modules["systemd"], modules["deploy"], work / "agentcapsule-slim-bridge",
                                                                       bridge / "config.example.json", certs, compose, docker_env, output, cleanup)
            if {name: tree_digests(path) for name, path in modules.items()} != frozen:
                raise RuntimeError("Go modified a frozen module; update committed dependencies first")
            if any(sha256(ROOT / name) != digest for name, digest in report["source_sha256"].items()):
                raise RuntimeError("sources changed during qualification")
            report["status"] = "passed" if args.services else "passed_libraries_only"
    except Exception as error:
        report["status"] = "failed"  # also when only the services' removal failed
        report["error"] = str(error)
    finally:
        report["int01_complete"] = report["status"] == "passed" and profile.get("int01_complete", False)
        report["elapsed_seconds"] = round(time.monotonic() - started, 3)
        (output / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report, indent=2))
    return 0 if report["status"] in ("passed", "passed_libraries_only") else 1


if __name__ == "__main__":
    raise SystemExit(main())
