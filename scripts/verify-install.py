#!/usr/bin/env python3
"""Install the platform from scratch, as the docs say (VAL-02).

Starting from a new, empty output directory, the run follows
docs/bootstrap.md and docs/install.md step by step, without root:

1. copies the tracked sources (go.mod, go.sum, cmd/, internal/) into it and
   builds every binary as bootstrap.md says (`go build -trimpath -o bin/
   ./cmd/...`), then installs them into a throwaway prefix that stands for
   /, with /opt/agentcapsule, /etc/agentcapsule, /var/lib and /run;
2. creates a PostgreSQL cluster, a role and the database it owns, reached
   over a Unix socket;
3. `agentcapsule-admin migrate`, twice: the second run only checks;
4. `agentcapsule-admin bootstrap-platform`: the receipt key and the platform
   token, private files; again with the same files (confirmed), and with
   another token file (refused);
5. the authority service in standalone mode: both authorities initialized,
   `agentcapsule-authority serve` started with its configuration;
6. a CA of its own and the API's certificate for api.example.net, then
   `agentcapsule-api -preflight` and the API itself, in production mode
   (HTTPS only), on the authority service's API socket: the API refuses to
   start without it, or with another installation's identities; its
   readiness reports the service; a plain HTTP request gets 400;
7. the platform header file, and the organization with its first owner
   (curl, as written in bootstrap.md), replayed and refused as a duplicate;
   its receipt names the day of the authority service's receipt key, and
   the service holds today's and tomorrow's;
8. the organization's identity trust (`configure-delegation -action
   install`, an Ed25519 key made here for the identity provider), replayed;
9. the owner signs in (`GET /v1/organizations/current`) and names an
   administrator; user IDs written by the caller are refused;
10. `agentcapsule-admin list-audit` and the organization's `GET /v1/audit`
    hold each step and no secret;
11. the worker's preflight with its configuration and the authority
    service: every check this host can pass must pass; `/dev/kvm` must be
    reported as it is (failed when this account cannot open it), and the
    artifacts (Firecracker, the jailer, the guest kernel and image) as
    missing unless given; when a mandatory check fails, the worker refuses
    to start (RUN-012) and creates no runtime root; then the garbage
    collection on demand (`-collect-garbage`, OPR-5): refused without
    `-confirm`, a dry run, a run, audited, and still no runtime root;
12. ends with an authenticated call to the API as the organization's owner.

Without root: the worker refuses a configuration that root does not own,
and the authority service admits only root on the worker's socket. The run
starts both in a user namespace where this account is root (`unshare -r`),
which changes no permission on the host: the KVM device, cgroups and mounts
are seen as this account sees them. Everything else runs as this account.

Nothing dials out (DEP-1): once Go's modules are downloaded, the whole run,
the build included, is in a network namespace of its own. Its only way out
is a dummy interface, which the default routes (IPv4 and IPv6) go through,
so that any attempt to reach another host sends a packet there. nftables
counts, in that namespace, the packets that leave by another interface than
loopback, the UDP datagrams (DNS included), and each TCP connection opened
on loopback by its port. The run fails when a packet left, when a datagram
was sent, or when a connection went to a port that nothing in the install
listens on; the counts are in summary.json, under egress.

The run writes summary.json (each step with its document, its duration and
what it checked; the preflight's results; the deviations from the docs it
had to make), the logs of every command with secrets redacted, and the
public configuration files. It removes the database, the binaries, the
sources and every secret, then searches the evidence for each secret.
"""

import argparse
import base64
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
# internal/volumestore links "-l:libcryptsetup.so.12", which Go refuses in a
# #cgo directive unless this pattern allows it.
CGO_LDFLAGS_ALLOW = r"-l:libcryptsetup\.so\.12"
API_NAME = "api.example.net"
ISSUER, AUDIENCE, KEY_ID = "https://idp.acme.example", "agentcapsule:acme", "2026-11"
OWNER_SCOPES = "org:read member:read member:manage audit:read"
# Every check the worker's preflight prints with this configuration.
PREFLIGHT_CHECKS = ("mode", "configuration", "kvm", "kernel", "cgroups", "namespaces", "runtime_filesystem",
                    "artifact_firecracker", "artifact_jailer", "artifact_kernel", "artifact_initrd", "clock",
                    "disk_runtime", "authority", "metrics_listen", "registry", "postgresql")
MANDATORY = ("kvm", "kernel", "cgroups", "namespaces", "runtime_filesystem", "disk_runtime",
             "artifact_firecracker", "artifact_jailer", "artifact_kernel", "artifact_initrd")
ARTIFACTS = ("firecracker", "jailer", "kernel", "initrd")
RESULT = re.compile(r"^(ok|warn|fail)\s+([a-z_]+): (.*)$")
# Deviations from the docs this run makes, and why.
DEVIATIONS = [
    "A throwaway prefix stands for /: /opt/agentcapsule, /etc/agentcapsule and /var/lib are under it; the sockets' "
    "directory is a short directory under /tmp, since a Unix socket path is limited to 107 bytes.",
    "The API listens on 127.0.0.1 and a free port instead of 0.0.0.0:8443; curl reaches it as api.example.net "
    "with --resolve, and trusts the run's CA with --cacert.",
    "PostgreSQL trusts local connections (initdb --auth-local=trust): a cluster of this run only, on a private "
    "socket directory (mode 0700).",
    "The worker's preflight and the authority service run in a user namespace where this account is root "
    "(unshare -r), not as root: the docs run them as root and as the account agentcapsule-authority.",
    "The API runs as this account, outside that namespace: the service sees it as root there, which its API socket "
    "admits too, so this run does not show the admission of api_uid (the Go tests do).",
    "The identity provider is played by this run: an Ed25519 key made here signs the owner's tokens.",
    "From the build on, the run is in a network namespace of its own whose only way out is a dummy interface, "
    "to count what would leave the host (DEP-1); Go's modules are downloaded before, with GOPROXY off after.",
]
# The network namespace of the run (DEP-1). The environment variable marks
# the run inside it.
NAMESPACE_ENV = "AGENTCAPSULE_INSTALL_IN_NAMESPACE"
EGRESS_RULES = """table inet egress {
  set loopback_tcp { type inet_service; flags dynamic; counter; }
  counter outside {}
  counter datagrams {}
  chain output {
    type filter hook output priority filter; policy accept;
    oifname != "lo" counter name outside
    meta l4proto udp counter name datagrams
    oifname "lo" tcp flags & (syn | ack) == syn add @loopback_tcp { tcp dport }
  }
}
"""
# Runs as root of a user namespace that owns a new network namespace: sets
# up loopback and the dummy way out, loads the rules, runs the rest as this
# account again (a nested user namespace), then saves the counters.
NAMESPACE_SETUP = r"""set -e
out=$1 rules=$2 uid=$3 gid=$4
shift 4
ip link set lo up
ip link add dummy0 type dummy
ip link set dummy0 addrgenmode none
ip link set dummy0 up
ip addr add 192.0.2.1/24 dev dummy0
ip route add default via 192.0.2.254 dev dummy0
ip -6 addr add 2001:db8::1/64 dev dummy0 nodad
ip -6 route add default via 2001:db8::fe dev dummy0
nft -f "$rules"
status=0
unshare --user --map-user="$uid" --map-group="$gid" -- "$@" || status=$?
mkdir -p "$out/egress"
nft -j list ruleset > "$out/egress/nft.json"
ip -j -s link show dev dummy0 > "$out/egress/dummy0.json"
exit $status
"""


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def b64url(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def parse_preflight(text):
    """Return ([(status, check, detail)], last line) from a preflight's output."""
    results, last = [], ""
    for line in text.splitlines():
        m = RESULT.match(line)
        if m:
            results.append((m.group(1), m.group(2), m.group(3)))
        elif line.strip():
            last = line.strip()
    return results, last


def assess_preflight(results, last, returncode, may_fail):
    """Return the problems of a worker preflight run: a check missing or
    printed twice, a failure this host should not have, a final line or exit
    code that does not match the failures. may_fail maps each check allowed
    to fail here to the reason."""
    problems, seen = [], {}
    for status, check, _ in results:
        if check in seen:
            problems.append(f"{check} is printed twice")
        seen[check] = status
    for check in PREFLIGHT_CHECKS:
        if check not in seen:
            problems.append(f"{check} is not printed")
    for check, status in seen.items():
        if status == "fail" and check not in may_fail:
            problems.append(f"{check} fails on this host")
    for check, reason in may_fail.items():
        if check.startswith("artifact_") or check == "kvm":
            if seen.get(check) != "fail":
                problems.append(f"{check} is {seen.get(check)} although {reason}")
    failed = any(status == "fail" for status in seen.values())
    expected_last = "preflight_failed" if failed else "preflight_passed"
    if last != expected_last:
        problems.append(f"the last line is {last!r}, not {expected_last}")
    if (returncode != 0) != failed:
        problems.append(f"exit code {returncode} with {'a failure' if failed else 'no failure'}")
    return problems


def kvm_usable():
    """Whether this account can open /dev/kvm read-write, as the worker does."""
    try:
        fd = os.open("/dev/kvm", os.O_RDWR | os.O_CLOEXEC)
    except OSError:
        return False
    os.close(fd)
    return True


def user_namespace_usable():
    try:
        return subprocess.run(["unshare", "-r", "true"], capture_output=True, timeout=10).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def go_environment(a, base_env):
    """The environment of the build: no go.work, no go env file, modules
    read-only, and none fetched inside the network namespace."""
    env = {**base_env, "CGO_ENABLED": "1", "CGO_LDFLAGS_ALLOW": CGO_LDFLAGS_ALLOW, "GOTOOLCHAIN": "local",
           "GOFLAGS": "-mod=readonly", "GOENV": "off", "GOWORK": "off"}
    for name in ("GOCACHE", "GOMODCACHE", "GOPATH", "TMPDIR"):
        if os.environ.get(name):
            env[name] = os.environ[name]
    if a.native_tools:
        env["CGO_CFLAGS"] = "-I" + str(a.native_tools.resolve() / "usr/include")
    if os.environ.get(NAMESPACE_ENV) == "1":
        env["GOPROXY"] = "off"
    return env


def base_environment(work):
    return {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": os.environ.get("HOME", str(work)), "LANG": "C.UTF-8"}


def assess_egress(directory, listeners):
    """Return what the network namespace counted, and its problems: a packet
    that left, a UDP datagram, a TCP connection to a port nothing of the
    install listens on, or counters that saw nothing of the run."""
    try:
        tx = json.loads((directory / "dummy0.json").read_text())[0]["stats64"]["tx"]["packets"]
        ruleset = json.loads((directory / "nft.json").read_text())["nftables"]
    except (OSError, ValueError, KeyError) as e:
        return {}, [f"the network namespace's counters are missing: {e}"]
    counters = {i["counter"]["name"]: i["counter"]["packets"] for i in ruleset if "counter" in i}
    ports = {}
    for item in ruleset:
        if item.get("set", {}).get("name") == "loopback_tcp":
            for elem in item["set"].get("elem", []):
                ports[elem["elem"]["val"]] = elem["elem"]["counter"]["packets"]
    configured = {port: name for name, port in listeners.items()}
    egress = {"dummy0_tx_packets": tx, "packets_out_of_loopback": counters.get("outside"), "udp_datagrams": counters.get("datagrams"),
              "loopback_tcp_connections": {f"{port} ({configured.get(port, 'nothing configured')})": n for port, n in sorted(ports.items())}}
    problems = []
    if tx != 0 or counters.get("outside") != 0:
        problems.append(f"{max(tx, counters.get('outside') or 0)} packets left by the dummy interface: something tried to reach another host")
    if counters.get("datagrams") != 0:
        problems.append(f"{counters.get('datagrams')} UDP datagrams were sent (a DNS query, telemetry?)")
    stray = sorted(port for port in ports if port not in configured)
    if stray:
        problems.append(f"TCP connections to loopback ports nothing of the install listens on: {stray}")
    if not ports.get(listeners.get("api")):
        problems.append("the counters saw no connection to the API: they do not see the run")
    return egress, problems


def run_in_namespace(a):
    """Download Go's modules, then run this script again in a network
    namespace of its own, and check what tried to leave it (DEP-1)."""
    out = a.output.resolve()
    if out.exists():
        raise SystemExit(f"{out} exists: give a new evidence directory")
    base_env = base_environment(Path(tempfile.gettempdir()))
    subprocess.run([str(a.go.resolve()), "mod", "download"], cwd=ROOT, env=go_environment(a, base_env), check=True, timeout=1200)
    with tempfile.NamedTemporaryFile("w", prefix="acpi-egress-", suffix=".nft", delete=False) as f:
        f.write(EGRESS_RULES)
        rules = f.name
    try:
        command = ["unshare", "--user", "--map-root-user", "--net", "--fork", "--", "sh", "-c", NAMESPACE_SETUP, "sh",
                   str(out), rules, str(os.getuid()), str(os.getgid()), sys.executable, str(Path(__file__).resolve()), *sys.argv[1:]]
        subprocess.run(command, env={**os.environ, NAMESPACE_ENV: "1"})
    finally:
        os.unlink(rules)
    summary = out / "summary.json"
    try:
        report = json.loads(summary.read_text())
    except (OSError, ValueError):
        report = {"status": "failed", "error": "the run in the network namespace wrote no summary"}
    report["egress"], problems = assess_egress(out / "egress", report.get("listeners", {}))
    if problems:
        report["status"] = "failed"
        report["error"] = "; ".join(([report["error"]] if report.get("error") else []) + problems)
        print("FAIL", "; ".join(problems), file=sys.stderr)
    out.mkdir(parents=True, exist_ok=True)
    summary.write_text(json.dumps(report, indent=2) + "\n")
    print(f"install from scratch: {report['status']}; nothing left the network namespace: {not problems}; evidence in {out}")
    return 0 if report["status"] == "passed" else 1


class Failure(Exception):
    pass


class Install:
    def __init__(self, out, args):
        self.out, self.args = out, args
        self.logs = out / "logs"
        self.logs.mkdir()
        self.secrets = []  # strings that must not appear in the evidence
        self.steps, self.current = [], None
        self.processes = {}

    def expect(self, condition, message):
        if not condition:
            raise Failure(message)

    def secret(self, value):
        if value:
            self.secrets.append(value)
        return value

    def redact(self, text):
        for value in sorted(self.secrets, key=len, reverse=True):
            text = text.replace(value, "<redacted>")
        return text

    def step(self, name, doc, does):
        self.current = {"step": name, "doc": doc, "does": does, "status": "running", "checked": []}
        self.steps.append(self.current)
        self.current["_start"] = time.monotonic()
        print(f"-- {name}: {does}", flush=True)

    def checked(self, what):
        self.current["checked"].append(what)

    def done(self):
        self.current["seconds"] = round(time.monotonic() - self.current.pop("_start"), 3)
        self.current["status"] = "passed"

    def run(self, label, command, env, check=True, cwd=None, shown=None, timeout=300):
        """Run a command; log it (shown, or the command) and its output, secrets redacted."""
        r = subprocess.run([str(c) for c in command], env=env, cwd=cwd, capture_output=True, text=True, timeout=timeout)
        with (self.logs / (label + ".log")).open("a") as log:
            log.write(self.redact("$ " + (shown or " ".join(str(c) for c in command)) + "\n" + r.stdout + r.stderr))
            log.write(f"[exit {r.returncode}]\n")
        if check and r.returncode:
            raise Failure(f"{label}: exit {r.returncode}; see logs/{label}.log")
        return r

    def start(self, label, command, env):
        log = (self.logs / (label + ".log")).open("a")
        log.write("$ " + " ".join(str(c) for c in command) + "\n")
        log.flush()
        self.processes[label] = (subprocess.Popen([str(c) for c in command], env=env, stdout=log, stderr=subprocess.STDOUT,
                                                  start_new_session=True), log)
        return self.processes[label][0]

    def stop(self, label):
        proc, log = self.processes.pop(label)
        if proc.poll() is None:
            proc.send_signal(signal.SIGTERM)
            try:
                proc.wait(timeout=30)
            except subprocess.TimeoutExpired:
                os.killpg(proc.pid, signal.SIGKILL)
                proc.wait()
        log.close()
        return proc.returncode

    def wait(self, label, condition, seconds, message):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            proc = self.processes.get(label, (None,))[0]
            if proc is not None and proc.poll() is not None:
                raise Failure(f"{label} exited ({proc.returncode}); see logs/{label}.log")
            if condition():
                return
            time.sleep(0.1)
        raise Failure(message)


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--go", type=Path, required=True, help="Go executable (1.27.4)")
    p.add_argument("--pg-bin", type=Path, required=True, help="PostgreSQL bin directory (initdb, pg_ctl, psql)")
    p.add_argument("--pg-library-path", type=Path, help="library directory for the PostgreSQL binaries")
    p.add_argument("--native-tools", type=Path, help="directory whose usr/include holds libcryptsetup's headers, if not system-wide")
    p.add_argument("--firecracker", type=Path, help="Firecracker 1.17.0 built by build-firecracker.py, for the artifact checks")
    p.add_argument("--jailer", type=Path, help="its jailer")
    p.add_argument("--kernel", type=Path, help="guest kernel (vmlinux) built by build-guest-kernel.py")
    p.add_argument("--initrd", type=Path, help="guest image built by build-product-guest.py")
    p.add_argument("--output", type=Path, required=True, help="new evidence directory")
    a = p.parse_args()
    for tool in ("openssl", "curl", "unshare", "ip", "nft"):
        if not shutil.which(tool):
            p.error(tool + " is required")
    if os.geteuid() == 0:
        p.error("run as an ordinary account: the run checks an install without root")
    if not user_namespace_usable():
        p.error("unshare -r fails: unprivileged user namespaces are disabled (on Ubuntu 24.04: "
                "sysctl kernel.apparmor_restrict_unprivileged_userns=0)")
    given = {name: getattr(a, name) for name in ARTIFACTS if getattr(a, name)}
    for name, path in given.items():
        if not path.is_file():
            p.error(f"--{name} {path} is not a file")
    if os.environ.get(NAMESPACE_ENV) != "1":
        return run_in_namespace(a)
    out = a.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    started = time.monotonic()
    run = Install(out, a)
    report = {"status": "failed", "deviations": DEVIATIONS, "steps": run.steps}
    short = Path(tempfile.mkdtemp(prefix="acpi-", dir="/tmp"))  # sockets: PostgreSQL's and the authority service's
    prefix, work = out / "prefix", out / "work"
    opt, etc = prefix / "opt/agentcapsule", prefix / "etc/agentcapsule"
    var = prefix / "var/lib"
    host_root = var / "agentcapsule/host"
    key_root, restore_root = var / "agentcapsule-key-authority", var / "agentcapsule-restore-authority"
    sockets = short / "run/agentcapsule-authority"
    pg_data, pg_socket = work / "postgres", short / "pg"
    client = work / "client"  # the operator's and the identity provider's own files
    base_env = base_environment(work)
    pg_env = dict(base_env)
    if a.pg_library_path:
        pg_env["LD_LIBRARY_PATH"] = str(a.pg_library_path.resolve())
    dsn = f"host={pg_socket} dbname=agentcapsule user=agentcapsule"
    # Production mode: AGENTCAPSULE_MODE is not set (docs/install.md, Modes).
    admin_env = {**base_env, "AGENTCAPSULE_DATABASE_URL": dsn}
    api_port, api_metrics, authority_metrics, worker_metrics = free_port(), free_port(), free_port(), free_port()
    # What the install listens on, for the count of connections (DEP-1).
    report["listeners"] = {"api": api_port, "api_metrics": api_metrics, "authority_metrics": authority_metrics,
                           "worker_metrics": worker_metrics}
    url = f"https://{API_NAME}:{api_port}"
    curl_tls = ["--cacert", str(client / "ca.pem"), "--resolve", f"{API_NAME}:{api_port}:127.0.0.1"]
    pg_started = False

    def admin(label, *args, check=True):
        return run.run(label, [opt / "agentcapsule-admin", *args], admin_env, check=check)

    def curl(label, method, path, headers=(), body=None, shown_headers=None):
        """curl as the docs write it; returns (status, parsed JSON or text)."""
        command = ["curl", "-sS", "-X", method, url + path, *curl_tls, "-o", str(work / "body"), "-w", "%{http_code}"]
        shown = list(command)
        for h, s in zip(headers, shown_headers or headers):
            command += ["-H", h]
            shown += ["-H", s]
        if body is not None:
            command += ["-H", "Content-Type: application/json", "-d", body]
            shown += ["-H", "Content-Type: application/json", "-d", body]
        r = run.run(label, command, base_env, shown=" ".join(shown), timeout=60)
        text = (work / "body").read_text() if (work / "body").exists() else ""
        with (run.logs / (label + ".log")).open("a") as log:
            log.write(run.redact(f"[http {r.stdout.strip()}] {text}\n"))
        try:
            parsed = json.loads(text) if text else None
        except json.JSONDecodeError:
            parsed = text
        return int(r.stdout.strip() or 0), parsed

    def idp_token(key, claims_override=None, header_override=None):
        now = int(time.time())
        header = {"alg": "EdDSA", "typ": "JWT", "kid": KEY_ID, **(header_override or {})}
        claims = {"iss": ISSUER, "aud": AUDIENCE, "sub": "alice", "jti": secrets.token_hex(16), "iat": now, "exp": now + 120,
                  "trust_generation": 1, "scope": OWNER_SCOPES, **(claims_override or {})}
        signing = b64url(json.dumps(header, separators=(",", ":")).encode()) + "." + b64url(json.dumps(claims, separators=(",", ":")).encode())
        (work / "jwt-input").write_text(signing)
        signature = subprocess.run(["openssl", "pkeyutl", "-sign", "-inkey", str(key), "-rawin", "-in", str(work / "jwt-input")],
                                   capture_output=True, check=True, timeout=30).stdout
        return run.secret(signing + "." + b64url(signature))

    def as_owner(label, method, path, body=None, token=None):
        token = token or idp_token(client / "idp.key")
        return curl(label, method, path, [f"Authorization: Bearer {token}", *(["Idempotency-Key: " + label] if body else [])],
                    body, [f"Authorization: Bearer $TOKEN", *(["Idempotency-Key: " + label] if body else [])])

    try:
        # ---- 1. Build and install (bootstrap.md, Before you start).
        run.step("build", "docs/bootstrap.md#before-you-start", "build every binary from the tracked sources, install them into the prefix")
        src = work / "src"
        listed = subprocess.run(["git", "ls-files", "-z", "--", "go.mod", "go.sum", "cmd", "internal"], cwd=ROOT,
                                capture_output=True, check=True).stdout.decode().split("\0")
        for name in filter(None, listed):
            target = src / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / name, target)
        go_env = go_environment(a, base_env)
        report["go"] = run.run("build", [a.go.resolve(), "version"], go_env).stdout.strip()
        run.run("build", [a.go.resolve(), "build", "-trimpath", "-o", "bin/", "./cmd/..."], go_env, cwd=src, timeout=1200,
                shown="go build -trimpath -o bin/ ./cmd/...")
        built = sorted(p.name for p in (src / "bin").iterdir())
        expected = sorted(p.name for p in (src / "cmd").iterdir() if p.is_dir())
        run.expect(built == expected, f"go build gave {built}, not one binary per command {expected}")
        opt.mkdir(parents=True)
        for name in built:
            shutil.copy2(src / "bin" / name, opt / name)
            (opt / name).chmod(0o755)
        report["binaries"] = {n: hashlib.sha256((opt / n).read_bytes()).hexdigest() for n in built}
        run.checked(f"{len(built)} binaries, one per command: {', '.join(built)}")
        run.done()

        # ---- 2. PostgreSQL (bootstrap.md, Before you start; install.md, PostgreSQL).
        run.step("postgresql", "docs/install.md#postgresql", "a cluster on a Unix socket, a role and the database it owns")
        work.mkdir(exist_ok=True)
        pg_socket.mkdir(mode=0o700)
        run.run("postgresql", [a.pg_bin / "initdb", "-D", pg_data, "--username=postgres", "--auth-local=trust", "--auth-host=reject",
                               "--no-locale", "--encoding=UTF8"], pg_env)
        run.run("postgresql", [a.pg_bin / "pg_ctl", "-D", pg_data, "-l", run.logs / "postgresql-server.log", "-w", "-o",
                               f"-c listen_addresses= -k {pg_socket} -c unix_socket_permissions=0700", "start"], pg_env)
        pg_started = True
        psql = [a.pg_bin / "psql", "-X", "-v", "ON_ERROR_STOP=1", "-h", pg_socket, "-U", "postgres", "-d", "postgres"]
        run.run("postgresql", [*psql, "-c", "CREATE ROLE agentcapsule LOGIN", "-c", "CREATE DATABASE agentcapsule OWNER agentcapsule"], pg_env)
        report["postgresql"] = run.run("postgresql", [*psql, "-tAc", "SHOW server_version"], pg_env).stdout.strip()
        run.checked(f"PostgreSQL {report['postgresql']}; AGENTCAPSULE_DATABASE_URL='{dsn}'")
        run.done()

        # ---- 3. Migrate (bootstrap.md, 1).
        run.step("migrate", "docs/bootstrap.md#1-migrate", "agentcapsule-admin migrate, then again")
        for attempt in (1, 2):
            r = admin("migrate", "migrate")
            run.expect("migration_complete" in r.stdout, f"migrate run {attempt} did not print migration_complete")
        run.checked("migration_complete twice; the second run only checks")
        run.done()

        # ---- 4. The platform operator's credential (bootstrap.md, 2).
        run.step("bootstrap-platform", "docs/bootstrap.md#2-create-the-platform-operators-credential",
                 "the receipt key and the platform token, private files; replayed; refused with another token file")
        run.run("bootstrap-platform", ["install", "-d", "-m", "700", etc], base_env)
        receipt, token_file = etc / "receipt.key", etc / "platform.token"
        r = admin("bootstrap-platform", "bootstrap-platform", "-receipt-key-file", receipt, "-token-file", token_file)
        run.expect("platform_bootstrap_complete" in r.stdout, "bootstrap-platform did not print platform_bootstrap_complete")
        token = run.secret(token_file.read_text().strip())
        credentials = admin("list-credentials", "list-credentials").stdout
        receipt_bytes = receipt.read_bytes()
        for form in (receipt_bytes.hex(), base64.b64encode(receipt_bytes).decode()):
            run.secret(form)
        run.expect(token.startswith("acpp_"), "the platform token does not start with acpp_")
        run.expect(len(receipt_bytes) == 32, "the receipt key is not 32 bytes")
        for f in (receipt, token_file):
            run.expect(f.stat().st_mode & 0o777 == 0o600, f"{f.name} is not mode 0600")
        run.expect(token not in r.stdout + r.stderr, "bootstrap-platform printed the token")
        run.checked("platform_bootstrap_complete; receipt.key (32 bytes) and platform.token (acpp_) mode 0600; the token not printed")
        r = admin("bootstrap-platform", "bootstrap-platform", "-receipt-key-file", receipt, "-token-file", token_file)
        run.expect("platform_bootstrap_complete" in r.stdout and token_file.read_text().strip() == token, "the replay changed the token")
        run.expect(admin("list-credentials", "list-credentials").stdout == credentials, "the replay changed the credential or its expiry")
        run.checked("the same command again confirms the same credential, without extending it")
        r = admin("bootstrap-platform", "bootstrap-platform", "-receipt-key-file", receipt, "-token-file", etc / "other.token", check=False)
        run.expect(r.returncode != 0 and "platform_bootstrap_rejected_conflict" in r.stdout + r.stderr,
                   "another token file was not refused with platform_bootstrap_rejected_conflict")
        left = (etc / "other.token").exists()
        if left:
            run.secret((etc / "other.token").read_text().strip())
        run.checked("another token file: platform_bootstrap_rejected_conflict" + ("; the refused token file is left behind" if left else
                                                                                   "; no token file left behind"))
        r = admin("list-credentials", "list-credentials")
        active = [line for line in r.stdout.splitlines() if '"platform"' in line or "ptok_" in line]
        run.expect(len(active) == 1, f"list-credentials shows {len(active)} platform credentials, not 1")
        run.checked("list-credentials: one platform credential")
        run.done()

        # ---- 5. The authority service, standalone (install.md, Operator steps; recovery.md, Install the authority service).
        run.step("authority", "docs/recovery.md#install-the-authority-service",
                 "both authorities initialized, then agentcapsule-authority serve without a replica (standalone)")
        run.run("authority", ["install", "-d", "-m", "0700", key_root, restore_root], base_env)
        r = admin("authority", "init-key-authority", "-root", key_root)
        key_id = json.loads(r.stdout)["authority_id"]
        r = admin("authority", "init-restore-authority", "-root", restore_root, "-data-root", host_root,
                  "-key-authority-root", key_root, "-key-authority-id", key_id)
        ids = json.loads(r.stdout)
        restore_id = ids["authority_id"]
        run.expect(key_id.startswith("keyauth_") and restore_id.startswith("restoreauth_") and ids.get("key_authority_id") == key_id,
                   "the authorities' identities are not keyauth_ and restoreauth_, or do not match")
        run.checked("init-key-authority and init-restore-authority print the identities to pin")
        sockets.mkdir(parents=True, mode=0o750)
        authority_config = {"version": 2, "role": "primary",
                            "key_authority": {"root": str(key_root), "identity": key_id},
                            "restore_authority": {"root": str(restore_root), "identity": restore_id},
                            "worker_socket": str(sockets / "worker.sock"), "api_socket": str(sockets / "api.sock"),
                            "api_uid": os.getuid(), "max_key_hold": "2m", "metrics_listen": f"127.0.0.1:{authority_metrics}"}
        (etc / "authority.json").write_text(json.dumps(authority_config, indent=2) + "\n")
        (etc / "authority.json").chmod(0o644)
        run.start("authority-service", ["unshare", "-r", opt / "agentcapsule-authority", "serve", "-config", etc / "authority.json"], base_env)

        def service_started():
            return '"service_started"' in (run.logs / "authority-service.log").read_text()
        run.wait("authority-service", service_started, 30, "the authority service did not log service_started")
        event = next(json.loads(line) for line in (run.logs / "authority-service.log").read_text().splitlines()
                     if '"service_started"' in line)
        run.expect(event.get("mode") == "standalone", f"the service started in mode {event.get('mode')}, not standalone")
        r = run.run("authority-metrics", ["curl", "-sS", f"http://127.0.0.1:{authority_metrics}/metrics"], base_env)
        run.expect("agentcapsule_authority" in r.stdout, "the service's metrics hold no agentcapsule_authority series")
        run.checked("service_started in mode standalone; its metrics answer on loopback")
        run.done()

        # ---- 6. The API's certificate, its preflight, the API (bootstrap.md, 3; install.md, API certificate).
        run.step("api", "docs/bootstrap.md#3-start-the-api",
                 "a CA of this run, the API's certificate, agentcapsule-api -preflight, then the API in production mode, "
                 "on the authority service")
        client.mkdir(mode=0o700)
        ossl = lambda *args: run.run("certificates", ["openssl", *args], base_env)
        ossl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-days", "90", "-subj", "/CN=install CA",
             "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign",
             "-keyout", client / "ca.key", "-out", client / "ca.pem")
        ossl("req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-subj", "/CN=" + API_NAME,
             "-keyout", etc / "api.key", "-out", work / "api.csr")
        (work / "api.ext").write_text(f"subjectAltName=DNS:{API_NAME}\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n")
        ossl("x509", "-req", "-in", work / "api.csr", "-CA", client / "ca.pem", "-CAkey", client / "ca.key", "-CAcreateserial",
             "-days", "90", "-extfile", work / "api.ext", "-out", etc / "api.crt")
        (etc / "api.key").chmod(0o600)
        (etc / "api.crt").chmod(0o644)
        for key in (etc / "api.key", client / "ca.key"):
            run.secret("".join(key.read_text().splitlines()[1:-1]))
        api_base = ["-receipt-key-file", receipt, "-host-id", "local", "-listen", f"127.0.0.1:{api_port}",
                    "-tls-cert", etc / "api.crt", "-tls-key", etc / "api.key", "-tls-server-name", API_NAME,
                    "-metrics-listen", f"127.0.0.1:{api_metrics}"]
        authority_args = ["-authority-socket", sockets / "api.sock", "-restore-authority-id", restore_id, "-key-authority-id", key_id]
        api_args = [*api_base, *authority_args]
        r = run.run("api-preflight", [opt / "agentcapsule-api", *api_args, "-preflight"], admin_env, check=False)
        results, last = parse_preflight(r.stdout)
        report["api_preflight"] = [{"status": s, "check": c, "detail": d} for s, c, d in results]
        run.expect(r.returncode == 0 and last == "preflight_passed",
                   f"agentcapsule-api -preflight: {last or 'no result'} (exit {r.returncode}); see logs/api-preflight.log")
        run.expect(("ok", "authority") in [(s, c) for s, c, _ in results], "the API's preflight has no passing authority check")
        run.checked("agentcapsule-api -preflight: " + ", ".join(f"{c} {s}" for s, c, _ in results) + "; preflight_passed")
        # Production refuses an API without the authority service, or pinned
        # to another installation's authorities, before it opens the database.
        other = ["-authority-socket", sockets / "api.sock", "-restore-authority-id", "restoreauth_" + "0" * 32, "-key-authority-id", key_id]
        for label, args, code in (("api-without-authority", api_base, "authority_required_in_production"),
                                  ("api-other-authority", [*api_base, *other], "authority_identity_mismatch")):
            r = run.run(label, [opt / "agentcapsule-api", *args], admin_env, check=False, timeout=60)
            run.expect(r.returncode == 1 and r.stderr.strip() == code, f"{label}: exit {r.returncode}, not 1 with {code}; see logs/{label}.log")
        run.checked("without the authority flags: authority_required_in_production; with another restore authority: "
                    "authority_identity_mismatch")
        run.start("api", [opt / "agentcapsule-api", *api_args], admin_env)

        def ready():
            r = subprocess.run(["curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}", *curl_tls, url + "/v1/health/ready"],
                               capture_output=True, text=True, timeout=10)
            return r.stdout.strip() == "200"
        run.wait("api", ready, 60, "the API did not become ready over HTTPS")
        run.checked("the API answers /v1/health/ready over HTTPS, its certificate checked against the run's CA for " + API_NAME)
        status, readiness = curl("api-ready", "GET", "/v1/health/ready")
        run.expect(status == 200 and isinstance(readiness, dict) and readiness.get("authority") == "standalone",
                   f"the API's readiness gave {status} {readiness}, not the authority service standalone")
        run.checked('its readiness reports the authority service: {"status": "ready", "authority": "standalone"}')
        r = run.run("api-plain-http", ["curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}", f"http://127.0.0.1:{api_port}/v1/health/ready"],
                    base_env, check=False)
        run.expect(r.stdout.strip() == "400", f"a plain HTTP request got {r.stdout.strip()}, not 400")
        run.checked("a plain HTTP request gets 400")
        run.run("platform-header", ["sh", "-c", "umask 077\nprintf 'Authorization: Bearer %s\\n' \"$(cat platform.token)\" > platform.header"],
                base_env, cwd=etc)
        run.expect((etc / "platform.header").stat().st_mode & 0o777 == 0o600, "platform.header is not mode 0600")
        run.checked("platform.header written with umask 077 (mode 0600)")
        run.done()

        # ---- 7. The organization and its first owner (bootstrap.md, 4).
        run.step("organization", "docs/bootstrap.md#4-create-the-organization-and-its-first-owner",
                 "POST /v1/organizations with the platform token; replayed; a second one of the same name refused")
        body = json.dumps({"name": "Acme", "initial_owner": {"issuer": ISSUER, "subject": "alice", "display_name": "Alice"}},
                          separators=(",", ":"))
        header = "@" + str(etc / "platform.header")
        status, org = curl("organization", "POST", "/v1/organizations", [header, "Idempotency-Key: create-acme"], body)
        run.expect(status == 201 and isinstance(org, dict), f"POST /v1/organizations gave {status}, not 201")
        tenant = org.get("id", "")
        run.expect(tenant.startswith("org_") and str(org.get("owner_principal_id", "")).startswith("prn_"),
                   "the answer has no org_ id or prn_ owner_principal_id")
        run.checked(f"201 with id {tenant[:8]}… and owner_principal_id")
        status, again = curl("organization", "POST", "/v1/organizations", [header, "Idempotency-Key: create-acme"], body)
        run.expect(status == 201 and again == org, f"the replay gave {status} and another answer")
        run.checked("the same Idempotency-Key returns the same answer")
        # Its receipt is encrypted with the authority service's key of the
        # day, which the service holds with tomorrow's (ADR 006 wave 6).
        r = run.run("organization", [a.pg_bin / "psql", "-X", "-v", "ON_ERROR_STOP=1", "-h", pg_socket, "-U", "postgres", "-d", "agentcapsule",
                                     "-tAc", "SELECT coalesce(key_day::text,'none') FROM http_receipts WHERE key='create-acme'"], pg_env)
        days = {time.strftime("%Y-%m-%d", time.gmtime(time.time() + d * 86400)) for d in (-1, 0, 1)}
        run.expect(r.stdout.strip() in days, f"the receipt names the key day {r.stdout.strip()!r}, not today's")
        r = run.run("authority-metrics", ["curl", "-sS", f"http://127.0.0.1:{authority_metrics}/metrics"], base_env)
        for line in ('agentcapsule_authority_receipt_key_ready{day="today"} 1', 'agentcapsule_authority_receipt_key_ready{day="tomorrow"} 1',
                     "agentcapsule_authority_receipt_keys_overdue 0"):
            run.expect(line in r.stdout, f"the service's metrics lack {line}")
        run.checked("the receipt names the day of its key (key_day); the service holds today's and tomorrow's receipt keys")
        status, refused = curl("organization", "POST", "/v1/organizations", [header, "Idempotency-Key: create-acme-2"],
                               body.replace('"Acme"', '"ACME"'))
        code = refused.get("code") if isinstance(refused, dict) else None
        run.expect(status == 409 and code == "organization_name_taken", f"a second Acme gave {status} {code}, not 409 organization_name_taken")
        run.checked("another organization of the same name, in another case: 409 organization_name_taken")
        run.done()

        # ---- 8. The organization's identity trust (bootstrap.md, 5).
        run.step("trust", "docs/bootstrap.md#5-register-the-organizations-identity-trust",
                 "the identity provider's Ed25519 key, the trust file, configure-delegation -action install; replayed")
        ossl("genpkey", "-algorithm", "ed25519", "-out", client / "idp.key")
        run.secret("".join((client / "idp.key").read_text().splitlines()[1:-1]))
        der = subprocess.run(["openssl", "pkey", "-in", str(client / "idp.key"), "-pubout", "-outform", "DER"],
                             capture_output=True, check=True).stdout
        public = base64.b64encode(der[-32:]).decode()
        trust = {"version": 1, "trusts": [{"tenant_id": tenant, "issuer": ISSUER, "audience": AUDIENCE,
                                            "allowed_scopes": ["org:read", "member:read", "member:manage", "audit:read"],
                                            "max_ttl_seconds": 300, "keys": [{"kid": KEY_ID, "public_key": public}]}]}
        trust_file = etc / "acme-trust.json"
        trust_file.write_text(json.dumps(trust, indent=2) + "\n")
        trust_file.chmod(0o644)
        install = ["configure-delegation", "-action", "install", "-operation-id", "acme-trust-1", "-tenant-id", tenant,
                   "-issuer", ISSUER, "-audience", AUDIENCE, "-trust-file", trust_file]
        r = admin("trust", *install)
        state = json.loads(r.stdout)
        run.expect(state.get("generation") == 1 and state.get("replayed") is False and "minimum_iat" in state,
                   f"the trust's state has no generation 1 and minimum_iat: {sorted(state)}")
        minimum_iat = datetime.fromisoformat(state["minimum_iat"]).timestamp()
        run.checked("generation 1 and minimum_iat")
        r = admin("trust", *install)
        run.expect(json.loads(r.stdout).get("replayed") is True, "the same -operation-id did not answer replayed: true")
        run.checked('the same -operation-id answers "replayed": true')
        run.done()

        # ---- 9. The first owner signs in and names an administrator (bootstrap.md, 6).
        run.step("owner", "docs/bootstrap.md#6-the-first-owner-signs-in-and-names-administrators",
                 "GET /v1/organizations/current as the owner; POST /v1/members; user IDs written by the caller refused")
        while time.time() < minimum_iat:
            time.sleep(0.1)
        status, current = as_owner("owner", "GET", "/v1/organizations/current")
        run.expect(status == 200 and isinstance(current, dict) and current.get("role") == "org_owner"
                   and current.get("organization", {}).get("id") == tenant,
                   f"GET /v1/organizations/current gave {status}, not the organization with role org_owner")
        run.checked("GET /v1/organizations/current: 200, this organization, role org_owner")
        bob = json.dumps({"issuer": ISSUER, "subject": "bob", "display_name": "Bob", "role": "org_admin"}, separators=(",", ":"))
        status, member = as_owner("make-bob-admin", "POST", "/v1/members", bob)
        run.expect(status == 201, f"POST /v1/members gave {status}, not 201")
        status, _ = as_owner("make-bob-admin-again", "POST", "/v1/members", bob)
        run.expect(status == 409, f"registering Bob twice gave {status}, not 409")
        run.checked("POST /v1/members: 201 for Bob as org_admin; 409 for Bob again")
        other = client / "other.key"
        ossl("genpkey", "-algorithm", "ed25519", "-out", other)
        run.secret("".join(other.read_text().splitlines()[1:-1]))
        unsigned = b64url(b'{"alg":"none","typ":"JWT"}') + "." + idp_token(client / "idp.key").split(".")[1] + "."
        refusals = {
            "a bare name as a bearer token": ["Authorization: Bearer alice"],
            "a header X-User-ID without a token": ["X-User-ID: alice"],
            "an unsigned token": [f"Authorization: Bearer {run.secret(unsigned)}"],
            "a token signed by another key": [f"Authorization: Bearer {idp_token(other)}"],
            "a token for a subject that is not a member": [f"Authorization: Bearer {idp_token(client / 'idp.key', {'sub': 'mallory'})}"],
        }
        for what, headers in refusals.items():
            status, _ = curl("refusals", "GET", "/v1/organizations/current", headers, shown_headers=[what])
            run.expect(status == 401, f"{what}: {status}, not 401")
        run.checked("401 for " + "; ".join(refusals))
        run.done()

        # ---- 10. The audit (bootstrap.md, What is audited).
        run.step("audit", "docs/bootstrap.md#what-is-audited",
                 "agentcapsule-admin list-audit and the organization's GET /v1/audit hold the steps, no secret")
        r = admin("list-audit", "list-audit")
        entries = [json.loads(line) for line in r.stdout.splitlines() if line.strip()]
        run.expect(len(entries) >= 3, f"list-audit printed {len(entries)} entries")
        text = r.stdout
        run.expect(all(s not in text for s in run.secrets), "list-audit printed a secret")
        report["audit_actions"] = sorted({str(e.get("action")) for e in entries})
        for action in ("platform_credential.created", "organization.created", "delegation.install"):
            run.expect(action in report["audit_actions"], f"list-audit has no {action}")
        run.checked(f"{len(entries)} entries, actions {', '.join(report['audit_actions'])}; no token or key")
        status, audit = as_owner("audit", "GET", "/v1/audit")
        actions = json.dumps(audit)
        run.expect(status == 200 and "organization.created" in actions and "delegation.install" in actions,
                   f"GET /v1/audit as the owner gave {status} without the organization's creation and its trust")
        run.expect(all(s not in actions for s in run.secrets), "GET /v1/audit returned a secret")
        run.checked("GET /v1/audit as the owner: the organization's creation and its trust, no secret")
        run.done()

        # ---- 11. The worker's preflight (install.md, Preflight).
        run.step("worker-preflight", "docs/install.md#preflight",
                 "agentcapsule-worker -preflight with its configuration, the authority service and PostgreSQL")
        example = json.loads((ROOT / "runtime/worker/config.example.json").read_text())
        worker = dict(example)
        worker.pop("directory")  # the private Directory needs Docker: not part of this install
        worker["host_id"] = "local"
        worker["root"] = str(host_root)
        for name in ARTIFACTS:
            path = given.get(name)
            worker[name] = {"path": str(path.resolve()), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()} if path else \
                {"path": str(opt / ("vmlinux" if name == "kernel" else name)), "sha256": "0" * 64}
        worker["authority"] = {"socket": str(sockets / "worker.sock"), "restore_authority_id": restore_id, "key_authority_id": key_id}
        worker["metrics_listen"] = f"127.0.0.1:{worker_metrics}"
        (etc / "worker.json").write_text(json.dumps(worker, indent=2) + "\n")
        (etc / "worker.json").chmod(0o644)
        may_fail = {f"artifact_{n}": "it was not given to this run" for n in ARTIFACTS if n not in given}
        kvm = kvm_usable()
        if not kvm:
            may_fail["kvm"] = "this account cannot open /dev/kvm read-write"
        r = run.run("worker-preflight", ["unshare", "-r", opt / "agentcapsule-worker", "-config", etc / "worker.json", "-preflight"],
                    admin_env, check=False, timeout=180)
        results, last = parse_preflight(r.stdout)
        report["worker_preflight"] = {"kvm_usable_by_this_account": kvm, "artifacts_given": sorted(given), "last_line": last,
                                      "exit_code": r.returncode, "may_fail_here": may_fail,
                                      "results": [{"status": s, "check": c, "detail": d} for s, c, d in results]}
        problems = assess_preflight(results, last, r.returncode, may_fail)
        run.expect(not problems, "the worker's preflight: " + "; ".join(problems) + "; see logs/worker-preflight.log")
        run.expect(not host_root.exists(), "the preflight created the runtime root")
        run.checked("; ".join(f"{c} {s}" for s, c, _ in results) + f"; {last}; the runtime root not created")
        if any(s == "fail" and c in MANDATORY for s, c, _ in results):
            r = run.run("worker-start", ["unshare", "-r", opt / "agentcapsule-worker", "-config", etc / "worker.json"], admin_env,
                        check=False, timeout=120)
            run.expect(r.returncode == 1 and "preflight_failed" in r.stderr, "the worker started although a mandatory check fails")
            run.expect(not host_root.exists(), "the refused worker created the runtime root")
            run.checked("the worker refuses to start: it prints the failed mandatory checks and preflight_failed (RUN-012)")
        else:
            run.checked("every mandatory check passes here: the worker was not started")
        # The garbage collection on demand (docs/worker.md, OPR-5): the guards
        # of ADR 014, and nothing created. This host has nothing to collect.
        collect = ["unshare", "-r", opt / "agentcapsule-worker", "-config", etc / "worker.json", "-collect-garbage"]
        r = run.run("worker-collect-garbage", collect, admin_env, check=False, timeout=120)
        run.expect(r.returncode == 1 and r.stderr.strip() == "confirmation_required", "the collection ran without -confirm")
        for extra, dry in ((["-dry-run"], True), (["-confirm", "local"], False)):
            r = run.run("worker-collect-garbage", [*collect, *extra], admin_env, check=False, timeout=120)
            outcome = json.loads(r.stdout) if r.returncode == 0 and r.stdout.strip() else {}
            run.expect(outcome.get("outcome") == "unchanged" and outcome.get("dry_run") is dry and outcome.get("target") == "local",
                       f"-collect-garbage {' '.join(extra)}: exit {r.returncode}; see logs/worker-collect-garbage.log")
        run.expect(not host_root.exists(), "the garbage collection created the runtime root")
        r = admin("list-audit", "list-audit")
        collected = [json.loads(line) for line in r.stdout.splitlines() if '"garbage.collected"' in line]
        run.expect(len(collected) == 1 and collected[0].get("outcome") == "unchanged",
                   f"list-audit holds {len(collected)} garbage collections, not the one that ran")
        run.checked("-collect-garbage: refused without -confirm, a dry run and a run print their outcome, the run alone is "
                    "audited (garbage.collected, unchanged); the runtime root not created")
        run.done()

        # ---- 12. The end: an authenticated call as the organization's owner.
        run.step("owner-call", "docs/bootstrap.md#6-the-first-owner-signs-in-and-names-administrators",
                 "an authenticated call to the API as the organization's owner")
        status, current = as_owner("owner-call", "GET", "/v1/organizations/current")
        run.expect(status == 200 and current.get("role") == "org_owner", f"the owner's call gave {status}")
        status, members = as_owner("owner-call", "GET", "/v1/members")
        run.expect(status == 200, f"GET /v1/members as the owner gave {status}")
        run.checked("GET /v1/organizations/current (org_owner) and GET /v1/members: 200")
        run.done()
        report["status"] = "passed"
    except (Failure, subprocess.SubprocessError, OSError, KeyError, ValueError) as e:
        if run.current is not None and run.current["status"] == "running":
            run.current["status"] = "failed"
            run.current.pop("_start", None)
        report["error"] = run.redact(str(e))
        print("FAIL", report["error"], file=sys.stderr)
    finally:
        for label in reversed(list(run.processes)):  # the API before the authority service
            code = run.stop(label)
            report.setdefault("stopped", {})[label] = code
        if report.get("stopped", {}).get("api") not in (None, 0) or report.get("stopped", {}).get("authority-service") not in (None, 0):
            report["status"] = "failed"
            report.setdefault("error", f"a service did not stop cleanly: {report['stopped']}")
        if pg_started:
            run.run("postgresql", [a.pg_bin / "pg_ctl", "-D", pg_data, "-m", "fast", "-w", "stop"], pg_env, check=False)
        # Keep the public configuration; drop the database, the binaries, the sources and every secret.
        kept = out / "configuration"
        kept.mkdir()
        for name in ("authority.json", "worker.json", "acme-trust.json", "api.crt"):
            if (etc / name).exists():
                shutil.copy2(etc / name, kept / name)
        if (client / "ca.pem").exists():
            shutil.copy2(client / "ca.pem", kept / "ca.pem")
        shutil.rmtree(prefix, ignore_errors=True)
        shutil.rmtree(work, ignore_errors=True)
        shutil.rmtree(short, ignore_errors=True)
        found = []
        for path in out.rglob("*"):
            if path.is_file():
                data = path.read_text(errors="replace")
                if any(s in data for s in run.secrets):
                    found.append(str(path.relative_to(out)))
        report["secrets_in_evidence"] = found
        if found:
            report["status"] = "failed"
        report["seconds"] = round(time.monotonic() - started, 1)
        (out / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
    print(f"install from scratch: {report['status']} in {report['seconds']} s; evidence in {out}")
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())
