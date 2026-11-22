"""The confinement of every shipped systemd unit (S-05, S-06).

Each unit must keep the directives its confinement relies on, and the worker,
which must stay root for the jailer, must not gain one that breaks it. A
directive that is left out stays explained in the unit. See
docs/worker.md#confinement and docs/install.md#service-confinement.
"""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]

# The authority service's profile, which the API and the SLIM bridge reuse.
UNPRIVILEGED = {
    "NoNewPrivileges": "yes", "CapabilityBoundingSet": "", "AmbientCapabilities": "",
    "ProtectSystem": "strict", "ProtectHome": "yes", "PrivateTmp": "yes", "PrivateDevices": "yes",
    "ProtectKernelTunables": "yes", "ProtectKernelModules": "yes", "ProtectKernelLogs": "yes",
    "ProtectControlGroups": "yes", "ProtectClock": "yes", "ProtectHostname": "yes",
    "ProtectProc": "invisible", "ProcSubset": "pid", "RestrictNamespaces": "yes",
    "RestrictRealtime": "yes", "RestrictSUIDSGID": "yes", "LockPersonality": "yes",
    "MemoryDenyWriteExecute": "yes", "RemoveIPC": "yes", "SystemCallArchitectures": "native",
    "SystemCallFilter": ["@system-service", "~@privileged @resources"], "SystemCallErrorNumber": "EPERM",
    "RestrictAddressFamilies": "AF_UNIX AF_INET AF_INET6",
}
# Every capability the worker and its children use (deploy/systemd/agentcapsule-worker.service).
WORKER_CAPABILITIES = {"CAP_SYS_ADMIN", "CAP_MKNOD", "CAP_CHOWN", "CAP_FOWNER", "CAP_DAC_OVERRIDE",
                       "CAP_SETUID", "CAP_SETGID", "CAP_SETPCAP", "CAP_KILL", "CAP_SYS_PTRACE"}
# Root services that switch to another account: setuid is in @privileged.
SWITCHING = {
    "NoNewPrivileges": "yes", "ProtectSystem": "strict", "ProtectHome": "yes", "PrivateTmp": "yes",
    "PrivateDevices": "yes", "ProtectKernelTunables": "yes", "ProtectKernelModules": "yes",
    "ProtectKernelLogs": "yes", "ProtectControlGroups": "yes", "ProtectClock": "yes", "ProtectHostname": "yes",
    "RestrictNamespaces": "yes", "RestrictRealtime": "yes", "RestrictSUIDSGID": "yes", "LockPersonality": "yes",
    "MemoryDenyWriteExecute": "yes", "SystemCallArchitectures": "native", "SystemCallFilter": "@system-service",
    "SystemCallErrorNumber": "EPERM",
}

REQUIRED = {
    "deploy/systemd/agentcapsule-authority.service": UNPRIVILEGED,
    "deploy/systemd/agentcapsule-slim-bridge.service": UNPRIVILEGED,
    "deploy/systemd/agentcapsule-api.service": dict(UNPRIVILEGED, LimitNOFILE="65536", MemoryMax="2G"),
    "deploy/systemd/agentcapsule-worker.service": {
        "Delegate": "yes", "KillMode": "process", "NoNewPrivileges": "yes",
        "CapabilityBoundingSet": " ".join(sorted(WORKER_CAPABILITIES)), "AmbientCapabilities": "",
        "ProtectSystem": "strict", "StateDirectory": "agentcapsule/host agentcapsule-archives",
        "StateDirectoryMode": "0700", "ReadWritePaths": "-/run/agentcapsule-worker",
        "InaccessiblePaths": "-/var/lib/agentcapsule-key-authority -/var/lib/agentcapsule-restore-authority "
                             "-/var/lib/agentcapsule-authority-replica",
        "ProtectHome": "yes", "PrivateTmp": "yes", "ProtectKernelTunables": "yes", "ProtectKernelModules": "yes",
        "ProtectKernelLogs": "yes", "ProtectClock": "yes", "ProtectHostname": "yes", "RestrictRealtime": "yes",
        "RestrictSUIDSGID": "yes", "LockPersonality": "yes", "MemoryDenyWriteExecute": "yes",
        "SystemCallArchitectures": "native",
        "SystemCallFilter": ["~@clock @cpu-emulation @debug @module @obsolete @raw-io @reboot @swap",
                             "~bpf open_by_handle_at"],
        "SystemCallErrorNumber": "EPERM", "RestrictAddressFamilies": "AF_UNIX AF_INET AF_INET6 AF_NETLINK AF_ALG",
    },
    "deploy/systemd/agentcapsule-interop.service": dict(
        SWITCHING, CapabilityBoundingSet="", AmbientCapabilities="", RuntimeDirectory="agentcapsule-interop",
        SystemCallFilter=["@system-service", "~@privileged @resources"], RestrictAddressFamilies="AF_UNIX",
        IPAddressDeny="any"),
    "deploy/backup/agentcapsule-pg-backup@.service": dict(
        SWITCHING, User="postgres", CapabilityBoundingSet="", AmbientCapabilities="", PrivateTmp=None,
        ReadWritePaths="/tmp -/var/log/pgbackrest -/var/spool/pgbackrest", ProtectProc="invisible",
        SystemCallFilter=["@system-service", "~@privileged"],
        RestrictAddressFamilies="AF_UNIX AF_INET AF_INET6 AF_NETLINK"),
    "deploy/backup/agentcapsule-backup-metrics.service": dict(
        SWITCHING, CapabilityBoundingSet="CAP_SETUID CAP_SETGID CAP_DAC_OVERRIDE",
        ReadWritePaths="/var/lib/prometheus/node-exporter -/var/log/pgbackrest",
        RestrictAddressFamilies="AF_UNIX AF_INET AF_INET6 AF_NETLINK"),
    "deploy/backup/agentcapsule-archive-ship.service": dict(
        SWITCHING, CapabilityBoundingSet="CAP_SETUID CAP_SETGID CAP_DAC_OVERRIDE",
        ReadWritePaths="/var/lib/prometheus/node-exporter", RestrictAddressFamilies="AF_UNIX AF_INET AF_INET6"),
    "deploy/standby/agentcapsule-standby-metrics.service": dict(
        SWITCHING, CapabilityBoundingSet="CAP_SETUID CAP_SETGID CAP_DAC_OVERRIDE", PrivateNetwork="yes",
        ReadWritePaths="/var/lib/prometheus/node-exporter", RestrictAddressFamilies="AF_UNIX"),
    "deploy/oidc/agentcapsule-oidc-edge.service": dict(
        UNPRIVILEGED, DynamicUser="yes", LimitNOFILE="16384", MemoryMax="256M",
        LoadCredential=["tls.crt:/etc/agentcapsule/oidc-tls/tls.crt", "tls.key:/etc/agentcapsule/oidc-tls/tls.key"]),
    # Podman runs Keycloak as root; its exposure is checked by test_oidc_edge.py.
    "deploy/oidc/agentcapsule-oidc.service": {"StateDirectoryMode": "0700", "Restart": "on-failure"},
    "deploy/backup/agentcapsule-pg-heartbeat.service": dict(
        SWITCHING, CapabilityBoundingSet="", PrivateNetwork="yes", SystemCallFilter=None,
        SystemCallErrorNumber=None, RestrictAddressFamilies="AF_UNIX"),
}
# What would break the worker (see its unit): each stays out, and explained.
WORKER_FORBIDDEN = ("PrivateDevices", "DevicePolicy", "ProtectControlGroups", "RestrictNamespaces", "ProtectProc",
                    "ProcSubset", "PrivateNetwork", "IPAddressDeny", "PrivateUsers", "User", "PrivateIPC", "MemoryMax")
# The host operation: what it keeps and what it must not get.
HOST_OPERATION = {"NoNewPrivileges": "yes", "ProtectKernelLogs": "yes", "ProtectClock": "yes", "ProtectHostname": "yes",
                  "LockPersonality": "yes", "RestrictRealtime": "yes", "SystemCallArchitectures": "native",
                  "RestrictAddressFamilies": "AF_UNIX AF_INET AF_INET6 AF_NETLINK AF_ALG"}
HOST_FORBIDDEN = ("RestrictNamespaces", "RestrictSUIDSGID", "ProtectKernelTunables", "ProtectKernelModules",
                  "MemoryDenyWriteExecute", "ProtectHome", "PrivateTmp", "ProtectSystem", "PrivateDevices",
                  "ProtectControlGroups", "CapabilityBoundingSet")


def service(text):
    """The [Service] section: directive -> list of values, in order."""
    out, section = {}, None
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("["):
            section = line
            continue
        if section == "[Service]":
            key, sep, value = line.partition("=")
            if not sep:
                raise ValueError("not a directive: " + line)
            out.setdefault(key.strip(), []).append(value.strip())
    return out


def comments(text):
    return "\n".join(line for line in text.splitlines() if line.lstrip().startswith("#"))


def host_operation_unit():
    """The agentcapsule-host@.service template that internal/hostops/host.py writes."""
    namespace = {"__name__": "unit_test"}
    for name in ("setup.py", "diagnose.py", "host.py"):
        exec(compile((ROOT / "internal/hostops" / name).read_bytes(), name, "exec"), namespace)
    written = {}
    namespace["write_file"] = lambda path, data, mode=0o600: written.update({Path(path).name: data.decode()})
    namespace["run"] = lambda *args, **kwargs: None
    namespace["launch"](Path("/var/lib/agentcapsule-install/operations/host_" + "0" * 32))
    return written["agentcapsule-host@.service"]


class UnitConfinementTests(unittest.TestCase):
    def check(self, name, text, required):
        directives = service(text)
        for key, want in required.items():
            got = directives.get(key)
            if want is None:
                self.assertIsNone(got, f"{name}: {key} must stay out")
                continue
            want = want if isinstance(want, list) else [want]
            if key == "CapabilityBoundingSet" and got:
                got = [" ".join(sorted(got[0].split()))]
                want = [" ".join(sorted(want[0].split()))]
            self.assertEqual(got, want, f"{name}: {key}")

    def test_units_keep_their_confinement(self):
        for name, required in REQUIRED.items():
            with self.subTest(unit=name):
                self.check(name, (ROOT / name).read_text(), required)

    def test_worker_capabilities_are_the_documented_ones(self):
        text = (ROOT / "deploy/systemd/agentcapsule-worker.service").read_text()
        granted = set(service(text)["CapabilityBoundingSet"][0].split())
        self.assertEqual(granted, WORKER_CAPABILITIES)
        notes = comments(text)
        for capability in granted:
            self.assertIn(capability, notes, "each capability says why the worker needs it")

    def test_worker_leaves_out_what_breaks_it_and_says_why(self):
        text = (ROOT / "deploy/systemd/agentcapsule-worker.service").read_text()
        directives = service(text)
        notes = comments(text)
        guide = (ROOT / "docs/worker.md").read_text()
        for key in WORKER_FORBIDDEN:
            with self.subTest(directive=key):
                self.assertNotIn(key, directives)
                self.assertTrue(re.search(r"\b" + re.escape(key) + r"\b", notes), "the unit explains why it is left out")
                self.assertTrue("`" + key + "`" in guide, "docs/worker.md explains why " + key + " is left out")

    def test_every_shipped_service_unit_is_checked(self):
        shipped = {p.relative_to(ROOT).as_posix() for d in ("deploy/systemd", "deploy/backup", "deploy/standby", "deploy/oidc")
                   for p in (ROOT / d).glob("*.service")}
        self.assertEqual(shipped, set(REQUIRED), "a new unit needs its confinement checked here")

    def test_host_operation_unit(self):
        text = host_operation_unit()
        self.check("agentcapsule-host@.service", text, HOST_OPERATION)
        directives = service(text)
        notes = comments(text)
        for key in HOST_FORBIDDEN:
            with self.subTest(directive=key):
                self.assertNotIn(key, directives)
        for key in ("RestrictNamespaces", "RestrictSUIDSGID", "ProtectKernelTunables", "ProtectKernelModules",
                    "MemoryDenyWriteExecute", "ProtectHome", "PrivateTmp"):
            self.assertIn(key, notes, "the template explains why it is left out")

    def test_parser_reads_repeated_and_empty_directives(self):
        parsed = service("[Unit]\nA=1\n[Service]\n# c\nX=\nY=a\nY=~b c\n[Install]\nZ=1\n")
        self.assertEqual(parsed, {"X": [""], "Y": ["a", "~b c"]})
        with self.assertRaises(ValueError):
            service("[Service]\nnot a directive\n")


if __name__ == "__main__":
    unittest.main()
