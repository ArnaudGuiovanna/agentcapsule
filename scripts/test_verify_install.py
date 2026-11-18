#!/usr/bin/env python3
"""Unit tests of scripts/verify-install.py's reading of the worker's preflight (VAL-02)
and of its network namespace's counters (DEP-1).

The install run must fail when a check this host should pass fails, when
/dev/kvm or a missing artifact is reported as fine, when a check is missing,
and when the last line or the exit code does not match the failures. It must
fail too when a packet left its network namespace, when a UDP datagram was
sent, when a connection went to a port nothing of the install listens on, and
when the counters saw nothing of the run.
"""

import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().with_name("verify-install.py")
SPEC = importlib.util.spec_from_file_location("verify_install", SCRIPT)
INSTALL = importlib.util.module_from_spec(SPEC)
sys.dont_write_bytecode = True
SPEC.loader.exec_module(INSTALL)

ARTIFACTS_MISSING = {f"artifact_{n}": "not given" for n in INSTALL.ARTIFACTS}


def output(failing=(), skip=(), last=None):
    """A worker preflight's output: every check ok except those failing."""
    lines = []
    for check in INSTALL.PREFLIGHT_CHECKS:
        if check in skip:
            continue
        if check in failing:
            lines += [f"fail {check}: something is wrong", "     fix: do something"]
        else:
            lines.append(f"ok   {check}: fine")
    lines.append(last or ("preflight_failed" if failing else "preflight_passed"))
    return "\n".join(lines) + "\n"


class Preflight(unittest.TestCase):
    def problems(self, text, returncode, may_fail):
        results, last = INSTALL.parse_preflight(text)
        return INSTALL.assess_preflight(results, last, returncode, may_fail)

    def test_parses_results_and_the_last_line(self):
        results, last = INSTALL.parse_preflight(output(failing=("kvm",)))
        self.assertEqual(len(results), len(INSTALL.PREFLIGHT_CHECKS))
        self.assertIn(("fail", "kvm", "something is wrong"), results)
        self.assertEqual(last, "preflight_failed")

    def test_missing_artifacts_reported_as_failures_pass(self):
        self.assertEqual(self.problems(output(failing=tuple(ARTIFACTS_MISSING)), 1, ARTIFACTS_MISSING), [])

    def test_a_host_that_passes_everything_passes(self):
        self.assertEqual(self.problems(output(), 0, {}), [])

    def test_an_unexpected_failure_fails(self):
        problems = self.problems(output(failing=("cgroups", *ARTIFACTS_MISSING)), 1, ARTIFACTS_MISSING)
        self.assertEqual(problems, ["cgroups fails on this host"])

    def test_kvm_reported_fine_when_the_account_cannot_open_it_fails(self):
        problems = self.problems(output(), 0, {"kvm": "this account cannot open /dev/kvm read-write"})
        self.assertEqual(problems, ["kvm is ok although this account cannot open /dev/kvm read-write"])

    def test_an_inspection_accepted_as_root_of_a_user_namespace_fails(self):
        reason = "the worker runs as root of a user namespace"
        self.assertEqual(self.problems(output(failing=("registry_inspection",)), 1, {"registry_inspection": reason}), [])
        problems = self.problems(output(), 0, {"registry_inspection": reason})
        self.assertEqual(problems, [f"registry_inspection is ok although {reason}"])

    def test_a_missing_artifact_reported_fine_fails(self):
        problems = self.problems(output(), 0, {"artifact_kernel": "not given"})
        self.assertEqual(problems, ["artifact_kernel is ok although not given"])

    def test_a_missing_check_fails(self):
        self.assertEqual(self.problems(output(skip=("authority",)), 0, {}), ["authority is not printed"])

    def test_a_check_printed_twice_fails(self):
        text = output().replace("ok   clock: fine\n", "ok   clock: fine\nok   clock: fine\n")
        self.assertEqual(self.problems(text, 0, {}), ["clock is printed twice"])

    def test_a_final_line_or_exit_code_that_hides_a_failure_fails(self):
        text = output(failing=tuple(ARTIFACTS_MISSING), last="preflight_passed")
        self.assertEqual(self.problems(text, 0, ARTIFACTS_MISSING),
                         ["the last line is 'preflight_passed', not preflight_failed", "exit code 0 with a failure"])


class Egress(unittest.TestCase):
    """DEP-1: the run fails on anything that tried to leave its network namespace."""

    LISTENERS = {"api": 8443, "api_metrics": 9464, "authority_metrics": 9466, "worker_metrics": 9465}

    def assess(self, tx=0, outside=0, udp=0, ports=None, files=True):
        ports = {8443: 12, 9466: 2} if ports is None else ports
        ruleset = {"nftables": [
            {"metainfo": {"version": "1.0.9"}},
            {"set": {"family": "inet", "name": "loopback_tcp", "table": "egress",
                     "elem": [{"elem": {"val": port, "counter": {"packets": n, "bytes": 60 * n}}} for port, n in ports.items()]}},
            {"counter": {"family": "inet", "name": "outside", "table": "egress", "packets": outside, "bytes": 0}},
            {"counter": {"family": "inet", "name": "datagrams", "table": "egress", "packets": udp, "bytes": 0}},
        ]}
        with tempfile.TemporaryDirectory() as d:
            if files:
                (Path(d) / "nft.json").write_text(json.dumps(ruleset))
                (Path(d) / "dummy0.json").write_text(json.dumps([{"ifname": "dummy0", "stats64": {"tx": {"packets": tx}}}]))
            return INSTALL.assess_egress(Path(d), self.LISTENERS)

    def test_a_run_that_stays_on_loopback_passes(self):
        egress, problems = self.assess()
        self.assertEqual(problems, [])
        self.assertEqual(egress["loopback_tcp_connections"], {"8443 (api)": 12, "9466 (authority_metrics)": 2})

    def test_a_packet_out_fails(self):
        self.assertEqual(len(self.assess(tx=3)[1]), 1)
        self.assertEqual(len(self.assess(outside=1)[1]), 1)

    def test_a_datagram_fails(self):
        self.assertEqual(self.assess(udp=1)[1], ["1 UDP datagrams were sent (a DNS query, telemetry?)"])

    def test_a_connection_to_a_port_nothing_listens_on_fails(self):
        self.assertEqual(self.assess(ports={8443: 3, 4317: 1})[1],
                         ["TCP connections to loopback ports nothing of the install listens on: [4317]"])

    def test_counters_that_saw_nothing_fail(self):
        self.assertEqual(self.assess(ports={})[1], ["the counters saw no connection to the API: they do not see the run"])
        self.assertEqual(len(self.assess(files=False)[1]), 1)


if __name__ == "__main__":
    unittest.main()
