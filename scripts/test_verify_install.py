#!/usr/bin/env python3
"""Unit tests of scripts/verify-install.py's reading of the worker's preflight (VAL-02).

The install run must fail when a check this host should pass fails, when
/dev/kvm or a missing artifact is reported as fine, when a check is missing,
and when the last line or the exit code does not match the failures.
"""

import importlib.util
from pathlib import Path
import sys
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


if __name__ == "__main__":
    unittest.main()
