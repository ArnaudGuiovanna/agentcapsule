#!/usr/bin/env python3
"""Exercise the local check runner, including failure/skip accounting.

The executable fixtures below simulate the Go JSON protocol; they do not claim
to test product behavior or run PostgreSQL/KVM.
"""

import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location("check_go", Path(__file__).with_name("check-go.py"))
CHECK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK)
MODULE = "example.invalid/capsule"
PACKAGE = MODULE + "/internal/controlplane"


def successful_events(with_pg_skip=False):
    events = [{"Action": "start", "Package": PACKAGE},
              {"Action": "pass", "Package": PACKAGE, "Test": "TestLocal"}]
    if with_pg_skip:
        events.extend([
            {"Action": "output", "Package": PACKAGE, "Test": "TestDatabase",
             "Output": "    store_test.go:28: run scripts/verify-postgres.py for real PostgreSQL integration checks\n"},
            {"Action": "skip", "Package": PACKAGE, "Test": "TestDatabase"},
        ])
    events.append({"Action": "pass", "Package": PACKAGE})
    return events


class LocalCheckTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.root = self.directory / "repo"
        self.root.mkdir()
        for relative, content in {
            "go.mod": "module " + MODULE + "\n\ngo 1.25.0\n",
            "go.sum": "",
            "cmd/example/main.go": "package main\nfunc main() {}\n",
            "internal/example/example.go": "package example\n",
            "internal/example/testdata/input.json": "{}\n",
            "evidence/old/main.go": "BROKEN ARCHIVED SOURCE\n",
        }.items():
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)

    def executable(self, events, *, mutate=False, exitcode=0, version=None):
        path = self.directory / "go"
        path.write_text("#!/usr/bin/env python3\n" +
                        "import json, os, pathlib, sys\n" +
                        "if sys.argv[1:] == ['version']:\n" +
                        "    print(" + repr(version or f"go version {CHECK.GO_VERSION} linux/amd64") + ")\n" +
                        "    raise SystemExit(0)\n" +
                        "assert sys.argv[1:] == ['test', '-race', '-json', '-count=1', '-timeout=180s', './cmd/...', './internal/...']\n" +
                        "assert not pathlib.Path('evidence').exists()\n" +
                        "assert os.environ.get('GOTOOLCHAIN') == 'local'\n" +
                        "assert os.environ.get('CGO_ENABLED') == '1'\n" +
                        "assert not any(k.startswith(('PG', 'AGENTCAPSULE_', 'AC_', 'CAPSULE_CRASH_')) for k in os.environ)\n" +
                        ("pathlib.Path('internal/example/example.go').write_text('changed')\n" if mutate else "") +
                        "for event in " + repr(events) + ":\n    print(json.dumps(event))\n" +
                        "raise SystemExit(" + repr(exitcode) + ")\n")
        path.chmod(0o700)
        return path

    def invoke(self, events, flags=(), **options):
        output = self.directory / "evidence"
        go = self.executable(events, **options)
        with mock.patch.object(CHECK, "ROOT", self.root), contextlib.redirect_stdout(io.StringIO()):
            code = CHECK.main(["--go", str(go), "--output", str(output), *flags])
        return code, json.loads((output / "summary.json").read_text())

    def test_freeze_includes_fixtures_but_never_archive(self):
        target = self.directory / "snapshot"
        hashes = CHECK.freeze_sources(self.root, target)
        self.assertIn("internal/example/testdata/input.json", hashes)
        self.assertFalse((target / "evidence").exists())
        self.assertEqual(hashes, CHECK.source_hashes(target))
        (self.root / "internal/example/example.go").write_text("later work")
        self.assertEqual(hashes, CHECK.source_hashes(target))

    def test_source_symlink_is_refused(self):
        (self.root / "internal/linked").symlink_to(self.root / "evidence", target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "linked source"):
            CHECK.freeze_sources(self.root, self.directory / "snapshot")

    def test_environment_removes_database_and_crash_helpers(self):
        original = {"PATH": "/usr/bin", "PGHOST": "db", "AGENTCAPSULE_TEST_POSTGRES": "secret",
                    "AC_ARCHIVE_CHILD": "fixture", "CAPSULE_CRASH_DB": "/private",
                    "GOTOOLCHAIN": "auto", "GOFLAGS": "-run=Nothing -tags=kvm_integration",
                    "GOWORK": "/foreign/go.work", "CGO_ENABLED": "0"}
        env = CHECK.local_environment(original, Path("/tools/go/bin/go"))
        self.assertEqual(env["PATH"], "/tools/go/bin:/usr/bin")
        self.assertEqual(env["GOFLAGS"], "-mod=readonly")
        self.assertEqual(env["GOENV"], "off")
        self.assertEqual(env["GOWORK"], "off")
        self.assertEqual(env["CGO_ENABLED"], "1")
        self.assertFalse(any(key.startswith(("PG", "AC_", "AGENTCAPSULE_", "CAPSULE_CRASH_")) for key in env))
        self.assertEqual(original["PGHOST"], "db")

    def test_expected_postgres_skip_is_separate_from_pass(self):
        result = CHECK.analyze_events(successful_events(True), MODULE)
        self.assertEqual(len(result["passed_tests"]), 1)
        self.assertEqual(len(result["required_postgres_tests_not_run"]), 1)
        self.assertEqual(result["unexpected_skips"], [])

    def test_unknown_skip_is_not_hidden(self):
        events = successful_events()
        events.insert(1, {"Action": "skip", "Package": PACKAGE, "Test": "TestFeature"})
        code, result = self.invoke(events)
        self.assertEqual(code, 1)
        self.assertEqual(result["unexpected_skips"][0]["test"], "TestFeature")

    def test_postgres_message_in_unrelated_package_is_not_allowed(self):
        events = successful_events(True)
        for event in events:
            event["Package"] = MODULE + "/internal/unrelated"
        result = CHECK.analyze_events(events, MODULE)
        self.assertEqual(len(result["unexpected_skips"]), 1)

    def test_testless_package_is_not_a_skipped_test(self):
        events = successful_events()
        empty = MODULE + "/cmd/example"
        events.extend([{"Action": "output", "Package": empty, "Output": "?\t" + empty + "\t[no test files]\n"},
                       {"Action": "skip", "Package": empty}])
        code, result = self.invoke(events)
        self.assertEqual(code, 0)
        self.assertEqual(result["packages_without_tests"], [empty])
        self.assertFalse(result["unexpected_skips"])

    def test_local_success_keeps_integration_required(self):
        with mock.patch.dict(os.environ, {"PGHOST": "never-connect", "AGENTCAPSULE_TEST_POSTGRES": "never-connect"}):
            code, result = self.invoke(successful_events(True))
        self.assertEqual(code, 0)
        self.assertEqual(result["status"], "passed_local_only")
        self.assertEqual(result["postgres_validation"], "required_not_run")
        self.assertEqual(result["kvm_validation"], "required_not_run")
        self.assertTrue(result["frozen_sources_unchanged"])
        self.assertEqual(result["command"][-2:], ["./cmd/...", "./internal/..."])

    def test_strict_skip_option_fails(self):
        code, result = self.invoke(successful_events(True), ["--fail-on-skip"])
        self.assertEqual(code, 1)
        self.assertEqual(result["status"], "failed")

    def test_empty_or_truncated_evidence_fails(self):
        code, result = self.invoke(successful_events()[:-1])
        self.assertEqual(code, 1)
        self.assertEqual(result["packages_without_terminal_event"], [PACKAGE])

    def test_no_executed_tests_fails(self):
        code, result = self.invoke([{"Action": "pass", "Package": PACKAGE}])
        self.assertEqual(code, 1)
        self.assertEqual(result["passed_tests"], [])

    def test_failure_event_even_with_zero_exit_fails(self):
        events = successful_events()
        events.insert(1, {"Action": "fail", "Package": PACKAGE, "Test": "TestBroken"})
        code, result = self.invoke(events)
        self.assertEqual(code, 1)
        self.assertEqual(result["failed_tests_or_packages"][0]["test"], "TestBroken")

    def test_nonzero_exit_and_source_mutation_fail(self):
        code, result = self.invoke(successful_events(), mutate=True, exitcode=2)
        self.assertEqual(code, 1)
        self.assertEqual(result["returncode"], 2)
        self.assertFalse(result["frozen_sources_unchanged"])

    def test_wrong_toolchain_is_rejected_before_tests(self):
        code, result = self.invoke(successful_events(), version="go version go1.25.0 linux/amd64")
        self.assertEqual(code, 1)
        self.assertIn("requires " + CHECK.GO_VERSION, result["error"])
        self.assertNotIn("command", result)

    def test_archive_package_event_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "outside cmd/internal"):
            CHECK.analyze_events([{"Action": "pass", "Package": MODULE + "/evidence/old"}], MODULE)


if __name__ == "__main__":
    unittest.main()
