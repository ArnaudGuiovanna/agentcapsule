#!/usr/bin/env python3
"""Unit tests of scripts/verify-runtime.py's worker phase and evidence handover.

The worker phase runs the KVM tests of internal/worker and only them: the
tests of the files its build tags compile and that need those tags. Every
such test is listed by the script, so that a test that stops running, or a
new one, fails the run instead of going unnoticed. The ordinary unit and
PostgreSQL tests run in the PostgreSQL campaign as an ordinary user.
"""

import importlib.util
import os
from pathlib import Path
import re
import sys
import tempfile
import unittest
from unittest import mock

SCRIPT = Path(__file__).resolve().with_name("verify-runtime.py")
SPEC = importlib.util.spec_from_file_location("verify_runtime", SCRIPT)
RUNTIME = importlib.util.module_from_spec(SPEC)
sys.dont_write_bytecode = True
SPEC.loader.exec_module(RUNTIME)

WORKER = RUNTIME.ROOT / "internal/worker"
CONTROL_TAGS = {"kvm_integration", "kvm_control_integration"}


class BuildConstraints(unittest.TestCase):
    def test_expressions(self):
        tags = {"linux", "cgo", "kvm_integration"}
        for expression, want in [("linux", True), ("linux && kvm_integration", True), ("linux && kvm_control_integration", False),
                                 ("!windows", True), ("linux && !cgo", False), ("darwin || (linux && cgo)", True),
                                 ("linux && (kvm_product_integration || kvm_control_integration)", False),
                                 ("!(linux && cgo) || kvm_integration", True)]:
            self.assertEqual(RUNTIME.build_satisfied(expression, tags), want, expression)
        for bad in ["linux &&", "(linux", "linux cgo", "&& linux", ""]:
            with self.assertRaises(ValueError):
                RUNTIME.build_satisfied(bad, tags)


class WorkerSelection(unittest.TestCase):
    def test_every_kvm_test_is_listed(self):
        for tags, listed in [({"kvm_integration"}, RUNTIME.PLACEMENT_TESTS | RUNTIME.PLACEMENT_HELPERS),
                             (CONTROL_TAGS, RUNTIME.PLACEMENT_TESTS | RUNTIME.PLACEMENT_HELPERS
                              | RUNTIME.CONTROL_TESTS | RUNTIME.CONTROL_HELPERS)]:
            declared = RUNTIME.kvm_worker_tests(WORKER, tags)
            self.assertTrue(declared)
            self.assertEqual(sorted(declared - listed), [], "KVM worker tests the run does not list")
            self.assertEqual(sorted(listed - declared), [], "listed KVM worker tests that do not exist")

    def test_the_selection_runs_the_tests_and_not_their_helpers(self):
        selected = RUNTIME.worker_tests(WORKER, CONTROL_TAGS)
        self.assertEqual(selected, RUNTIME.PLACEMENT_TESTS | RUNTIME.CONTROL_TESTS)
        self.assertEqual(RUNTIME.worker_tests(WORKER, {"kvm_integration"}), RUNTIME.PLACEMENT_TESTS)
        pattern = RUNTIME.run_pattern(selected)
        for name in selected:
            self.assertIsNotNone(re.search(pattern, name), name)
        # Run by their parents in a child process, or by phases of their own.
        for name in RUNTIME.PLACEMENT_HELPERS | RUNTIME.CONTROL_HELPERS | {name + "X" for name in selected}:
            self.assertIsNone(re.search(pattern, name), name)

    def test_the_capacity_tests_are_required(self):
        # ADR 017 and ADR 021: one slot, three stores, and the preparation of a dispatch.
        self.assertLessEqual({"TestDispatchPreparationAndOneSlotCapacity", "TestBarrierCapacityOneSlotThreeStoresAndReplay"},
                             RUNTIME.CONTROL_TESTS)

    def test_ordinary_and_product_tests_are_not_selected(self):
        selected = RUNTIME.worker_tests(WORKER, CONTROL_TAGS)
        # Failed as root on 2026-11-18: they assume an ordinary user, the
        # repository's layout, or a short temporary directory.
        for name in ["TestWorkerConfigurationExampleReachesTheService", "TestInspectionRunsAsAReservedUID",
                     "TestModelErrorsReachTheGuestAndLeaveItsVMRunning", "TestSLIMConfigNeedsTwoSocketsAndAnUnprivilegedBridge",
                     "TestProductWorkerProvisioningAndEncryptedWake", "TestCapacityBenchmark",
                     "TestAsRootTheImporterNeedsAnInspectionUID"]:
            self.assertNotIn(name, selected)

    def test_tests_of_other_tags_are_not_found(self):
        with tempfile.TemporaryDirectory() as tmp:
            files = {
                "a_integration_test.go": "//go:build linux && kvm_integration\n\npackage worker\n\nfunc TestKVM(t *testing.T) {}\n",
                "b_integration_test.go": "//go:build linux && kvm_integration && kvm_control_integration\n\npackage worker\n\n"
                                         "func TestControl(t *testing.T) {}\n// func TestCommentedOut(t *testing.T) {}\n",
                "c_integration_test.go": "//go:build linux && cgo && kvm_integration && kvm_product_integration\n\npackage worker\n\n"
                                         "func TestProduct(t *testing.T) {}\n",
                "d_test.go": "//go:build linux && cgo\n\npackage worker\n\nfunc TestOrdinary(t *testing.T) {}\n",
                "e_test.go": "package worker\n\nfunc TestPlain(t *testing.T) {}\n",
                "f_root_test.go": "//go:build linux && root_integration\n\npackage worker\n\nfunc TestAsRoot(t *testing.T) {}\n",
                "g_integration.go": "//go:build linux && kvm_integration\n\npackage worker\n\nfunc TestNotATestFile(t *testing.T) {}\n",
            }
            for name, text in files.items():
                Path(tmp, name).write_text(text)
            self.assertEqual(RUNTIME.kvm_worker_tests(Path(tmp), {"kvm_integration"}), {"TestKVM"})
            self.assertEqual(RUNTIME.kvm_worker_tests(Path(tmp), CONTROL_TAGS), {"TestKVM", "TestControl"})


class EvidenceHandover(unittest.TestCase):
    def tree(self, tmp):
        out = Path(tmp, "runtime")
        (out / "sources/internal").mkdir(parents=True)
        (out / "summary.json").write_text("[]\n")
        (out / "sources/internal/x.go").write_text("package x\n")
        (out / "link").symlink_to("/etc/passwd")
        return out

    def test_the_invoking_user_gets_the_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = self.tree(tmp)
            with mock.patch.object(RUNTIME.os, "chown") as chown:
                RUNTIME.hand_back(out, {"SUDO_UID": "1000", "SUDO_GID": "1001"})
            changed = {Path(c.args[0]) for c in chown.call_args_list}
            self.assertEqual(changed, {out, out / "sources", out / "sources/internal", out / "summary.json",
                                       out / "sources/internal/x.go", out / "link"})
            for c in chown.call_args_list:
                self.assertEqual(c.args[1:], (1000, 1001))
                # A link is changed itself, never what it points to.
                self.assertEqual(c.kwargs, {"follow_symlinks": False})

    def test_no_handover_without_an_ordinary_invoking_user(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = self.tree(tmp)
            for environ in [{}, {"SUDO_UID": "1000"}, {"SUDO_UID": "0", "SUDO_GID": "0"},
                            {"SUDO_UID": "x", "SUDO_GID": "1000"}, {"SUDO_UID": "", "SUDO_GID": ""}]:
                with mock.patch.object(RUNTIME.os, "chown") as chown:
                    RUNTIME.hand_back(out, environ)
                self.assertEqual(chown.call_args_list, [], environ)

    def test_the_handover_is_real_for_this_user(self):
        # Without root, a file can be given only to its own owner.
        with tempfile.TemporaryDirectory() as tmp:
            out = self.tree(tmp)
            RUNTIME.hand_back(out, {"SUDO_UID": str(os.getuid()), "SUDO_GID": str(os.getgid())})
            self.assertEqual(out.stat().st_uid, os.getuid())


if __name__ == "__main__":
    unittest.main()
