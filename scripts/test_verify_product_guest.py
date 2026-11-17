#!/usr/bin/env python3
"""Unit tests of scripts/verify-product-guest.py's list of worker scenarios.

Every TestProductWorker* test under internal/worker must be required by the
KVM run, or required when its optional input is given, so that a scenario
that stops running fails the run instead of going unnoticed.
"""

import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().with_name("verify-product-guest.py")
SPEC = importlib.util.spec_from_file_location("verify_product_guest", SCRIPT)
GUEST = importlib.util.module_from_spec(SPEC)
sys.dont_write_bytecode = True
SPEC.loader.exec_module(GUEST)


class WorkerScenarios(unittest.TestCase):
    def test_every_product_worker_test_is_listed(self):
        declared = GUEST.declared_worker_tests(GUEST.ROOT / "internal/worker")
        listed = GUEST.REQUIRED_WORKER | GUEST.PI_WORKER | GUEST.SLIM_WORKER | GUEST.RCLONE_WORKER
        self.assertTrue(declared)
        self.assertEqual(sorted(declared - listed), [], "product worker tests the KVM run does not require")
        self.assertEqual(sorted(listed - declared), [], "required product worker tests that do not exist")

    def test_conditional_scenarios_stay_conditional(self):
        self.assertFalse(GUEST.REQUIRED_WORKER & (GUEST.PI_WORKER | GUEST.SLIM_WORKER | GUEST.RCLONE_WORKER))
        self.assertEqual(GUEST.RCLONE_WORKER, {"TestProductWorkerRestoresAgentFromShippedArchiveOnAnotherHost"})
        self.assertEqual(GUEST.PI_WORKER, {"TestProductWorkerTenantRunsPiOnARealModel"})
        self.assertEqual(GUEST.SLIM_WORKER, {"TestProductWorkerTenantAgentsTalkOverSLIM", "TestProductWorkerTenantFlagshipJourney",
                                             "TestProductWorkerDeletionRemovesTheVolumeTheKeyAndTheDirectoryRecord"})

    def test_an_unlisted_test_is_found(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "x_integration_test.go").write_text(
                "package worker\n\nfunc TestProductWorkerSomethingNew(t *testing.T) {}\nfunc TestOther(t *testing.T) {}\n"
                "// func TestProductWorkerCommentedOut(t *testing.T) {}\n")
            Path(tmp, "x.go").write_text("package worker\n\nfunc TestProductWorkerNotATestFile() {}\n")
            self.assertEqual(GUEST.declared_worker_tests(Path(tmp)), {"TestProductWorkerSomethingNew"})


if __name__ == "__main__":
    unittest.main()
