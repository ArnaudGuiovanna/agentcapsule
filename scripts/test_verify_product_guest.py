#!/usr/bin/env python3
"""Unit tests of scripts/verify-product-guest.py's list of worker scenarios.

Every TestProduct* scenario under internal/worker must be required by the
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
        self.assertEqual(GUEST.PI_WORKER, {"TestProductWorkerTenantRunsPiOnARealModel", "TestProductPiStreamsBeforeTheProviderFinishes"})
        self.assertEqual(GUEST.SLIM_WORKER, {"TestProductWorkerTenantAgentsTalkOverSLIM", "TestProductWorkerTenantFlagshipJourney",
                                             "TestProductWorkerDeletionRemovesTheVolumeTheKeyAndTheDirectoryRecord"})
        # The stuck harness's tests need no optional input: every run requires them.
        self.assertLessEqual({"TestProductWorkerStopsAGuestThatNeverAnswersAnInvocation",
                              "TestProductWorkerDeletesAnAgentWhoseHarnessNeverAnswers"}, GUEST.REQUIRED_WORKER)
        self.assertLessEqual({"TestProductDeploymentCampaignKVM", "TestProductVolumeGrowthKVM"}, GUEST.REQUIRED_WORKER)

    def test_an_unlisted_test_is_found(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "x_integration_test.go").write_text(
                "package worker\n\nfunc TestProductWorkerSomethingNew(t *testing.T) {}\nfunc TestOther(t *testing.T) {}\n"
                "func TestProductResourceChangeKVM(t *testing.T) {}\n"
                "func TestProductLiveStream(t *testing.T) {}\n"
                "func TestProductionConfiguration(t *testing.T) {}\n"
                "// func TestProductWorkerCommentedOut(t *testing.T) {}\n")
            Path(tmp, "x.go").write_text("package worker\n\nfunc TestProductWorkerNotATestFile() {}\n")
            self.assertEqual(GUEST.declared_worker_tests(Path(tmp)), {"TestProductWorkerSomethingNew", "TestProductResourceChangeKVM", "TestProductLiveStream"})


def measured(n):
    """A measured step of the capacity benchmark for n agents."""
    stat = {"count": n, "min": 1.0, "p50": 1.5, "p90": 2.0, "max": 2.0, "mean": 1.5, "sum": 1.5 * n}
    return {"agents": n, "status": "measured", "boot_seconds": dict(stat), "wake_to_running_seconds": dict(stat),
            "all_running_seconds": 3.0, "vmm_rss_mib": dict(stat), "first_answer_seconds": dict(stat),
            "wake_from_stopped_answer_seconds": dict(stat), "host_used_by_vms_mib": 300.0,
            "host_cpu_busy_ratio_idle": 0.02, "vmm_cpu_seconds_per_second_idle": 0.01}


class CapacityBenchmark(unittest.TestCase):
    def report(self, *steps):
        return {"schema": GUEST.CAPACITY_SCHEMA, "started_at": "2026-11-17T00:00:00Z", "finished_at": "2026-11-17T01:00:00Z",
                "config": {"agents": [s["agents"] for s in steps]}, "steps": list(steps)}

    def test_sizes_are_sorted_and_bounded(self):
        self.assertEqual(GUEST.capacity_sizes("20,1, 5,10,5"), [1, 5, 10, 20])
        for bad in ["0", "65", "1,x", "", "-1"]:
            with self.assertRaises(ValueError):
                GUEST.capacity_sizes(bad)

    def test_a_complete_report_is_summarized(self):
        not_run = {"agents": 20, "status": "not_run", "reason": "9000 MiB available, 6144 needed"}
        summary = GUEST.check_capacity_report(self.report(measured(1), measured(5), not_run), [1, 5, 20])
        self.assertEqual([s["status"] for s in summary], ["measured", "measured", "not_run"])
        self.assertEqual(summary[1]["boot_p50_seconds"], 1.5)
        self.assertEqual(summary[2]["reason"], not_run["reason"])

    def test_an_incomplete_report_fails(self):
        short = measured(5)
        short["first_answer_seconds"]["count"] = 4
        no_cpu = measured(1)
        del no_cpu["host_cpu_busy_ratio_idle"]
        unfinished = self.report(measured(1))
        del unfinished["finished_at"]
        for report, sizes in [(self.report(short), [5]), (self.report(no_cpu), [1]), (self.report(measured(1)), [1, 5]),
                              (unfinished, [1]), ({**self.report(measured(1)), "schema": "other"}, [1]),
                              (self.report({"agents": 1, "status": "not_run"}), [1])]:
            with self.assertRaises(ValueError):
                GUEST.check_capacity_report(report, sizes)

    def test_the_benchmark_is_not_a_required_scenario(self):
        # It runs only with --capacity-agents, so it is not a TestProductWorker*.
        declared = GUEST.declared_worker_tests(GUEST.ROOT / "internal/worker")
        self.assertNotIn("TestCapacityBenchmark", declared)
        source = (GUEST.ROOT / "internal/worker/capacity_benchmark_integration_test.go").read_text()
        self.assertIn("func TestCapacityBenchmark(t *testing.T)", source)
        self.assertIn(GUEST.CAPACITY_SCHEMA, (GUEST.ROOT / "internal/worker/capacity_test.go").read_text())


if __name__ == "__main__":
    unittest.main()
