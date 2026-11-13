#!/usr/bin/env python3
"""Unit tests of the loss assessment of scripts/verify-failover.py (REC-03).

assess_loss decides whether the failover exercise passes: the writes the
client was told were saved, against what the promoted standby serves and the
window the operator announces. The exercise itself runs it on real writes.
"""

import importlib.util
from pathlib import Path
import sys
import unittest

SCRIPT = Path(__file__).resolve().with_name("verify-failover.py")
SPEC = importlib.util.spec_from_file_location("verify_failover", SCRIPT)
FAILOVER = importlib.util.module_from_spec(SPEC)
sys.dont_write_bytecode = True
SPEC.loader.exec_module(FAILOVER)

BOUND = 45.0  # archive_timeout plus the push, as in the run


def writes(count, start=1000.0, every=1.0):
    """count writes acknowledged every second from start: (n, ID, acknowledged at)."""
    return [(n, f"org_{n}", start + n * every) for n in range(1, count + 1)]


class Assessment(unittest.TestCase):
    def test_a_loss_inside_the_window(self):
        acknowledged = writes(10)
        present = {w[1] for w in acknowledged[:6]}
        # The sixth write's commit is the last one replayed; its answer
        # reached the client just after.
        measures, failures = FAILOVER.assess_loss(acknowledged, present, 1005.99, 1010.5, BOUND)
        self.assertEqual(failures, [])
        self.assertEqual((measures["acknowledged"], measures["present"], measures["missing"]), (10, 6, 4))
        self.assertEqual(measures["oldest_missing_age_seconds"], 3.5)
        self.assertEqual(measures["newest_missing_age_seconds"], 0.5)
        self.assertEqual(measures["window_seconds"], 4.51)
        self.assertEqual((measures["acknowledged_older_than_window"], measures["acknowledged_inside_window"]), (5, 5))

    def test_nothing_lost(self):
        acknowledged = writes(5)
        measures, failures = FAILOVER.assess_loss(acknowledged, {w[1] for w in acknowledged}, 1004.99, 1005.2, BOUND)
        self.assertEqual(failures, [])
        self.assertEqual((measures["missing"], measures["oldest_missing_age_seconds"]), (0, 0.0))

    def test_a_gap_is_not_a_prefix(self):
        acknowledged = writes(6)
        present = {w[1] for w in acknowledged} - {"org_3"}
        _, failures = FAILOVER.assess_loss(acknowledged, present, 1005.99, 1006.5, BOUND)
        self.assertIn("the writes on the standby are not a prefix of the acknowledged writes", failures)
        self.assertIn("an acknowledged write older than the window is missing", failures)

    def test_a_window_announced_too_late_misses_a_loss(self):
        # The standby lacks writes 5 and 6, but the window starts after
        # write 5 was acknowledged: the announcement would not cover it.
        acknowledged = writes(6)
        present = {w[1] for w in acknowledged[:4]}
        _, failures = FAILOVER.assess_loss(acknowledged, present, 1005.5, 1006.5, BOUND)
        self.assertIn("an acknowledged write older than the window is missing", failures)
        self.assertIn("a missing write is outside the window", failures)

    def test_a_write_acknowledged_after_the_disaster(self):
        acknowledged = writes(3)
        _, failures = FAILOVER.assess_loss(acknowledged, {"org_1"}, 1001.5, 1002.5, BOUND)
        self.assertIn("a write was acknowledged after the disaster", failures)
        self.assertIn("a missing write is outside the window", failures)

    def test_a_loss_beyond_the_bound(self):
        acknowledged = writes(60)
        present = {w[1] for w in acknowledged[:5]}
        measures, failures = FAILOVER.assess_loss(acknowledged, present, 1005.5, 1060.5, BOUND)
        self.assertEqual(measures["oldest_missing_age_seconds"], 54.5)
        self.assertIn("a write acknowledged more than archive_timeout plus the push before the disaster was lost", failures)
        self.assertIn("the standby was further behind than archive_timeout plus the push", failures)


if __name__ == "__main__":
    unittest.main()
