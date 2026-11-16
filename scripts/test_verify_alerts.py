#!/usr/bin/env python3
"""Unit tests of scripts/verify-alerts.py's check that every alert rule is tested.

Each rule of deploy/prometheus/alerts.yml needs a promtool case where it
fires and one where it stays silent: a rule that never fires, or always
does, cannot pass both.
"""

import importlib.util
from pathlib import Path
import sys
import unittest

SCRIPT = Path(__file__).resolve().with_name("verify-alerts.py")
SPEC = importlib.util.spec_from_file_location("verify_alerts", SCRIPT)
ALERTS = importlib.util.module_from_spec(SPEC)
sys.dont_write_bytecode = True
SPEC.loader.exec_module(ALERTS)

RULES = """groups:
  - name: g
    rules:
      - alert: Fires
        expr: up == 0
      - alert: NeverTested
        expr: up == 2
      - alert: OnlySilent
        expr: up == 3
"""

TESTS = """tests:
  - interval: 1m
    alert_rule_test:
      - eval_time: 1m
        alertname: Fires
        exp_alerts: []
      - eval_time: 5m
        alertname: Fires
        exp_alerts:
          - exp_labels: {severity: warning}
      - eval_time: 5m
        alertname: OnlySilent
        exp_alerts: []
"""


class EveryRuleTested(unittest.TestCase):
    def test_the_repository_rules_are_all_tested(self):
        rules = (ALERTS.RULES / "alerts.yml").read_text()
        tests = (ALERTS.RULES / "alerts_test.yml").read_text()
        self.assertEqual(ALERTS.untested_rules(rules, tests), [])

    def test_a_rule_without_both_cases_is_reported(self):
        self.assertEqual(ALERTS.untested_rules(RULES, TESTS), [
            "NeverTested has no promtool case where it fires",
            "NeverTested has no promtool case where it stays silent",
            "OnlySilent has no promtool case where it fires",
        ])

    def test_a_case_for_an_unknown_rule_is_reported(self):
        self.assertEqual(ALERTS.untested_rules(RULES.split("      - alert: NeverTested")[0], TESTS),
                         ["OnlySilent is tested but is not a rule"])


if __name__ == "__main__":
    unittest.main()
