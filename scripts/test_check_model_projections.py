#!/usr/bin/env python3
"""Unit tests of scripts/check-model-projections.py (VAL-01).

The check must fail on a run missing from spec/projections.md, on a Go test
that does not exist, and on a row that ignores a Go test named after its run.
"""

import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().with_name("check-model-projections.py")
SPEC = importlib.util.spec_from_file_location("check_model_projections", SCRIPT)
CHECK = importlib.util.module_from_spec(SPEC)
sys.dont_write_bytecode = True
SPEC.loader.exec_module(CHECK)

MODEL = """
module demo {
  run fooBarTest = init
  // run commentedTest = init
  val doneWitness = true
}
module demoBroken {
  action traceInit = all { init }
}
"""


class Inventory(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        root = Path(self.dir.name)
        (root / "spec").mkdir()
        (root / "spec" / "demo.qnt").write_text(MODEL)
        (root / "pkg").mkdir()
        (root / "pkg" / "a_test.go").write_text(
            "package pkg\nfunc TestFooBar(t *testing.T) {}\nfunc TestReplay(t *testing.T) { t.Run(\"case-one\", nil) }\n")
        self.items = CHECK.model_items(root / "spec")
        self.tests = CHECK.go_tests(root, ["pkg/a_test.go"])

    def tearDown(self):
        self.dir.cleanup()

    def errors(self, table):
        return CHECK.check(self.items, self.tests, CHECK.table_rows(table))

    def test_finds_runs_and_witnesses(self):
        self.assertEqual(sorted(self.items), ["demo.doneWitness", "demo.fooBarTest", "demoBroken"])

    def test_a_complete_table_passes(self):
        table = ("| `demo.fooBarTest` | full | `TestFooBar`, `TestReplay/case-one` | |\n"
                 "| `demo.doneWitness` | model-only | — | target |\n"
                 "| `demoBroken` | model-only | — | broken |\n")
        self.assertEqual(self.errors(table), [])

    def test_an_unlisted_run_fails(self):
        errors = self.errors("| `demo.fooBarTest` | full | `TestFooBar` | |\n| `demoBroken` | gap | — | |\n")
        self.assertEqual(len(errors), 1)
        self.assertIn("demo.doneWitness is not in spec/projections.md", errors[0])

    def test_unknown_tests_cases_and_runs_fail(self):
        table = ("| `demo.fooBarTest` | full | `TestFooBar`, `TestGone`, `TestReplay/case-two` | |\n"
                 "| `demo.doneWitness` | model-only | — | |\n| `demoBroken` | gap | — | |\n"
                 "| `demo.goneTest` | gap | — | |\n")
        errors = "\n".join(self.errors(table))
        self.assertIn("Go test TestGone does not exist", errors)
        self.assertIn("no case 'case-two'", errors)
        self.assertIn("demo.goneTest is not a run or witness", errors)

    def test_a_row_must_name_the_test_named_after_its_run(self):
        table = ("| `demo.fooBarTest` | gap | — | |\n"
                 "| `demo.doneWitness` | model-only | — | |\n| `demoBroken` | gap | — | |\n")
        self.assertIn("TestFooBar is named after demo.fooBarTest", "\n".join(self.errors(table)))

    def test_statuses_and_tests_agree(self):
        table = ("| `demo.fooBarTest` | done | `TestFooBar` | |\n"
                 "| `demo.doneWitness` | partial | — | |\n| `demoBroken` | gap | `TestFooBar` | |\n")
        errors = "\n".join(self.errors(table))
        self.assertIn("unknown status 'done'", errors)
        self.assertIn("a partial projection must name its Go test", errors)
        self.assertIn("a gap row names Go tests", errors)


if __name__ == "__main__":
    unittest.main()
