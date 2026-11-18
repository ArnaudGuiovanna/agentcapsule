#!/usr/bin/env python3
"""Unit tests of scripts/check-models.py (VAL-01).

No Java here: the tests cover the inventory of the checks, the coverage rule,
the reading of Quint's output and the refusal of a missing or changed tool.
"""

import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().with_name("check-models.py")
SPEC = importlib.util.spec_from_file_location("check_models", SCRIPT)
CHECK = importlib.util.module_from_spec(SPEC)
sys.dont_write_bytecode = True
SPEC.loader.exec_module(CHECK)

WITNESS = """
module demoGuard {
  run guardTest = init.then(a).fail()
}
module demoBroken {
  var pc: int
  action traceInit = all { init, pc' = 0 }
  action traceStep = any {
    all { pc == 0, a, pc' = pc+1 },
    // all { pc == 7, b, pc' = pc+1 },
    all { pc == 1, b, pc' = pc+1 }
  }
  val checked = safety
}
module demoSchedule {
  const FRESH: bool
  action traceInit = all { init, pc' = 0 }
}
"""


class Inventory(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.spec = Path(self.dir.name)
        (self.spec / "demo_witness.qnt").write_text(WITNESS)

    def tearDown(self):
        self.dir.cleanup()

    def test_schedule_length_ignores_comments(self):
        found = CHECK.modules(self.spec / "demo_witness.qnt")
        self.assertEqual(found["demoBroken"], {"const": False, "trace": True, "schedule": 2})
        self.assertTrue(found["demoSchedule"]["const"])
        self.assertFalse(found["demoGuard"]["trace"])

    def test_a_witness_must_fail_at_its_last_step(self):
        (check,) = CHECK.witnesses(self.spec, "demo_witness.qnt")
        self.assertEqual((check.module, check.prop, check.steps, check.expected),
                         ("demoBroken", "checked", 2, CHECK.VIOLATION))
        self.assertEqual((check.init, check.step), ("traceInit", "traceStep"))
        self.assertTrue(check.last_step)

    def test_a_schedule_without_a_check_is_reported(self):
        self.assertEqual(CHECK.coverage(self.spec, []), ["demo_witness.qnt: demoBroken"])
        self.assertEqual(CHECK.coverage(self.spec, CHECK.witnesses(self.spec, "demo_witness.qnt")), [])

    def test_every_module_of_a_checker_file_needs_a_check(self):
        (self.spec / "bounded.qnt").write_text("module fooDepth8 {\n  val safety = true\n}\n")
        self.assertIn("bounded.qnt: fooDepth8", CHECK.coverage(self.spec, []))

    def test_a_check_keeps_only_the_modules_it_needs(self):
        (self.spec / "base.qnt").write_text(
            "/** doc */\nmodule base {\n  const N: int\n  val s = \"}\" // }\n}\n"
            "module baseOk {\n  import base(N = 1).*\n}\n"
            "module baseOther {\n  import base(N = 2).*\n}\n")
        (self.spec / "uses.qnt").write_text(
            "module usesBroken {\n  import base(N = Map(0->(0,1)).get(0)._1)\n"
            "    .* from \"./base\"\n  import helper.*\n}\n"
            "module helper {\n  val h = 1\n}\nmodule unrelated {\n  val u = 2\n}\n")
        files = CHECK.isolate(self.spec, "uses.qnt", "usesBroken")
        self.assertEqual(sorted(files), ["base.qnt", "uses.qnt"])
        self.assertEqual(list(CHECK.module_texts(files["uses.qnt"])), ["usesBroken", "helper"])
        self.assertEqual(list(CHECK.module_texts(files["base.qnt"])), ["base"])
        self.assertIn('val s = "}" // }', files["base.qnt"])
        self.assertEqual(list(CHECK.isolate(self.spec, "base.qnt", "baseOk")), ["base.qnt"])

    def test_the_repository_table_covers_the_models(self):
        table = CHECK.checks()
        self.assertEqual(CHECK.coverage(CHECK.SPEC, table), [])
        ids = [c.id for c in table]
        self.assertEqual(len(ids), len(set(ids)))
        for c in table:
            self.assertTrue((CHECK.SPEC / c.file).is_file(), c.file)
            self.assertIn(c.expected, (CHECK.OK, CHECK.VIOLATION))
            if c.backend == "apalache":
                self.assertIsNotNone(c.steps, c.id)
            else:
                self.assertIsNone(c.steps, c.id)


def check(backend="apalache", kind="invariant"):
    return CHECK.Check("m.qnt", "m", "safety", CHECK.OK, backend, kind=kind, steps=3 if backend == "apalache" else None)


class Classify(unittest.TestCase):
    def test_apalache(self):
        c = check()
        self.assertEqual(CHECK.classify(c, 0, "[ok] No violation found (8053ms).", False), "ok")
        self.assertEqual(CHECK.classify(c, 1, "[violation] Found an issue (43043ms).\n"
                                              "error: found a counterexample", False), "violation")
        self.assertEqual(CHECK.classify(c, 1, "error: Failed to launch Apalache server", False), "error")
        # Quint 0.33.1 can exit 0 with no result when the spec is too large.
        self.assertEqual(CHECK.classify(c, 0, "The Apalache server is running on port 1.", False), "error")
        self.assertEqual(CHECK.classify(c, None, "", True), "timeout")

    def test_tlc_needs_its_completion_line(self):
        c = check("tlc")
        done = "Model checking completed. No error has been found.\n[ok] No violation found (966ms)."
        self.assertEqual(CHECK.classify(c, 0, done, False), "ok")
        self.assertEqual(CHECK.classify(c, 0, "[ok] No violation found (966ms).", False), "error")

    def test_tlc_violation_is_an_invariant_or_a_temporal_property(self):
        c = check("tlc", "temporal")
        # TLC's words, as Quint 0.33.1 names the property.
        self.assertEqual(CHECK.classify(c, 1, "Error: Temporal property q_temporalProps was violated.\n"
                                              "error: found a counterexample", False), "violation")
        self.assertEqual(CHECK.classify(c, 1, "Error: Temporal properties were violated.\n"
                                              "error: found a counterexample", False), "violation")
        self.assertEqual(CHECK.classify(c, 1, "Error: Invariant q_inv is violated.\n"
                                              "error: found a counterexample", False), "violation")
        # The normal form TLC refuses is a tool error, not a counterexample.
        self.assertEqual(CHECK.classify(c, 1, "Error: Temporal formulas containing actions must be of "
                                              "forms <>[]A or []<>A.\nerror: TLC error (see output above)",
                                        False), "error")

    def test_tlc_numbers(self):
        out = ("Progress(7) at x: 3,960,801 states generated (3,873,910 s/min), 959,157 distinct states found "
               "(923,468 ds/min), 795,409 states left on queue.\n"
               "53 states generated, 20 distinct states found, 0 states left on queue.\n"
               "The depth of the complete state graph search is 8.\n")
        self.assertEqual(CHECK.tlc_numbers(out), {"generated": 53, "distinct": 20, "left": 0, "depth": 8})
        partial = CHECK.tlc_numbers(out.splitlines()[0])
        self.assertEqual((partial["progress_depth"], partial["distinct"]), (7, 959157))


class Tools(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.tools = Path(self.dir.name)

    def tearDown(self):
        self.dir.cleanup()

    def test_a_missing_record_is_refused(self):
        with self.assertRaisesRegex(ValueError, "model-checkers.json is missing"):
            CHECK.find_tools(self.tools)

    def test_a_missing_or_changed_tool_is_refused(self):
        home = self.tools / "apalache" / "apalache-dist-0.62.4" / "apalache"
        (home / "lib").mkdir(parents=True)
        (home / "lib" / "apalache.jar").write_bytes(b"changed")
        record = {"jdk": {"home": "jdk/none", "version": "21.0.13+9"},
                  "apalache": {"version": "0.62.4", "quint_home": "apalache",
                               "home": "apalache/apalache-dist-0.62.4/apalache", "jar": "lib/apalache.jar",
                               "jar_sha256": hashlib.sha256(b"recorded").hexdigest()}}
        (self.tools / "model-checkers.json").write_text(json.dumps(record))
        with self.assertRaises(ValueError) as e:
            CHECK.find_tools(self.tools)
        self.assertIn("no Java runtime", str(e.exception))
        self.assertIn("does not match the SHA-256", str(e.exception))


if __name__ == "__main__":
    unittest.main()
