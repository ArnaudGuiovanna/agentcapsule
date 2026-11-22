#!/usr/bin/env python3
"""Unit tests of scripts/check-model-projections.py (VAL-01).

The check must fail on a run missing from spec/projections.md, on a Go test
that does not exist, and on a row that ignores a Go test named after its run.
Since the v0.1.0 audit (A-10) it also follows an ITF replay's case to the
model its trace was drawn from, and fails on a stale copy of a model.
"""

import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

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


REPLAY_TEST = """package pkg
var demoCases = map[string]bool{
	"case-one": true, "case-two": true,
}
func TestDemoITF(t *testing.T) { dir := "testdata/demo-itf"; _ = dir }
"""


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class Replay(unittest.TestCase):
    """A replay's case is checked through its manifest to the model copy."""

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.root = root = Path(self.dir.name)
        (root / "spec").mkdir()
        (root / "spec" / "demo.qnt").write_text(MODEL)
        (root / "spec" / "other.qnt").write_text("module other {\n  run otherTest = init\n}\n")
        (root / "spec" / "user.qnt").write_text('module user {\n  import demo.* from "./demo"\n  run userTest = init\n}\n')
        self.pkg = root / "pkg"
        self.fixture = self.pkg / "testdata" / "demo-itf"
        (self.fixture / "sources").mkdir(parents=True)
        (self.pkg / "a_test.go").write_text(REPLAY_TEST)
        (self.fixture / "sources" / "demo.qnt").write_text(MODEL)
        cases = []
        for name in ("case-one", "case-two", "case-three"):
            (self.fixture / f"{name}.qnt").write_text('module trace {\n  import demo.* from "./sources/demo"\n}\n')
            (self.fixture / f"{name}.itf.json").write_text(json.dumps({"states": [name]}))
            cases.append({"name": name, "driver": f"{name}.qnt", "driver_sha256": digest(self.fixture / f"{name}.qnt"),
                          "trace": f"{name}.itf.json", "trace_sha256": digest(self.fixture / f"{name}.itf.json")})
        (self.fixture / "manifest.json").write_text(json.dumps({"model_sha256": digest(self.fixture / "sources" / "demo.qnt"),
                                                                "cases": cases}))
        patcher = patch.object(CHECK, "ITF_REPLAYS", {"TestDemoITF": ("testdata/demo-itf", "demoCases")})
        patcher.start()
        self.addCleanup(patcher.stop)

    def errors(self, rows):
        CHECK.sha256.cache_clear()
        CHECK.read_json.cache_clear()
        items = CHECK.model_items(self.root / "spec")
        tests = CHECK.go_tests(self.root, ["pkg/a_test.go"])
        table = "".join(f"| `{item}` | {status} | {named} | |\n" for item, status, named in rows)
        return "\n".join(CHECK.check(items, tests, CHECK.table_rows(table),
                                     lambda test, case: CHECK.replay_case(self.root, tests, test, case),
                                     CHECK.model_imports(self.root / "spec")))

    def rows(self, case="case-one", item="demo.fooBarTest", status="full"):
        rows = [("demo.fooBarTest", "gap", "—"), ("demo.doneWitness", "model-only", "—"), ("demoBroken", "model-only", "—"),
                ("other.otherTest", "gap", "—"), ("user.userTest", "gap", "—")]
        return [(i, status, f"`TestDemoITF/{case}`") if i == item else (i, s, n) for i, s, n in rows]

    def test_a_replayed_case_of_the_rows_model_passes(self):
        self.assertEqual(self.errors(self.rows()), "")
        # A model that imports the trace's model projects it too.
        self.assertEqual(self.errors(self.rows(item="user.userTest")), "")

    def test_a_case_the_test_does_not_replay_fails(self):
        # Named in the fixture, so the name check alone accepted it.
        self.assertIn("TestDemoITF does not replay 'case-three': demoCases leaves it out", self.errors(self.rows("case-three")))
        self.assertIn("TestDemoITF has no case 'case-four'", self.errors(self.rows("case-four")))

    def test_a_trace_driver_or_copy_that_differs_from_the_manifest_fails(self):
        (self.fixture / "case-one.itf.json").write_text("{}")
        self.assertIn("case-one.itf.json differs from the trace digest of 'case-one'", self.errors(self.rows()))
        (self.fixture / "case-two.qnt").write_text('module trace {\n  import demo.* from "./sources/demo"\n  // edited\n}\n')
        self.assertIn("case-two.qnt differs from the driver digest of 'case-two'", self.errors(self.rows("case-two")))
        (self.fixture / "sources" / "demo.qnt").write_text(MODEL + "// changed\n")
        self.assertIn("sources/demo.qnt is not the model copy", self.errors(self.rows("case-two")))

    def test_a_test_that_reads_another_fixture_fails(self):
        (self.pkg / "a_test.go").write_text(REPLAY_TEST.replace("demo-itf", "other-itf"))
        self.assertIn("TestDemoITF no longer reads testdata/demo-itf", self.errors(self.rows()))

    def test_a_full_row_replays_a_trace_of_its_own_model(self):
        self.assertIn("replays a trace of demo.qnt, which other.qnt neither imports nor is extended by",
                      self.errors(self.rows(item="other.otherTest")))
        self.assertEqual(self.errors(self.rows(item="other.otherTest", status="partial")), "")
        with patch.object(CHECK, "FINER", {"other.qnt": ("demo.qnt",)}):
            self.assertEqual(self.errors(self.rows(item="other.otherTest")), "")


class Pinned(unittest.TestCase):
    """Every copy of a model is declared current (identical) or frozen."""

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.root = root = Path(self.dir.name)
        (root / "spec").mkdir()
        (root / "spec" / "demo.qnt").write_text(MODEL)
        for copy in ("pkg/testdata/a/demo.qnt", "pkg/testdata/b/sources/demo.qnt", "pkg/testdata/a/driver.qnt"):
            (root / copy).parent.mkdir(parents=True, exist_ok=True)
            (root / copy).write_text(MODEL)
        self.files = ["spec/demo.qnt", "pkg/testdata/a/demo.qnt", "pkg/testdata/b/sources/demo.qnt", "pkg/testdata/a/driver.qnt"]

    def errors(self, *entries):
        copies = CHECK.pinned_copies(self.root, self.files)
        self.assertEqual(copies, ["pkg/testdata/a/demo.qnt", "pkg/testdata/b/sources/demo.qnt"])
        return "\n".join(CHECK.check_pinned(self.root, {"copies": list(entries)}, copies))

    def entry(self, copy="pkg/testdata/a/demo.qnt", status="current", **more):
        return dict(copy=copy, model="spec/demo.qnt", status=status, **more)

    def test_declared_copies_pass(self):
        (self.root / "pkg/testdata/b/sources/demo.qnt").write_text(MODEL + "// older\n")
        self.assertEqual(self.errors(self.entry(), self.entry("pkg/testdata/b/sources/demo.qnt", "frozen", reason="kept")), "")

    def test_a_copy_that_drifted_from_its_model_is_stale(self):
        (self.root / "spec" / "demo.qnt").write_text(MODEL + "// newer\n")
        errors = self.errors(self.entry(), self.entry("pkg/testdata/b/sources/demo.qnt"))
        self.assertIn("pkg/testdata/a/demo.qnt is stale: it differs from spec/demo.qnt", errors)
        self.assertIn("pkg/testdata/b/sources/demo.qnt is stale", errors)

    def test_every_copy_is_declared_once_and_exactly(self):
        self.assertIn("pkg/testdata/b/sources/demo.qnt: a copy of spec/demo.qnt that spec/pinned-models.json does not declare",
                      self.errors(self.entry()))
        errors = self.errors(self.entry(), self.entry(), self.entry("pkg/testdata/b/sources/demo.qnt", "frozen"),
                             self.entry("pkg/gone/demo.qnt"), self.entry("pkg/testdata/a/driver.qnt"),
                             self.entry("pkg/testdata/c/demo.qnt", status="pinned"))
        self.assertIn("pkg/testdata/a/demo.qnt is declared twice", errors)
        self.assertIn("pkg/testdata/b/sources/demo.qnt is identical to spec/demo.qnt: declare it current", errors)
        self.assertIn("pkg/testdata/b/sources/demo.qnt: a frozen copy needs its reason", errors)
        self.assertIn("pkg/gone/demo.qnt is not a tracked copy of a model", errors)
        self.assertIn("pkg/testdata/a/driver.qnt: its model must be the file of spec/ of the same name", errors)
        self.assertIn("pkg/testdata/c/demo.qnt: unknown status 'pinned'", errors)

    def test_the_repositorys_copies_are_declared(self):
        root = Path(__file__).resolve().parents[1]
        registry = json.loads((root / "spec" / "pinned-models.json").read_text())
        files = [p.relative_to(root).as_posix() for p in root.glob("internal/**/*.qnt")]
        self.assertEqual(CHECK.check_pinned(root, registry, CHECK.pinned_copies(root, files)), [])


if __name__ == "__main__":
    unittest.main()
