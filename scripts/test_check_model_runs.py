#!/usr/bin/env python3
"""Unit tests of scripts/check-model-runs.py (audit finding A-10), with a fake
Quint: the comparison of a replayed trace with the pinned one, the commands,
the discovery of the fixtures' schedules, and what fails. CI's "models" job
runs the script with the real Quint.
"""

import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().with_name("check-model-runs.py")
SPEC = importlib.util.spec_from_file_location("check_model_runs", SCRIPT)
RUNS = importlib.util.module_from_spec(SPEC)
sys.dont_write_bytecode = True
SPEC.loader.exec_module(RUNS)

# A stand-in for Quint. `test` passes the runs named in FAKE_PASSED and exits
# FAKE_TEST_EXIT; `run` writes a trace whose state carries the first line of
# the model the driver imports, so the tests see which model it read.
FAKE_QUINT = r'''#!/usr/bin/env python3
import json, os, re, sys
from pathlib import Path
verb, path, flags = sys.argv[1], Path(sys.argv[2]), sys.argv[3:]
log = os.environ.get("FAKE_LOG")
if log:
    with open(log, "a") as f:
        f.write(json.dumps([os.getcwd()] + sys.argv[1:]) + "\n")
if verb == "test":
    for name in os.environ.get("FAKE_PASSED", "").split():
        print(f"    ok {name} passed 1 test(s)")
    sys.exit(int(os.environ.get("FAKE_TEST_EXIT", "0")))
imported = re.search(r'from\s+"\./([\w./-]+)"', path.read_text()).group(1)
model = (path.parent / (imported + ".qnt")).read_text().splitlines()[0]
out = next(f.split("=", 1)[1] for f in flags if f.startswith("--out-itf="))
states = [{"#meta": {"index": i}, "s": {"model": model, "step": i, "gained": True}} for i in range(int(os.environ.get("FAKE_STATES", "2")))]
Path(out).write_text(json.dumps({"#meta": {"source": str(path)}, "states": states}))
sys.exit(int(os.environ.get("FAKE_RUN_EXIT", "0")))
'''


class Compare(unittest.TestCase):
    def test_fields_the_model_gained_are_ignored(self):
        pinned = {"states": [{"s": {"a": 1, "m": {"#map": [[0, {"x": 1}]]}}}]}
        replayed = {"states": [{"s": {"a": 1, "b": 2, "m": {"#map": [[0, {"x": 1, "y": 0}]]}}, "pc": 3}]}
        self.assertIsNone(RUNS.compare(pinned, replayed))

    def test_a_changed_value_or_length_is_a_difference(self):
        pinned = {"states": [{"s": {"a": 1}}, {"s": {"a": 2}}]}
        self.assertEqual(RUNS.compare(pinned, {"states": [{"s": {"a": 1}}, {"s": {"a": 3}}]}), "state 1 differs (s)")
        self.assertEqual(RUNS.compare(pinned, {"states": [{"s": {"a": 1}}]}), "1 states, the pinned trace has 2")
        self.assertEqual(RUNS.compare({"states": [{"s": {"m": {"#set": [1, 2]}}}]}, {"states": [{"s": {"m": {"#set": [1]}}}]}),
                         "state 0 differs (s)")

    def test_the_replay_sets_its_own_backend_output_and_verbosity(self):
        command = ["node_modules/.bin/quint", "run", "quint/evidence/case.qnt", "--main=preparedTrace", "--backend=rust",
                   "--invariant=checked", "--out-itf=quint/evidence/case.itf.json", "--max-steps=7", "--verbosity=1"]
        self.assertEqual(RUNS.replay_flags(command), ["--main=preparedTrace", "--invariant=checked", "--max-steps=7"])

    def test_runs_are_grouped_by_module(self):
        items = {"a.oneTest": ("a.qnt", "run"), "a.twoTest": ("a.qnt", "run"), "b.x": ("b.qnt", "schedule"),
                 "c.doneWitness": ("c.qnt", "witness"), "d.threeTest": ("d.qnt", "run")}
        self.assertEqual(RUNS.run_modules(items), {("a.qnt", "a"): ["oneTest", "twoTest"], ("d.qnt", "d"): ["threeTest"]})


class Fixture(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.root = root = Path(self.dir.name)
        quint = root / RUNS.QUINT
        quint.parent.mkdir(parents=True)
        quint.write_text(FAKE_QUINT)
        quint.chmod(0o755)
        (root / "spec" / "demo.qnt").write_text("// current model\nmodule demo {}\n")
        self.fixture = root / "pkg" / "testdata" / "demo-itf"
        (self.fixture / "sources").mkdir(parents=True)
        (self.fixture / "sources" / "demo.qnt").write_text("// pinned copy\nmodule demo {}\n")
        (self.fixture / "case.qnt").write_text('module trace {\n  import demo.* from "./sources/demo"\n}\n')
        states = [{"#meta": {"index": i}, "s": {"model": "// current model", "step": i}} for i in range(2)]
        (self.fixture / "case.itf.json").write_text(json.dumps({"states": states}))
        self.case = {"name": "case", "driver": "case.qnt", "trace": "case.itf.json",
                     "command": ["node_modules/.bin/quint", "run", "elsewhere/case.qnt", "--main=preparedTrace", "--init=traceInit",
                                 "--step=traceStep", "--invariant=checked", "--backend=rust", "--max-steps=1",
                                 "--out-itf=elsewhere/case.itf.json", "--verbosity=1"],
                     "rejection_command": ["node_modules/.bin/quint", "test", "elsewhere/case.qnt", "--main=preparedTrace",
                                           "--backend=rust", "--max-samples=1"]}
        self.registry = {"copies": [{"copy": "pkg/testdata/demo-itf/sources/demo.qnt", "model": "spec/demo.qnt", "status": "frozen"}]}
        self.log = root / "quint.log"
        env = patch.dict(os.environ, FAKE_LOG=str(self.log))
        env.start()
        self.addCleanup(env.stop)

    def jobs(self, *cases):
        manifest = self.fixture / "manifest.json"
        manifest.write_text(json.dumps({"cases": list(cases)}))
        return RUNS.fixture_cases(self.root, self.registry, ["pkg/testdata/demo-itf/manifest.json"])

    def calls(self):
        return [json.loads(line) for line in self.log.read_text().splitlines()]

    def test_a_schedule_replays_on_the_current_model(self):
        jobs, errors = self.jobs(self.case, dict(self.case, name="negative", negative=True), {"name": "mbt", "trace": "x"})
        self.assertEqual((len(jobs), errors), (1, []))
        self.assertIsNone(RUNS.replay(self.root, jobs[0]))
        run, test = self.calls()
        self.assertEqual(run[1:2] + run[3:7], ["run", "--main=preparedTrace", "--init=traceInit", "--step=traceStep", "--invariant=checked"])
        self.assertEqual(run[7:9], ["--max-steps=1", "--backend=typescript"])
        self.assertTrue(run[9].startswith("--out-itf=") and run[10] == "--verbosity=1")
        self.assertTrue(run[2].endswith("/case.qnt") and not run[2].startswith(str(self.fixture)), "a copy of the driver")
        self.assertEqual(test[1:2] + test[3:], ["test", "--main=preparedTrace", "--max-samples=1", "--backend=typescript"])

    def test_a_schedule_that_no_longer_holds_fails(self):
        job, = self.jobs(self.case)[0]
        with patch.dict(os.environ, FAKE_RUN_EXIT="1"):
            self.assertIn("demo-itf/manifest.json: case: the schedule fails on demo.qnt (exit 1)", RUNS.replay(self.root, job))
        with patch.dict(os.environ, FAKE_STATES="3"):
            self.assertIn("gives other states: 3 states, the pinned trace has 2", RUNS.replay(self.root, job))
        with patch.dict(os.environ, FAKE_TEST_EXIT="1"):
            self.assertIn("a refusal no longer holds on demo.qnt", RUNS.replay(self.root, job))
        # A trace drawn from the pinned copy differs from the current model's.
        (self.root / "spec" / "demo.qnt").write_text("// newer model\nmodule demo {}\n")
        self.assertIn("state 0 differs (s)", RUNS.replay(self.root, job))

    def test_a_copy_missing_from_the_registry_fails(self):
        self.registry = {"copies": []}
        jobs, errors = self.jobs(self.case)
        self.assertEqual(jobs, [])
        self.assertEqual(errors, ["pkg/testdata/demo-itf/manifest.json: case: its model copy "
                                  "pkg/testdata/demo-itf/sources/demo.qnt is not in spec/pinned-models.json"])

    def test_every_run_of_a_module_must_pass(self):
        with patch.dict(os.environ, FAKE_PASSED="oneTest twoTest"):
            self.assertIsNone(RUNS.test_module(self.root, "demo.qnt", "demo", ["oneTest", "twoTest"]))
        with patch.dict(os.environ, FAKE_PASSED="oneTest"):
            self.assertIn("not passed: twoTest", RUNS.test_module(self.root, "demo.qnt", "demo", ["oneTest", "twoTest"]))
        with patch.dict(os.environ, FAKE_PASSED="oneTest", FAKE_TEST_EXIT="1"):
            self.assertIn("exit 1; not passed: none", RUNS.test_module(self.root, "demo.qnt", "demo", ["oneTest"]))
        call = self.calls()[0]
        self.assertEqual(call, [str(self.root / "spec"), "test", "--backend=typescript", "--main=demo", "demo.qnt"])


if __name__ == "__main__":
    unittest.main()
