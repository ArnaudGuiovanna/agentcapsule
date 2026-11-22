#!/usr/bin/env python3
"""Check whether the inductive obligations detect the documented broken model choices."""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import tempfile

p = argparse.ArgumentParser(description=__doc__)
p.add_argument("solver", type=Path)
p.add_argument("--evidence", type=Path)
args = p.parse_args()
here = Path(__file__).resolve().parent
evidence = (args.evidence or here).resolve()
source = json.loads((evidence / "rules.json").read_text())
controls = [
    ("FENCE_OLD", False, "oldPrimaryFenced", "oldPrimaryResends"),
    ("NEW_EPOCH", False, "oldPrimaryFenced", "promote"),
    ("ROOT_ROLLBACK", True, "keyDestructionSurvives", "install"),
    ("DECIDED_REVOCATIONS", True, "revocationsSurvive", "finishRevocation"),
    ("DESTROY_DEGRADED", True, "keyDestructionSurvives", "destroyKey"),
    ("REPLAY_FIRST", False, "subjectsCopiedBack", "openApi"),
    ("HISTORY_GUARD", False, "lossGuarantees", "activate"),
    ("RECHECK", False, "executableFences", "activate"),
    ("ACK_EPOCH", False, "acksSound", "recordReceipt"),
    ("RETIRE_GUARD", False, "retiredBeforeInstall", "skipRetirement"),
    ("RAW_KEK", True, "erasedKeysUnavailable", "decryptBackup"),
]
report = []
for flag, value, property, action in controls:
    if not (source[flag]["kind"] == "bool" and source[flag]["value"] != value):
        raise ValueError("Source operator or argument shape changed in instance control")
    with tempfile.TemporaryDirectory() as d:
        w = Path(d)
        rules = w / "rules.json"
        rules.write_text(json.dumps(source | {flag: {"kind": "bool", "value": value}}))
        tool = "prove_components.py"
        run = subprocess.run(
            [
                sys.executable,
                "-B",
                str(here / tool),
                str(rules),
                str(args.solver.resolve()),
                str(w),
            ],
            capture_output=True,
            text=True,
        )
        out = w / property / "coverage.json"
        if not out.exists():
            raise RuntimeError(run.stdout + "\n" + run.stderr)
        observed = json.loads(out.read_text())["verdicts"][action]
        report.append(
            {
                "changed_instance_flag": flag,
                "value": value,
                "property": property,
                "action": action,
                "expected": "sat",
                "observed": observed,
            }
        )
(evidence / "projection-controls.json").write_text(json.dumps(report, indent=2) + "\n")
for r in report:
    print(r["changed_instance_flag"], r["property"], r["action"], r["observed"])
if any(r["observed"] != r["expected"] for r in report):
    sys.exit("Unexpected control result")
with tempfile.TemporaryDirectory() as d:
    w = Path(d)
    bad = subprocess.run(
        [
            sys.executable,
            "-B",
            str(here / "prove_components.py"),
            "--inconsistent-control",
            str(evidence / "rules.json"),
            str(args.solver.resolve()),
            str(w),
        ],
        capture_output=True,
        text=True,
    )
    caught = bad.returncode != 0 and "Inconsistent proof context" in bad.stderr
    (evidence / "vacuity-control.json").write_text(
        json.dumps(
            {
                "injected": "assert false in theory preamble",
                "expected": "qualification refuses inconsistent theory",
                "detected": caught,
                "exit": bad.returncode,
            },
            indent=2,
        )
        + "\n"
    )
    print("contradictory SMT assumptions detected", caught)
    if not caught:
        raise SystemExit("Vacuous proof accepted")
