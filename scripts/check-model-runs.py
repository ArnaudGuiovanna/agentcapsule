#!/usr/bin/env python3
"""Run the formal models' runs, and replay the fixtures' schedules on the
current models (audit finding A-10). Needs Quint: `npm ci --prefix spec`.

scripts/check-model-projections.py checks names, digests and copies without
running anything. This script runs Quint with its TypeScript evaluator, which
downloads nothing:

* `quint test` of every module of spec/ that declares a run: every run must
  pass, so that each row of spec/projections.md names a behaviour the current
  model has;
* every fixed schedule of an ITF fixture (a manifest's case with a driver and
  the command that produced its trace), with the current model of spec/ in
  place of the fixture's copy (spec/pinned-models.json). The schedule must run
  to its end with its invariant holding, give the pinned trace's states on
  every field the trace has (a field the model has gained since is ignored),
  and its refusals (`rejection_command`) must still hold. A frozen copy is
  kept only while its schedules replay on the current model.

It exits 1 on any failure. CI runs it on every change (job "models").
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent.parent
QUINT = Path("spec") / "node_modules" / ".bin" / "quint"
TIMEOUT = 900
PASSED = re.compile(r"^\s*ok (\w+) passed", re.M)
# Flags of a fixture's command that this replay sets itself.
OWN_FLAGS = ("--backend", "--out-itf", "--verbosity")


def projections():
    spec = importlib.util.spec_from_file_location("check_model_projections", ROOT / "scripts" / "check-model-projections.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


CHECK = projections()


def run_modules(items):
    """Return {(model file, module): [run names]} from model_items' result."""
    modules = {}
    for item, (path, kind) in sorted(items.items()):
        if kind == "run":
            module, _, name = item.rpartition(".")
            modules.setdefault((path, module), []).append(name)
    return modules


def project(pinned, replayed):
    """Return replayed restricted to the shape of pinned: the record fields a
    model gained after the trace was pinned are dropped, at any depth."""
    if isinstance(pinned, dict) and isinstance(replayed, dict):
        return {key: project(value, replayed.get(key)) for key, value in pinned.items()}
    if isinstance(pinned, list) and isinstance(replayed, list) and len(pinned) == len(replayed):
        return [project(a, b) for a, b in zip(pinned, replayed)]
    return replayed


def compare(pinned, replayed):
    """Return the first difference between two ITF traces' states, or None."""
    pinned, replayed = pinned.get("states", []), replayed.get("states", [])
    if len(pinned) != len(replayed):
        return f"{len(replayed)} states, the pinned trace has {len(pinned)}"
    for index, (a, b) in enumerate(zip(pinned, replayed)):
        if project(a, b) != a:
            changed = sorted(k for k in a if project(a[k], b.get(k)) != a[k])
            return f"state {index} differs ({', '.join(changed)})"
    return None


def replay_flags(command):
    """The flags of a fixture's Quint command (after the verb and the input),
    without those the replay sets itself."""
    return [arg for arg in command[3:] if not arg.startswith(OWN_FLAGS)]


def fixture_cases(root, registry, manifests):
    """Return (jobs, errors): one job per fixed schedule of the fixtures."""
    models = {entry["copy"]: entry["model"] for entry in registry.get("copies", [])}
    jobs, errors = [], []
    for manifest_path in manifests:
        directory = (root / manifest_path).parent
        manifest = json.loads((root / manifest_path).read_text())
        for case in manifest.get("cases", []):
            if case.get("negative") or not case.get("driver") or not case.get("command"):
                continue
            where = f"{manifest_path}: {case['name']}"
            driver = directory / case["driver"]
            m = CHECK.IMPORT.search(driver.read_text())
            if not m:
                errors.append(f"{where}: {case['driver']} imports no model")
                continue
            imported = m.group(1).removesuffix(".qnt") + ".qnt"
            copy = (directory / imported).relative_to(root).as_posix()
            if copy not in models:
                errors.append(f"{where}: its model copy {copy} is not in spec/pinned-models.json")
                continue
            jobs.append(dict(name=where, driver=driver, imported=imported, model=root / models[copy],
                             command=case["command"], rejection=case.get("rejection_command"),
                             trace=directory / case["trace"]))
    return jobs, errors


def quint(root, argv, cwd):
    try:
        p = subprocess.run([str((root / QUINT).resolve()), *argv], cwd=cwd, capture_output=True, text=True, timeout=TIMEOUT)
        return p.returncode, p.stdout + p.stderr
    except subprocess.TimeoutExpired:
        return 124, f"timed out after {TIMEOUT} s"


def tail(output, lines=12):
    return "\n".join(output.strip().splitlines()[-lines:])


def test_module(root, path, module, runs):
    code, output = quint(root, ["test", "--backend=typescript", f"--main={module}", path], root / "spec")
    missing = sorted(set(runs) - set(PASSED.findall(output)))
    if code or missing:
        return f"quint test {module} ({path}): exit {code}; not passed: {', '.join(missing) or 'none'}\n{tail(output)}"
    return None


def replay(root, job):
    with tempfile.TemporaryDirectory(prefix="model-replay-") as work:
        work = Path(work)
        driver = work / job["driver"].name
        shutil.copyfile(job["driver"], driver)
        model = work / job["imported"]
        model.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(job["model"], model)
        verb = job["command"][1]
        out = work / "replayed.itf.json"
        code, output = quint(root, [verb, str(driver), *replay_flags(job["command"]), "--backend=typescript",
                                    f"--out-itf={out}", "--verbosity=1"], work)
        if code or not out.is_file():
            return f"{job['name']}: the schedule fails on {job['model'].name} (exit {code})\n{tail(output)}"
        difference = compare(json.loads(job["trace"].read_text()), json.loads(out.read_text()))
        if difference:
            return f"{job['name']}: on {job['model'].name} the schedule gives other states: {difference}"
        if job["rejection"]:
            code, output = quint(root, ["test", str(driver), *replay_flags(job["rejection"]), "--backend=typescript"], work)
            if code:
                return f"{job['name']}: a refusal no longer holds on {job['model'].name} (exit {code})\n{tail(output)}"
    return None


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--jobs", type=int, default=min(4, os.cpu_count() or 1), help="Quint processes at once")
    args = parser.parse_args()
    if not (ROOT / QUINT).is_file():
        print(f"FAIL {QUINT} is missing: run npm ci --prefix spec")
        return 1
    modules = run_modules(CHECK.model_items(ROOT / "spec"))
    manifests = [f for f in subprocess.run(["git", "ls-files", "-z", "internal/**/testdata/*/manifest.json"], cwd=ROOT,
                                           check=True, capture_output=True).stdout.decode().split("\0") if f]
    jobs, errors = fixture_cases(ROOT, json.loads((ROOT / CHECK.PINNED).read_text()), manifests)
    work = [lambda m=m, r=r: test_module(ROOT, m[0], m[1], r) for m, r in modules.items()]
    work += [lambda j=j: replay(ROOT, j) for j in jobs]
    with ThreadPoolExecutor(max(1, args.jobs)) as pool:
        errors += [e for e in pool.map(lambda f: f(), work) if e]
    for e in errors:
        print("FAIL", e)
    runs = sum(len(r) for r in modules.values())
    print(f"model runs: {runs} runs in {len(modules)} modules; {len(jobs)} fixture schedules replayed on the current "
          f"models; {len(errors)} failure(s)")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
