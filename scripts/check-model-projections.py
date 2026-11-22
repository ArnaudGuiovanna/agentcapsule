#!/usr/bin/env python3
"""Check that every run and witness of the formal models is in spec/projections.md.

The table lists each run (`module.run`), each fixed witness schedule (a module
with `traceInit`, named by its module) and each simulation witness (a `val`
whose name ends in `Witness`, as `module.val`), with its status and the Go
tests that project it. The check recomputes the list from spec/*.qnt and the
Go test names from the tracked *_test.go files, and fails when:

* a run or witness of the models is not in the table, or is listed twice;
* the table lists one that the models no longer have;
* a status is not one of full, partial, model-only, pending, gap;
* a full or partial row names no Go test, or another row names one;
* a named Go test does not exist (for `TestX/case`, TestX must exist and
  `case` must appear in its package's tests or test data);
* a Go test named after a run exists (run `fooTest`, test `TestFoo`) and the
  run's row does not name it.

A case of an ITF replay (`TestPreimplementationP1ITF/<case>`, ...; see
ITF_REPLAYS) is checked through to the model (audit finding A-10). The test
must still read its fixture and select the case; the case must be in the
fixture's manifest, with its trace, driver and observations at the digests
the manifest pins; the driver's model copy must be at the manifest's model
digest; and in a full row, the copy must be of the row's model or of a model
it imports.

Each copy of a model under internal/**/testdata (a tracked .qnt named like a
model of spec/) must be declared in spec/pinned-models.json: `current`, byte
for byte the model of spec/, or `frozen`, an older revision kept with its
traces, with the reason. A copy that differs from its model without being
declared frozen is stale and fails the check. scripts/check-model-runs.py
replays every fixed schedule of the fixtures on the current models (CI).

It prints the count of each status.
"""
import argparse
import functools
import hashlib
import json
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PINNED = Path("spec") / "pinned-models.json"
PINNED_STATUSES = ("current", "frozen")
# The Go tests that replay the fixed schedules of a pinned model, with the
# fixture they read (from their package's directory) and the Go map of the
# cases they select (None: every case of the manifest).
ITF_REPLAYS = {
    "TestPreimplementationP1ITF": ("testdata/preimplementation-concurrency", "p1Cases"),
    "TestPreimplementationP3ITF": ("testdata/preimplementation-progress", "p3Cases"),
    "TestProtocolITFMicrosteps": ("testdata/protocol-itf", None),
}
# A manifest's case names its files, each with the key of its digest.
CASE_FILES = (("trace", ("trace_sha256", "sha256")), ("driver", ("driver_sha256",)),
              ("observations", ("observations_sha256",)))
IMPORT = re.compile(r'\bfrom\s+"\./([\w./-]+)"')
# A full projection may drive a finer schedule of its run (spec/projections.md):
# the trace of a model that extends the run's model. concurrent_protocol.qnt
# extends protocol_composition.qnt's transaction granularity (its header).
FINER = {"protocol_composition.qnt": ("concurrent_protocol.qnt",)}
STATUSES = ("full", "partial", "model-only", "pending", "gap")
MODULE = re.compile(r"^\s*module\s+(\w+)")
RUN = re.compile(r"^\s*run\s+(\w+)")
TRACE = re.compile(r"^\s*action\s+traceInit\b")
WITNESS = re.compile(r"^\s*val\s+(\w+Witness)\s*=")
TEST = re.compile(r"^func (Test\w+)\(", re.M)
ROW = re.compile(r"^\|\s*`([\w.]+)`\s*\|\s*([\w-]+)\s*\|([^|]*)\|")
NAMED = re.compile(r"`(Test[\w/.-]+)`")


def model_items(spec):
    """Return {id: (file, kind)} for every run and witness under spec/."""
    items = {}
    for path in sorted(spec.glob("*.qnt")):
        module = None
        for line in path.read_text().splitlines():
            line = line.split("//")[0]
            m = MODULE.match(line)
            if m:
                module = m.group(1)
                continue
            for pattern, kind in ((RUN, "run"), (WITNESS, "witness")):
                m = pattern.match(line)
                if m:
                    items.setdefault(f"{module}.{m.group(1)}", (path.name, kind))
            if TRACE.match(line):
                items.setdefault(module, (path.name, "schedule"))
    return items


def go_tests(root, files=None):
    """Return {TestName: package directory} for every Go test function."""
    if files is None:
        out = subprocess.run(["git", "ls-files", "-z", "*_test.go"], cwd=root,
                             check=True, capture_output=True).stdout
        files = [p for p in out.decode().split("\0") if p]
    tests = {}
    for name in files:
        path = root / name
        if path.is_file():
            for m in TEST.finditer(path.read_text(errors="replace")):
                tests.setdefault(m.group(1), path.parent)
    return tests


def table_rows(text):
    """Return [(line number, id, status, [Go tests])] from the Markdown table."""
    rows = []
    for number, line in enumerate(text.splitlines(), 1):
        m = ROW.match(line)
        if m:
            rows.append((number, m.group(1), m.group(2), NAMED.findall(m.group(3))))
    return rows


def case_exists(directory, case):
    for path in directory.rglob("*"):
        if path.is_file() and (path.suffix in (".go", ".json") or path.name.endswith(".qnt")):
            if case in path.read_text(errors="replace"):
                return True
    return False


def conventional(item):
    run = item.rsplit(".", 1)[-1]
    if not run.endswith("Test") or run == "guardTest":
        return None
    base = run[: -len("Test")]
    return "Test" + base[:1].upper() + base[1:]


def relative(path, root=ROOT):
    return path.relative_to(root) if path.is_relative_to(root) else path


@functools.cache
def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


@functools.cache
def read_json(path):
    return json.loads(path.read_text())


def model_imports(spec):
    """Return {model file: the model files it reads, itself included, transitively}."""
    direct = {p.name: {m.group(1).removesuffix(".qnt") + ".qnt" for m in IMPORT.finditer(p.read_text())}
              for p in spec.glob("*.qnt")}
    closure = {}
    for name in direct:
        seen, todo = {name}, [name]
        while todo:
            for other in direct.get(todo.pop(), ()):
                if other not in seen:
                    seen.add(other)
                    todo.append(other)
        closure[name] = seen
    return closure


def selection(package, name):
    """Return the keys of the Go map literal `var <name> = map[string]bool{...}`
    of a package's tests, or None when there is none."""
    pattern = re.compile(r"^var " + re.escape(name) + r" = map\[string\]bool\{(.*?)^\}", re.S | re.M)
    for path in sorted(package.glob("*_test.go")):
        m = pattern.search(path.read_text(errors="replace"))
        if m:
            return set(re.findall(r'"([\w-]+)":\s*true', m.group(1)))
    return None


def replay_case(root, tests, test, case):
    """Check that the Go test `test` replays the ITF case `case` of a pinned
    model copy. Return (errors, the model copy its trace was drawn from)."""
    fixture, selector = ITF_REPLAYS[test]
    package = tests[test]
    directory = package / fixture
    sources = "".join(p.read_text(errors="replace") for p in sorted(package.glob("*_test.go")))
    if f'"{fixture}"' not in sources:
        return [f"{test} no longer reads {fixture}"], None
    manifest_path = directory / "manifest.json"
    try:
        manifest = read_json(manifest_path)
    except (OSError, ValueError):
        return [f"{relative(manifest_path, root)} is missing or not JSON"], None
    cases = {c.get("name"): c for c in manifest.get("cases", [])}
    if case not in cases:
        return [f"{test} has no case {case!r} in {relative(manifest_path, root)}"], None
    if selector:
        selected = selection(package, selector)
        if selected is None:
            return [f"{test} selects its cases with {selector}, which {relative(package, root)} no longer has"], None
        if case not in selected:
            return [f"{test} does not replay {case!r}: {selector} leaves it out"], None
    entry, errors = cases[case], []
    for key, digests in CASE_FILES:
        if not entry.get(key):
            continue
        path = directory / entry[key]
        digest = next((entry[d] for d in digests if entry.get(d)), None)
        if not path.is_file():
            errors.append(f"{relative(path, root)}, the {key} of {case!r}, is missing")
        elif sha256(path) != digest:
            errors.append(f"{relative(path, root)} differs from the {key} digest of {case!r} in its manifest")
    driver = directory / entry.get("driver", "")
    if not entry.get("driver") or not driver.is_file():
        return errors + [f"{case!r} has no driver in {relative(manifest_path, root)}"], None
    m = IMPORT.search(driver.read_text())
    if not m:
        return errors + [f"{relative(driver, root)} imports no model"], None
    copy = directory / (m.group(1).removesuffix(".qnt") + ".qnt")
    if not copy.is_file() or sha256(copy) != (manifest.get("model_sha256") or manifest.get("source_sha256")):
        errors.append(f"{relative(copy, root)} is not the model copy {relative(manifest_path, root)} pins")
    return errors, copy


def pinned_copies(root, files):
    """Return the tracked .qnt files outside spec/ named like a model of spec/."""
    models = {p.name for p in (root / "spec").glob("*.qnt")}
    return sorted(f for f in files if not f.startswith("spec/") and Path(f).name in models)


def check_pinned(root, registry, copies):
    """Check spec/pinned-models.json against the tracked copies of the models."""
    errors, declared = [], set()
    for entry in registry.get("copies", []):
        copy, model, status = entry.get("copy", ""), entry.get("model", ""), entry.get("status")
        where = f"{PINNED}: {copy or '(no copy)'}"
        if copy in declared:
            errors.append(f"{where} is declared twice")
            continue
        declared.add(copy)
        if status not in PINNED_STATUSES:
            errors.append(f"{where}: unknown status {status!r} (one of {', '.join(PINNED_STATUSES)})")
        if model != "spec/" + Path(copy).name or not (root / model).is_file():
            errors.append(f"{where}: its model must be the file of spec/ of the same name, not {model!r}")
            continue
        if copy not in copies:
            errors.append(f"{where} is not a tracked copy of a model")
            continue
        same = (root / copy).read_bytes() == (root / model).read_bytes()
        if status == "current" and not same:
            errors.append(f"{where} is stale: it differs from {model}. Copy the model and regenerate the fixture's "
                          "traces, or declare the copy frozen with the reason")
        if status == "frozen" and same:
            errors.append(f"{where} is identical to {model}: declare it current")
        if status == "frozen" and not str(entry.get("reason", "")).strip():
            errors.append(f"{where}: a frozen copy needs its reason")
    for copy in copies:
        if copy not in declared:
            errors.append(f"{copy}: a copy of spec/{Path(copy).name} that {PINNED} does not declare (current or frozen)")
    return errors


def check(items, tests, rows, replay=None, imports=None):
    """Check the table's rows. replay(test, case) checks a case of an ITF
    replay (replay_case); imports is model_imports' result."""
    errors, seen = [], {}
    for number, item, status, named in rows:
        where = f"spec/projections.md:{number}"
        if item in seen:
            errors.append(f"{where}: {item} is already listed at line {seen[item]}")
            continue
        seen[item] = number
        if item not in items:
            errors.append(f"{where}: {item} is not a run or witness of the models")
        if status not in STATUSES:
            errors.append(f"{where}: unknown status {status!r} (one of {', '.join(STATUSES)})")
        if status in ("full", "partial") and not named:
            errors.append(f"{where}: a {status} projection must name its Go test")
        if status not in ("full", "partial") and named:
            errors.append(f"{where}: a {status} row names Go tests; make it partial or drop them")
        for test in named:
            name, _, case = test.partition("/")
            if name not in tests:
                errors.append(f"{where}: Go test {name} does not exist")
            elif case and replay and name in ITF_REPLAYS:
                problems, copy = replay(name, case)
                errors += [f"{where}: {p}" for p in problems]
                model = items.get(item, (None,))[0]
                own = {m for read in (imports or {}).get(model, {model}) for m in (read, *FINER.get(read, ()))}
                if copy and imports and status == "full" and model and copy.name not in own:
                    errors.append(f"{where}: {test} replays a trace of {copy.name}, which {model} neither imports "
                                  "nor is extended by; a full projection replays its own model or a finer one")
            elif case and not case_exists(tests[name], case):
                errors.append(f"{where}: {name} has no case {case!r} in {relative(tests[name])}")
        expected = conventional(item)
        if expected and expected in tests and expected not in [t.partition("/")[0] for t in named]:
            errors.append(f"{where}: {expected} is named after {item}; list it in its row")
    for item, (path, kind) in sorted(items.items()):
        if item not in seen:
            errors.append(f"spec/{path}: {kind} {item} is not in spec/projections.md")
    return errors


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--list", action="store_true", help="print every run and witness found in the models")
    args = parser.parse_args()
    items = model_items(ROOT / "spec")
    if args.list:
        for item, (path, kind) in sorted(items.items(), key=lambda x: x[1][0]):
            print(f"{path}\t{kind}\t{item}")
        return 0
    rows = table_rows((ROOT / "spec" / "projections.md").read_text())
    tests = go_tests(ROOT)
    errors = check(items, tests, rows, lambda test, case: replay_case(ROOT, tests, test, case), model_imports(ROOT / "spec"))
    files = subprocess.run(["git", "ls-files", "-z", "*.qnt"], cwd=ROOT, check=True, capture_output=True).stdout
    try:
        registry = read_json(ROOT / PINNED)
    except (OSError, ValueError) as error:
        errors.append(f"{PINNED}: {error}")
    else:
        errors += check_pinned(ROOT, registry, pinned_copies(ROOT, [f for f in files.decode().split("\0") if f]))
    for e in errors:
        print("FAIL", e)
    counts = Counter(status for _, _, status, _ in rows)
    print("model projections: " + ", ".join(f"{counts[s]} {s}" for s in STATUSES)
          + f"; {len(items)} runs and witnesses; {len(errors)} error(s)")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
