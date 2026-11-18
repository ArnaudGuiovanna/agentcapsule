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

It prints the count of each status, and the rows still open (pending, gap).
"""
import argparse
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
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


def check(items, tests, rows):
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
            elif case and not case_exists(tests[name], case):
                errors.append(f"{where}: {name} has no case {case!r} in {tests[name].relative_to(ROOT) if tests[name].is_relative_to(ROOT) else tests[name]}")
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
    errors = check(items, go_tests(ROOT), rows)
    for e in errors:
        print("FAIL", e)
    counts = Counter(status for _, _, status, _ in rows)
    print("model projections: " + ", ".join(f"{counts[s]} {s}" for s in STATUSES)
          + f"; {len(items)} runs and witnesses; {len(errors)} error(s)")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
