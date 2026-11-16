#!/usr/bin/env python3
"""Check docs/acceptance.md against docs/product.md and the tests it cites (VAL-02).

docs/acceptance.md gives each MVP requirement of docs/product.md §4 a status
and the tests that prove its acceptance criterion, in tables whose rows start
with an ID: `| ID | ... | status | proof | missing |`. The check fails when:

* a requirement of docs/product.md §4 has no row, or has two;
* a row names a requirement ID that docs/product.md no longer has;
* a status is not one of met, partial, not met, needs KVM;
* a met row cites no test or campaign script;
* a link points to a file that does not exist;
* a link named after a Go test (`TestX`, or `TestX/case`) points to a file
  that does not define `func TestX(` (and, for a case, does not contain it),
  or one named after a Python test (`test_x`) to a file without `def test_x(`;
* a Go test named in backquotes anywhere in the page exists in no tracked
  *_test.go file.

It prints the count of each status.
"""
import argparse
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
STATUSES = ("met", "partial", "not met", "needs KVM")
REQUIREMENT = re.compile(r"^\|\s*([A-Z][A-Z0-9]{2}-\d{3})\s*\|")
ROW = re.compile(r"^\|\s*([A-Z][A-Z0-9]{1,3}-[A-Z0-9]{1,3})\s*\|")
LINK = re.compile(r"\[([^\]]+)\]\(([^)\s#]+)(?:#[^)]*)?\)")
NAMED = re.compile(r"`(Test[A-Za-z0-9_]+)(?:/[^`]*)?`")
GO_TEST = re.compile(r"^Test[A-Za-z0-9_]+(/\S+)?$")
PY_TEST = re.compile(r"^test_[a-z0-9_]+$")
TEST_FUNC = re.compile(r"^func (Test\w+)\(", re.M)


def requirements(product):
    """Return the requirement IDs of docs/product.md §4, in order."""
    ids, inside = [], False
    for line in product.splitlines():
        if line.startswith("## "):
            inside = line.startswith("## 4.")
            continue
        m = REQUIREMENT.match(line)
        if inside and m:
            ids.append(m.group(1))
    return ids


def rows(text):
    """Return [(line number, ID, status, proof cell, whole line)] of the tables."""
    out = []
    for number, line in enumerate(text.splitlines(), 1):
        m = ROW.match(line)
        if not m:
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        status = cells[2] if len(cells) > 2 else ""
        proof = cells[3] if len(cells) > 3 else ""
        out.append((number, m.group(1), status, proof, line))
    return out


def go_tests(root):
    out = subprocess.run(["git", "ls-files", "-z", "*_test.go"], cwd=root, check=True, capture_output=True).stdout
    names = set()
    for name in filter(None, out.decode().split("\0")):
        path = root / name
        if path.is_file():
            names.update(TEST_FUNC.findall(path.read_text(errors="replace")))
    return names


def check_link(page, number, text, target):
    """Return the problem of one link, or None."""
    where = f"docs/acceptance.md:{number}"
    path = (page.parent / target).resolve()
    if not path.exists():
        return f"{where}: {target} does not exist"
    if GO_TEST.match(text):
        name, _, case = text.partition("/")
        source = path.read_text(errors="replace") if path.is_file() else ""
        if not re.search(rf"^func {name}\(", source, re.M):
            return f"{where}: {target} does not define {name}"
        if case and case not in source:
            return f"{where}: {target} has no case {case!r} of {name}"
    elif PY_TEST.match(text):
        source = path.read_text(errors="replace") if path.is_file() else ""
        if not re.search(rf"^\s*def {text}\(", source, re.M):
            return f"{where}: {target} does not define {text}"
    return None


def proves(text, target):
    """Whether a link cites a test or a campaign script."""
    name = Path(target).name
    return bool(GO_TEST.match(text) or PY_TEST.match(text) or
                (name.startswith(("verify-", "test_")) and name.endswith(".py")))


def check(page, text, product_ids, tests):
    errors, seen = [], {}
    for number, line in enumerate(text.splitlines(), 1):
        for label, target in LINK.findall(line):
            if "://" in target:
                continue
            problem = check_link(page, number, label.strip("`"), target)
            if problem:
                errors.append(problem)
        for name in NAMED.findall(line):
            if name not in tests:
                errors.append(f"docs/acceptance.md:{number}: Go test {name} does not exist")
    for number, item, status, proof, line in rows(text):
        where = f"docs/acceptance.md:{number}"
        if item in seen:
            errors.append(f"{where}: {item} is already listed at line {seen[item]}")
            continue
        seen[item] = number
        if REQUIREMENT.match(line) and item not in product_ids:
            errors.append(f"{where}: {item} is not a requirement of docs/product.md §4")
        if status not in STATUSES:
            errors.append(f"{where}: unknown status {status!r} (one of {', '.join(STATUSES)})")
        if status == "met" and not any(proves(label.strip("`"), target) for label, target in LINK.findall(proof)):
            errors.append(f"{where}: {item} is met but cites no test or campaign script")
    for item in product_ids:
        if item not in seen:
            errors.append(f"docs/product.md: {item} has no row in docs/acceptance.md")
    return errors


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.parse_args()
    page = ROOT / "docs" / "acceptance.md"
    text = page.read_text()
    product_ids = requirements((ROOT / "docs" / "product.md").read_text())
    errors = check(page, text, product_ids, go_tests(ROOT))
    for e in errors:
        print("FAIL", e)
    counts = Counter(status for _, item, status, _, _ in rows(text) if item in product_ids)
    print("acceptance: " + ", ".join(f"{counts[s]} {s}" for s in STATUSES)
          + f" of {len(product_ids)} requirements; {len(errors)} error(s)")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
