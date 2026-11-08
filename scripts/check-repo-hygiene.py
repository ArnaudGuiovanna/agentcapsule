#!/usr/bin/env python3
"""Stop new hygiene regressions in tracked files.

Two rules, each checked against a baseline of files that already exist:

* no tracked file may contain a personal absolute path such as /home/<user>;
* no Go source may be committed under _evidence/, where the verification runners
  write frozen source copies (Go tooling ignores `_` directories, git must too).

The baseline (scripts/hygiene-baseline.json) lists the offenders that predate
the rules. Fixing one is welcome and never fails the check. A file that is not
in the baseline fails. Regenerate the baseline with --update only to record a
deliberate, reviewed decision, never to silence a new offender.
"""
import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BASELINE = ROOT / "scripts" / "hygiene-baseline.json"
HOME = re.compile(rb"/home/[A-Za-z0-9_.-]+")


def tracked():
    out = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT, check=True, capture_output=True).stdout
    return [p for p in out.decode().split("\0") if p]


def scan():
    home, evidence_go = [], []
    for name in tracked():
        if name == "scripts/hygiene-baseline.json":
            continue
        if name.startswith("_evidence/") and name.endswith(".go"):
            evidence_go.append(name)
        path = ROOT / name
        if not path.is_file() or path.is_symlink():
            continue
        # The checker itself spells the pattern out in its own documentation.
        if name == "scripts/check-repo-hygiene.py":
            continue
        if HOME.search(path.read_bytes()):
            home.append(name)
    return sorted(home), sorted(evidence_go)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--update", action="store_true", help="rewrite the baseline from the current tree")
    args = parser.parse_args()
    home, evidence_go = scan()
    if args.update:
        BASELINE.write_text(json.dumps({"home_paths": home, "evidence_go": evidence_go}, indent=1) + "\n")
        print(f"baseline written: {len(home)} files with personal paths, {len(evidence_go)} evidence Go files")
        return 0
    base = json.loads(BASELINE.read_text())
    new_home = sorted(set(home) - set(base["home_paths"]))
    new_go = sorted(set(evidence_go) - set(base["evidence_go"]))
    for name in new_home:
        print(f"FAIL personal absolute path (/home/<user>) in new file: {name}")
    for name in new_go:
        print(f"FAIL Go source committed under _evidence/: {name}")
    fixed = (len(base["home_paths"]) - len(set(home) & set(base["home_paths"]))) + (
        len(base["evidence_go"]) - len(set(evidence_go) & set(base["evidence_go"])))
    print(f"hygiene: {len(new_home) + len(new_go)} new offender(s); {fixed} baseline entr(ies) already fixed")
    return 1 if new_home or new_go else 0


if __name__ == "__main__":
    sys.exit(main())
