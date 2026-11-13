#!/usr/bin/env python3
"""Check deploy/prometheus (OPS-02, REC-03): the alert rules and their unit tests.

Always: every agentcapsule_* metric the rules and tests use is registered by
the platform's code (internal/, cmd/) or declared by one of the textfile
scripts for node_exporter (TEXTFILE_SCRIPTS: base-backup freshness, volume
archive shipping, the standby's replay), so that a renamed metric cannot
leave an alert that never fires. For the scripts' metrics, every label the
rules and tests match must be one the script declares, with one of its
declared values. With --promtool (a promtool
executable) or --promtool-image (a Prometheus image pinned by digest, run
with Docker): promtool check rules, then promtool test rules on
alerts_test.yml.
"""

import argparse
import importlib.util
from pathlib import Path
import re
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
RULES = ROOT / "deploy/prometheus"
TEXTFILE_SCRIPTS = [ROOT / "deploy/backup/agentcapsule-backup-metrics.py", ROOT / "deploy/backup/agentcapsule-archive-ship.py",
                    ROOT / "deploy/standby/agentcapsule-standby-metrics.py"]


def textfile_metrics():
    """{name: {label: allowed values}} declared by the textfile scripts, read from their own declarations."""
    declared = {}
    sys.dont_write_bytecode = True  # no __pycache__ in deploy/
    for script in TEXTFILE_SCRIPTS:
        spec = importlib.util.spec_from_file_location(script.stem.replace("-", "_"), script)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        for name, (_, labels) in module.METRICS.items():
            if name in declared:
                raise SystemExit(f"{name} is declared by two textfile scripts")
            declared[name] = {label: set(module.LABELS[label]) for label in labels}
    return declared


def label_errors(declared):
    """Selectors and test series of the textfile's metrics that match a label or value it does not declare."""
    errors = []
    selector = re.compile(r"\b(agentcapsule_[a-z0-9_]+)\{([^}]*)\}")
    matcher = re.compile(r'([a-zA-Z_][a-zA-Z0-9_]*)\s*(=~|!=|!~|=)\s*"([^"]*)"')
    for name in ("alerts.yml", "alerts_test.yml"):
        for metric, labels in selector.findall((RULES / name).read_text()):
            if metric not in declared:
                continue
            for label, op, value in matcher.findall(labels):
                if label in ("job", "instance"):
                    continue  # set by Prometheus
                if label not in declared[metric]:
                    errors.append(f"{name}: {metric} has no label {label}")
                elif op in ("=", "!=") and value not in declared[metric][label]:
                    errors.append(f'{name}: {metric}{{{label}="{value}"}} is not a declared value')
    return errors


def registered_metrics():
    """Metric names registered in Go code: string literals passed to Counter, Gauge or Histogram."""
    names = set()
    pattern = re.compile(r'\.(?:Counter|Gauge|Histogram)\(\s*"(agentcapsule_[a-z0-9_]+)"')
    for base in ("internal", "cmd"):
        for path in (ROOT / base).rglob("*.go"):
            if not path.name.endswith("_test.go"):
                names.update(pattern.findall(path.read_text()))
    return names


def used_metrics():
    used = set()
    for name in ("alerts.yml", "alerts_test.yml"):
        for metric in re.findall(r"\b(agentcapsule_[a-z0-9_]+)", (RULES / name).read_text()):
            used.add(re.sub(r"_(bucket|sum|count)$", "", metric))
    return used


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--promtool", type=Path, help="promtool executable")
    p.add_argument("--promtool-image", help="Prometheus image pinned by digest (name@sha256:...), run with Docker")
    a = p.parse_args()
    if a.promtool and a.promtool_image:
        p.error("give --promtool or --promtool-image, not both")
    if a.promtool_image and "@sha256:" not in a.promtool_image:
        p.error("--promtool-image must be pinned by digest (name@sha256:...)")
    registered, textfile, used = registered_metrics(), textfile_metrics(), used_metrics()
    if registered & textfile.keys():
        print("metrics both registered and declared by a textfile script:", ", ".join(sorted(registered & textfile.keys())), file=sys.stderr)
        return 1
    unknown = sorted(used - registered - textfile.keys())
    if unknown:
        print("metrics used by the alerts but registered nowhere:", ", ".join(unknown), file=sys.stderr)
        return 1
    errors = label_errors(textfile)
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print(f"{len(used)} metrics used by the alerts: {len(used - textfile.keys())} registered by the code, "
          f"{len(used & textfile.keys())} declared by the textfile scripts")
    if a.promtool:
        promtool = [str(a.promtool.resolve())]
    elif a.promtool_image:
        if not shutil.which("docker"):
            p.error("--promtool-image needs Docker")
        promtool = ["docker", "run", "--rm", "--network", "none", "-v", f"{RULES}:/rules:ro", "-w", "/rules",
                    "--entrypoint", "promtool", a.promtool_image]
    else:
        print("promtool not run: give --promtool or --promtool-image")
        return 0
    for command in (["check", "rules", "alerts.yml"], ["test", "rules", "alerts_test.yml"]):
        result = subprocess.run(promtool + command, cwd=RULES, capture_output=True, text=True, timeout=300)
        print(result.stdout.strip())
        if result.returncode:
            print(result.stderr.strip(), file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
