#!/usr/bin/env python3
"""Check deploy/prometheus (OPS-02): the alert rules and their unit tests.

Always: every agentcapsule_* metric the rules and tests use is registered by
the platform's code (internal/, cmd/), so that a renamed metric cannot leave an
alert that never fires. With --promtool (a promtool executable) or
--promtool-image (a Prometheus image pinned by digest, run with Docker):
promtool check rules, then promtool test rules on alerts_test.yml.
"""

import argparse
from pathlib import Path
import re
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
RULES = ROOT / "deploy/prometheus"


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
    registered, used = registered_metrics(), used_metrics()
    unknown = sorted(used - registered)
    if unknown:
        print("metrics used by the alerts but registered nowhere:", ", ".join(unknown), file=sys.stderr)
        return 1
    print(f"{len(used)} metrics used by the alerts, all registered")
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
