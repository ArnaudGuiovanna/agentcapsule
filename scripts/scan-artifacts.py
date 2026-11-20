#!/usr/bin/env python3
"""Scan the release artifacts and the deploy images for known vulnerabilities.

grype, pinned by scripts/release-tools.json, scans:

  --sbom FILE          an SPDX SBOM written by release-sbom.py: what is
                       scanned is what is published (binaries, guest image,
                       harness packages);
  --deploy-images      the images in deploy/ YAML and the Keycloak image run
                       by the OIDC systemd unit, pulled by digest from their
                       registries without Docker;
  --image REF          another image, pinned by digest;
  --manifest FILE      the lock file of a shipped dependency set (Python
                       requirements, npm package-lock.json), cataloged by
                       syft first (development dependencies included);
  --dev-manifest FILE  the same for tools that do not ship: reported, never
                       blocking.

A High or Critical finding fails the scan unless an entry of
scripts/vulnerability-allowlist.json covers it (same ID or alias, same
package, a target pattern that matches). An expired or malformed entry also
fails it. Lower severities are reported. Go findings carry no severity in the
Go vulnerability database: audit-dependencies.py gates them by reachability.

The vulnerability database is updated once per run (grype checks its
digest) and its build date is recorded. The new --output directory receives
one grype report per target and summary.json.
"""

import hashlib
import argparse
import datetime
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys

SCRIPTS = Path(__file__).resolve().parent
ROOT = SCRIPTS.parent
SPEC = importlib.util.spec_from_file_location("release_tools", SCRIPTS / "release_tools.py")
TOOLS = importlib.util.module_from_spec(SPEC)
sys.dont_write_bytecode = True
SPEC.loader.exec_module(TOOLS)

BLOCKING = {"Critical", "High"}
SEVERITIES = ("Critical", "High", "Medium", "Low", "Negligible", "Unknown")
IMAGE_LINE = re.compile(r"^\s*(?:-\s*)?image:\s*['\"]?([^'\"\s#]+)", re.M)
PINNED = re.compile(r"@sha256:[0-9a-f]{64}$")


def deploy_images(root=ROOT):
    """(pinned images, unpinned images) named by the files under deploy/."""
    pinned, unpinned = {}, []
    for path in sorted((root / "deploy").rglob("*")):
        if not path.is_file() or path.suffix not in (".yml", ".yaml"):
            continue
        for match in IMAGE_LINE.finditer(path.read_text()):
            image = match.group(1)
            where = f"{path.relative_to(root)}"
            if PINNED.search(image):
                pinned.setdefault(image, where)
            else:
                unpinned.append(f"{where}: {image}")
    oidc = TOOLS.oidc_image(root)
    pinned.setdefault(oidc, str(TOOLS.OIDC_UNIT))
    return pinned, unpinned


def findings(report, target):
    """Normalize grype's JSON matches."""
    out = []
    for match in report.get("matches", []):
        vulnerability, artifact = match["vulnerability"], match["artifact"]
        fix = vulnerability.get("fix") or {}
        out.append({
            "source": "grype",
            "target": target,
            "id": vulnerability["id"],
            "aliases": sorted({r["id"] for r in match.get("relatedVulnerabilities") or [] if r.get("id")}
                              - {vulnerability["id"]}),
            "package": artifact["name"],
            "version": artifact.get("version", ""),
            "type": artifact.get("type", ""),
            "severity": vulnerability.get("severity") or "Unknown",
            "fix_state": fix.get("state") or "",
            "fixed_in": fix.get("versions") or [],
            "locations": sorted({loc.get("path", "") for loc in artifact.get("locations") or []})[:5],
        })
    return out


def catalog_size(source):
    """Packages in an SBOM given to grype (None for an image)."""
    if not source.startswith("sbom:"):
        return None
    data = json.loads(Path(source[len("sbom:"):]).read_text())
    return len(data.get("packages", data.get("artifacts", [])))


def target_name(kind, value):
    if kind == "sbom":
        name = Path(value).name
        return "sbom:" + (name[:-len(".spdx.json")] if name.endswith(".spdx.json") else name)
    if kind == "image":
        return "image:" + value.split("@", 1)[0]
    return f"{kind}:{value}"


def offline_image_policies(index, sboms):
    """Apply the image's existing policy to its byte-checked local inventory."""
    profile = json.loads((ROOT / "runtime/interop/profile.json").read_bytes())
    approved = dict(profile["services"])
    approved["oidc"] = TOOLS.oidc_image(ROOT)
    by_name = {path.name: path for path in sboms}
    policies = {}
    for image in json.loads(index.read_bytes())["images"]:
        service = image["service"]
        ref = approved.pop(service)
        filename = "oci-" + service + ".spdx.json"
        if image["ref"] != ref or not PINNED.search(ref) or image["sbom"] != filename:
            raise ValueError("offline inventory does not match the pinned service " + service)
        sbom = by_name[filename]
        with sbom.open("rb") as stream:
            if hashlib.file_digest(stream, "sha256").hexdigest() != image["sbom_sha256"]:
                raise ValueError("offline inventory digest differs for " + service)
        policies[target_name("sbom", sbom)] = target_name("image", ref)
    if approved:
        raise ValueError("missing offline image inventories")
    return policies


def slug(name):
    return re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip("_")


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--sbom", action="append", default=[], type=Path)
    p.add_argument("--offline-image-index", type=Path, help="associate shipped OCI SBOMs with the exact pinned image policy")
    p.add_argument("--deploy-images", action="store_true")
    p.add_argument("--image", action="append", default=[])
    p.add_argument("--manifest", action="append", default=[], type=Path)
    p.add_argument("--dev-manifest", action="append", default=[], type=Path)
    p.add_argument("--allowlist", type=Path, default=TOOLS.ALLOWLIST)
    p.add_argument("--cache", type=Path, default=TOOLS.default_cache())
    p.add_argument("--no-db-update", action="store_true", help="use the database already in the cache")
    p.add_argument("--output", required=True, type=Path, help="new output directory")
    a = p.parse_args(argv)

    policies = offline_image_policies(a.offline_image_index, a.sbom) if a.offline_image_index else {}
    targets = []  # (name, grype source, blocking)
    for sbom in a.sbom:
        targets.append((target_name("sbom", sbom), f"sbom:{sbom.resolve()}", True))
    unpinned = []
    if a.deploy_images:
        pinned, unpinned = deploy_images()
        for image in pinned:
            targets.append((target_name("image", image), f"registry:{image}", True))
    for image in a.image:
        if not PINNED.search(image):
            unpinned.append(f"--image: {image}")
            continue
        targets.append((target_name("image", image), f"registry:{image}", True))
    manifests = [(m, True) for m in a.manifest] + [(m, False) for m in a.dev_manifest]
    if not targets and not unpinned and not manifests:
        p.error("nothing to scan")

    out = a.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    entries, problems = TOOLS.load_allowlist(a.allowlist)
    grype = TOOLS.tool("grype", a.cache)
    env = TOOLS.quiet_env(a.cache)
    if manifests:
        syft = TOOLS.tool("syft", a.cache)
        for manifest, shipped in manifests:
            name = target_name("manifest" if shipped else "dev-manifest", manifest.resolve().relative_to(ROOT)
                               if manifest.resolve().is_relative_to(ROOT) else manifest)
            catalog = out / (slug(name) + ".syft.json")
            subprocess.run([str(syft), f"file:{manifest.resolve()}", "-q", "-o", f"syft-json={catalog}"],
                           env=dict(env, SYFT_JAVASCRIPT_INCLUDE_DEV_DEPENDENCIES="true"), check=True, timeout=600)
            targets.append((name, f"sbom:{catalog}", shipped))
    if not a.no_db_update:
        subprocess.run([str(grype), "db", "update"], env=env, check=True, timeout=1800,
                       stdout=subprocess.DEVNULL)
    env["GRYPE_DB_AUTO_UPDATE"] = "false"
    status = subprocess.run([str(grype), "db", "status", "-o", "json"], env=env, capture_output=True, text=True,
                            check=True).stdout
    summary = {
        "date": datetime.date.today().isoformat(),
        "grype": TOOLS.pins()["grype"]["version"],
        "database": json.loads(status),
        "allowlist": str(a.allowlist.relative_to(ROOT) if a.allowlist.resolve().is_relative_to(ROOT) else a.allowlist),
        "allowlist_problems": problems,
        "unpinned_images": unpinned,
        "targets": [],
    }
    failed = bool(problems or unpinned)
    for name, source, blocking in targets:
        report_path = out / (slug(name) + ".grype.json")
        command = [str(grype), source, "-o", f"json={report_path}", "-q"]
        if source.startswith("registry:"):
            command += ["--platform", "linux/amd64"]
        run = subprocess.run(command, env=env, capture_output=True, text=True, timeout=1800, check=False)
        if run.returncode:
            summary["targets"].append({"name": name, "error": (run.stderr or run.stdout)[-2000:]})
            failed = True
            print(f"ERROR {name}: grype failed", file=sys.stderr)
            continue
        found = findings(json.loads(report_path.read_text()), policies.get(name, name))
        blocked, allowed, other = TOOLS.apply_allowlist(
            found, entries, lambda f: blocking and f["severity"] in BLOCKING)
        counts = {s: sum(1 for f in found if f["severity"] == s) for s in SEVERITIES}
        summary["targets"].append({"name": name, "blocking": blocking, "packages": catalog_size(source),
                                   "counts": counts,
                                   "blocked": blocked, "allowlisted": allowed,
                                   "report": report_path.name})
        failed |= bool(blocked)
        print(f"{'FAIL' if blocked else 'ok  '} {name}: " +
              (", ".join(f"{counts[s]} {s.lower()}" for s in SEVERITIES if counts[s]) or "no finding") +
              (f"; {len(allowed)} allowlisted" if allowed else "") + ("" if blocking else " (not shipped, reported only)"))
        for f in blocked:
            print(f"     {f['severity']} {f['id']} in {f['package']} {f['version']}"
                  f" (fixed in {', '.join(f['fixed_in']) or 'no release yet'})")
    summary["unused_allowlist_entries"] = TOOLS.unused_entries(entries)
    summary["status"] = "failed" if failed else "passed"
    (out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    for problem in problems:
        print("ALLOWLIST " + problem, file=sys.stderr)
    for image in unpinned:
        print("NOT PINNED BY DIGEST " + image, file=sys.stderr)
    print(f"{summary['status']}: {out / 'summary.json'}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
