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
                       blocking;
  --verify-runtime-images
                       the release's check of the three runtime images with
                       the OpenSSL backports (runtime_images.py verify): each
                       pinned image must be its pinned upstream base plus one
                       layer, and carry the build provenance of the
                       runtime-images workflow. Any failure, a missing tool
                       included, fails the scan.

A High or Critical finding fails the scan unless an entry of
scripts/vulnerability-allowlist.json covers it (same ID or alias, same
package, a target pattern that matches). An expired or malformed entry also
fails it; an entry that expires within release_tools.ALLOWLIST_WARNING_DAYS
gets a warning annotation. Lower severities are reported. Go findings carry no severity in the
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
RUNTIME_SPEC = importlib.util.spec_from_file_location("runtime_images", SCRIPTS / "runtime_images.py")
RUNTIME = importlib.util.module_from_spec(RUNTIME_SPEC)
RUNTIME_SPEC.loader.exec_module(RUNTIME)

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
            "purl": artifact.get("purl", ""),
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


def verify_backport_inventory(document, packages):
    """Require the qualified APK, its ownership of the file and its SHA-256."""
    owners = {(r["spdxElementId"], r["relatedSpdxElement"])
              for r in document.get("relationships", []) if r["relationshipType"] == "CONTAINS"}
    for name, expected in packages.items():
        artifacts = [p for p in document["packages"] if p["name"] == name]
        files = [f for f in document["files"] if f["fileName"].removeprefix("./") == expected["path"]]
        if len(artifacts) != 1 or len(files) != 1:
            raise ValueError("missing or ambiguous backport inventory for " + name)
        artifact, file = artifacts[0], files[0]
        purls = [ref["referenceLocator"] for ref in artifact.get("externalRefs", []) if ref["referenceType"] == "purl"]
        hashes = [v["checksumValue"] for v in file["checksums"] if v["algorithm"] == "SHA256"]
        if (purls != [expected["purl"]] or hashes != [expected["sha256"]]
                or (artifact["SPDXID"], file["SPDXID"]) not in owners):
            raise ValueError("OpenSSL backport verification failed for " + name)


def verified_backports(found, source, profile, qualification, out, env, cache):
    if profile is None:
        return [], found
    packages = qualification["profiles"][profile]
    fixed, remaining = [], []
    for finding in found:
        package = packages.get(finding["package"])
        if (finding["id"] in qualification["advisories"] and finding["type"] == "apk"
                and finding["version"] == qualification["version"] and package and finding["purl"] == package["purl"]):
            fixed.append({**finding, "file": package["path"], "sha256": package["sha256"],
                          "patch_commit": qualification["advisories"][finding["id"]]})
        else:
            remaining.append(finding)
    if fixed:
        if source.startswith("registry:"):
            inventory = out / (slug(source) + ".spdx.json")
            subprocess.run([str(TOOLS.tool("syft", cache)), "scan", source, "--platform", "linux/amd64",
                            "-q", "-o", "spdx-json=" + str(inventory)], env=env, check=True, timeout=1800)
        else:
            inventory = Path(source.removeprefix("sbom:"))
        verify_backport_inventory(json.loads(inventory.read_bytes()), packages)
    return fixed, remaining


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--sbom", action="append", default=[], type=Path)
    p.add_argument("--offline-image-index", type=Path, help="associate shipped OCI SBOMs with the exact pinned image policy")
    p.add_argument("--deploy-images", action="store_true")
    p.add_argument("--image", action="append", default=[])
    p.add_argument("--manifest", action="append", default=[], type=Path)
    p.add_argument("--dev-manifest", action="append", default=[], type=Path)
    p.add_argument("--verify-runtime-images", action="store_true",
                   help="refuse a runtime image without its upstream base and its workflow provenance")
    p.add_argument("--allowlist", type=Path, default=TOOLS.ALLOWLIST)
    p.add_argument("--cache", type=Path, default=TOOLS.default_cache())
    p.add_argument("--no-db-update", action="store_true", help="use the database already in the cache")
    p.add_argument("--output", required=True, type=Path, help="new output directory")
    a = p.parse_args(argv)

    policies = offline_image_policies(a.offline_image_index, a.sbom) if a.offline_image_index else {}
    qualification = json.loads((ROOT / "deploy/images/openssl/qualification.json").read_bytes())
    profiles = {"sbom:" + str(p.resolve()): qualification["harness_sboms"].get(p.name) for p in a.sbom}
    for ref, profile in qualification["registry_images"].items():
        profiles["registry:" + ref] = profile
    if a.offline_image_index:
        offline_refs = {r["sbom"]: r["ref"] for r in json.loads(a.offline_image_index.read_bytes())["images"]}
        for p in a.sbom:
            if p.name in offline_refs:
                profiles["sbom:" + str(p.resolve())] = qualification["registry_images"].get(offline_refs[p.name])
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
    if not targets and not unpinned and not manifests and not a.verify_runtime_images:
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
        "allowlist_warnings": TOOLS.allowlist_warnings(entries),
        "unpinned_images": unpinned,
        "targets": [],
    }
    failed = bool(problems or unpinned)
    if a.verify_runtime_images:
        try:
            images, refused = RUNTIME.verify()
        except (OSError, ValueError, KeyError) as error:
            images, refused = [], [f"runtime images: {error}"]
        summary["runtime_images"] = {"images": images, "problems": refused}
        failed |= bool(refused)
        for image in images:
            print(f"{'ok  ' if image['layers'] == image['provenance'] == 'verified' else 'FAIL'} runtime image "
                  f"{image['name']}: layers {image['layers']}, provenance {image['provenance']}")
        for problem in refused:
            print("RUNTIME IMAGE " + problem, file=sys.stderr)
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
        fixed, remaining = verified_backports(found, source, profiles.get(source), qualification, out, env, a.cache)
        blocked, allowed, other = TOOLS.apply_allowlist(
            remaining, entries, lambda f: blocking and f["severity"] in BLOCKING)
        counts = {s: sum(1 for f in found if f["severity"] == s) for s in SEVERITIES}
        summary["targets"].append({"name": name, "blocking": blocking, "packages": catalog_size(source),
                                   "counts": counts,
                                   "blocked": blocked, "allowlisted": allowed,
                                   "verified_backports": fixed,
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
    TOOLS.annotate("warning", summary["allowlist_warnings"])
    for image in unpinned:
        print("NOT PINNED BY DIGEST " + image, file=sys.stderr)
    print(f"{summary['status']}: {out / 'summary.json'}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
