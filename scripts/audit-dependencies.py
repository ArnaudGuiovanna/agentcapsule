#!/usr/bin/env python3
"""Audit the dependencies: known vulnerabilities in reachable code, and licenses.

1. Vulnerabilities. govulncheck, pinned by scripts/tools/go.sum, checks every
   Go module of the repository (MODULES below) on a frozen copy of the
   sources that git tracks or does not ignore. It fails on a vulnerability
   whose vulnerable function the code calls (govulncheck's symbol level),
   unless an entry of scripts/vulnerability-allowlist.json covers it. A vulnerability in an
   imported package or a required module that the code does not call is
   reported, never blocking. The Dagger module and the audit's own tools are
   checked at module level only: their code does not ship.

2. Licenses. Every Go module linked into a shipped program (SHIPPED below)
   and every Python package of a shipped harness example
   (PYTHON_REQUIREMENTS) must be under licenses that scripts/license-policy.json
   allows: permissive licenses compatible with redistribution under MIT.
   syft, pinned by scripts/release-tools.json, reads them from each module's
   license files in the module cache, and from PyPI for Python packages. A
   module whose files name no license needs a "declared" entry with its
   evidence; a license outside the list needs an "accepted" entry with its
   reason. Otherwise the audit fails.

With --release (the release workflow), the allowlist does not cover a
vulnerability the code calls: a release waits for its fix (ADR 013).

The new --output directory receives summary.json, govulncheck's JSON per
module, licenses.json (the inventory) and third-party-licenses.txt: the
license and notice files of every linked module, which a binary release must
carry.
"""

import argparse
import datetime
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

SCRIPTS = Path(__file__).resolve().parent
ROOT = SCRIPTS.parent
SPEC = importlib.util.spec_from_file_location("release_tools", SCRIPTS / "release_tools.py")
TOOLS = importlib.util.module_from_spec(SPEC)
sys.dont_write_bytecode = True
SPEC.loader.exec_module(TOOLS)

POLICY = SCRIPTS / "license-policy.json"
STATIC_TAGS = "netgo,osusergo,sqlite_omit_load_extension"
# (module directory, govulncheck arguments, scan level, blocking, what it is)
MODULES = (
    (".", ["./..."], "symbol", True, "the platform: cmd/, internal/, examples/"),
    ("runtime/slimbridge", ["./..."], "symbol", True, "the SLIM bridge"),
    ("runtime/interop/probe", ["-test", "-tags=interop_services", "./..."], "symbol", True,
     "the interoperability probes (tests only)"),
    ("runtime/interop/a2aslim", ["-test", "-tags=interop_services", "./..."], "symbol", True,
     "the A2A over SLIM probe (tests only)"),
    (".dagger", [], "module", False, "the Dagger module: build tooling, its generated client is not in the repository"),
    ("scripts/tools", [], "module", False, "the audit's own tools"),
)
# (module directory, packages, build tags) linked into what a release ships.
SHIPPED = (
    (".", ["./cmd/agentcapsule-api", "./cmd/agentcapsule-worker", "./cmd/agentcapsule-admin",
           "./cmd/agentcapsule-authority", "./cmd/agentcapsule-harness", "./cmd/capsule-adapter",
           "./cmd/capsule-init", "./cmd/capsule-echo", "./examples/a2a-agent"], ("", STATIC_TAGS)),
    ("runtime/slimbridge", ["."], ("",)),
)
PYTHON_REQUIREMENTS = ("examples/adapted-agent/requirements.txt",)
LICENSE_FILE = re.compile(r"^(LICEN[CS]E|COPYING|NOTICE|PATENTS)([.-].*)?$", re.I)
SPDX_ID = re.compile(r"^[A-Za-z0-9.+-]+$")


def source_files():
    """The tracked files and the new files git does not ignore, as in the working tree."""
    out = subprocess.run(["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"], cwd=ROOT,
                         capture_output=True, check=True).stdout
    return sorted({name for name in out.decode().split("\0") if name})


def freeze(target):
    """Copy the sources to target: untracked local files (evidence, caches) stay out."""
    for name in source_files():
        source = ROOT / name
        if not source.is_file() or source.is_symlink():
            continue
        destination = target / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)


def go_env(go, native_tools):
    env = dict(os.environ, GOTOOLCHAIN="local", GOWORK="off", GOFLAGS="-mod=readonly")
    env["PATH"] = f"{Path(go).resolve().parent}:{env.get('PATH', '')}"
    if native_tools:
        env["CGO_CFLAGS"] = f"-I{Path(native_tools).resolve() / 'usr/include'}"
    return env


# --- govulncheck ----------------------------------------------------------------

def govulncheck_findings(stream, target):
    """Normalize govulncheck's JSON stream: one finding per (vulnerability, module), at its deepest level."""
    decoder, text, index = json.JSONDecoder(), stream.strip(), 0
    osv, found = {}, {}
    levels = {"module": 0, "package": 1, "symbol": 2}
    while index < len(text):
        message, end = decoder.raw_decode(text, index)
        index = end
        while index < len(text) and text[index].isspace():
            index += 1
        if "osv" in message and isinstance(message["osv"], dict):
            osv[message["osv"]["id"]] = message["osv"]
        elif "finding" in message:
            finding = message["finding"]
            frame = finding["trace"][0]
            level = "symbol" if frame.get("function") else "package" if frame.get("package") else "module"
            key = (finding["osv"], frame.get("module", ""))
            current = found.get(key)
            if current is None or levels[level] > levels[current["reachable"]]:
                call = ""
                if level == "symbol" and len(finding["trace"]) > 1:
                    caller = finding["trace"][-1]
                    position = caller.get("position") or {}
                    call = f"{caller.get('package', '')}.{caller.get('function', '')}" + (
                        f" ({Path(position.get('filename', '')).name}:{position.get('line', '')})" if position else "")
                found[key] = {"source": "govulncheck", "target": target, "id": finding["osv"],
                              "package": frame.get("module", ""), "version": frame.get("version", ""),
                              "fixed_in": [finding["fixed_version"]] if finding.get("fixed_version") else [],
                              "reachable": level, "example_call": call}
    for finding in found.values():
        entry = osv.get(finding["id"], {})
        finding["aliases"] = sorted(entry.get("aliases", []))
        finding["summary"] = entry.get("summary", "")
    return sorted(found.values(), key=lambda f: (f["id"], f["package"]))


def vulnerability_gate(found, entries, blocking, release):
    """(blocked, allowlisted, not called). A release ignores the allowlist: it waits for the fix."""
    return TOOLS.apply_allowlist(found, [] if release else entries,
                                 lambda f: blocking and f["reachable"] == "symbol")


def run_govulncheck(govulncheck, sources, out, env, entries, release=False):
    results, failed = [], False
    for directory, arguments, level, blocking, what in MODULES:
        module_dir = sources / directory
        if level == "module":
            # Module level needs only the requirement graph: check it on a stub package, so that
            # code generated outside the repository (the Dagger client) is not needed.
            stub = out / "stubs" / directory.replace("/", "_")
            stub.mkdir(parents=True)
            for name in ("go.mod", "go.sum"):
                shutil.copy2(module_dir / name, stub / name)
            (stub / "main.go").write_text("package main\n\nfunc main() {}\n")
            module_dir = stub
        command = [str(govulncheck), "-format", "json", "-scan", level, *arguments]
        run = subprocess.run(command, cwd=module_dir, env=env, capture_output=True, text=True, timeout=1800, check=False)
        name = directory.replace("/", "_").strip(".") or "root"
        (out / f"govulncheck-{name}.json").write_text(run.stdout)
        if run.returncode:
            results.append({"module": directory, "what": what, "error": run.stderr[-2000:]})
            failed = True
            print(f"ERROR {directory}: govulncheck failed: {run.stderr.strip()[-300:]}", file=sys.stderr)
            continue
        found = govulncheck_findings(run.stdout, directory)
        blocked, allowed, other = vulnerability_gate(found, entries, blocking, release)
        failed |= bool(blocked)
        results.append({"module": directory, "what": what, "scan": level, "blocking": blocking,
                        "blocked": blocked, "allowlisted": allowed, "not_called": other})
        print(f"{'FAIL' if blocked else 'ok  '} govulncheck {directory}: {len(blocked)} called and not allowlisted, "
              f"{len(allowed)} called and allowlisted, {len(other)} not called"
              + ("" if blocking else " (module level, reported only)"))
        for f in blocked:
            print(f"     {f['id']} in {f['package']} {f['version']} (fixed in {', '.join(f['fixed_in']) or '?'}): "
                  f"{f['summary']}; called from {f['example_call']}")
    return results, failed


# --- licenses ---------------------------------------------------------------------

def linked_modules(go, sources, env):
    """{(path, version): module directory} of the modules linked into the shipped programs."""
    modules = {}
    template = "{{with .Module}}{{if not .Main}}{{.Path}}\t{{.Version}}\t{{.Dir}}" \
               "{{with .Replace}}\t{{.Path}}\t{{.Version}}\t{{.Dir}}{{end}}{{end}}{{end}}"
    for directory, packages, tag_sets in SHIPPED:
        for tags in tag_sets:
            command = [str(go), "list", "-deps", "-f", template] + ([f"-tags={tags}"] if tags else []) + packages
            out = subprocess.run(command, cwd=sources / directory, env=env, capture_output=True, text=True,
                                 check=True, timeout=900).stdout
            for line in out.splitlines():
                fields = line.split("\t")
                if len(fields) in (3, 6):
                    # A replaced module's files (its licenses) are the replacement's.
                    modules[(fields[0], fields[1])] = fields[5] if len(fields) == 6 else fields[2]
    return modules


def syft_licenses(syft, source, env, extra=()):
    out = subprocess.run([str(syft), "scan", source, "-q", "-o", "syft-json", *extra], env=env, capture_output=True,
                         text=True, check=True, timeout=900).stdout
    found = {}
    for artifact in json.loads(out).get("artifacts", []):
        values = [entry.get("spdxExpression") or entry.get("value") or "" for entry in artifact.get("licenses") or []]
        found[(artifact["name"].lower() if artifact.get("type") == "python" else artifact["name"], artifact["version"])] = values
    return found


def expression_allowed(expression, allowed):
    """True when an SPDX expression leaves a choice, or a combination, of allowed licenses."""
    text = expression.replace("(", " ").replace(")", " ")
    for alternative in re.split(r"\s+OR\s+", text.strip()):
        terms = [t.strip() for t in re.split(r"\s+AND\s+", alternative) if t.strip()]
        if terms and all(t.split(" WITH ")[0] in allowed for t in terms):
            return True
    return False


def is_expression(value):
    """True for an SPDX license expression; false for syft's digest of an unrecognized license text."""
    terms = re.split(r"\s+(?:AND|OR|WITH)\s+", value.replace("(", " ").replace(")", " ").strip())
    return bool(value) and not value.startswith("sha256:") and all(SPDX_ID.match(t) for t in terms)


def license_decision(name, values, policy):
    """(status, licenses, note) of one package under the policy."""
    allowed = set(policy["allowed"])
    classified = sorted({v for v in values if is_expression(v)})
    unclassified = sorted({v for v in values if v and not is_expression(v)})
    declared = {d["package"]: d for d in policy.get("declared", [])}
    accepted = {(a["package"], a["license"]) for a in policy.get("accepted", [])}
    if not classified:
        if name in declared:
            return "allowed", [declared[name]["license"]], "declared: " + declared[name]["evidence"]
        return "unknown", [], "no license file found: add a declared entry with its evidence"
    refused = [v for v in classified if not expression_allowed(v, allowed) and (name, v) not in accepted]
    note = ("unclassified license text also present" if unclassified else "")
    if refused:
        return "refused", classified, f"not on the allowed list: {', '.join(refused)}"
    if any((name, v) in accepted for v in classified):
        note = "; ".join(filter(None, [note, "accepted: " + ", ".join(
            a["reason"] for a in policy["accepted"] if a["package"] == name)]))
    return "allowed", classified, note


# Native code in the release binaries, which no Go module describes.
NATIVE_NOTICES = """\
==============================================================================
Native code
==============================================================================
agentcapsule-slim-bridge links the SLIM native library (slim-bindings, see
runtime/interop/profile.json), under Apache-2.0, as its repository states.
Its own Rust dependencies are not listed here.

capsule-adapter, which the audit builds but a release does not publish (ADR
013), links the GNU C Library statically (LGPL-2.1-or-later): the build host's
libc6-dev, whose version its SBOM names. The published binaries link the
host's C library dynamically and, for agentcapsule-worker, libcryptsetup.
"""


def license_texts(goroot, modules, declared):
    parts = ["Third-party licenses of the Agent Capsule release binaries\n",
             "Each section holds the license and notice files of one Go module linked into a release binary.\n"]
    sections = [("Go standard library and runtime", "", Path(goroot))]
    sections += [(f"{path} {version}", path, Path(folder)) for (path, version), folder in sorted(modules.items())]
    for title, path, folder in sections:
        files = sorted(f for f in folder.iterdir() if f.is_file() and LICENSE_FILE.match(f.name)) if folder.is_dir() else []
        parts.append("=" * 78 + f"\n{title}\n" + "=" * 78 + "\n")
        if not files and path in declared:
            parts.append(f"No license file in the module. Its repository states {declared[path]['license']}: "
                         f"{declared[path]['evidence']}\n\n")
        elif not files:
            parts.append("No license file in the module.\n\n")
        for f in files:
            parts.append(f"--- {f.name} ---\n{f.read_text(errors='replace').rstrip()}\n\n")
    parts.append(NATIVE_NOTICES)
    return "".join(parts)


def run_licenses(go, syft, sources, out, env, policy):
    modules = linked_modules(go, sources, env)
    gomodcache = subprocess.run([str(go), "env", "GOMODCACHE"], env=env, capture_output=True, text=True,
                                check=True).stdout.strip()
    syft_env = dict(TOOLS.quiet_env(TOOLS.default_cache()), SYFT_GOLANG_SEARCH_LOCAL_MOD_CACHE_LICENSES="true",
                    SYFT_GOLANG_LOCAL_MOD_CACHE_DIR=gomodcache)
    detected = {}
    for directory, _, _ in SHIPPED:
        detected.update(syft_licenses(syft, f"file:{sources / directory / 'go.mod'}", syft_env))
    inventory = []
    for (path, version), folder in sorted(modules.items()):
        status, licenses, note = license_decision(path, detected.get((path, version), []), policy)
        inventory.append({"ecosystem": "go", "package": path, "version": version, "status": status,
                          "licenses": licenses, "note": note})
    for requirements in PYTHON_REQUIREMENTS:
        found = syft_licenses(syft, f"file:{sources / requirements}", syft_env, ["--enrich", "python"])
        for (name, version), values in sorted(found.items()):
            status, licenses, note = license_decision(name, values, policy)
            inventory.append({"ecosystem": "python", "shipped_in": requirements, "package": name, "version": version,
                              "status": status, "licenses": licenses, "note": note})
    goroot = subprocess.run([str(go), "env", "GOROOT"], env=env, capture_output=True, text=True, check=True).stdout.strip()
    declared = {d["package"]: d for d in policy.get("declared", [])}
    (out / "third-party-licenses.txt").write_text(license_texts(goroot, modules, declared))
    (out / "licenses.json").write_text(json.dumps(inventory, indent=2) + "\n")
    problems = [i for i in inventory if i["status"] != "allowed"]
    print(f"{'FAIL' if problems else 'ok  '} licenses: {len(inventory)} packages, {len(problems)} not allowed")
    for item in problems:
        print(f"     {item['ecosystem']} {item['package']} {item['version']}: {item['status']}, {item['note']}")
    return inventory, problems


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--go", required=True, type=Path, help="Go executable of the pinned version")
    p.add_argument("--native-tools", type=Path, help="directory whose usr/include holds the libcryptsetup headers")
    p.add_argument("--allowlist", type=Path, default=TOOLS.ALLOWLIST)
    p.add_argument("--policy", type=Path, default=POLICY)
    p.add_argument("--cache", type=Path, default=TOOLS.default_cache())
    p.add_argument("--skip-licenses", action="store_true", help="vulnerabilities only (no network to PyPI)")
    p.add_argument("--release", action="store_true", help="refuse a called vulnerability even when allowlisted")
    p.add_argument("--output", required=True, type=Path, help="new output directory")
    a = p.parse_args(argv)

    out = a.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    sources = out / "sources"
    freeze(sources)
    env = go_env(a.go, a.native_tools)
    entries, problems = TOOLS.load_allowlist(a.allowlist)
    govulncheck = TOOLS.govulncheck(a.go, a.cache)
    summary = {"date": datetime.date.today().isoformat(), "govulncheck": TOOLS.govulncheck_version(),
               "go": subprocess.run([str(a.go), "version"], env=env, capture_output=True, text=True).stdout.strip(),
               "allowlist_problems": problems}
    results, failed = run_govulncheck(govulncheck, sources, out, env, entries, a.release)
    summary["release"] = a.release
    summary["vulnerabilities"] = results
    failed |= bool(problems)
    if not a.skip_licenses:
        policy = json.loads(a.policy.read_text())
        inventory, refused = run_licenses(a.go, TOOLS.tool("syft", a.cache), sources, out, env, policy)
        summary["licenses"] = {"packages": len(inventory), "not_allowed": refused}
        failed |= bool(refused)
    else:
        summary["licenses"] = "not_run"
    summary["unused_allowlist_entries"] = TOOLS.unused_entries(entries)
    summary["status"] = "failed" if failed else "passed"
    (out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    shutil.rmtree(sources)
    for problem in problems:
        print("ALLOWLIST " + problem, file=sys.stderr)
    print(f"{summary['status']}: {out / 'summary.json'}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
