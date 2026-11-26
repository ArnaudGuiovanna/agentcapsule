#!/usr/bin/env python3
"""Prepare signed package references offline; publish the exact packages from that build."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

NAMES = ("pi-agent", "agentcapsule-corpus-builder")
REPOSITORY = "arnaudguiovanna/agentcapsule/runtime"
REGISTRY = "ghcr.io"


def output(*args):
    return subprocess.check_output(args, text=True).strip()


def check_identity(report, name, tag):
    if (report.get("name"), report.get("version"), report.get("base")) != (name, tag[1:], "agentcapsule-guest/2"):
        raise ValueError(f"expected {name} {tag[1:]} for agentcapsule-guest/2")


def package_reference(report, name, tag):
    check_identity(report, name, tag)
    digest = report["digest"]
    if not re.fullmatch(r"sha256:[a-f0-9]{64}", digest):
        raise ValueError("invalid package digest")
    return f"{REGISTRY}/{REPOSITORY}@{digest}"


def prepare(args):
    args.packages.mkdir(parents=True, exist_ok=True)
    refs = {}
    with tempfile.TemporaryDirectory() as tmp:
        key = Path(tmp)/"publisher"
        subprocess.run([args.tool, "keygen", "--out", key], check=True)
        for name, target in zip(NAMES, ("pi-agent", "corpus-builder")):
            directory = args.packages/name
            subprocess.run([args.dagger, "call", target, "--release-version", args.tag[1:],
                            "export", "--path", directory], check=True)
            report = json.loads(output(args.tool, "sign-offline", "--json", "--dir", directory, "--key",
                                       key.with_suffix(".key"), "--out", args.packages/(name+".sigstore.json")))
            refs[name] = package_reference(report, name, args.tag)
        catalog = dict(schema="agentcapsule.pi/v1", release=args.tag, packages=refs,
                       publisher_key=key.with_suffix(".pub").read_text())
        args.catalog.write_text(json.dumps(catalog, indent=2, sort_keys=True)+"\n")


def publish(args):
    catalog = json.loads(args.catalog.read_bytes())
    if catalog["schema"] != "agentcapsule.pi/v1" or catalog["release"] != args.tag or set(catalog["packages"]) != set(NAMES):
        raise ValueError("the signed catalog does not match this release")
    with tempfile.TemporaryDirectory() as tmp:
        key = Path(tmp)/"publisher.pub"
        key.write_text(catalog["publisher_key"])
        # Check both identities, all bytes and both offline signatures before
        # updating the first tag. A rerun can safely reuse uploaded layers.
        for name in NAMES:
            report = json.loads(output(args.tool, "digest", "--json", "--dir", args.packages/name,
                                       "--key", key, "--bundle", args.packages/(name+".sigstore.json")))
            if catalog["packages"][name] != package_reference(report, name, args.tag):
                raise ValueError("staged package differs from the signed catalog")
        for name in NAMES:
            tag = f"{name}-{args.tag}"
            expected = catalog["packages"][name]
            ref = output(args.tool, "push", "--registry", REGISTRY, "--repository", REPOSITORY,
                         "--tag", tag, "--dir", args.packages/name, "--username", args.username)
            if ref != expected.replace("@", ":"+tag+"@"):
                raise ValueError("published package differs from signed catalog")
            subprocess.run([args.tool, "attach", "--ref", expected, "--bundle", args.packages/(name+".sigstore.json"),
                            "--key", key, "--username", args.username], check=True)
            # A public package must work on a new worker with no GitHub credentials.
            public_env = dict(os.environ)
            public_env.pop("AGENTCAPSULE_REGISTRY_PASSWORD", None)
            raw = subprocess.check_output([args.tool, "verify", "--ref", expected, "--key", key, "--max-mib", "2048",
                                           "--blob-host", "pkg-containers.githubusercontent.com", "--unconfined"], env=public_env)
            check_identity(json.loads(raw), name, args.tag)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("prepare", "publish"))
    parser.add_argument("--tag", required=True)
    parser.add_argument("--tool", type=Path, required=True)
    parser.add_argument("--catalog", type=Path, required=True)
    parser.add_argument("--packages", type=Path, required=True)
    parser.add_argument("--dagger", default="dagger")
    parser.add_argument("--username")
    args = parser.parse_args()
    if not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+(?:-[a-zA-Z0-9.]+)?", args.tag):
        parser.error("invalid release tag")
    if args.action == "publish" and not args.username:
        parser.error("--username is required for publication")
    (prepare if args.action == "prepare" else publish)(args)


if __name__ == "__main__":
    main()
