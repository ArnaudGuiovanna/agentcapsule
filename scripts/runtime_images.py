#!/usr/bin/env python3
"""Build, push and verify the three runtime images with the OpenSSL backports.

deploy/images/openssl/images.json is the build plan: for each image, the
Dockerfile's three arguments (the build stage's base, the runtime's upstream
base, both pinned by digest, and the runtime's user) and its qualification
profile. deploy/images/openssl/qualification.json pins the image that the
platform uses, by tag and digest; the files of PIN_FILES pin the same
references.

  build --tag-suffix YYYYMMDD --record FILE
      what .github/workflows/runtime-images.yml runs: build each image for
      linux/amd64 from the Dockerfile and push it under a new tag
      <repository>:<name>-<suffix>; record the registry's digest, the SHA-256
      of the OpenSSL files the image holds and of the APKs the build stage
      made. A tag that exists already is refused.
  verify [--record FILE] [--output FILE]
      check each pinned image (or each image of a build record): its
      configuration is its pinned upstream base plus exactly one layer, with
      the base's entry point and command, and the plan's user; and it carries
      a SLSA provenance attestation from this repository's runtime-images
      workflow on main (gh attestation verify). Any failure, a missing tool
      included, exits 1. scan-artifacts.py --verify-runtime-images runs the
      same check in the release.
  summary --record FILE
      Markdown for the workflow's job summary: the references to pin.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile

ROOT = Path(__file__).resolve().parents[1]
SPEC_FILE = "deploy/images/openssl/images.json"
QUALIFICATION = "deploy/images/openssl/qualification.json"
# Every file that names a runtime image by its reference; each must name one
# that the qualification pins.
PIN_FILES = ("deploy/interop/compose.yml", "runtime/interop/profile.json", ".dagger/main.go",
             "examples/python-echo/Dockerfile", "examples/adapted-agent/Dockerfile")
OPENSSL_FILES = ("usr/lib/libcrypto.so.3", "usr/lib/libssl.so.3", "usr/bin/openssl")
SLSA = "https://slsa.dev/provenance/v1"
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
TIMEOUT = 600


def load_spec(root=ROOT):
    spec = json.loads((root / SPEC_FILE).read_bytes())
    for key in ("repository", "source_repository", "workflow", "source_ref", "context", "images"):
        if not isinstance(spec.get(key), (str, dict)) or not spec[key]:
            raise ValueError("invalid runtime image plan: " + key)
    for name, image in spec["images"].items():
        if (not re.fullmatch(r"[a-z]+-[0-9.]+", name) or set(image) != {"build_base", "runtime_base", "runtime_user", "profile"}
                or not all(re.search(r"@sha256:[0-9a-f]{64}$", image[k]) for k in ("build_base", "runtime_base"))):
            raise ValueError("invalid runtime image plan for " + name)
    return spec


def split(ref):
    """(repository, tag, digest) of repository:tag@sha256:hex."""
    match = re.fullmatch(r"(.+):([A-Za-z0-9._-]+)@(sha256:[0-9a-f]{64})", ref)
    if not match or "/" in match[2]:
        raise ValueError("expected repository:tag@sha256:digest, got " + ref)
    return match[1], match[2], match[3]


def registry_ref(ref):
    """The fully qualified, tagless reference that skopeo and gh accept."""
    name, sep, digest = ref.partition("@")
    if not sep or not DIGEST.fullmatch(digest):
        raise ValueError("not pinned by digest: " + ref)
    path = name.split("/")
    if ":" in path[-1]:
        path[-1] = path[-1].split(":", 1)[0]
    if len(path) == 1:
        path = ["docker.io", "library", *path]
    elif "." not in path[0] and ":" not in path[0] and path[0] != "localhost":
        path = ["docker.io", *path]
    return "/".join(path) + "@" + digest


def output_name(name):
    """The workflow step output holding the digest of image name."""
    return "digest-" + name.split("-", 1)[0]


def build_arguments(image):
    return ["--build-arg", "BUILD_BASE=" + image["build_base"], "--build-arg", "RUNTIME_BASE=" + image["runtime_base"],
            "--build-arg", "RUNTIME_USER=" + image["runtime_user"]]


def pinned(root=ROOT, spec=None):
    """{name: reference} of the runtime images that the qualification pins.

    Each image of the plan once, with its profile; and every reference to the
    runtime repository in PIN_FILES is one of them, by digest.
    """
    spec = spec or load_spec(root)
    repository = spec["repository"]
    refs = {}
    for ref, profile in json.loads((root / QUALIFICATION).read_bytes())["registry_images"].items():
        repo, tag, _ = split(ref)
        name = re.fullmatch(r"(.+)-[0-9]{8}", tag)
        if repo != repository or not name or name[1] not in spec["images"] or name[1] in refs:
            raise ValueError("the qualification pins an unknown or doubled runtime image: " + ref)
        if spec["images"][name[1]]["profile"] != profile:
            raise ValueError("the qualification profile of " + ref + " differs from the build plan")
        refs[name[1]] = ref
    if set(refs) != set(spec["images"]):
        raise ValueError("the qualification does not pin every runtime image")
    for path in PIN_FILES:
        text = (root / path).read_text()
        for match in re.finditer(re.escape(repository) + r":[A-Za-z0-9._-]+(@sha256:[0-9a-f]{64})?", text):
            if not match[1]:
                raise ValueError(f"{path} names {match[0]}, not pinned by digest")
            if match[0] not in refs.values():
                raise ValueError(f"{path} pins {match[0]}, which {QUALIFICATION} does not name")
    return refs


def image_config(ref, run, skopeo):
    out = run([skopeo, "inspect", "--override-os", "linux", "--override-arch", "amd64", "--config",
               "docker://" + registry_ref(ref)], capture_output=True, text=True, check=True, timeout=TIMEOUT).stdout
    return json.loads(out)


def check_layers(name, ref, image, run, skopeo):
    """The image is its pinned upstream base plus the one layer of the Dockerfile's runtime stage."""
    built, base = image_config(ref, run, skopeo), image_config(image["runtime_base"], run, skopeo)
    ids, base_ids = built["rootfs"]["diff_ids"], base["rootfs"]["diff_ids"]
    if len(ids) != len(base_ids) + 1 or ids[:len(base_ids)] != base_ids:
        raise ValueError(f"{name}: {ref} is not its pinned upstream base plus one layer")
    if (built.get("os"), built.get("architecture")) != ("linux", "amd64"):
        raise ValueError(f"{name}: {ref} is not a linux/amd64 image")
    own, upstream = built.get("config") or {}, base.get("config") or {}
    for key in ("Entrypoint", "Cmd"):
        if own.get(key) != upstream.get(key):
            raise ValueError(f"{name}: {ref} changes the upstream {key}")
    if (own.get("User") or "root") != image["runtime_user"]:
        raise ValueError(f"{name}: {ref} runs as {own.get('User') or 'root'}, not {image['runtime_user']}")


def check_provenance(name, ref, spec, run, gh):
    """A SLSA provenance attestation by the runtime-images workflow of this repository, on main."""
    digest = ref.rsplit("@", 1)[1]
    subject = spec["repository"] + "@" + digest
    result = run([gh, "attestation", "verify", "oci://" + subject, "--repo", spec["source_repository"],
                  "--signer-workflow", spec["source_repository"] + "/" + spec["workflow"],
                  "--source-ref", spec["source_ref"], "--predicate-type", SLSA,
                  "--deny-self-hosted-runners", "--format", "json"],
                 capture_output=True, text=True, check=False, timeout=TIMEOUT)
    refused = ValueError(f"{name}: {ref} has no build provenance from {spec['workflow']} on {spec['source_ref']}")
    if result.returncode:
        raise refused
    answers = json.loads(result.stdout)
    if not isinstance(answers, list) or not answers:
        raise refused
    for answer in answers:
        subjects = answer["verificationResult"]["statement"]["subject"]
        if digest.removeprefix("sha256:") not in {s.get("digest", {}).get("sha256") for s in subjects}:
            raise refused


def verify(refs=None, root=ROOT, run=subprocess.run, which=shutil.which):
    """(results, problems) for each pinned image, or for refs ({name: reference})."""
    spec = load_spec(root)
    skopeo, gh = which("skopeo"), which("gh")
    missing = [tool for tool, path in (("skopeo", skopeo), ("gh", gh)) if not path]
    if missing:
        return [], [" and ".join(missing) + " needed to verify the runtime images"]
    refs = refs if refs is not None else pinned(root, spec)
    results, problems = [], []
    for name, ref in sorted(refs.items()):
        entry = {"name": name, "ref": ref}
        for field, check in (("layers", lambda: check_layers(name, ref, spec["images"][name], run, skopeo)),
                             ("provenance", lambda: check_provenance(name, ref, spec, run, gh))):
            try:
                check()
                entry[field] = "verified"
            except (OSError, ValueError, KeyError, TypeError, AttributeError,
                    subprocess.SubprocessError) as error:
                entry[field] = "refused"
                problems.append(f"{name} {field}: {error}" if not str(error).startswith(name) else str(error))
        results.append(entry)
    return results, problems


def package_digests(image, root=ROOT, popen=subprocess.Popen):
    """SHA-256 of the APKs the build stage made (from the build cache)."""
    spec = load_spec(root)
    command = ["docker", "buildx", "build", "--platform", "linux/amd64", "--target", "build",
               "--build-arg", "BUILD_BASE=" + image["build_base"], "--output", "type=tar,dest=-",
               str(root / spec["context"])]
    digests = {}
    with popen(command, stdout=subprocess.PIPE) as process:
        with tarfile.open(fileobj=process.stdout, mode="r|") as tar:
            for member in tar:
                if member.isfile() and member.name.startswith("out/") and member.name.endswith(".apk"):
                    digests[Path(member.name).name] = hashlib.sha256(tar.extractfile(member).read()).hexdigest()
        if process.wait(timeout=TIMEOUT):
            raise ValueError("the build stage's packages could not be exported")
    return digests


def contents(ref, run):
    """SHA-256 of the OpenSSL files of the pushed image, and its OpenSSL package versions."""
    script = ("for f in " + " ".join("/" + f for f in OPENSSL_FILES) + "; do [ -e \"$f\" ] && sha256sum \"$f\"; done; "
              "apk info -v 2>/dev/null")
    out = run(["docker", "run", "--rm", "--pull=always", "--network=none", "--entrypoint", "/bin/sh",
               registry_ref(ref), "-c", script], capture_output=True, text=True, check=True, timeout=TIMEOUT).stdout
    files, versions = {}, {}
    for line in out.splitlines():
        if match := re.fullmatch(r"([0-9a-f]{64})  /(\S+)", line):
            files[match[2]] = match[1]
        elif match := re.fullmatch(r"(libcrypto3|libssl3|openssl)-(\d\S*-r\d+)", line):
            versions[match[1]] = match[2]
    return files, versions


def build(suffix, root=ROOT, run=subprocess.run, packages=None):
    """Build and push every image under <name>-<suffix>; the record of what was pushed."""
    if not re.fullmatch(r"[0-9]{8}", suffix):
        raise ValueError("the tag suffix is a date, YYYYMMDD")
    spec = load_spec(root)
    version = json.loads((root / QUALIFICATION).read_bytes())["version"]
    packages = packages or (lambda image: package_digests(image, root))
    tags = {name: f"{spec['repository']}:{name}-{suffix}" for name in spec["images"]}
    for tag in tags.values():
        if run(["docker", "buildx", "imagetools", "inspect", tag], capture_output=True, check=False,
               timeout=TIMEOUT).returncode == 0:
            raise ValueError(tag + " exists already: choose another tag suffix")
    record = {"tag_suffix": suffix, "commit": os.environ.get("GITHUB_SHA"), "images": {}}
    for name, image in spec["images"].items():
        tag = tags[name]
        run(["docker", "buildx", "build", "--platform", "linux/amd64", "--provenance=false", "--sbom=false",
             *build_arguments(image), "--tag", tag, "--push", str(root / spec["context"])], check=True)
        manifest = json.loads(run(["docker", "buildx", "imagetools", "inspect", "--format", "{{json .Manifest}}", tag],
                                  capture_output=True, text=True, check=True, timeout=TIMEOUT).stdout)
        if not DIGEST.fullmatch(manifest.get("digest", "")):
            raise ValueError("the registry gave no digest for " + tag)
        ref = tag + "@" + manifest["digest"]
        files, versions = contents(ref, run)
        if versions.get("libcrypto3") != version or versions.get("libssl3") != version:
            raise ValueError(f"{ref} does not hold the qualified OpenSSL {version}")
        record["images"][name] = {"ref": ref, "digest": manifest["digest"], "files": files, "versions": versions,
                                  "packages": packages(image), "profile": image["profile"]}
    return record


def summary(record):
    lines = [f"## Runtime images {record['tag_suffix']}", "",
             "Pin these references in " + ", ".join(f"`{p}`" for p in (QUALIFICATION, *PIN_FILES)) +
             " (and update the file and package digests of the qualification's profiles):", ""]
    for name, entry in sorted(record["images"].items()):
        lines += [f"### {name}", "", "```", entry["ref"], "```", ""]
        lines += [f"- `{path}`: `{digest}`" for path, digest in sorted(entry["files"].items())]
        lines += [f"- `{package}` {version}" for package, version in sorted(entry["versions"].items())]
        lines += [f"- `{apk}` (APK): `{digest}`" for apk, digest in sorted(entry.get("packages", {}).items())]
        lines.append("")
    return "\n".join(lines)


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = p.add_subparsers(dest="command", required=True)
    b = commands.add_parser("build")
    b.add_argument("--tag-suffix", required=True)
    b.add_argument("--record", required=True, type=Path)
    b.add_argument("--github-output", type=Path, help="append each image's digest-<name> output here")
    v = commands.add_parser("verify")
    v.add_argument("--record", type=Path, help="verify the images of a build record instead of the pinned ones")
    v.add_argument("--output", type=Path)
    s = commands.add_parser("summary")
    s.add_argument("--record", required=True, type=Path)
    a = p.parse_args(argv)
    if a.command == "build":
        record = build(a.tag_suffix)
        a.record.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
        if a.github_output:
            with a.github_output.open("a") as out:
                for name, entry in record["images"].items():
                    out.write(f"{output_name(name)}={entry['digest']}\n")
        return 0
    if a.command == "summary":
        print(summary(json.loads(a.record.read_bytes())))
        return 0
    refs = {n: e["ref"] for n, e in json.loads(a.record.read_bytes())["images"].items()} if a.record else None
    results, problems = verify(refs)
    if a.output:
        a.output.write_text(json.dumps({"images": results, "problems": problems}, indent=2) + "\n")
    for result in results:
        print(f"{result['name']}: layers {result['layers']}, provenance {result['provenance']} ({result['ref']})")
    for problem in problems:
        print("REFUSED " + problem, file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
