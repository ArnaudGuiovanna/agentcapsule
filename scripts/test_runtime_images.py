#!/usr/bin/env python3
"""Unit tests of runtime_images.py, without Docker, a registry or GitHub.

The three runtime images (deploy/images/openssl) are built, pushed and
attested by .github/workflows/runtime-images.yml. These tests check the build
plan against the Dockerfile and the manual commands, the repository's pins,
and that the release verification refuses an image that is not the pinned
upstream base plus one layer, or that lacks the workflow's provenance.
"""

import io
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest

SCRIPTS = Path(__file__).resolve().parent
ROOT = SCRIPTS.parent
sys.dont_write_bytecode = True
sys.path.insert(0, str(SCRIPTS))
import runtime_images as RI  # noqa: E402

DIGEST = "b" * 64
SPEC = RI.load_spec()


def config(diff_ids, user="", entrypoint=None, cmd=None, arch="amd64"):
    return {"architecture": arch, "os": "linux", "rootfs": {"type": "layers", "diff_ids": diff_ids},
            "config": {"User": user, "Entrypoint": entrypoint, "Cmd": cmd}}


class FakeRun:
    """subprocess.run for skopeo, gh and docker, from canned answers."""

    def __init__(self, configs=None, attestations=None, existing=(), digests=None):
        self.configs, self.attestations = configs or {}, attestations or {}
        self.existing, self.digests = set(existing), digests or {}
        self.calls = []

    def __call__(self, args, **kwargs):
        args = [str(a) for a in args]
        self.calls.append(args)
        if args[1] == "inspect":  # skopeo
            ref = args[-1].removeprefix("docker://")
            return subprocess.CompletedProcess(args, 0, stdout=json.dumps(self.configs[ref]))
        if args[1] == "attestation":  # gh
            subject = args[3].removeprefix("oci://")
            answer = self.attestations.get(subject)
            if answer is None:
                return subprocess.CompletedProcess(args, 1, stdout="", stderr="no attestation")
            return subprocess.CompletedProcess(args, 0, stdout=json.dumps(answer))
        if args[1:4] == ["buildx", "imagetools", "inspect"]:
            tag = args[-1]
            if "--format" not in args:
                return subprocess.CompletedProcess(args, 0 if tag in self.existing else 1, stdout=b"", stderr=b"")
            self.existing.add(tag)
            return subprocess.CompletedProcess(args, 0, stdout=json.dumps({"digest": self.digests[tag]}))
        if args[1:3] == ["buildx", "build"] and "--push" in args:
            return subprocess.CompletedProcess(args, 0)
        if args[1] == "run":
            return subprocess.CompletedProcess(args, 0, stdout=(
                "1" * 64 + "  /usr/lib/libcrypto.so.3\n" + "2" * 64 + "  /usr/lib/libssl.so.3\n"
                "libcrypto3-3.5.9-r20261121\nlibssl3-3.5.9-r20261121\n"))
        raise AssertionError(f"unexpected command {args}")


def attested(digest):
    return [{"verificationResult": {"statement": {"subject": [
        {"name": SPEC["repository"], "digest": {"sha256": digest}}]}}}]


class Spec(unittest.TestCase):
    def test_the_build_plan_is_the_dockerfile_and_the_manual_commands(self):
        dockerfile = (ROOT / SPEC["context"] / "Dockerfile").read_text()
        defaults = dict(re.findall(r"^ARG (BUILD_BASE|RUNTIME_BASE)=(\S+)$", dockerfile, re.M))
        python, haproxy, oasf = (SPEC["images"][n] for n in ("python-3.13", "haproxy-3.2", "oasf-2.0.0"))
        self.assertEqual((python["build_base"], python["runtime_base"]),
                         (defaults["BUILD_BASE"], defaults["RUNTIME_BASE"]))
        self.assertEqual(haproxy["build_base"], defaults["BUILD_BASE"])
        self.assertIn("ARG RUNTIME_USER=root", dockerfile)
        self.assertEqual(python["runtime_user"], "root")
        readme = (ROOT / SPEC["context"] / "README.md").read_text()
        for image in (haproxy, oasf):
            self.assertIn("RUNTIME_BASE=" + image["runtime_base"], readme)
            self.assertIn("RUNTIME_USER=" + image["runtime_user"], readme)
        self.assertIn("BUILD_BASE=" + oasf["build_base"], readme)

    def test_every_image_is_built_with_all_three_arguments(self):
        for name, image in SPEC["images"].items():
            with self.subTest(name=name):
                args = RI.build_arguments(image)
                self.assertEqual(args, ["--build-arg", "BUILD_BASE=" + image["build_base"],
                                        "--build-arg", "RUNTIME_BASE=" + image["runtime_base"],
                                        "--build-arg", "RUNTIME_USER=" + image["runtime_user"]])

    def test_registry_references_drop_the_tag_and_name_the_registry(self):
        self.assertEqual(RI.registry_ref("python:3.13-alpine@sha256:" + DIGEST),
                         "docker.io/library/python@sha256:" + DIGEST)
        self.assertEqual(RI.registry_ref("agntcy/x:1@sha256:" + DIGEST), "docker.io/agntcy/x@sha256:" + DIGEST)
        self.assertEqual(RI.registry_ref("ghcr.io/a/b/runtime:haproxy-3.2-20261121@sha256:" + DIGEST),
                         "ghcr.io/a/b/runtime@sha256:" + DIGEST)
        self.assertEqual(RI.registry_ref("localhost:5000/x@sha256:" + DIGEST), "localhost:5000/x@sha256:" + DIGEST)
        with self.assertRaises(ValueError):
            RI.registry_ref("python:3.13-alpine")


class Pins(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="runtime-images-test-"))
        self.addCleanup(shutil.rmtree, self.dir)

    def copy(self):
        for name in [*RI.PIN_FILES, RI.QUALIFICATION, RI.SPEC_FILE]:
            target = self.dir / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, target)

    def test_the_qualification_names_each_runtime_image_once(self):
        refs = RI.pinned()
        self.assertEqual(set(refs), set(SPEC["images"]))
        qualification = json.loads((ROOT / RI.QUALIFICATION).read_text())["registry_images"]
        self.assertEqual(set(refs.values()), set(qualification))

    def test_a_pin_that_the_qualification_does_not_name_is_refused(self):
        self.copy()
        compose = self.dir / "deploy/interop/compose.yml"
        compose.write_text(re.sub(r"(runtime:haproxy-3\.2-\d+@sha256:)[0-9a-f]{64}", r"\g<1>" + DIGEST,
                                  compose.read_text()))
        with self.assertRaisesRegex(ValueError, "deploy/interop/compose.yml"):
            RI.pinned(self.dir)
        self.copy()
        dockerfile = self.dir / "examples/python-echo/Dockerfile"
        dockerfile.write_text(dockerfile.read_text().replace("@sha256:", " #@sha256:", 1))
        with self.assertRaisesRegex(ValueError, "not pinned by digest"):
            RI.pinned(self.dir)

    def test_a_missing_or_doubled_image_in_the_qualification_is_refused(self):
        self.copy()
        path = self.dir / RI.QUALIFICATION
        qualification = json.loads(path.read_text())
        ref = next(r for r in qualification["registry_images"] if ":oasf-" in r)
        doubled = dict(qualification["registry_images"], **{ref.split("@")[0] + "@sha256:" + DIGEST: "alpine-3.23"})
        for images in ({r: p for r, p in qualification["registry_images"].items() if r != ref}, doubled,
                       dict(qualification["registry_images"], **{ref: "alpine-3.24"})):
            with self.subTest(images=sorted(images)):
                path.write_text(json.dumps(dict(qualification, registry_images=images)))
                with self.assertRaises(ValueError):
                    RI.pinned(self.dir)

    def test_every_file_that_pins_a_runtime_image_is_checked(self):
        repository = SPEC["repository"]
        skip = {RI.QUALIFICATION, "scripts/vulnerability-allowlist.json"}
        found = set()
        for path in ROOT.rglob("*"):
            relative = path.relative_to(ROOT).as_posix()
            if (not path.is_file() or relative.split("/")[0] in (".git", "node_modules") or relative in skip
                    or path.suffix in (".md", ".py") or "/node_modules/" in relative):
                continue
            try:
                if repository + ":" in path.read_text(errors="strict"):
                    found.add(relative)
            except (UnicodeDecodeError, OSError):
                continue
        self.assertEqual(found, set(RI.PIN_FILES))


class Verification(unittest.TestCase):
    def setUp(self):
        self.refs = RI.pinned()
        base_ids = ["sha256:" + c * 64 for c in "cd"]
        self.configs, self.attestations = {}, {}
        for name, ref in self.refs.items():
            image = SPEC["images"][name]
            base = config(base_ids, entrypoint=["/entry"], cmd=["serve"])
            self.configs[RI.registry_ref(image["runtime_base"])] = base
            self.configs[RI.registry_ref(ref)] = config([*base_ids, "sha256:" + "e" * 64],
                                                        user=image["runtime_user"], entrypoint=["/entry"],
                                                        cmd=["serve"])
            digest = ref.rsplit("@sha256:", 1)[1]
            self.attestations[SPEC["repository"] + "@sha256:" + digest] = attested(digest)

    def verify(self, which=lambda name: "/usr/bin/" + name):
        run = FakeRun(self.configs, self.attestations)
        results, problems = RI.verify(run=run, which=which)
        return run, results, problems

    def test_the_pinned_images_pass_with_their_base_and_their_provenance(self):
        run, results, problems = self.verify()
        self.assertEqual(problems, [])
        self.assertEqual({r["name"] for r in results}, set(SPEC["images"]))
        self.assertTrue(all(r["layers"] == "verified" and r["provenance"] == "verified" for r in results))
        gh = [c for c in run.calls if c[1] == "attestation"]
        self.assertEqual(len(gh), 3)
        for call in gh:
            self.assertRegex(call[3], r"^oci://ghcr\.io/arnaudguiovanna/agentcapsule/runtime@sha256:[0-9a-f]{64}$")
            flags = dict(zip(call[4::2], call[5::2]))
            self.assertEqual(flags["--repo"], "ArnaudGuiovanna/agentcapsule")
            self.assertEqual(flags["--signer-workflow"],
                             "ArnaudGuiovanna/agentcapsule/.github/workflows/runtime-images.yml")
            self.assertEqual(flags["--source-ref"], "refs/heads/main")
            self.assertEqual(flags["--predicate-type"], "https://slsa.dev/provenance/v1")
            self.assertIn("--deny-self-hosted-runners", call)
        for call in (c for c in run.calls if c[1] == "inspect"):
            self.assertEqual(call[2:7], ["--override-os", "linux", "--override-arch", "amd64", "--config"])
            self.assertNotRegex(call[-1], r":[^/@]+@")

    def test_an_image_without_the_workflow_provenance_is_refused(self):
        name, ref = next(iter(sorted(self.refs.items())))
        subject = SPEC["repository"] + "@sha256:" + ref.rsplit("@sha256:", 1)[1]
        for answer in (None, [], attested("f" * 64), {"not": "a list"}):
            with self.subTest(answer=answer):
                self.attestations[subject] = answer
                _, results, problems = self.verify()
                self.assertEqual(len(problems), 1)
                self.assertIn(name, problems[0])
                self.assertEqual(next(r for r in results if r["name"] == name)["provenance"], "refused")

    def test_an_image_that_is_not_its_base_plus_one_layer_is_refused(self):
        name, ref = next(iter(sorted(self.refs.items())))
        good = self.configs[RI.registry_ref(ref)]
        ids = good["rootfs"]["diff_ids"]
        changes = {
            "extra layer": config([*ids, "sha256:" + "f" * 64], good["config"]["User"], ["/entry"], ["serve"]),
            "other base": config(["sha256:" + "f" * 64, *ids[1:]], good["config"]["User"], ["/entry"], ["serve"]),
            "same as base": config(ids[:-1], good["config"]["User"], ["/entry"], ["serve"]),
            "entry point": config(ids, good["config"]["User"], ["/bin/sh"], ["serve"]),
            "command": config(ids, good["config"]["User"], ["/entry"], ["sh"]),
            "user": config(ids, "nobody", ["/entry"], ["serve"]),
            "architecture": config(ids, good["config"]["User"], ["/entry"], ["serve"], arch="arm64"),
        }
        for change, bad in changes.items():
            with self.subTest(change=change):
                self.configs[RI.registry_ref(ref)] = bad
                _, results, problems = self.verify()
                self.assertEqual(len(problems), 1, problems)
                self.assertIn(name, problems[0])
                self.assertEqual(next(r for r in results if r["name"] == name)["layers"], "refused")

    def test_verification_fails_closed_without_skopeo_or_gh(self):
        for missing in ("skopeo", "gh"):
            with self.subTest(missing=missing):
                run, results, problems = self.verify(lambda name: None if name == missing else "/usr/bin/" + name)
                self.assertEqual(results, [])
                self.assertEqual(len(problems), 1)
                self.assertIn(missing, problems[0])
                self.assertEqual(run.calls, [])

    def test_a_tool_failure_is_a_problem_not_a_pass(self):
        def broken(args, **kwargs):
            raise subprocess.TimeoutExpired(args, 300)
        results, problems = RI.verify(run=broken, which=lambda name: name)
        self.assertEqual(len(problems), 6)
        self.assertTrue(all(r["layers"] == "refused" and r["provenance"] == "refused" for r in results))


class Build(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="runtime-images-build-"))
        self.addCleanup(shutil.rmtree, self.dir)

    def packages(self):
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w") as tar:
            for name, data in (("out/main/x86_64/libcrypto3-3.5.9-r20261121.apk", b"crypto"),
                               ("out/main/x86_64/APKINDEX.tar.gz", b"index"), ("etc/passwd", b"x")):
                info = tarfile.TarInfo(name)
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
        return stream.getvalue()

    def test_build_pushes_new_tags_and_records_registry_digests(self):
        repository = SPEC["repository"]
        tags = {f"{repository}:{name}-20261201": "sha256:" + c * 64 for name, c in zip(SPEC["images"], "123")}
        run = FakeRun(digests=tags)
        record = RI.build("20261201", run=run, packages=lambda image: {"libcrypto3-3.5.9-r20261121.apk": "a" * 64})
        self.assertEqual(set(record["images"]), set(SPEC["images"]))
        for name, entry in record["images"].items():
            tag = f"{repository}:{name}-20261201"
            self.assertEqual(entry["ref"], tag + "@" + tags[tag])
            self.assertEqual(entry["files"]["usr/lib/libcrypto.so.3"], "1" * 64)
            self.assertEqual(entry["versions"], {"libcrypto3": "3.5.9-r20261121", "libssl3": "3.5.9-r20261121"})
        builds = [c for c in run.calls if c[1:3] == ["buildx", "build"]]
        self.assertEqual(len(builds), 3)
        for call in builds:
            self.assertIn("--push", call)
            self.assertEqual(call[call.index("--platform") + 1], "linux/amd64")
            self.assertIn("--provenance=false", call)
            self.assertEqual(call[-1], str(ROOT / SPEC["context"]))
        runs = [c for c in run.calls if c[1] == "run"]
        self.assertTrue(all("--pull=always" in c and re.search(r"runtime@sha256:", c[c.index("--entrypoint") + 2])
                            for c in runs))

    def test_build_refuses_a_tag_that_exists_and_a_bad_suffix(self):
        repository = SPEC["repository"]
        name = next(iter(SPEC["images"]))
        run = FakeRun(existing={f"{repository}:{name}-20261121"})
        with self.assertRaisesRegex(ValueError, "exists"):
            RI.build("20261121", run=run, packages=lambda image: {})
        self.assertFalse([c for c in run.calls if c[1:3] == ["buildx", "build"]])
        for suffix in ("2026112", "latest", "20261121-1"):
            with self.assertRaises(ValueError):
                RI.build(suffix, run=FakeRun(), packages=lambda image: {})

    def test_build_refuses_an_image_without_the_qualified_openssl(self):
        repository = SPEC["repository"]
        tags = {f"{repository}:{name}-20261201": "sha256:" + c * 64 for name, c in zip(SPEC["images"], "123")}
        run = FakeRun(digests=tags)
        original = run.__call__

        def old_openssl(args, **kwargs):
            result = original(args, **kwargs)
            if args[1] == "run":
                result.stdout = result.stdout.replace("r20261121", "r0")
            return result
        with self.assertRaisesRegex(ValueError, "OpenSSL"):
            RI.build("20261201", run=old_openssl, packages=lambda image: {})

    def test_package_digests_come_from_the_build_stage_output(self):
        data = self.packages()

        class Popen:
            def __init__(self, args, stdout):
                self.args, self.stdout = args, io.BytesIO(data)

            def wait(self, timeout=None):
                return 0

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False
        image = SPEC["images"]["oasf-2.0.0"]
        digests = RI.package_digests(image, popen=Popen)
        self.assertEqual(digests, {"libcrypto3-3.5.9-r20261121.apk":
                                   "da2f073e06f78938166f247273729dfe465bf7e46105c13ce7cc651047bf0ca4"})

    def test_the_summary_names_each_reference_to_pin(self):
        record = {"tag_suffix": "20261201", "commit": "c" * 40, "images": {
            name: {"ref": f"{SPEC['repository']}:{name}-20261201@sha256:{DIGEST}", "files": {"usr/lib/libssl.so.3": "1" * 64},
                   "versions": {"libssl3": "3.5.9-r20261121"}, "packages": {"libssl3.apk": "2" * 64}}
            for name in SPEC["images"]}}
        text = RI.summary(record)
        for name in SPEC["images"]:
            self.assertIn(f"{SPEC['repository']}:{name}-20261201@sha256:{DIGEST}", text)
        for path in RI.PIN_FILES:
            self.assertIn(path, text)


class Workflow(unittest.TestCase):
    TEXT = (ROOT / SPEC["workflow"]).read_text()

    def test_the_workflow_runs_only_by_hand_on_main(self):
        trigger = re.search(r"^on:\n((?:  .*\n|\n)+)", self.TEXT, re.M).group(1)
        self.assertRegex(trigger, r"^  workflow_dispatch:", "manual trigger")
        self.assertEqual(re.findall(r"^  (\w+):", trigger, re.M), ["workflow_dispatch"])
        self.assertIn('test "$GITHUB_REF" = refs/heads/main', self.TEXT)

    def test_every_action_is_pinned_and_attestation_reuses_the_release_pin(self):
        uses = re.findall(r"uses:\s*(\S+)", self.TEXT)
        self.assertTrue(uses)
        for action in uses:
            self.assertRegex(action, r"^[\w.-]+/[\w.-]+@[0-9a-f]{40}$")
        release = (ROOT / ".github/workflows/release.yml").read_text()
        attest = re.search(r"actions/attest-build-provenance@[0-9a-f]{40}", release).group(0)
        self.assertEqual(self.TEXT.count(attest), len(SPEC["images"]))

    def test_permissions_are_minimal(self):
        top = re.search(r"^permissions:\n((?:  .*\n)+)", self.TEXT, re.M).group(1)
        self.assertEqual(top.split(), ["contents:", "read"])
        job = re.findall(r"^    permissions:\n((?:      .*\n)+)", self.TEXT, re.M)
        self.assertEqual(len(job), 1)
        self.assertEqual(sorted(job[0].split()), sorted(["contents:", "read", "packages:", "write", "id-token:", "write",
                                                         "attestations:", "write"]))
        self.assertNotIn("pull_request_target", self.TEXT)

    def test_each_image_is_attested_and_pushed_with_its_provenance(self):
        for name in SPEC["images"]:
            output = RI.output_name(name)
            with self.subTest(name=name):
                self.assertIn(f"subject-digest: ${{{{ steps.build.outputs.{output} }}}}", self.TEXT)
        self.assertEqual(self.TEXT.count("subject-name: " + SPEC["repository"]), len(SPEC["images"]))
        self.assertEqual(self.TEXT.count("push-to-registry: true"), len(SPEC["images"]))
        self.assertIn("scripts/runtime_images.py verify --record", self.TEXT)

    def test_the_release_refuses_runtime_images_without_their_provenance(self):
        release = (ROOT / ".github/workflows/release.yml").read_text()
        self.assertIn("--verify-runtime-images", release)
        self.assertRegex(release, r"\n    permissions:\n      contents: read\n(      #.*\n)?      attestations: read\n")


if __name__ == "__main__":
    unittest.main()
