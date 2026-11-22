#!/usr/bin/env python3
"""Unit tests of scripts/build-firecracker.py, without network, Rust or root
(audit finding A-09).

The script runs from a copy in a temporary tree, with its own pinned manifest
and patch, so the tests can give it inputs that match or differ from their
pins. Cargo and patch are replaced by a recorder: the tests check the commands
and environment the release build gets, the order of its phases, what it
retains and records, and that a wrong input or a failed phase stops it.
test_build_inputs.py tests check_digest itself, also under python -O.
"""

import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parent
ROOT = SCRIPTS.parent
sys.dont_write_bytecode = True
VERSION = "1.17.0"
TARGET = "x86_64-unknown-linux-musl"


def sha(data):
    return hashlib.sha256(data).hexdigest()


class PinnedInputsTest(unittest.TestCase):
    def test_the_repository_patch_matches_its_pin(self):
        manifest = json.loads((ROOT / "runtime/firecracker/manifest.json").read_text())
        patch_file = ROOT / "runtime/firecracker" / manifest["patch"]
        self.assertEqual(sha(patch_file.read_bytes()), manifest["patch_sha256"])
        self.assertRegex(manifest["source_sha256"], r"^[a-f0-9]{64}$")
        self.assertEqual(manifest["source_url"],
                         f"https://github.com/firecracker-microvm/firecracker/archive/refs/tags/v{manifest['version']}.tar.gz")
        self.assertRegex(manifest["rust_toolchain"], r"^[0-9]+\.[0-9]+\.[0-9]+$", "a pinned toolchain, never a channel")


class BuildTest(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="build-firecracker-test-"))
        self.addCleanup(shutil.rmtree, self.dir)
        tree = self.dir / "tree"
        (tree / "scripts").mkdir(parents=True)
        (tree / "runtime/firecracker").mkdir(parents=True)
        self.script = tree / "scripts/build-firecracker.py"
        shutil.copyfile(SCRIPTS / "build-firecracker.py", self.script)
        self.patch = tree / "runtime/firecracker/volume-lock.patch"
        self.patch.write_bytes(b"--- a/x\n+++ b/x\n")
        self.lock = b'[[package]]\nname = "firecracker"\nversion = "1.17.0"\n'
        self.archive = self.dir / "upstream.tgz"
        with tarfile.open(self.archive, "w:gz") as tar:
            for name, data in ((f"firecracker-{VERSION}/Cargo.lock", self.lock), (f"firecracker-{VERSION}/README.md", b"readme")):
                info = tarfile.TarInfo(name)
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
        self.manifest = {"version": VERSION, "source_url": "https://example.invalid/firecracker.tar.gz",
                         "source_sha256": sha(self.archive.read_bytes()), "rust_toolchain": "1.97.0", "target": TARGET,
                         "patch": "volume-lock.patch", "patch_sha256": sha(self.patch.read_bytes())}
        self.write_manifest()
        self.out = self.dir / "out"
        self.calls = []
        self.failures = {}

    def write_manifest(self):
        (self.script.parents[1] / "runtime/firecracker/manifest.json").write_text(json.dumps(self.manifest))

    def load(self):
        spec = importlib.util.spec_from_file_location("build_firecracker", self.script)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def run_command(self, command, cwd=None, env=None, stdout=None, stderr=None, timeout=None):
        self.calls.append(dict(command=[str(c) for c in command], cwd=cwd, env=env, timeout=timeout))
        phase = command[1] if command[0] != "patch" else "patch"
        if phase in self.failures:
            if self.failures[phase] == "timeout":
                raise subprocess.TimeoutExpired(command, timeout)
            return SimpleNamespace(returncode=self.failures[phase])
        if phase == "build":
            release = Path(env["CARGO_TARGET_DIR"]) / TARGET / "release"
            release.mkdir(parents=True)
            (release / "firecracker").write_bytes(b"vmm binary")
            (release / "jailer").write_bytes(b"jailer binary")
        return SimpleNamespace(returncode=0)

    def build(self, *extra, source_archive=True):
        module = self.load()
        argv = ["build-firecracker.py", "--output", str(self.out), "--cargo", "/opt/cargo", *extra]
        if source_archive:
            argv += ["--source-archive", str(self.archive)]
        fake = SimpleNamespace(run=self.run_command, STDOUT=subprocess.STDOUT, TimeoutExpired=subprocess.TimeoutExpired)
        downloads = []

        def urlretrieve(url, dest):
            downloads.append(url)
            shutil.copyfile(self.archive, dest)
        with patch.object(sys, "argv", argv), patch.object(module, "subprocess", fake), \
                patch.object(module.urllib.request, "urlretrieve", urlretrieve), contextlib.redirect_stdout(io.StringIO()):
            module.main()
        return downloads

    def test_builds_the_patched_release_with_locked_dependencies_and_records_it(self):
        self.build()
        source = self.out / f"firecracker-{VERSION}"
        target_dir = source / "build/cargo_target"
        self.assertEqual([c["command"] for c in self.calls], [
            ["patch", "--batch", "--fuzz=0", "-p1", "-i", str(self.patch)],
            ["/opt/cargo", "--version"],
            ["/opt/cargo", "build", "--locked", "--release", "--target", TARGET, "-p", "firecracker", "-p", "jailer",
             "--bin", "firecracker", "--bin", "jailer"],
            ["/opt/cargo", "test", "--locked", "--release", "--target", TARGET, "-p", "vmm", "test_disk_backing_file_lock",
             "--", "--nocapture"]])
        self.assertEqual([c["timeout"] for c in self.calls], [60, 60, 1200, 1200])
        for call in self.calls:
            self.assertEqual(call["cwd"], source)
            env = call["env"]
            self.assertEqual((env["RUSTUP_TOOLCHAIN"], env["CARGO_BUILD_JOBS"], env["CARGO_TARGET_DIR"]),
                             ("1.97.0", "2", str(target_dir)))
            self.assertEqual(env["CFLAGS_x86_64_unknown_linux_musl"], "-isystem " + str(self.out / "linux-uapi"))
        # Only the Linux UAPI headers, never glibc's include directory.
        self.assertEqual({p.name: str(p.readlink()) for p in (self.out / "linux-uapi").iterdir()},
                         {"linux": "/usr/include/linux", "asm-generic": "/usr/include/asm-generic",
                          "asm": "/usr/include/x86_64-linux-gnu/asm"})
        artifacts = json.loads((self.out / "artifacts.json").read_text())
        self.assertEqual(artifacts["variant"], "agentcapsule-volume-lock-v1")
        self.assertEqual(artifacts["upstream"], self.manifest)
        self.assertEqual(artifacts["sha256"], {"Cargo.lock": sha(self.lock), "firecracker": sha(b"vmm binary"),
                                               "jailer": sha(b"jailer binary")})
        self.assertEqual(artifacts["build_script_sha256"], sha(self.script.read_bytes()))
        for name in ("manifest.json", "volume-lock.patch", "build-firecracker.py", "upstream.tgz", "Cargo.lock", "firecracker", "jailer"):
            self.assertTrue((self.out / name).is_file(), name)
        summary = json.loads((self.out / "summary.json").read_text())
        self.assertEqual([(r["phase"], r["passed"]) for r in summary],
                         [("patch", True), ("cargo-version", True), ("build", True), ("lock-unit-tests", True)])

    def test_downloads_the_pinned_url_and_shares_a_target_directory(self):
        downloads = self.build("--target-dir", str(self.dir / "cache"), source_archive=False)
        self.assertEqual(downloads, ["https://example.invalid/firecracker.tar.gz"])
        self.assertTrue(all(c["env"]["CARGO_TARGET_DIR"] == str(self.dir / "cache") for c in self.calls))

    def test_a_patch_that_differs_from_its_pin_stops_before_any_output(self):
        self.patch.write_bytes(b"another patch")
        with self.assertRaisesRegex(ValueError, "patch checksum mismatch"):
            self.build()
        self.assertFalse(self.out.exists())
        self.assertEqual(self.calls, [])

    def test_a_source_that_differs_from_its_pin_is_never_built(self):
        self.manifest["source_sha256"] = "0" * 64
        self.write_manifest()
        with self.assertRaisesRegex(ValueError, "upstream checksum mismatch"):
            self.build()
        self.assertEqual(self.calls, [])
        self.assertFalse((self.out / f"firecracker-{VERSION}").exists(), "the archive is not extracted")

    def test_an_existing_output_is_never_reused(self):
        self.out.mkdir()
        with self.assertRaises(FileExistsError):
            self.build()
        self.assertEqual(self.calls, [])

    def test_a_failed_or_timed_out_phase_stops_the_build(self):
        for failure, code in ((101, 101), ("timeout", 124)):
            with self.subTest(failure=failure):
                self.calls, self.failures = [], {"build": failure}
                shutil.rmtree(self.out, ignore_errors=True)
                with self.assertRaisesRegex(RuntimeError, f"build failed \\({code}\\)"):
                    self.build()
                self.assertEqual([c["command"][1] for c in self.calls], ["--batch", "--version", "build"])
                summary = json.loads((self.out / "summary.json").read_text())
                self.assertEqual((summary[-1]["phase"], summary[-1]["returncode"], summary[-1]["passed"]), ("build", code, False))
                self.assertFalse((self.out / "artifacts.json").exists())


if __name__ == "__main__":
    unittest.main()
