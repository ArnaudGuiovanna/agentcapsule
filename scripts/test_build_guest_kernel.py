#!/usr/bin/env python3
"""Unit tests of scripts/build-guest-kernel.py, without network, a compiler
or root (audit finding A-09).

The script runs from a copy in a temporary tree, with its own pinned
kernel.json and base configuration. Its processes are replaced by a
recorder: the tests check the commands and environment of each phase, that
the pinned inputs are checked before they are used, that a configuration
without a required built-in stops the build, and what the build records.
test_build_inputs.py tests check_digest and check_builtins themselves.
"""

import contextlib
import hashlib
import importlib.util
import io
import json
import lzma
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import Mock, patch

SCRIPTS = Path(__file__).resolve().parent
ROOT = SCRIPTS.parent
sys.dont_write_bytecode = True
VERSION = "6.1.188"
BUILTINS = ["MD", "BLK_DEV_DM", "DM_CRYPT"]


def sha(data):
    return hashlib.sha256(data).hexdigest()


class PinnedInputsTest(unittest.TestCase):
    def test_the_repository_configuration_matches_its_pin(self):
        spec = json.loads((ROOT / "runtime/guest/kernel.json").read_text())
        config = ROOT / "runtime/guest" / spec["base_config"]
        self.assertEqual(sha(config.read_bytes()), spec["base_config_sha256"])
        self.assertRegex(spec["source_sha256"], r"^[a-f0-9]{64}$")
        self.assertEqual(spec["source_url"], f"https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-{spec['version']}.tar.xz")
        for name in ("DM_CRYPT", "BLK_DEV_DM", "EXT4_FS", "VIRTIO_VSOCKETS"):
            self.assertIn(name, spec["required_builtins"])


class FakeProcess:
    def __init__(self, test, command, cwd=None, env=None, stdin=None, stdout=None, stderr=None, start_new_session=False):
        test.calls.append(dict(command=list(command), cwd=cwd, env=env, session=start_new_session, stdin=stdin))
        self.pid = 4242
        self.test = test
        self.phase = command[-1] if command[0] == "make" else "config"
        build = Path(next((c[2:] for c in command if c.startswith("O=")), "")) if command[0] == "make" else None
        if self.phase == "olddefconfig":
            (build / ".config").write_text("".join(f"CONFIG_{n}=y\n" for n in test.built_in) + "# CONFIG_X is not set\n")
        elif self.phase == "vmlinux":
            (build / "vmlinux").write_bytes(b"\x7fELF kernel")

    def wait(self, timeout=None):
        self.test.timeouts.append(timeout)
        outcome = self.test.failures.get(self.phase, 0)
        if outcome == "timeout":
            # The group ends on SIGTERM: the next wait returns.
            self.test.failures[self.phase] = -signal.SIGTERM
            raise subprocess.TimeoutExpired("make", timeout)
        return outcome


class BuildTest(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="build-guest-kernel-test-"))
        self.addCleanup(shutil.rmtree, self.dir)
        tree = self.dir / "tree"
        (tree / "scripts").mkdir(parents=True)
        (tree / "runtime/guest").mkdir(parents=True)
        self.script = tree / "scripts/build-guest-kernel.py"
        shutil.copyfile(SCRIPTS / "build-guest-kernel.py", self.script)
        self.config = tree / "runtime/guest/base.config"
        self.config.write_text("CONFIG_MD=n\n")
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w") as tar:
            data = b"#!/bin/sh\n"
            info = tarfile.TarInfo(f"linux-{VERSION}/scripts/config")
            info.size, info.mode = len(data), 0o755
            tar.addfile(info, io.BytesIO(data))
        self.archive = self.dir / "linux.tar.xz"
        self.archive.write_bytes(lzma.compress(buffer.getvalue()))
        self.spec = {"version": VERSION, "source_url": "https://example.invalid/linux.tar.xz",
                     "source_sha256": sha(self.archive.read_bytes()), "base_config": "base.config",
                     "base_config_sha256": sha(self.config.read_bytes()), "required_builtins": BUILTINS,
                     "localversion": "-agentcapsule1"}
        self.write_spec()
        self.out = self.dir / "out"
        self.calls, self.timeouts, self.failures = [], [], {}
        self.built_in = list(BUILTINS)
        self.killed = Mock()

    def write_spec(self):
        (self.script.parents[1] / "runtime/guest/kernel.json").write_text(json.dumps(self.spec))

    def build(self, *extra, source_archive=True, download=None):
        spec = importlib.util.spec_from_file_location("build_guest_kernel", self.script)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        argv = ["build-guest-kernel.py", "--output", str(self.out), *extra]
        if source_archive:
            argv += ["--source-archive", str(self.archive)]
        urls = []

        def urlopen(url, timeout=None):
            urls.append((url, timeout))
            return io.BytesIO(download if download is not None else self.archive.read_bytes())
        with patch.object(sys, "argv", argv), patch.object(module.subprocess, "Popen", lambda *a, **kw: FakeProcess(self, *a, **kw)), \
                patch.object(module.subprocess, "check_output", Mock(return_value="gcc (Ubuntu 13.3.0) 13.3.0\n")), \
                patch.object(module.urllib.request, "urlopen", urlopen), patch.object(module.os, "killpg", self.killed), \
                contextlib.redirect_stdout(io.StringIO()):
            module.main()
        return urls

    def test_configures_and_builds_the_pinned_kernel_and_records_it(self):
        tools = self.dir / "tools"
        (tools / "usr/bin").mkdir(parents=True)
        (tools / "packages.json").write_text('{"bison": "2:3.8.2"}')
        self.build("--tools", str(tools), "--jobs", "3")
        source, build = self.out / "source" / f"linux-{VERSION}", self.out / "build"
        self.assertEqual([c["command"] for c in self.calls], [
            [str(source / "scripts/config"), "--file", str(build / ".config"), "--enable", "MD", "--enable", "BLK_DEV_DM",
             "--enable", "DM_CRYPT", "--set-str", "LOCALVERSION", "-agentcapsule1", "--disable", "LOCALVERSION_AUTO"],
            ["make", "O=" + str(build), "olddefconfig"],
            ["make", "O=" + str(build), "-j3", "vmlinux"]])
        self.assertEqual(self.timeouts, [120, 120, 3600])
        for call in self.calls:
            self.assertEqual((call["cwd"], call["session"], call["stdin"]), (source, True, subprocess.DEVNULL))
            env = call["env"]
            self.assertEqual({k: env[k] for k in ("KBUILD_BUILD_TIMESTAMP", "KBUILD_BUILD_USER", "KBUILD_BUILD_HOST", "KBUILD_BUILD_VERSION")},
                             {"KBUILD_BUILD_TIMESTAMP": "2026-11-07 00:00:00 UTC", "KBUILD_BUILD_USER": "agentcapsule",
                              "KBUILD_BUILD_HOST": "guest-build", "KBUILD_BUILD_VERSION": "1"})
            self.assertTrue(env["PATH"].startswith(str(tools / "usr/bin") + ":"))
            self.assertEqual((env["CPATH"], env["M4"], env["LIBRARY_PATH"], env["LD_LIBRARY_PATH"]),
                             (str(tools / "usr/include"), str(tools / "usr/bin/m4"), str(tools / "usr/lib/x86_64-linux-gnu"),
                              str(tools / "usr/lib/x86_64-linux-gnu")))
        self.assertEqual((self.out / "build-tools.json").read_text(), '{"bison": "2:3.8.2"}')
        self.assertEqual((self.out / "base.config").read_bytes(), self.config.read_bytes())
        artifacts = json.loads((self.out / "artifacts.json").read_text())
        self.assertEqual(artifacts["source"], self.spec)
        self.assertEqual(artifacts["sha256"], {"vmlinux": sha(b"\x7fELF kernel"), "config": sha((build / ".config").read_bytes())})
        self.assertEqual(artifacts["script_sha256"], sha(self.script.read_bytes()))
        self.assertEqual(artifacts["compiler"], "gcc (Ubuntu 13.3.0) 13.3.0")
        summary = json.loads((self.out / "summary.json").read_text())
        self.assertEqual([(r["phase"], r["status"], r["returncode"]) for r in summary],
                         [("config", "passed", 0), ("olddefconfig", "passed", 0), ("kernel", "passed", 0)])

    def test_downloads_the_pinned_url_and_checks_what_it_got(self):
        urls = self.build(source_archive=False)
        self.assertEqual(urls, [("https://example.invalid/linux.tar.xz", 90)])
        shutil.rmtree(self.out)
        self.calls = []
        with self.assertRaisesRegex(ValueError, "Linux source checksum mismatch"):
            self.build(source_archive=False, download=b"another archive")
        self.assertEqual(self.calls, [])
        self.assertFalse((self.out / "source").exists())

    def test_jobs_are_bounded(self):
        for jobs in ("0", "17"):
            with self.subTest(jobs=jobs), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    self.build("--jobs", jobs)
                self.assertFalse(self.out.exists())

    def test_a_configuration_that_differs_from_its_pin_stops_before_any_output(self):
        self.config.write_text("CONFIG_MD=y\n")
        with self.assertRaisesRegex(ValueError, "base config checksum mismatch"):
            self.build()
        self.assertFalse(self.out.exists())

    def test_a_cached_source_is_checked_before_it_is_copied(self):
        self.spec["source_sha256"] = "0" * 64
        self.write_spec()
        with self.assertRaisesRegex(ValueError, "cached Linux source checksum mismatch"):
            self.build()
        self.assertFalse((self.out / "linux.tar.xz").exists())
        self.assertEqual(self.calls, [])

    def test_a_missing_built_in_stops_the_build_before_compiling(self):
        self.built_in = ["MD", "BLK_DEV_DM"]
        with self.assertRaisesRegex(ValueError, "required built-in unavailable: DM_CRYPT"):
            self.build()
        self.assertEqual([c["command"][-1] for c in self.calls], ["LOCALVERSION_AUTO", "olddefconfig"])
        self.assertFalse((self.out / "artifacts.json").exists())

    def test_a_failed_phase_stops_the_build(self):
        self.failures = {"olddefconfig": 2}
        with self.assertRaisesRegex(RuntimeError, "olddefconfig failed"):
            self.build()
        summary = json.loads((self.out / "summary.json").read_text())
        self.assertEqual((summary[-1]["phase"], summary[-1]["status"], summary[-1]["returncode"]), ("olddefconfig", "failed", 2))
        self.assertEqual(len(self.calls), 2)

    def test_a_phase_past_its_time_is_killed_with_its_process_group(self):
        self.failures = {"vmlinux": "timeout"}
        with self.assertRaises(subprocess.TimeoutExpired):
            self.build()
        self.killed.assert_called_once_with(4242, signal.SIGTERM)
        summary = json.loads((self.out / "summary.json").read_text())
        self.assertEqual((summary[-1]["phase"], summary[-1]["status"]), ("kernel", "interrupted_or_timed_out"))
        self.assertFalse((self.out / "artifacts.json").exists())


if __name__ == "__main__":
    unittest.main()
