#!/usr/bin/env python3
"""Unit tests of scripts/fetch-backup-tools.py.

Small .deb files built here with dpkg-deb, with shell scripts standing for
pgBackRest and rclone, are served from file:// URLs: no network. The CI job of
the backup qualifications fetches the real packages.
"""

import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

SCRIPT = Path(__file__).resolve().parent / "fetch-backup-tools.py"
SPEC = importlib.util.spec_from_file_location("fetch_backup_tools", SCRIPT)
FETCH = importlib.util.module_from_spec(SPEC)
sys.dont_write_bytecode = True
SPEC.loader.exec_module(FETCH)

# Stands for pgBackRest: it runs only with its own library directory, and the
# directory named "libpq" when present, on the library path.
PGBACKREST = """#!/bin/sh
case ":$LD_LIBRARY_PATH:" in *"/pgbackrest/usr/lib/x86_64-linux-gnu:"*) ;; *) echo "libssh2.so.1: not found" >&2; exit 127;; esac
if [ -n "$NEED_LIBPQ" ]; then
  case ":$LD_LIBRARY_PATH:" in *"/libpq:"*) ;; *) echo "libpq.so.5: cannot open shared object file" >&2; exit 127;; esac
fi
echo "pgBackRest 2.58.0"
"""
RCLONE = """#!/bin/sh
echo "rclone v1.60.1-DEV"
echo "- os/version: test"
"""


def build_deb(pool_dir, package, version, files):
    """A .deb of package holding files {path: (text, mode)}; returns its pool path and SHA-256."""
    tree = pool_dir.parent / "trees" / f"{package}_{version}"
    (tree / "DEBIAN").mkdir(parents=True)
    (tree / "DEBIAN/control").write_text(f"Package: {package}\nVersion: {version}\nArchitecture: amd64\n"
                                         "Maintainer: Test <test@example.invalid>\nDescription: test package\n")
    for relative, (text, mode) in files.items():
        path = tree / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        path.chmod(mode)
    pool_dir.mkdir(parents=True, exist_ok=True)
    deb = pool_dir / f"{package}_{version}_amd64.deb"
    subprocess.run(["dpkg-deb", "--root-owner-group", "--build", str(tree), str(deb)], check=True, capture_output=True)
    return f"pool/{deb.name}", hashlib.sha256(deb.read_bytes()).hexdigest()


@unittest.skipUnless(shutil.which("dpkg-deb"), "dpkg-deb is required")
class Fetching(unittest.TestCase):
    def setUp(self):
        # dpkg-deb refuses a control directory that is not 0755; another
        # test may leave the process with umask 077.
        self.addCleanup(os.umask, os.umask(0o022))
        self.dir = Path(tempfile.mkdtemp(prefix="fetch-test-"))
        self.addCleanup(shutil.rmtree, self.dir)
        self.archive = self.dir / "archive"
        self.packages = [self.package("pgbackrest", "pgbackrest", "2.58.0-1", {"usr/bin/pgbackrest": (PGBACKREST, 0o755)}),
                         self.package("pgbackrest", "libssh2-1t64", "1.11.1-1",
                                      {"usr/lib/x86_64-linux-gnu/libssh2.so.1": ("not a library", 0o644)}),
                         self.package("rclone", "rclone", "1.60.1+dfsg-4", {"usr/bin/rclone": (RCLONE, 0o755)})]
        snapshot = mock.patch.object(FETCH, "SNAPSHOT", self.archive.as_uri())
        snapshot.start()
        self.addCleanup(snapshot.stop)
        self.env = mock.patch.dict(os.environ, {"NEED_LIBPQ": ""})
        self.env.start()
        self.addCleanup(self.env.stop)

    def package(self, tool, name, version, files):
        pool, digest = build_deb(self.archive / "pool", name, version, files)
        return (tool, name, version, pool, digest)

    def fetch(self, output, packages=None, **kw):
        with contextlib.redirect_stderr(io.StringIO()):
            return FETCH.fetch(output, packages or self.packages, **kw)

    def test_extracts_checks_and_runs_each_tool(self):
        out = self.dir / "tools"
        report = self.fetch(out)
        self.assertEqual(report["tools"]["pgbackrest"]["version"], "pgBackRest 2.58.0")
        self.assertEqual(report["tools"]["pgbackrest"]["path"], str(out / "pgbackrest/usr/bin/pgbackrest"))
        self.assertEqual(report["tools"]["pgbackrest"]["library_path"], str(out / "pgbackrest/usr/lib/x86_64-linux-gnu"))
        self.assertEqual(report["tools"]["rclone"], {"path": str(out / "rclone/usr/bin/rclone"), "version": "rclone v1.60.1-DEV"})
        self.assertTrue((out / "pgbackrest/usr/lib/x86_64-linux-gnu/libssh2.so.1").is_file())
        self.assertFalse((out / "rclone/usr/bin/pgbackrest").exists(), "each tool has its own directory")
        self.assertEqual(sorted(p.name for p in (out / "debs").iterdir()), sorted(Path(p[3]).name for p in self.packages))
        written = json.loads((out / "packages.json").read_text())
        self.assertEqual(written, report)
        self.assertEqual([(p["package"], p["sha256"], p["source"]) for p in written["packages"]],
                         [(p[1], p[4], "downloaded") for p in self.packages])
        self.assertTrue(all(p["url"].startswith(self.archive.as_uri() + "/pool/") for p in written["packages"]))

    def test_a_file_with_another_sha256_is_refused_and_nothing_is_left(self):
        tool, name, version, pool, digest = self.packages[1]
        packages = [self.packages[0], (tool, name, version, pool, "0" * 64), self.packages[2]]
        out, cache = self.dir / "tools", self.dir / "cache"
        with self.assertRaisesRegex(RuntimeError, "SHA-256"):
            self.fetch(out, packages, cache=cache)
        self.assertFalse(out.exists(), "no directory that looks usable")
        self.assertNotIn(Path(pool).name, os.listdir(cache), "the cache keeps only checked files")

    def test_the_cache_is_used_when_it_holds_the_same_file_and_replaced_otherwise(self):
        cache = self.dir / "cache"
        self.fetch(self.dir / "first", cache=cache)
        self.assertEqual(sorted(os.listdir(cache)), sorted(Path(p[3]).name for p in self.packages))
        with mock.patch.object(FETCH, "SNAPSHOT", (self.dir / "nowhere").as_uri()):
            report = self.fetch(self.dir / "offline", cache=cache)
        self.assertEqual({p["source"] for p in report["packages"]}, {"cache"})
        damaged = cache / Path(self.packages[2][3]).name
        damaged.write_bytes(b"damaged")
        report = self.fetch(self.dir / "repaired", cache=cache)
        self.assertEqual([p["source"] for p in report["packages"]], ["cache", "cache", "downloaded"])
        self.assertEqual(hashlib.sha256(damaged.read_bytes()).hexdigest(), self.packages[2][4])

    def test_a_tool_that_prints_another_version_is_refused(self):
        packages = [*self.packages[:2], self.package("rclone", "rclone", "1.61.0", {"usr/bin/rclone": ("#!/bin/sh\necho 'rclone v1.61.0'\n", 0o755)})]
        out = self.dir / "tools"
        with self.assertRaisesRegex(RuntimeError, "expected 'rclone v1.60.1'"):
            self.fetch(out, packages)
        self.assertFalse(out.exists())

    def test_a_missing_libpq_is_named_and_library_path_supplies_it(self):
        os.environ["NEED_LIBPQ"] = "1"
        with self.assertRaisesRegex(RuntimeError, "install libpq5, or pass --library-path"):
            self.fetch(self.dir / "without")
        (self.dir / "libpq").mkdir()
        report = self.fetch(self.dir / "with", library_path=[self.dir / "libpq"])
        self.assertEqual(report["tools"]["pgbackrest"]["version"], "pgBackRest 2.58.0")

    def test_an_existing_output_is_refused_and_kept(self):
        out = self.dir / "tools"
        out.mkdir()
        (out / "keep").write_text("mine")
        with self.assertRaises(FileExistsError):
            self.fetch(out)
        self.assertEqual((out / "keep").read_text(), "mine")

    def test_a_failed_download_is_retried(self):
        real = FETCH.urllib.request.urlopen
        calls = []

        def flaky(url, timeout):
            calls.append(url)
            if len(calls) < 3:
                raise OSError("connection reset")
            return real(url, timeout=timeout)

        with mock.patch.object(FETCH.urllib.request, "urlopen", flaky), mock.patch.object(FETCH.time, "sleep"):
            report = self.fetch(self.dir / "tools", self.packages[2:])
        self.assertEqual(len(calls), 3)
        self.assertEqual(report["tools"]["rclone"]["version"], "rclone v1.60.1-DEV")
        with mock.patch.object(FETCH.urllib.request, "urlopen", side_effect=OSError("down")), mock.patch.object(FETCH.time, "sleep"):
            with self.assertRaisesRegex(RuntimeError, "cannot download"):
                self.fetch(self.dir / "never", self.packages[2:])
        self.assertFalse((self.dir / "never").exists())


class Pins(unittest.TestCase):
    def test_every_package_comes_from_a_fixed_snapshot_with_a_sha256(self):
        self.assertRegex(FETCH.SNAPSHOT, r"^https://snapshot\.ubuntu\.com/ubuntu/\d{8}T\d{6}Z$")
        names = set()
        for tool, package, version, pool, digest in FETCH.PACKAGES:
            self.assertIn(tool, FETCH.TOOLS)
            self.assertRegex(digest, r"^[0-9a-f]{64}$")
            self.assertEqual(Path(pool).name, f"{package}_{version}_amd64.deb")
            self.assertRegex(pool, r"^pool/(main|universe)/(lib)?[a-z0-9]/[a-z0-9.+-]+/[^/]+$")
            names.add(package)
        self.assertEqual(len(names), len(FETCH.PACKAGES))
        self.assertEqual({p[0] for p in FETCH.PACKAGES}, set(FETCH.TOOLS))

    def test_the_qualified_versions(self):
        versions = {package: version for _, package, version, _, _ in FETCH.PACKAGES}
        self.assertEqual(versions["pgbackrest"], "2.58.0-1")
        self.assertTrue(versions["rclone"].startswith("1.60.1+"))
        self.assertEqual(FETCH.TOOLS["pgbackrest"][2], "pgBackRest 2.58.0")
        self.assertEqual(FETCH.TOOLS["rclone"][2], "rclone v1.60.1")
        # The scripts that take these tools find the libraries next to the executable.
        self.assertTrue(re.fullmatch(r"usr/bin/[a-z]+", FETCH.TOOLS["pgbackrest"][0]))
        self.assertEqual(FETCH.LIBRARIES, "usr/lib/x86_64-linux-gnu")


if __name__ == "__main__":
    unittest.main()
