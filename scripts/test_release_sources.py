#!/usr/bin/env python3
"""Unit tests of scripts/release_sources.py, without network (audit finding
A-09).

The release keeps the upstream sources of what it ships: Cargo crates by
their locked checksums, Git dependencies by their pinned commits, and
downloads by their pinned digests. These tests check the inputs it accepts,
the commands it runs, its retries, and that nothing reaches the release
without its digest. test_release_audit.py tests the download cache.
"""

import hashlib
import importlib.util
import io
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from urllib.error import HTTPError, URLError

SCRIPTS = Path(__file__).resolve().parent
sys.dont_write_bytecode = True
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))  # release_sources imports release_tools
spec = importlib.util.spec_from_file_location("release_sources", SCRIPTS / "release_sources.py")
SOURCES = importlib.util.module_from_spec(spec)
spec.loader.exec_module(SOURCES)
REV = "0123456789abcdef0123456789abcdef01234567"


def sha(data):
    return hashlib.sha256(data).hexdigest()


class Temporary(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="release-sources-test-"))
        self.addCleanup(shutil.rmtree, self.dir)
        self.work = self.dir / "work"
        self.work.mkdir()


class GitSourceTest(Temporary):
    def git(self, *argv, cwd=None):
        # A private configuration: no user setting (signing, hooks) applies.
        env = dict(os.environ, HOME=str(self.dir), GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull,
                   GIT_AUTHOR_NAME="test", GIT_AUTHOR_EMAIL="test@example.invalid",
                   GIT_COMMITTER_NAME="test", GIT_COMMITTER_EMAIL="test@example.invalid")
        return subprocess.run(["git", *argv], cwd=cwd, env=env, check=True, capture_output=True, text=True).stdout.strip()

    def test_refuses_an_unpinned_or_unexpected_reference_before_running_git(self):
        run = Mock()
        with patch.object(SOURCES.subprocess, "run", run):
            for repository, revision in (("owner", REV), ("owner/repo/extra", REV), ("../owner/repo", REV), ("owner/re po", REV),
                                         ("owner/repo", "main"), ("owner/repo", REV[:12]), ("owner/repo", REV.upper()),
                                         ("owner/repo", REV + "0"), ("owner/repo", "--upload-pack=x" + REV[15:])):
                with self.subTest(repository=repository, revision=revision):
                    with self.assertRaisesRegex(ValueError, "invalid upstream Git repository or revision"):
                        SOURCES.git_source(repository, revision, self.work)
        run.assert_not_called()

    def test_archives_the_pinned_commit_from_a_local_cache(self):
        origin = self.dir / "origin"
        origin.mkdir()
        self.git("init", "-q", cwd=origin)
        (origin / "lib.rs").write_text("pub fn f() {}\n")
        self.git("add", "lib.rs", cwd=origin)
        self.git("commit", "-q", "-m", "fixture", cwd=origin)
        revision = self.git("rev-parse", "HEAD", cwd=origin)
        cache = self.dir / "git-db"
        cache.mkdir()
        self.git("clone", "-q", "--bare", str(origin), str(cache / "micro-http-1a2b"))
        dest = SOURCES.git_source("firecracker-microvm/micro-http", revision, self.work, cache)
        self.assertEqual(dest, self.work / f"firecracker-microvm-micro-http-{revision}.tar.gz")
        with tarfile.open(dest) as tar:
            self.assertEqual(tar.extractfile("lib.rs").read(), b"pub fn f() {}\n")

    def test_fetches_the_pinned_commit_when_the_cache_lacks_it_and_checks_it(self):
        cache = self.dir / "git-db"
        (cache / "micro-http-1a2b").mkdir(parents=True)
        calls = []

        def run(argv, **kw):
            calls.append([str(a) for a in argv])
            return SimpleNamespace(returncode=128, stdout="")
        fake = SimpleNamespace(run=run, check_output=Mock(return_value="f" * 40 + "\n"))
        with patch.object(SOURCES, "subprocess", fake):
            with self.assertRaisesRegex(ValueError, "upstream checkout differs from the pinned commit"):
                SOURCES.git_source("firecracker-microvm/micro-http", REV, self.work, cache)
        self.assertIn("rev-parse", calls[0])
        self.assertEqual(calls[0][-1], REV + "^{commit}")
        fetch = next(c for c in calls if "fetch" in c)
        self.assertEqual(fetch[-4:], ["--quiet", "--depth=1", "https://github.com/firecracker-microvm/micro-http.git", REV])
        self.assertFalse(any("archive" in c for c in calls), "nothing is archived from an unverified checkout")


class CheckedDownloadTest(Temporary):
    def download(self, answers, expected):
        attempts = []

        def urlopen(url, timeout=None):
            attempts.append((url, timeout))
            answer = answers.pop(0)
            if isinstance(answer, Exception):
                raise answer
            return io.BytesIO(answer)
        sleeps = []
        with patch.object(SOURCES, "urlopen", urlopen), patch.object(SOURCES.time, "sleep", sleeps.append):
            try:
                return SOURCES.checked_download("https://example.invalid/src.tar.gz", self.work / "src.tar.gz", expected)
            finally:
                self.attempts, self.sleeps = attempts, sleeps

    def http(self, code):
        error = HTTPError("https://example.invalid/src.tar.gz", code, "status", {}, None)
        self.addCleanup(error.close)
        return error

    def test_retries_server_errors_and_rate_limits_with_backoff(self):
        dest = self.download([self.http(503), self.http(429), b"source"], sha(b"source"))
        self.assertEqual(dest.read_bytes(), b"source")
        self.assertEqual(self.attempts, [("https://example.invalid/src.tar.gz", 120)] * 3)
        self.assertEqual(self.sleeps, [1, 2])

    def test_a_client_error_is_not_retried(self):
        with self.assertRaises(HTTPError):
            self.download([self.http(404), b"source"], sha(b"source"))
        self.assertEqual(len(self.attempts), 1)

    def test_gives_up_after_three_attempts(self):
        with self.assertRaises(URLError):
            self.download([URLError("down"), ConnectionResetError(), URLError("down")], sha(b"source"))
        self.assertEqual(len(self.attempts), 3)

    def test_bytes_that_differ_from_the_pin_are_refused_and_not_cached(self):
        cache = self.dir / "cache"
        with patch.object(SOURCES, "urlopen", lambda url, timeout=None: io.BytesIO(b"tampered")):
            with self.assertRaisesRegex(ValueError, "upstream source checksum mismatch for src.tar.gz"):
                SOURCES.checked_download("https://example.invalid/src.tar.gz", self.work / "src.tar.gz", sha(b"source"), cache)
        self.assertFalse(cache.exists())


class LockedCratesTest(Temporary):
    CRATE = b"crate bytes"

    def lock(self, *packages):
        return "\n".join("[[package]]\n" + "\n".join(f'{k} = "{v}"' for k, v in p.items()) + "\n" for p in packages).encode()

    def crate(self, name="serde", version="1.0.228", checksum=None, source="registry+https://github.com/rust-lang/crates.io-index"):
        return {"name": name, "version": version, "source": source, "checksum": checksum or sha(self.CRATE)}

    def materialize(self, lock, **kw):
        downloads, gits = [], []

        def download(url, dest, checksum, cache=None):
            downloads.append((url, dest.name, checksum, cache))
            dest.write_bytes(self.CRATE)
            return dest

        def git(project, revision, work, cache=None):
            gits.append((project, revision, cache))
            dest = work / f"{project.replace('/', '-')}-{revision}.tar.gz"
            dest.write_bytes(b"git")
            return dest
        with patch.object(SOURCES, "checked_download", download), patch.object(SOURCES, "git_source", git):
            files = SOURCES.locked_crates(lock, self.work, **kw)
        return files, downloads, gits

    def test_keeps_each_external_source_once_by_its_lock(self):
        git = "git+https://github.com/firecracker-microvm/micro-http"
        lock = self.lock({"name": "firecracker", "version": "1.17.0"},
                         self.crate(),
                         {"name": "micro_http", "version": "0.1.0", "source": f"{git}#{REV}"},
                         {"name": "micro_http_extra", "version": "0.1.0", "source": f"{git}#{REV}"})
        files, downloads, gits = self.materialize(lock, source_cache=self.dir / "cache", git_projects=("firecracker-microvm/micro-http",))
        self.assertEqual(set(files), {"cargo/serde-1.0.228.crate", f"cargo/firecracker-microvm-micro-http-{REV}.tar.gz"})
        self.assertEqual(downloads, [("https://static.crates.io/crates/serde/serde-1.0.228.crate", "serde-1.0.228.crate",
                                      sha(self.CRATE), self.dir / "cache")])
        self.assertEqual(gits, [("firecracker-microvm/micro-http", REV, None)])

    def test_reuses_cargos_cache_only_for_the_locked_checksum(self):
        cargo = self.dir / "cargo"
        cached = cargo / "registry/cache/index.crates.io-1949cf8c6b5b557f/serde-1.0.228.crate"
        cached.parent.mkdir(parents=True)
        cached.write_bytes(self.CRATE)
        files, downloads, _ = self.materialize(self.lock(self.crate()), cargo_home=cargo)
        self.assertEqual(downloads, [])
        self.assertEqual(files["cargo/serde-1.0.228.crate"].read_bytes(), self.CRATE)
        cached.write_bytes(b"corrupt")
        with self.assertRaisesRegex(ValueError, "Cargo cache checksum mismatch for serde-1.0.228.crate"):
            self.materialize(self.lock(self.crate()), cargo_home=cargo)

    def test_refuses_sources_nobody_reviewed_and_malformed_entries(self):
        cases = {
            "review the Cargo source registry for serde": self.crate(source="registry+https://mirror.invalid/index"),
            "review the Cargo Git dependency for other": {"name": "other", "version": "0.1.0",
                                                          "source": f"git+https://github.com/someone/other#{REV}"},
            # A branch or tag in the URL is not the reviewed source either.
            "review the Cargo Git dependency for micro_http": {"name": "micro_http", "version": "0.1.0",
                                                               "source": f"git+https://github.com/firecracker-microvm/micro-http?branch=main#{REV}"},
            "invalid locked crate identifier or checksum": self.crate(name="../serde"),
        }
        for message, package in cases.items():
            with self.subTest(message=message):
                with self.assertRaisesRegex(ValueError, message):
                    self.materialize(self.lock(package), git_projects=("firecracker-microvm/micro-http",))
        for package in (self.crate(version="1.0 ; rm"), self.crate(checksum="A" * 64), self.crate(checksum="0" * 63)):
            with self.subTest(package=package):
                with self.assertRaisesRegex(ValueError, "invalid locked crate identifier or checksum"):
                    self.materialize(self.lock(package))


if __name__ == "__main__":
    unittest.main()
