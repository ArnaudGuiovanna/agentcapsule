#!/usr/bin/env python3
"""Tests of install.sh, the `curl | sh` installer of the workstation CLI.

The script runs as it would from `curl -fsSL .../install.sh | sh -s -- ...`:
read from standard input by /bin/sh, against a local server with GitHub's
release layout. PATH holds only the commands the script may use, so cosign
is present only when a test puts a fake one there. The script must pick the
executable for the system, install it only when its digest is the single
SHA256SUMS entry for its name, call cosign with the release workflow's
identity for the exact tag when cosign exists, and leave an installed CLI
untouched whenever a check fails.
"""

import hashlib
import http.server
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import threading
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "install.sh"
TOOLS = ("sh", "curl", "awk", "grep", "cut", "sed", "mktemp", "id", "mkdir", "cp", "chmod", "mv", "rm", "cat",
         "sha256sum", "printf", "env")
ASSETS = ("agentcapsule-linux-amd64", "agentcapsule-linux-arm64", "agentcapsule-darwin-amd64",
          "agentcapsule-darwin-arm64", "agentcapsule-windows-amd64.exe", "agentcapsule-windows-arm64.exe")


def fake_cli(tag, asset):
    return f"#!/bin/sh\nprintf '{{\"release\":\"{tag}\",\"asset\":\"{asset}\"}}\\n'\n".encode()


class Releases(http.server.BaseHTTPRequestHandler):
    root = None
    latest = None
    requests = None

    def do_GET(self):
        self.requests.append(self.path)
        if self.path == "/releases/latest":
            self.send_response(302)
            self.send_header("Location", "/releases/tag/" + self.latest)
            self.end_headers()
            return
        if self.path.startswith("/releases/tag/"):
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        prefix = "/releases/download/"
        file = self.root / self.path[len(prefix):] if self.path.startswith(prefix) else None
        if file is None or ".." in self.path or not file.is_file():
            self.send_error(404)
            return
        body = file.read_bytes()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class InstallScriptTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="install-cli-"))
        self.addCleanup(shutil.rmtree, self.tmp)
        self.releases = self.tmp / "releases"
        for tag in ("v0.0.1", "v0.0.2"):
            self.publish(tag)
        handler = type("Handler", (Releases,), dict(root=self.releases, latest="v0.0.2", requests=[]))
        self.requests = handler.requests
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.bin = self.tmp / "bin"
        self.bin.mkdir()
        for tool in TOOLS:
            found = shutil.which(tool)
            if found is None:
                self.skipTest(f"{tool} is not installed")
            (self.bin / tool).symlink_to(found)
        self.uname("Linux", "x86_64")
        self.home = self.tmp / "home"
        self.home.mkdir()

    def publish(self, tag, sums=None):
        directory = self.releases / tag
        directory.mkdir(parents=True, exist_ok=True)
        lines = []
        for asset in ASSETS:
            body = fake_cli(tag, asset)
            (directory / asset).write_bytes(body)
            lines.append(f"{hashlib.sha256(body).hexdigest()}  {asset}")
        (directory / "SHA256SUMS.sigstore.json").write_text("{}\n")
        (directory / "SHA256SUMS").write_text("\n".join(sums if sums is not None else lines) + "\n")
        return directory

    def uname(self, system, machine):
        script = self.bin / "uname"
        script.unlink(missing_ok=True)
        script.write_text(f"#!/bin/sh\ncase \"$1\" in -s) echo '{system}' ;; -m) echo '{machine}' ;; esac\n")
        script.chmod(0o755)

    def cosign(self, status):
        script = self.bin / "cosign"
        script.write_text(f"#!/bin/sh\nprintf '%s\\n' \"$@\" > '{self.tmp}/cosign-args'\nexit {status}\n")
        script.chmod(0o755)

    def run_script(self, *args, **env):
        environment = {"PATH": str(self.bin), "HOME": str(self.home),
                       "AGENTCAPSULE_RELEASE_BASE_URL": f"http://127.0.0.1:{self.server.server_port}/releases"}
        environment.update(env)
        return subprocess.run([str(self.bin / "sh"), "-s", "--", *args], input=SCRIPT.read_bytes(),
                              env=environment, capture_output=True, timeout=60, check=False)

    def assert_installed(self, run, path, tag, asset):
        self.assertEqual(run.returncode, 0, run.stderr.decode())
        self.assertEqual(path.read_bytes(), fake_cli(tag, asset))
        self.assertEqual(path.stat().st_mode & 0o777, 0o755)
        self.assertIn(f'"release":"{tag}"'.encode(), run.stdout)
        self.assertEqual([p for p in os.listdir(path.parent) if p.startswith(".")], [])

    def test_latest_release_into_the_user_bin_directory(self):
        run = self.run_script()
        self.assert_installed(run, self.home / ".local/bin/agentcapsule", "v0.0.2", "agentcapsule-linux-amd64")
        self.assertIn("/releases/latest", self.requests)
        self.assertIn("/releases/download/v0.0.2/agentcapsule-linux-amd64", self.requests)
        self.assertIn(b"cosign not found", run.stderr)
        self.assertIn(b"to your PATH", run.stderr)

    def test_explicit_version_and_directory(self):
        target = self.tmp / "opt bin"
        run = self.run_script("--version", "v0.0.1", "--dir", str(target))
        self.assert_installed(run, target / "agentcapsule", "v0.0.1", "agentcapsule-linux-amd64")
        self.assertNotIn("/releases/latest", self.requests)
        environment = self.run_script(AGENTCAPSULE_VERSION="v0.0.1", AGENTCAPSULE_INSTALL_DIR=str(target))
        self.assert_installed(environment, target / "agentcapsule", "v0.0.1", "agentcapsule-linux-amd64")

    def test_each_system_and_architecture(self):
        cases = [("Linux", "aarch64", "agentcapsule-linux-arm64", "agentcapsule"),
                 ("Darwin", "arm64", "agentcapsule-darwin-arm64", "agentcapsule"),
                 ("MINGW64_NT-10.0-26100", "x86_64", "agentcapsule-windows-amd64.exe", "agentcapsule.exe"),
                 ("MSYS_NT-10.0", "ARM64", "agentcapsule-windows-arm64.exe", "agentcapsule.exe")]
        for system, machine, asset, name in cases:
            with self.subTest(system=system, machine=machine):
                self.uname(system, machine)
                target = self.tmp / asset
                run = self.run_script("--version", "v0.0.1", "--dir", str(target))
                self.assert_installed(run, target / name, "v0.0.1", asset)

    def test_unsupported_system_or_architecture(self):
        for system, machine in (("Linux", "riscv64"), ("FreeBSD", "amd64")):
            with self.subTest(system=system, machine=machine):
                self.uname(system, machine)
                run = self.run_script("--version", "v0.0.1")
                self.assertNotEqual(run.returncode, 0)
                self.assertIn(b"unsupported", run.stderr)
                self.assertFalse((self.home / ".local/bin/agentcapsule").exists())

    def installed_then_refused(self, run):
        self.assertNotEqual(run.returncode, 0)
        self.assertEqual((self.tmp / "dir/agentcapsule").read_bytes(), b"previous")
        self.assertEqual(os.listdir(self.tmp / "dir"), ["agentcapsule"])

    def previous(self):
        (self.tmp / "dir").mkdir()
        (self.tmp / "dir/agentcapsule").write_bytes(b"previous")

    def test_altered_executable_is_refused(self):
        self.previous()
        (self.releases / "v0.0.1/agentcapsule-linux-amd64").write_bytes(b"#!/bin/sh\necho altered\n")
        run = self.run_script("--version", "v0.0.1", "--dir", str(self.tmp / "dir"))
        self.installed_then_refused(run)
        self.assertIn(b"checksum mismatch", run.stderr)

    def test_missing_duplicate_or_malformed_entry_is_refused(self):
        digest = hashlib.sha256(fake_cli("v0.0.1", "agentcapsule-linux-amd64")).hexdigest()
        cases = {"missing": [f"{digest}  agentcapsule-linux-arm64"],
                 "duplicate": [f"{digest}  agentcapsule-linux-amd64", f"{'0' * 64}  agentcapsule-linux-amd64"],
                 "malformed": [f"{digest.upper()}  agentcapsule-linux-amd64"]}
        self.previous()
        for name, sums in cases.items():
            with self.subTest(name):
                self.publish("v0.0.1", sums)
                run = self.run_script("--version", "v0.0.1", "--dir", str(self.tmp / "dir"))
                self.installed_then_refused(run)
                self.assertIn(b"SHA256SUMS", run.stderr)

    def test_signature_required_without_cosign_is_refused(self):
        self.previous()
        run = self.run_script("--version", "v0.0.1", "--dir", str(self.tmp / "dir"), "--require-signature")
        self.installed_then_refused(run)
        self.assertIn(b"needs cosign", run.stderr)

    def test_cosign_checks_the_release_workflow_of_the_exact_tag(self):
        self.cosign(0)
        target = self.tmp / "signed"
        run = self.run_script("--version", "v0.0.1", "--dir", str(target), "--require-signature")
        self.assert_installed(run, target / "agentcapsule", "v0.0.1", "agentcapsule-linux-amd64")
        args = (self.tmp / "cosign-args").read_text().splitlines()
        self.assertEqual(args[0], "verify-blob")
        self.assertEqual(args[args.index("--certificate-identity") + 1],
                         "https://github.com/ArnaudGuiovanna/agentcapsule/.github/workflows/release.yml@refs/tags/v0.0.1")
        self.assertEqual(args[args.index("--certificate-oidc-issuer") + 1], "https://token.actions.githubusercontent.com")
        self.assertTrue(args[args.index("--bundle") + 1].endswith("/SHA256SUMS.sigstore.json"))
        self.assertTrue(args[-1].endswith("/SHA256SUMS"))
        self.assertIn("/releases/download/v0.0.1/SHA256SUMS.sigstore.json", self.requests)

    def test_a_failed_signature_is_refused(self):
        self.cosign(1)
        self.previous()
        run = self.run_script("--version", "v0.0.1", "--dir", str(self.tmp / "dir"))
        self.installed_then_refused(run)
        self.assertIn(b"signature of SHA256SUMS", run.stderr)

    def test_bad_tag_or_source_is_refused_before_any_download(self):
        for args, env, message in ((("--version", "v0.0.1;id"), {}, b"not a release tag"),
                                   (("--version", "latest"), {}, b"not a release tag"),
                                   ((), {"AGENTCAPSULE_RELEASE_BASE_URL": "http://example.org/releases"}, b"https://"),
                                   (("--bogus",), {}, b"unknown argument")):
            with self.subTest(args=args, env=env):
                self.requests.clear()
                run = self.run_script(*args, **env)
                self.assertNotEqual(run.returncode, 0)
                self.assertIn(message, run.stderr)
                self.assertEqual(self.requests, [])

    def test_unknown_latest_release_is_refused(self):
        self.server.RequestHandlerClass.latest = "not-a-tag"
        run = self.run_script()
        self.assertNotEqual(run.returncode, 0)
        self.assertIn(b"not a release tag", run.stderr)
        self.assertFalse((self.home / ".local/bin/agentcapsule").exists())

    def test_help(self):
        run = self.run_script("--help")
        self.assertEqual(run.returncode, 0)
        self.assertIn(b"--require-signature", run.stdout)
        self.assertEqual(self.requests, [])


if __name__ == "__main__":
    unittest.main()
