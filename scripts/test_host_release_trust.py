"""The host helper's release trust (S-16, L-13).

S-16: a release is installed only when cosign verifies its signature by the
release workflow of its tag, run by the push of the tag in this repository,
and the signing certificate names the protected release environment; the two
releases signed before that environment existed pass by their digest only.
L-13: no install or update goes below the highest release the host has had,
nor an empty host below its CLI's release, without --allow-older.
"""
import base64
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
HELPERS = ROOT / "internal/hostops"


def certificate(directory, days=1, extensions=(), key=None, name="cert"):
    """A self-signed certificate (PEM path) with the given extensions."""
    directory.mkdir(parents=True, exist_ok=True)
    out = directory / (name + ".pem")
    keyargs = ["-key", key] if key else ["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
                                         "-keyout", directory / (name + ".key")]
    extra = [arg for ext in extensions for arg in ("-addext", ext)]
    subprocess.run(["openssl", "req", "-x509", *keyargs, "-out", out, "-subj", "/CN=test", "-days", str(days), *extra],
                   check=True, capture_output=True)
    return out


def bundle(directory, environment, chain=False):
    extensions = ["1.3.6.1.4.1.57264.1.20=ASN1:UTF8String:push"]
    if environment:
        extensions.append(f"1.3.6.1.4.1.57264.1.23=ASN1:UTF8String:{environment}")
    pem = certificate(directory, extensions=extensions, name="signer-" + (environment or "none"))
    der = subprocess.run(["openssl", "x509", "-in", pem, "-outform", "DER"], check=True, capture_output=True).stdout
    raw = base64.b64encode(der).decode()
    material = {"x509CertificateChain": {"certificates": [{"rawBytes": raw}]}} if chain else \
        {"certificate": {"rawBytes": raw}}
    return json.dumps({"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
                       "verificationMaterial": material}).encode()


class HostReleaseTrustTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.api = {"__name__": "host_test"}
        for file in ("setup.py", "diagnose.py", "host.py"):
            exec(compile((HELPERS / file).read_bytes(), file, "exec"), self.api)
        self.state = self.root / "state"
        self.state.mkdir()
        self.active = self.root / "active"
        self.api.update(STATE=self.state, ACTIVE=self.active, RELEASES=self.root / "releases",
                        OPERATIONS=self.state / "operations", ETC=self.root / "etc", TRUSTED_ROOT=b"embedded root")

    def installed(self, version):
        self.active.mkdir(exist_ok=True)
        (self.active / "bundle.json").write_text(json.dumps({"version": version}))

    # S-16

    def test_cosign_binds_the_signing_run(self):
        args = self.api["cosign_verification"]("cosign", "bundle.json", "v1.2.3")
        expected = {"--certificate-identity":
                    "https://github.com/ArnaudGuiovanna/agentcapsule/.github/workflows/release.yml@refs/tags/v1.2.3",
                    "--certificate-oidc-issuer": "https://token.actions.githubusercontent.com",
                    "--certificate-github-workflow-trigger": "push",
                    "--certificate-github-workflow-repository": "ArnaudGuiovanna/agentcapsule",
                    "--certificate-github-workflow-ref": "refs/tags/v1.2.3", "--bundle": "bundle.json"}
        self.assertEqual(args[:2], ["cosign", "verify-blob"])
        for flag, value in expected.items():
            self.assertEqual(args[args.index(flag) + 1], value, flag)

    def test_signing_environment_reads_the_certificate(self):
        read = self.api["signing_environment"]
        self.assertEqual(read(bundle(self.root, "release")), "release")
        self.assertEqual(read(bundle(self.root, "release", chain=True)), "release")
        self.assertEqual(read(bundle(self.root, "staging")), "staging")
        self.assertIsNone(read(bundle(self.root, "")))
        for broken in (b"{", b'{"verificationMaterial":{}}', b'{"verificationMaterial":{"certificate":{"rawBytes":"%"}}}',
                       b'{"verificationMaterial":{"certificate":{"rawBytes":"AAAA"}}}'):
            with self.subTest(broken=broken), self.assertRaises((ValueError, KeyError)):
                read(broken)

    def test_releases_signed_before_the_environment_pass_by_their_digest_only(self):
        sums = self.root / "SHA256SUMS"
        sums.write_text("0" * 64 + "  agentcapsule-linux-amd64\n")
        unsigned = self.root / "unsigned.json"
        unsigned.write_bytes(bundle(self.root, ""))
        check = self.api["check_signing_environment"]
        with self.assertRaisesRegex(ValueError, "protected release environment"):
            check(unsigned, sums, "v0.1.0")
        pins = self.api["SIGNED_BEFORE_ENVIRONMENT"]
        self.assertEqual(set(pins), {"v0.0.1", "v0.1.0"})
        with patch.dict(pins, {"v0.1.0": hashlib.sha256(sums.read_bytes()).hexdigest()}):
            check(unsigned, sums, "v0.1.0")
            with self.assertRaisesRegex(ValueError, "protected release environment"):
                check(unsigned, sums, "v0.1.1")

    def test_staging_verifies_the_sigstore_signer(self):
        version = "v0.2.0"
        assets = self.root / "offline"
        assets.mkdir()
        cosign = self.state / "cosign"
        record = self.root / "cosign-args"
        cosign.write_text(f"#!/bin/sh\nprintf '%s\\n' \"$@\" > '{record}'\n")
        cosign.chmod(0o700)
        self.api["COSIGN_HASH"] = hashlib.sha256(cosign.read_bytes()).hexdigest()
        manifest = assets / "agentcapsule-bundle.json"
        manifest.write_text(json.dumps(dict(schema="agentcapsule.bundle/v1", version=version,
                                            platform="ubuntu-24.04-amd64", migrations=[], commit="c")))
        for name in ("SERVER", "DEBS", "IMAGES"):
            (assets / self.api[name]).write_bytes(b"sample")
        files = sorted(p for p in assets.iterdir())
        (assets / "SHA256SUMS").write_text("".join(hashlib.sha256(p.read_bytes()).hexdigest() + "  " + p.name + "\n"
                                                   for p in files))
        trusted = self.root / "trusted-root.json"
        trusted.write_bytes(b"embedded root")
        request = dict(action="install", version=version, offline=str(assets), trusted_root=str(trusted))
        (assets / "SHA256SUMS.sigstore.json").write_bytes(bundle(self.root, "staging"))
        with self.assertRaisesRegex(ValueError, "protected release environment"):
            self.api["stage"](request, True)
        (assets / "SHA256SUMS.sigstore.json").write_bytes(bundle(self.root, "release"))
        plan = self.api["stage"](request, True)
        self.assertEqual(plan["added_migrations"], [])
        args = record.read_text().splitlines()
        self.assertEqual(args[args.index("--certificate-github-workflow-trigger") + 1], "push")
        self.assertEqual(args[args.index("--certificate-github-workflow-ref") + 1], "refs/tags/" + version)
        self.assertIn("--offline", args)

    # L-13

    def test_release_floor_is_the_highest_installed_release(self):
        floor, check, record = (self.api[n] for n in ("release_floor", "validate_release_floor", "record_highest"))
        self.assertIsNone(floor())
        check(dict(action="install", version="v0.0.1"))
        self.installed("v0.2.0")
        self.assertEqual(floor(), "v0.2.0")
        record("v0.3.0", "v0.2.0")
        self.installed("v0.2.5")  # a rollback does not lower the record
        record("v0.2.5", "v0.3.0")
        self.assertEqual(floor(), "v0.3.0")
        for action in ("install", "update"):
            with self.subTest(action=action), self.assertRaisesRegex(ValueError, "--allow-older"):
                check(dict(action=action, version="v0.2.9"))
            check(dict(action=action, version="v0.2.9", allow_older=True))
            check(dict(action=action, version="v0.3.0"))
        check(dict(action="rollback", version="v0.1.0"))
        record("v0.4.0-rc.1", "v0.3.0")
        self.assertEqual(floor(), "v0.4.0-rc.1")

    def test_activation_records_the_highest_release(self):
        release, dist = self.root / "releases/v0.3.0", self.state / "downloads/v0.3.0"
        release.mkdir(parents=True)
        dist.mkdir(parents=True)
        self.installed("v0.2.0")
        with patch.dict(self.api, activate=lambda *_: None):
            self.api["activate_verified"](self.state / "op", dict(action="update", version="v0.3.0"), release, dist)
        self.assertEqual(self.api["highest_recorded"](), "v0.3.0")
        with patch.dict(self.api, activate=lambda *_: None):
            self.api["activate_verified"](self.state / "op", dict(action="update", version="v0.2.1"), release, dist)
        self.assertEqual(self.api["highest_recorded"](), "v0.3.0")

    def plan(self, *args, cli="v0.2.0"):
        with patch.dict(self.api, preflight=lambda: None, stage=lambda *_, **__: {}, latest=lambda: "v0.1.0",
                        HELPER_SOURCE=b"helper"):
            return self.api["main"](list(args), cli)

    def test_an_empty_host_installs_no_release_older_than_its_cli_without_the_flag(self):
        with self.assertRaisesRegex(ValueError, r"older than this CLI \(v0.2.0\).*--allow-older"):
            self.plan("install", "--plan-only", "--to", "v0.1.0")
        self.assertEqual(self.plan("install", "--plan-only", "--to", "v0.1.0", "--allow-older")["state"], "planned")
        self.assertEqual(self.plan("install", "--plan-only")["target"], "v0.2.0")

    def test_update_check_reports_the_floor(self):
        self.installed("v0.2.0")
        self.api["record_highest"]("v0.3.0", "v0.2.0")
        with patch.dict(self.api, latest=lambda: "v0.2.1"):
            report = self.api["main"](["update", "check"], "v0.3.0")
        self.assertEqual((report["highest_installed"], report["older"]), ("v0.3.0", True))

    def test_execute_refuses_an_install_below_the_floor(self):
        self.api["record_highest"]("v0.3.0", None)
        op = self.state / "operations" / ("host_" + "c" * 32)
        op.mkdir(parents=True)
        self.api["save"](op / "request.json", dict(action="install", version="v0.2.0", profile={}, **{"from": None}))
        self.api["state"](op, state="queued")
        with patch.dict(self.api, preflight=lambda: None), self.assertRaisesRegex(ValueError, "--allow-older"):
            self.api["execute"](op)
        self.assertEqual(self.api["read"](op / "status.json")["state"], "failed")


if __name__ == "__main__":
    unittest.main()
