"""Certificate renewal and expiry diagnostics of the host helper (L-14).

The certificates the installer generates last 365 days. An update renews
those that expire within 30 days, with the same keys for the API and the
identity provider; an operator's certificates are never touched. `host
diagnose certificates` reports each certificate's expiry.
"""
import argparse
import datetime
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

HELPERS = Path(__file__).resolve().parents[1] / "internal/hostops"


def certificate(directory, days=1, name="cert"):
    """A self-signed certificate (PEM path), its key beside it."""
    directory.mkdir(parents=True, exist_ok=True)
    out = directory / (name + ".pem")
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
                    "-keyout", directory / (name + ".key"), "-out", out, "-subj", "/CN=test", "-days", str(days)],
                   check=True, capture_output=True)
    return out


class HostCertificateTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.api = {"__name__": "host_test"}
        for file in ("setup.py", "diagnose.py", "host.py"):
            exec(compile((HELPERS / file).read_bytes(), file, "exec"), self.api)
        self.state = self.root / "state"
        self.state.mkdir()
        self.api.update(STATE=self.state, ACTIVE=self.root / "active", RELEASES=self.root / "releases",
                        OPERATIONS=self.state / "operations", ETC=self.root / "etc")


    def profile(self, **fields):
        return self.api["normalize_profile"](dict(api_name="api.example.net", **fields))

    def days_left(self, path):
        end = subprocess.run(["openssl", "x509", "-noout", "-enddate", "-in", path], check=True,
                             capture_output=True, text=True).stdout.strip().removeprefix("notAfter=")
        expiry = datetime.datetime.strptime(end, "%b %d %H:%M:%S %Y GMT").replace(tzinfo=datetime.timezone.utc)
        return (expiry - datetime.datetime.now(datetime.timezone.utc)).days

    def public_key(self, path):
        return subprocess.run(["openssl", "x509", "-noout", "-pubkey", "-in", path], check=True,
                              capture_output=True).stdout

    def test_update_renews_the_generated_certificates_that_expire_soon(self):
        etc = self.api["ETC"]
        api = certificate(etc, days=10, name="api")
        os.replace(api, etc / "api.crt")
        oidc = etc / "oidc-tls"
        certificate(oidc, days=365, name="tls")
        os.replace(oidc / "tls.pem", oidc / "tls.crt")
        interop = etc / "interop"
        for name in self.api["INTEROP_CERTIFICATES"]:
            pem = certificate(self.root / "interop-work", days=20, name="x")
            (interop / name).parent.mkdir(parents=True, exist_ok=True)
            os.replace(pem, interop / name)
        key_before = self.public_key(etc / "api.crt")

        def new_interop(_):
            (etc / "interop").mkdir()
            (etc / "interop/renewed").write_text("yes")
        with patch.dict(self.api, setup_interop=new_interop), patch("os.chown"):
            renewed = self.api["renew_certificates"](self.profile())
        self.assertEqual(renewed, ["api"] + ["interop/" + n for n in sorted(self.api["INTEROP_CERTIFICATES"])])
        self.assertGreater(self.days_left(etc / "api.crt"), 360)
        self.assertEqual(self.public_key(etc / "api.crt"), key_before)
        self.assertTrue((etc / "interop/renewed").is_file())
        self.assertEqual([p.name for p in etc.iterdir() if p.name.startswith(".interop")], [])
        self.assertLess(self.days_left(oidc / "tls.crt"), 366)

    def test_operator_certificates_are_never_renewed(self):
        etc = self.api["ETC"]
        api = certificate(etc, days=3, name="api")
        os.replace(api, etc / "api.crt")
        before = (etc / "api.crt").read_bytes()
        self.assertEqual(self.api["renew_certificates"](self.profile(tls_certificate="/srv/api.crt",
                                                                     tls_key="/srv/api.key")), [])
        self.assertEqual((etc / "api.crt").read_bytes(), before)

    def test_diagnose_reports_each_certificate_expiry(self):
        etc = self.api["ETC"]
        os.replace(certificate(etc, days=10, name="api"), etc / "api.crt")
        (etc / "oidc-tls").mkdir()
        os.replace(certificate(etc, days=200, name="oidc"), etc / "oidc-tls/tls.crt")
        self.api["save"](self.state / "profile.json", self.profile(oidc_cert="/srv/o.crt", oidc_key="/srv/o.key"))
        report = self.api["diagnose"](argparse.Namespace(sub="certificates"))
        found = {c["certificate"]: c for c in report["certificates"]}
        self.assertEqual(set(found), {"api", "oidc"})
        self.assertEqual((found["api"]["status"], found["api"]["renewed_by"]), ("renewal_due", "update"))
        self.assertEqual((found["oidc"]["status"], found["oidc"]["renewed_by"]), ("ok", "operator"))
        self.assertIn(found["api"]["days_remaining"], (9, 10))


if __name__ == "__main__":
    unittest.main()
