#!/usr/bin/env python3
"""Unit tests of the release audit's scripts, without network, Go or Docker.

release_tools.py (pinned downloads, the allowlist), scan-artifacts.py (grype's
findings, the deploy images' pins), release-sbom.py (the guest archive, ELF,
the attribution of native files, deterministic SPDX) and
audit-dependencies.py (govulncheck's findings, the license policy). The CI
release-audit job runs the real tools.
"""

import datetime
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import stat
import sys
import tarfile
import tempfile
import unittest

SCRIPTS = Path(__file__).resolve().parent
sys.dont_write_bytecode = True


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


TOOLS = load("release_tools", "release_tools.py")
SCAN = load("scan_artifacts", "scan-artifacts.py")
SBOM = load("release_sbom", "release-sbom.py")
AUDIT = load("audit_dependencies", "audit-dependencies.py")
OCI = load("release_oci", "release_oci.py")
GUEST = load("build_product_guest", "build-product-guest.py")
TODAY = datetime.date(2026, 11, 16)


class Temporary(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="release-audit-test-"))
        self.addCleanup(shutil.rmtree, self.dir)

    def write_json(self, name, data):
        path = self.dir / name
        path.write_text(json.dumps(data))
        return path


class PinnedToolTest(Temporary):
    def test_source_cache_reuses_only_digest_verified_bytes(self):
        source = self.dir / "upstream"
        source.write_bytes(b"upstream source")
        url = source.as_uri()
        checksum = TOOLS.sha256(source)
        cache = self.dir / "cache"
        dest = self.dir / "download"
        OCI.checked_download(url, dest, checksum, cache)
        entry, = cache.iterdir()
        self.assertEqual(entry.read_bytes(), source.read_bytes())
        source.unlink()
        dest.unlink()
        OCI.checked_download(url, dest, checksum, cache)
        self.assertEqual(TOOLS.sha256(dest), checksum)
        entry.write_bytes(b"corrupted")
        source.write_bytes(b"different source")
        with self.assertRaisesRegex(ValueError, "checksum mismatch"):
            OCI.checked_download(url, dest, checksum, cache)
        source.write_bytes(b"upstream source")
        OCI.checked_download(url, dest, checksum, cache)
        self.assertEqual(TOOLS.sha256(entry), checksum)

    def test_firecracker_bundle_retains_lock_and_refuses_corrupt_crate(self):
        import os
        from unittest.mock import patch

        crate = b"fixture source"
        checksum = hashlib.sha256(crate).hexdigest()
        work = self.dir / "work"
        work.mkdir()
        vmm = self.dir / "vmm"
        vmm.mkdir()
        lock = vmm / "Cargo.lock"
        lock.write_text('[[package]]\nname = "fixture"\nversion = "1.0.0"\n'
                        'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
                        f'checksum = "{checksum}"\n')
        (vmm / "artifacts.json").write_text(json.dumps({"sha256": {"Cargo.lock": TOOLS.sha256(lock)}}))
        cached = self.dir / "cargo/registry/cache/index.crates.io/fixture-1.0.0.crate"
        cached.parent.mkdir(parents=True)
        cached.write_bytes(crate)
        with patch.dict(os.environ, CARGO_HOME=str(self.dir / "cargo")):
            files = OCI.BUNDLE["firecracker_sources"](vmm, work)
            self.assertEqual(set(files), {"firecracker-Cargo.lock", "cargo/fixture-1.0.0.crate"})
            self.assertEqual(files["cargo/fixture-1.0.0.crate"].read_bytes(), crate)
            cached.write_bytes(b"corrupt source")
            with self.assertRaisesRegex(ValueError, "Cargo cache checksum mismatch"):
                OCI.BUNDLE["firecracker_sources"](vmm, work)
            lock.write_bytes(lock.read_bytes() + b"\n")
            with self.assertRaisesRegex(ValueError, "build lock checksum mismatch"):
                OCI.BUNDLE["firecracker_sources"](vmm, work)

    def pin(self, payload, digest=None):
        archive = self.dir / "tool.tar.gz"
        member = self.dir / "member"
        member.write_bytes(payload)
        with tarfile.open(archive, "w:gz") as tar:
            tar.add(member, arcname="tool")
        pins = {"tool": {"version": "1.0.0", "url": archive.as_uri(), "sha256": digest or TOOLS.sha256(archive),
                         "member": "tool", "version_command": ["--version"], "version_output": "1.0.0"}}
        return self.write_json("pins.json", pins)

    def fetch(self, pins):
        original = TOOLS.PINS
        TOOLS.PINS = pins
        try:
            return TOOLS.fetch("tool", self.dir / "cache")
        finally:
            TOOLS.PINS = original

    def test_unpacks_the_archive_of_the_pinned_digest(self):
        executable = self.fetch(self.pin(b"#!/bin/sh\necho 1.0.0\n"))
        self.assertEqual(executable.read_bytes(), b"#!/bin/sh\necho 1.0.0\n")
        self.assertTrue(executable.stat().st_mode & stat.S_IXUSR)

    def test_refuses_a_file_of_another_digest_and_keeps_nothing(self):
        pins = self.pin(b"payload", digest="0" * 64)
        with self.assertRaisesRegex(RuntimeError, "pinned"):
            self.fetch(pins)
        self.assertEqual(list((self.dir / "cache" / "files").iterdir()), [])

    def test_a_changed_cached_archive_is_downloaded_again(self):
        pins = self.pin(b"good")
        self.fetch(pins)
        cached = next((self.dir / "cache" / "files").iterdir())
        cached.write_bytes(b"tampered")
        self.assertEqual(self.fetch(pins).read_bytes(), b"good")

    def test_every_pin_names_a_digest_and_a_version_check(self):
        for name, pin in TOOLS.pins().items():
            self.assertRegex(pin["sha256"], r"^[0-9a-f]{64}$", name)
            self.assertTrue(pin["url"].startswith("https://"), name)
            self.assertIn(pin["version"], pin["url"], name)
            self.assertTrue(pin["version_output"], name)


class AllowlistTest(Temporary):
    def entries(self, *entries):
        return TOOLS.load_allowlist(self.write_json("allowlist.json", {"entries": list(entries)}), TODAY)

    def entry(self, **changes):
        base = {"ids": ["CVE-1"], "package": "zlib", "reason": "reviewed", "expires": "2026-12-01"}
        base.update(changes)
        return base

    def finding(self, **changes):
        base = {"id": "CVE-1", "aliases": [], "package": "zlib", "target": "image:example/haproxy", "severity": "High"}
        base.update(changes)
        return base

    def test_an_expired_entry_is_a_problem_and_covers_nothing(self):
        entries, problems = self.entries(self.entry(expires="2026-11-15"))
        self.assertEqual(entries, [])
        self.assertIn("expired", problems[0])

    def test_an_entry_beyond_ninety_days_is_refused(self):
        _, problems = self.entries(self.entry(expires="2027-03-01"))
        self.assertIn("90 days", problems[0])

    def test_an_entry_without_a_reason_is_refused(self):
        _, problems = self.entries(self.entry(reason=" "))
        self.assertIn("missing reason", problems[0])

    def test_a_single_id_is_accepted(self):
        entry = self.entry()
        del entry["ids"]
        entries, problems = self.entries(dict(entry, id="CVE-1"))
        self.assertEqual(problems, [])
        self.assertIsNotNone(TOOLS.allowlist_entry(self.finding(), entries))

    def test_an_alias_matches(self):
        entries, _ = self.entries(self.entry(ids=["GHSA-x"]))
        self.assertIsNotNone(TOOLS.allowlist_entry(self.finding(aliases=["GHSA-x"]), entries))

    def test_another_package_or_target_is_not_covered(self):
        entries, _ = self.entries(self.entry(targets=["image:example/haproxy"]))
        self.assertIsNone(TOOLS.allowlist_entry(self.finding(package="sqlite-libs"), entries))
        self.assertIsNone(TOOLS.allowlist_entry(self.finding(target="sbom:product.initrd"), entries))

    def test_blocking_findings_are_split_and_entries_marked_used(self):
        entries, _ = self.entries(self.entry(), self.entry(ids=["CVE-9"]))
        findings = [self.finding(), self.finding(id="CVE-2"), self.finding(id="CVE-3", severity="Low")]
        blocked, allowed, other = TOOLS.apply_allowlist(findings, entries, lambda f: f["severity"] == "High")
        self.assertEqual([f["id"] for f in blocked], ["CVE-2"])
        self.assertEqual([f["id"] for f in allowed], ["CVE-1"])
        self.assertEqual([f["id"] for f in other], ["CVE-3"])
        self.assertEqual(TOOLS.unused_entries(entries), [{"ids": ["CVE-9"], "package": "zlib", "targets": ["*"]}])

    def test_the_repository_allowlist_is_well_formed(self):
        data = json.loads(TOOLS.ALLOWLIST.read_text())
        for entry in data["entries"]:
            self.assertTrue(entry.get("ids") or entry.get("id"))
            for field in ("package", "reason", "expires"):
                self.assertTrue(str(entry.get(field, "")).strip(), field)
            datetime.date.fromisoformat(entry["expires"])


class ScanTest(Temporary):
    def test_deploy_images_must_be_pinned_by_digest(self):
        deploy = self.dir / "deploy" / "interop"
        deploy.mkdir(parents=True)
        digest = "a" * 64
        (deploy / "compose.yml").write_text(
            f"services:\n  a:\n    image: ghcr.io/x/a:1@sha256:{digest}\n  b:\n    image: docker.io/library/b:2\n")
        (deploy / "notes.txt").write_text("image: not/yaml:1\n")
        pinned, unpinned = SCAN.deploy_images(self.dir)
        self.assertEqual(list(pinned), [f"ghcr.io/x/a:1@sha256:{digest}"])
        self.assertEqual(unpinned, ["deploy/interop/compose.yml: docker.io/library/b:2"])

    def test_the_repository_deploy_images_are_all_pinned(self):
        pinned, unpinned = SCAN.deploy_images()
        self.assertEqual(unpinned, [])
        self.assertGreater(len(pinned), 0)

    def test_grype_matches_with_null_fields_are_normalized(self):
        report = {"matches": [{
            "vulnerability": {"id": "CVE-1", "severity": "Critical", "fix": None},
            "relatedVulnerabilities": None,
            "artifact": {"name": "zlib", "version": "1.3", "type": "apk", "locations": None}}, {
            "vulnerability": {"id": "GHSA-1", "severity": "High", "fix": {"state": "fixed", "versions": ["4.1.6"]}},
            "relatedVulnerabilities": [{"id": "CVE-2"}, {"id": "GHSA-1"}],
            "artifact": {"name": "go-jose", "version": "4.1.5", "type": "go-module",
                         "locations": [{"path": "/usr/bin/x"}]}}]}
        first, second = SCAN.findings(report, "image:x")
        self.assertEqual((first["fixed_in"], first["aliases"], first["locations"]), ([], [], []))
        self.assertEqual((second["aliases"], second["fixed_in"]), (["CVE-2"], ["4.1.6"]))

    def test_offline_inventory_uses_only_the_pinned_image_policy(self):
        profile = json.loads((SCAN.ROOT / "runtime/interop/profile.json").read_text())["services"]
        unit = (SCAN.ROOT / "deploy/oidc/agentcapsule-oidc.service").read_text()
        profile["oidc"] = SCAN.re.search(r"quay\.io/keycloak/keycloak@sha256:[0-9a-f]{64}", unit)[0]
        docs, records = [], []
        for service, ref in profile.items():
            sbom = self.dir / ("oci-" + service + ".spdx.json")
            sbom.write_bytes(b"{}")
            docs.append(sbom)
            records.append({"service":service,"ref":ref,"sbom":sbom.name,"sbom_sha256":hashlib.sha256(b"{}").hexdigest()})
        index = self.dir / "component-sources.json"
        index.write_text(json.dumps({"images":records}))
        policies = SCAN.offline_image_policies(index, docs)
        self.assertEqual(policies["sbom:oci-directory"], SCAN.target_name("image", profile["directory"]))
        docs[0].write_bytes(b"changed after inspection")
        with self.assertRaisesRegex(ValueError, "digest"):
            SCAN.offline_image_policies(index, docs)
        docs[0].write_bytes(b"{}")
        records[0]["ref"] = "unrelated@sha256:" + "a" * 64
        index.write_text(json.dumps({"images":records}))
        with self.assertRaisesRegex(ValueError, "pinned"):
            SCAN.offline_image_policies(index, docs)

    def test_target_names(self):
        self.assertEqual(SCAN.target_name("sbom", "/x/agentcapsule-api.spdx.json"), "sbom:agentcapsule-api")
        self.assertEqual(SCAN.target_name("image", "ghcr.io/a/b:1@sha256:" + "0" * 64), "image:ghcr.io/a/b:1")


class GuestSbomTest(Temporary):
    def test_offline_host_inventory_checks_source_digest_and_distro(self):
        deb = self.dir / "runc_1.0_amd64.deb"
        deb.write_bytes(b"package fixture")
        archive = self.dir / "packages.tar"
        with tarfile.open(archive, "w") as tar:
            tar.add(deb, arcname=deb.name)
        record = {"file": deb.name, "package": "runc", "version": "1.0", "source": "runc-app",
                  "sha256": TOOLS.sha256(deb)}
        ref = {"referenceType": "purl", "referenceLocator": "pkg:deb/runc@1.0?arch=amd64&upstream=runc-app"}
        deb_entry = {"SPDXID": "deb", "name": "runc", "versionInfo": "1.0", "externalRefs": [ref]}
        doc = {"packages": [{"SPDXID": "root"}, deb_entry],
               "relationships": [{"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES",
                                  "relatedSpdxElement": "root"}]}
        SBOM.attribute_host_packages(doc, archive, [record], "ubuntu-24.04-amd64")
        self.assertEqual(ref["referenceLocator"], "pkg:deb/ubuntu/runc@1.0?arch=amd64&distro=ubuntu-24.04&upstream=runc-app")
        self.assertEqual(deb_entry["checksums"][0]["checksumValue"], TOOLS.sha256(deb))
        with self.assertRaisesRegex(ValueError, "source package differs"):
            SBOM.attribute_host_packages(doc, archive, [dict(record, source="runc")], "ubuntu-24.04-amd64")
        with self.assertRaisesRegex(ValueError, "digest differs"):
            SBOM.attribute_host_packages(doc, archive, [dict(record, sha256="0" * 64)], "ubuntu-24.04-amd64")
        with self.assertRaisesRegex(ValueError, "incomplete"):
            SBOM.attribute_host_packages(doc, archive, [record, dict(record, file="extra.deb", package="extra")],
                                         "ubuntu-24.04-amd64")

    def test_the_guest_archive_unpacks_byte_for_byte(self):
        entries = {"init": (0o500, b"init-binary"), "sbin/cryptsetup": (0o500, b"\x7fELF..."),
                   "etc/capsule/runtime.json": (0o400, b"{}\n")}
        files = SBOM.unpack_cpio(bytes(GUEST.archive(entries)), self.dir)
        self.assertEqual(files, {name: hashlib.sha256(data).hexdigest() for name, (_, data) in entries.items()})
        self.assertEqual((self.dir / "sbin/cryptsetup").read_bytes(), b"\x7fELF...")
        self.assertFalse((self.dir / "dev/console").exists())

    def test_an_entry_outside_the_root_is_refused(self):
        with self.assertRaisesRegex(ValueError, "outside"):
            SBOM.unpack_cpio(bytes(GUEST.archive({"../escape": (0o400, b"x")})), self.dir / "root")

    def elf(self, interpreter):
        header = bytearray(64)
        header[:6] = b"\x7fELF\x02\x01"
        header[32:40] = (64).to_bytes(8, "little")
        header[54:56] = (56).to_bytes(2, "little")
        header[56:58] = (2).to_bytes(2, "little")
        table = bytearray(112)
        table[0:4] = (1).to_bytes(4, "little")
        table[56:60] = (3 if interpreter else 1).to_bytes(4, "little")
        path = self.dir / ("dynamic" if interpreter else "static")
        path.write_bytes(bytes(header + table))
        return path

    def test_a_static_executable_has_no_interpreter(self):
        self.assertTrue(SBOM.elf_is_static(self.elf(False)))
        self.assertFalse(SBOM.elf_is_static(self.elf(True)))

    def test_a_native_file_that_differs_from_its_build_record_is_unresolved(self):
        natives = {"sbin/cryptsetup": {"source": str(self.dir / "cryptsetup"), "sha256": "1" * 64}}
        packages, unresolved = SBOM.attribute_native(natives, {"sbin/cryptsetup": "2" * 64}, {})
        self.assertEqual(packages, [])
        self.assertIn("differs from the build record", unresolved[0]["reason"])

    def test_a_native_file_is_attributed_to_the_deb_that_holds_it(self):
        source = str((self.dir / "usr/sbin/cryptsetup").resolve())
        entry = {"name": "cryptsetup-bin", "version": "2:2.8.4-1", "arch": "amd64", "source": "cryptsetup",
                 "deb": "cryptsetup-bin.deb", "deb_sha256": "0" * 64}
        natives = {"sbin/cryptsetup": {"source": source, "sha256": "3" * 64}}
        packages, unresolved = SBOM.attribute_native(natives, {"sbin/cryptsetup": "3" * 64}, {source: (entry, "3" * 64)})
        self.assertEqual(unresolved, [])
        self.assertEqual((packages[0]["name"], packages[0]["files"]), ("cryptsetup-bin", ["sbin/cryptsetup"]))
        _, unresolved = SBOM.attribute_native(natives, {"sbin/cryptsetup": "3" * 64}, {source: (entry, "4" * 64)})
        self.assertIn("differs from cryptsetup-bin.deb", unresolved[0]["reason"])

    def test_debian_purls_encode_the_version_and_name_the_release(self):
        purl = SBOM.deb_purl({"name": "libc6", "version": "2:2.39+x", "arch": "amd64", "source": "glibc"},
                             {"id": "ubuntu", "version_id": "24.04"})
        self.assertEqual(purl, "pkg:deb/ubuntu/libc6@2%3A2.39%2Bx?arch=amd64&upstream=glibc&distro=ubuntu-24.04")


class SpdxTest(unittest.TestCase):
    def document(self):
        return {"spdxVersion": "SPDX-2.3", "documentNamespace": "https://example/random-uuid",
                "creationInfo": {"created": "2026-11-16T10:00:00Z", "creators": ["Tool: syft"]},
                "packages": [
                    {"SPDXID": "SPDXRef-root", "name": "x", "versionInfo": ""},
                    {"SPDXID": "SPDXRef-deb-openssl", "name": "openssl", "versionInfo": "3.5.5-1",
                     "externalRefs": [{"referenceType": "purl",
                                       "referenceLocator": "pkg:deb/ubuntu/openssl@3.5.5-1?distro=ubuntu"}]}],
                "relationships": [
                    {"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES",
                     "relatedSpdxElement": "SPDXRef-root"},
                    {"spdxElementId": "SPDXRef-root", "relationshipType": "CONTAINS",
                     "relatedSpdxElement": "SPDXRef-deb-openssl"}]}

    def test_finalize_is_deterministic_and_binds_the_digest(self):
        first = SBOM.finalize(self.document(), "x", "v1.0.0", "ab" * 32, 0)
        second = SBOM.finalize(self.document(), "x", "v1.0.0", "ab" * 32, 0)
        self.assertEqual(first, second)
        self.assertEqual(first["creationInfo"]["created"], "1970-01-01T00:00:00Z")
        self.assertTrue(first["documentNamespace"].endswith("x-v1.0.0-" + "ab" * 32))
        root = next(p for p in first["packages"] if p["SPDXID"] == "SPDXRef-root")
        self.assertEqual(root["checksums"], [{"algorithm": "SHA256", "checksumValue": "ab" * 32}])
        self.assertEqual(root["versionInfo"], "v1.0.0")

    def test_an_unversioned_deb_from_an_elf_note_gives_way_to_dpkg(self):
        document = self.document()
        natives = [{"name": "libssl3t64", "source": "openssl", "version": "3.5.5-1"}]
        self.assertEqual(SBOM.drop_unversioned_debs(document, natives), 1)
        self.assertEqual([p["name"] for p in document["packages"]], ["x"])
        self.assertEqual(len(document["relationships"]), 1)

    def test_an_elf_note_package_of_another_version_is_kept(self):
        document = self.document()
        self.assertEqual(SBOM.drop_unversioned_debs(document, [{"name": "openssl", "source": "openssl",
                                                                  "version": "3.0.0"}]), 0)


class GovulncheckTest(unittest.TestCase):
    STREAM = "\n".join(json.dumps(m, indent=1) for m in [
        {"config": {"scanner_version": "v1.9.0"}},
        {"osv": {"id": "GO-1", "aliases": ["CVE-1"], "summary": "called"}},
        {"osv": {"id": "GO-2", "aliases": [], "summary": "imported"}},
        {"finding": {"osv": "GO-1", "fixed_version": "v1.27.4",
                     "trace": [{"module": "stdlib", "version": "v1.27.3", "package": "net/http"}]}},
        {"finding": {"osv": "GO-1", "fixed_version": "v1.27.4",
                     "trace": [{"module": "stdlib", "version": "v1.27.3", "package": "net/http",
                                "function": "Read", "receiver": "*maxBytesReader"},
                               {"module": "example.com/m", "package": "example.com/m/server", "function": "Serve",
                                "position": {"filename": "/src/server.go", "line": 12}}]}},
        {"finding": {"osv": "GO-2", "trace": [{"module": "golang.org/x/net", "version": "v0.60.0",
                                               "package": "golang.org/x/net/html"}]}},
    ])

    def test_findings_keep_their_deepest_level(self):
        found = AUDIT.govulncheck_findings(self.STREAM, ".")
        self.assertEqual([(f["id"], f["reachable"]) for f in found], [("GO-1", "symbol"), ("GO-2", "package")])
        self.assertEqual(found[0]["aliases"], ["CVE-1"])
        self.assertEqual(found[0]["fixed_in"], ["v1.27.4"])
        self.assertEqual(found[0]["example_call"], "example.com/m/server.Serve (server.go:12)")

    def test_only_a_called_vulnerability_blocks(self):
        found = AUDIT.govulncheck_findings(self.STREAM, ".")
        blocked, _, other = AUDIT.vulnerability_gate(found, [], True, False)
        self.assertEqual([f["id"] for f in blocked], ["GO-1"])
        self.assertEqual([f["id"] for f in other], ["GO-2"])
        self.assertEqual(AUDIT.vulnerability_gate(found, [], False, False)[0], [])

    def test_a_release_waits_for_the_fix_of_an_allowlisted_called_vulnerability(self):
        entry = {"ids": ["CVE-1"], "package": "stdlib", "targets": ["*"], "reason": "r", "expires": "2026-12-01"}
        found = AUDIT.govulncheck_findings(self.STREAM, ".")
        blocked, allowed, _ = AUDIT.vulnerability_gate(found, [dict(entry)], True, False)
        self.assertEqual(([f["id"] for f in blocked], [f["id"] for f in allowed]), ([], ["GO-1"]))
        blocked, allowed, _ = AUDIT.vulnerability_gate(found, [dict(entry)], True, True)
        self.assertEqual(([f["id"] for f in blocked], allowed), (["GO-1"], []))


class LicensePolicyTest(unittest.TestCase):
    POLICY = {"allowed": ["MIT", "Apache-2.0", "BSD-3-Clause"],
              "declared": [{"package": "example.com/bare", "license": "Apache-2.0", "evidence": "https://example/L"}],
              "accepted": [{"package": "example.com/docs", "license": "CC-BY-SA-4.0", "reason": "documentation only"}]}

    def decide(self, name, values):
        return AUDIT.license_decision(name, values, self.POLICY)

    def test_allowed_licenses_and_choices(self):
        self.assertEqual(self.decide("a", ["MIT"])[0], "allowed")
        self.assertEqual(self.decide("a", ["GPL-2.0-only OR MIT"])[0], "allowed")
        self.assertEqual(self.decide("a", ["(MIT AND BSD-3-Clause)"])[0], "allowed")

    def test_a_copyleft_license_is_refused(self):
        self.assertEqual(self.decide("a", ["GPL-3.0-only"])[0], "refused")
        self.assertEqual(self.decide("a", ["MIT AND LGPL-2.1-or-later"])[0], "refused")
        self.assertEqual(self.decide("a", ["MIT", "AGPL-3.0-only"])[0], "refused")

    def test_a_module_without_license_needs_a_declaration(self):
        self.assertEqual(self.decide("example.com/none", [])[0], "unknown")
        self.assertEqual(self.decide("example.com/none", ["sha256:" + "0" * 64])[0], "unknown")
        status, licenses, note = self.decide("example.com/bare", [])
        self.assertEqual((status, licenses), ("allowed", ["Apache-2.0"]))
        self.assertIn("https://example/L", note)

    def test_an_accepted_license_applies_to_its_package_only(self):
        self.assertEqual(self.decide("example.com/docs", ["Apache-2.0", "CC-BY-SA-4.0"])[0], "allowed")
        self.assertEqual(self.decide("example.com/other", ["Apache-2.0", "CC-BY-SA-4.0"])[0], "refused")

    def test_the_repository_policy_allows_no_copyleft_beyond_mpl(self):
        policy = json.loads(AUDIT.POLICY.read_text())
        for refused in ("GPL-2.0-only", "GPL-3.0-or-later", "LGPL-2.1-or-later", "AGPL-3.0-only", "SSPL-1.0"):
            self.assertNotIn(refused, policy["allowed"])
        for entry in policy["declared"]:
            self.assertTrue(entry["evidence"].startswith("https://"))


if __name__ == "__main__":
    unittest.main()
