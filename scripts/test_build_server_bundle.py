#!/usr/bin/env python3
"""Unit tests of scripts/build-server-bundle.py, without network, root, APT,
Docker, skopeo or a release build (audit finding A-09).

The release workflow runs the script once per tag. These tests run its logic
on every change: the reproducible archives, the digests it checks before it
trusts a build, the pinned images and packages, the commands it gives
skopeo, apt-get and dpkg, the split of the source archives, and what the
server bundle carries. test_release_audit.py tests firecracker_sources.
"""

import gzip
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import shutil
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import Mock, patch

SCRIPTS = Path(__file__).resolve().parent
ROOT = SCRIPTS.parent
sys.dont_write_bytecode = True


def load():
    spec = importlib.util.spec_from_file_location("build_server_bundle", SCRIPTS / "build-server-bundle.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


BUNDLE = load()
EPOCH = 1_763_000_000
DIGEST = re.compile(r"[a-f0-9]{64}")


def sha(data):
    return hashlib.sha256(data).hexdigest()


class Temporary(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="server-bundle-test-"))
        self.addCleanup(shutil.rmtree, self.dir)

    def write(self, name, data=b"x", mode=0o644):
        path = self.dir / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        path.chmod(mode)
        return path


class WriteTarTest(Temporary):
    def files(self):
        return {"b/program": self.write("program", b"#!/bin/sh\n", 0o750), "a.json": b"{}\n",
                "c/notes.txt": self.write("notes.txt", b"notes", 0o600)}

    def test_archives_are_reproducible_and_normalized(self):
        for compress in (False, True):
            first, second = self.dir / f"first-{compress}", self.dir / f"second-{compress}"
            BUNDLE.write_tar(first, self.files(), EPOCH, compress)
            # Another mtime and insertion order give the same bytes.
            os.utime(self.dir / "program", (1, 1))
            BUNDLE.write_tar(second, dict(reversed(list(self.files().items()))), EPOCH, compress)
            self.assertEqual(first.read_bytes(), second.read_bytes())
            raw = first.read_bytes()
            if compress:
                self.assertEqual(int.from_bytes(raw[4:8], "little"), EPOCH, "gzip header mtime")
                self.assertEqual(raw[3] & 0x08, 0, "no file name in the gzip header")
                raw = gzip.decompress(raw)
            with tarfile.open(fileobj=io.BytesIO(raw)) as tar:
                members = tar.getmembers()
                self.assertEqual([m.name for m in members], ["a.json", "b/program", "c/notes.txt"])
                for m in members:
                    self.assertTrue(m.isfile())
                    self.assertEqual((m.uid, m.gid, m.uname, m.gname, m.mtime), (0, 0, "", "", EPOCH))
                self.assertEqual({m.name: m.mode for m in members},
                                 {"a.json": 0o644, "b/program": 0o755, "c/notes.txt": 0o644})
                self.assertEqual(tar.extractfile("c/notes.txt").read(), b"notes")

    def test_an_existing_archive_is_never_overwritten(self):
        path = self.write("out.tar", b"previous")
        with self.assertRaises(FileExistsError):
            BUNDLE.write_tar(path, {"a": b"a"}, EPOCH)
        self.assertEqual(path.read_bytes(), b"previous")


class TreeTest(Temporary):
    def test_keeps_regular_files_under_the_prefix_and_skips_links(self):
        self.write("unit/a.service")
        self.write("unit/conf.d/b.conf")
        (self.dir / "unit/empty").mkdir()
        (self.dir / "unit/link.service").symlink_to(self.dir / "unit/a.service")
        files = BUNDLE.tree(self.dir / "unit", "systemd")
        self.assertEqual(files, {"systemd/a.service": self.dir / "unit/a.service",
                                 "systemd/conf.d/b.conf": self.dir / "unit/conf.d/b.conf"})


class RuntimeFilesTest(Temporary):
    def setUp(self):
        super().setUp()
        self.dist, self.kernel, self.vmm = self.dir / "dist", self.dir / "kernel", self.dir / "vmm"
        for name in BUNDLE.HOST_PROGRAMS:
            self.write("dist/" + name, name.encode(), 0o755)
        initrd = self.write("dist/product.initrd", b"initrd")
        (self.dist / "product-guest.json").write_text(json.dumps({"artifacts": {"product.initrd": sha(initrd.read_bytes())}}))
        self.built = {"vmlinux": self.write("kernel/vmlinux", b"kernel"), "firecracker": self.write("vmm/firecracker", b"vmm", 0o755),
                      "jailer": self.write("vmm/jailer", b"jailer", 0o755)}
        self.record(self.kernel, ["vmlinux"])
        self.record(self.vmm, ["firecracker", "jailer"])

    def record(self, build, names):
        digests = {name: sha(self.built[name].read_bytes()) for name in names}
        (build / "artifacts.json").write_text(json.dumps({"sha256": digests}))

    def test_the_bundle_carries_the_host_programs_runtime_services_and_docs(self):
        files = BUNDLE.runtime_files(self.dist, self.kernel, self.vmm)
        for name in (*BUNDLE.HOST_PROGRAMS, "product.initrd", "vmlinux", "firecracker", "jailer",
                     "agentcapsule-archive-ship.py", "config/worker.json", "config/slim-bridge.json",
                     "openapi/openapi.yaml", "docs/install.md", "docs/release.md", "docs/cli-host.md",
                     "systemd/agentcapsule-worker.service", "backup/pgbackrest.conf", "interop/compose.yml",
                     "oidc/agentcapsule-oidc.service", "oidc/agentcapsule-oidc-edge.service", "oidc/realm.json"):
            self.assertIn(name, files)
            self.assertTrue(Path(files[name]).is_file(), name)
        self.assertEqual(files["config/worker.json"], ROOT / "runtime/worker/config.example.json")

    def test_the_oidc_helper_ships_and_no_go_source_does(self):
        # A-09: the Go package that embeds the helper lives in internal/, and
        # the bundle carries the helper itself, never Go source.
        files = BUNDLE.runtime_files(self.dist, self.kernel, self.vmm)
        self.assertEqual(files["oidc/container.py"], ROOT / "internal/oidclifecycle/container.py")
        self.assertEqual([name for name in files if name.endswith(".go")], [])

    def test_deploy_holds_no_go_package(self):
        # Everything under deploy/ is shipped or installed as it is.
        found = sorted(p.relative_to(ROOT).as_posix() for p in (ROOT / "deploy").rglob("*.go"))
        self.assertEqual(found, [], "Go code belongs under cmd/ or internal/")

    def test_a_build_that_differs_from_its_record_is_refused(self):
        for name, data in (("vmlinux", b"other kernel"), ("firecracker", b"other vmm"), ("jailer", b"other jailer")):
            with self.subTest(artifact=name):
                original = self.built[name].read_bytes()
                self.built[name].write_bytes(data)
                with self.assertRaisesRegex(ValueError, "runtime build digest mismatch: " + name):
                    BUNDLE.runtime_files(self.dist, self.kernel, self.vmm)
                self.built[name].write_bytes(original)
        (self.dist / "product.initrd").write_bytes(b"another guest")
        with self.assertRaisesRegex(ValueError, "product guest digest mismatch"):
            BUNDLE.runtime_files(self.dist, self.kernel, self.vmm)


class ImageArchiveTest(Temporary):
    OIDC = "quay.io/keycloak/keycloak@sha256:" + "d" * 64

    def setUp(self):
        super().setUp()
        self.out, self.work = self.dir / "out", self.dir / "work"
        self.out.mkdir()
        self.work.mkdir()
        self.commands = []
        self.tags = {}

    def skopeo(self, *argv, **kw):
        argv = [str(a) for a in argv]
        self.commands.append(argv)
        _, path, tag = argv[-1].split(":", 2)
        config = json.dumps({"tag": tag}).encode()
        tags = self.tags.get(Path(path).stem, [tag])
        with tarfile.open(path, "w") as tar:
            for name, data in (("manifest.json", json.dumps([{"Config": "config.json", "RepoTags": tags}]).encode()),
                               ("config.json", config)):
                info = tarfile.TarInfo(name)
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))

    def archive(self, services):
        runpy = Mock()
        runpy.run_path.return_value = {"oidc_image": lambda root: self.OIDC}
        self.write("root/runtime/interop/profile.json", json.dumps({"services": services}).encode())
        with patch.object(BUNDLE, "runpy", runpy), patch.object(BUNDLE, "run", self.skopeo), \
                patch.object(BUNDLE, "ROOT", self.dir / "root"):
            return BUNDLE.image_archive(self.out, self.work, EPOCH)

    def test_each_pinned_image_is_copied_by_digest_into_a_checked_archive(self):
        ref = "ghcr.io/agntcy/slim:3.4.6@sha256:" + "a" * 64
        metadata = self.archive({"slim": ref})
        self.assertEqual(self.commands, [
            ["skopeo", "--override-os", "linux", "--override-arch", "amd64", "copy", "--retry-times", "3",
             "docker://ghcr.io/agntcy/slim@sha256:" + "a" * 64,
             f"docker-archive:{self.work / 'slim.tar'}:localhost/agentcapsule-offline/slim:{'a' * 64}"],
            ["skopeo", "--override-os", "linux", "--override-arch", "amd64", "copy", "--retry-times", "3",
             "docker://" + self.OIDC, f"docker-archive:{self.work / 'oidc.tar'}:localhost/agentcapsule-offline/oidc:{'d' * 64}"]])
        slim, oidc = metadata
        self.assertEqual((slim["service"], slim["engine"], slim["ref"], slim["file"]), ("slim", "docker", ref, "slim.tar"))
        self.assertEqual((oidc["service"], oidc["engine"]), ("oidc", "podman"))
        config = json.dumps({"tag": "localhost/agentcapsule-offline/slim:" + "a" * 64}).encode()
        self.assertEqual(slim["config_id"], "sha256:" + sha(config))
        with tarfile.open(self.out / "agentcapsule-images-linux-amd64.tar.gz") as tar:
            self.assertEqual(tar.getnames(), ["oidc.tar", "slim.tar"])

    def test_an_image_without_a_manifest_digest_is_refused_before_any_copy(self):
        with self.assertRaisesRegex(ValueError, "image must have a manifest digest"):
            self.archive({"slim": "ghcr.io/agntcy/slim:3.4.6"})
        self.assertEqual(self.commands, [])

    def test_an_archive_of_another_image_is_refused(self):
        self.tags["slim"] = ["localhost/agentcapsule-offline/slim:" + "b" * 64]
        with self.assertRaisesRegex(ValueError, "wrong image in offline archive"):
            self.archive({"slim": "ghcr.io/agntcy/slim:3.4.6@sha256:" + "a" * 64})

    def test_the_shipped_images_are_pinned_by_digest(self):
        services = json.loads((ROOT / "runtime/interop/profile.json").read_text())["services"]
        tools = importlib.util.spec_from_file_location("release_tools", SCRIPTS / "release_tools.py")
        release_tools = importlib.util.module_from_spec(tools)
        tools.loader.exec_module(release_tools)
        for ref in (*services.values(), release_tools.oidc_image(ROOT)):
            self.assertRegex(ref, r"@sha256:[a-f0-9]{64}$")


class PackageArchiveTest(Temporary):
    def setUp(self):
        super().setUp()
        self.out, self.src, self.work = self.dir / "out", self.dir / "src", self.dir / "work"
        for d in (self.out, self.src, self.work):
            d.mkdir()
        self.commands = []
        self.sources = {name: name + " (1.0-1)" for name in (*BUNDLE.PACKAGES, *BUNDLE.BASE_UPGRADES)}
        self.sources["curl"] = None  # a binary package named after its source

    def apt(self, *argv, **kw):
        argv = [str(a) for a in argv]
        self.commands.append(argv)
        cache = next(a.split("=", 1)[1] for a in argv if a.startswith("Dir::Cache::archives="))
        for name in self.sources:
            (Path(cache) / f"{name}_1.0-1_amd64.deb").write_bytes(name.encode())

    def dpkg(self, *argv, **kw):
        deb = Path(argv[2]).name
        name = deb.split("_")[0]
        fields = {"Package": name, "Version": "1.0-1"}
        if self.sources[name]:
            fields["Source"] = self.sources[name]
        if len(argv) == 3:
            return "\n".join(f"{k}: {v}" for k, v in fields.items()) + "\nArchitecture: amd64"
        return "\n".join(f"{k}: {fields[k]}" for k in argv[3:] if k in fields)

    def archive(self):
        with patch.object(BUNDLE, "run", self.apt), patch.object(BUNDLE, "output", self.dpkg):
            return BUNDLE.package_archive(self.out, self.src, self.work, EPOCH)

    def test_downloads_the_closure_offline_and_indexes_it(self):
        records, sources = self.archive()
        apt, = self.commands
        self.assertEqual(apt[:4], ["apt-get", "-o", "Debug::NoLocking=true", "-o"])
        self.assertIn("Dir::State::status=/dev/null", apt)
        self.assertIn("Dir::Cache::archives=" + str(self.work / "debs"), apt)
        self.assertEqual(apt[apt.index("--download-only"):apt.index("install") + 1],
                         ["--download-only", "--no-install-recommends", "install"])
        self.assertEqual(apt[apt.index("install") + 1:], [*BUNDLE.PACKAGES, *BUNDLE.BASE_UPGRADES])
        self.assertIn("curl=1.0-1", sources)
        self.assertIn("podman=1.0-1", sources)
        self.assertEqual({r["package"] for r in records}, set(self.sources))
        for r in records:
            self.assertEqual(r["sha256"], sha(r["package"].encode()))
        with tarfile.open(self.out / "agentcapsule-packages-linux-amd64.tar") as tar:
            index = tar.extractfile("Packages").read().decode()
            roots = json.loads(tar.extractfile("roots.json").read())
        self.assertIn("Filename: ./podman_1.0-1_amd64.deb\nSize: 6\nSHA256: " + sha(b"podman"), index)
        self.assertEqual(sorted(roots), sorted(name + "=1.0-1" for name in BUNDLE.PACKAGES))

    def test_an_incomplete_closure_is_refused(self):
        del self.sources["podman"]
        with self.assertRaisesRegex(ValueError, "incomplete host package closure"):
            self.archive()

    def test_an_unreadable_source_field_is_refused(self):
        self.sources["podman"] = "podman (1.0-1); rm -rf /"
        with self.assertRaisesRegex(ValueError, "invalid Debian package source"):
            self.archive()


class SourcesTest(Temporary):
    def test_run_owner_takes_one_package_for_the_exact_path(self):
        answers = {"/usr/lib/x86_64-linux-gnu/libc.so.6": "libc6:amd64: /usr/lib/x86_64-linux-gnu/libc.so.6\n",
                   "/usr/share/doc/shared": "libc6:amd64, libc6:i386: /usr/share/doc/shared\n",
                   "/usr/bin/tool": "pkg: /usr/bin/tool.real\n"}
        calls = []

        def query(argv, **kw):
            calls.append(argv)
            return Mock(stdout=answers.get(argv[2], ""))
        with patch.object(BUNDLE.subprocess, "run", query):
            self.assertEqual(BUNDLE.run_owner("/usr/lib/x86_64-linux-gnu/libc.so.6"), "libc6:amd64")
            self.assertIsNone(BUNDLE.run_owner("/usr/share/doc/shared"))
            self.assertIsNone(BUNDLE.run_owner("/usr/bin/tool"))
            self.assertIsNone(BUNDLE.run_owner("/missing"))
        self.assertEqual(calls[0], ["dpkg-query", "-S", "/usr/lib/x86_64-linux-gnu/libc.so.6"])

    def test_run_owner_skips_diversion_lines(self):
        # dpkg-query -S lists a path's diversions before its owner, in the
        # same "<left>: <path>" form (FIX-2): their left part is no package.
        answers = {"/usr/bin/sh": "diversion by dash from: /usr/bin/sh\ndiversion by dash to: /usr/bin/sh.distrib\n"
                                  "dash: /usr/bin/sh\n",
                   "/usr/bin/local": "local diversion from: /usr/bin/local\nlocal diversion to: /usr/bin/local.orig\n"}
        with patch.object(BUNDLE.subprocess, "run", lambda argv, **kw: Mock(stdout=answers.get(argv[2], ""))):
            self.assertEqual(BUNDLE.run_owner("/usr/bin/sh"), "dash")
            self.assertIsNone(BUNDLE.run_owner("/usr/bin/local"))

    def test_matching_sources_follows_merged_usr_and_fetches_each_source_once(self):
        owners = {"/usr/lib/libz.so.1": "zlib1g", "/usr/bin/busybox": "busybox-static"}
        guest = {"native_files": {"a": {"source": "/lib/libz.so.1"}, "b": {"source": "/usr/bin/busybox"}}}
        fetched = []
        src = self.dir / "src"
        src.mkdir()

        def output(*argv, **kw):
            return {"zlib1g": "zlib=1:1.3", "busybox-static": "busybox=1:1.36", "libc6-dev": "glibc=2.39"}[argv[-1]]

        def run(*argv, cwd=None, **kw):
            fetched.append((list(argv), cwd))
            (src / (argv[-1].replace("=", "_") + ".dsc")).write_text("dsc")
        with patch.object(BUNDLE, "run_owner", owners.get), patch.object(BUNDLE, "output", output), patch.object(BUNDLE, "run", run):
            files = BUNDLE.matching_sources({"podman=4.9"}, guest, src)
        self.assertEqual([a[-1] for a, _ in fetched], ["busybox=1:1.36", "glibc=2.39", "podman=4.9", "zlib=1:1.3"])
        self.assertTrue(all(a[:3] == ["apt-get", "--download-only", "source"] and cwd == src for a, cwd in fetched))
        self.assertEqual(set(files), {"busybox_1:1.36.dsc", "glibc_2.39.dsc", "podman_4.9.dsc", "zlib_1:1.3.dsc"})
        guest["native_files"]["c"] = {"source": "/opt/unknown"}
        with patch.object(BUNDLE, "run_owner", owners.get), patch.object(BUNDLE, "output", output), patch.object(BUNDLE, "run", run):
            with self.assertRaisesRegex(ValueError, "no corresponding package for /opt/unknown"):
                BUNDLE.matching_sources(set(), guest, src)

    def sparse(self, name, size):
        path = self.dir / name
        with path.open("wb") as f:
            f.truncate(size)
        return path

    def test_source_archives_stay_under_the_release_asset_limit(self):
        mib = 1 << 20
        files = {"a.tar": self.sparse("a", 900 * mib), "b.tar": self.sparse("b", 700 * mib), "c.dsc": b"dsc",
                 "d.tar": self.sparse("d", 1500 * mib)}
        written = []
        with patch.object(BUNDLE, "write_tar", lambda path, group, epoch: written.append((path.name, sorted(group), epoch))):
            BUNDLE.source_archives(self.dir, files, EPOCH)
        self.assertEqual(written, [("agentcapsule-sources-01.tar", ["a.tar"], EPOCH),
                                   ("agentcapsule-sources-02.tar", ["b.tar", "c.dsc"], EPOCH),
                                   ("agentcapsule-sources-03.tar", ["d.tar"], EPOCH)])
        files["e.tar"] = self.sparse("e", 1500 * mib + 1)
        with patch.object(BUNDLE, "write_tar", Mock()) as write:
            with self.assertRaisesRegex(ValueError, "source package too large"):
                BUNDLE.source_archives(self.dir, files, EPOCH)
        write.assert_not_called()


class MainTest(Temporary):
    def build(self, **changes):
        record = dict(status="passed", reproducible=True, commit="c" * 40, version="v0.1.0", source_date_epoch=EPOCH)
        record.update(changes)
        build = self.dir / "build"
        build.mkdir(exist_ok=True)
        (build / "build.json").write_text(json.dumps(record))
        return build

    def main(self, build):
        argv = ["build-server-bundle.py", "--build", str(build), "--kernel", str(self.dir / "kernel"), "--vmm", str(self.dir / "vmm"),
                "--out", str(self.dir / "out"), "--licenses", str(self.dir / "licenses.txt")]
        reached = RuntimeError("the checks passed")
        with patch.object(sys, "argv", argv), patch.object(BUNDLE, "output", lambda *a, **kw: "c" * 40), \
                patch.object(BUNDLE, "runtime_files", Mock(side_effect=reached)):
            BUNDLE.main()

    def test_only_the_reproducible_build_of_the_checked_out_tag_is_bundled(self):
        for changes in (dict(status="failed"), dict(reproducible="yes"), dict(reproducible=False), dict(commit="d" * 40),
                        dict(version="0.1.0"), dict(version="v0.1"), dict(version="v0.1.0;"), dict(version="latest")):
            with self.subTest(**changes):
                with self.assertRaisesRegex(ValueError, "successful reproducible build of the checked-out release tag"):
                    self.main(self.build(**changes))
                self.assertFalse((self.dir / "out").exists(), "nothing is written before the build is accepted")
        for version in ("v0.1.0", "v1.2.3-rc.1"):
            with self.subTest(version=version):
                with self.assertRaisesRegex(RuntimeError, "the checks passed"):
                    self.main(self.build(version=version))


if __name__ == "__main__":
    unittest.main()
