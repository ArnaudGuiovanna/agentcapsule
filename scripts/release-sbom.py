#!/usr/bin/env python3
"""Write one SPDX 2.3 SBOM (JSON) per release artifact.

syft, pinned by scripts/release-tools.json, catalogs each artifact:

  --binary FILE        a Go binary: the modules and the Go version that Go
                       records in it (`go version -m`), with the licenses
                       found in the local module cache. A binary linked
                       statically with cgo also gets the C library of the
                       build host (libc6-dev), and the SLIM bridge the SLIM
                       native library pinned by runtime/interop/profile.json.
  --guest-build DIR    the guest image written by build-product-guest.py (or
                       the dist/ directory of build-release.py):
                       product.initrd is unpacked, cataloged, and each native
                       file recorded in artifacts.json is attributed to the
                       Debian package it comes from (dpkg on the build host,
                       or the .deb files of --extracted-debs), after checking
                       that the file in the image is the packaged one.
  --harness-package DIR
                       a harness package (harness.yaml, checksums.json,
                       harness.ext4): its checksums are checked, then the
                       ext4 image is unpacked with debugfs, without root, and
                       cataloged (Alpine, Debian and Python packages, Go
                       binaries).
  --host-assets DIR    the server archive, its offline Ubuntu packages and
                       the private userspace. Verify each package inventory
                       against the signed distribution's build inputs.

SBOMs are deterministic: their creation time is SOURCE_DATE_EPOCH (or the
commit's time) and their namespace derives from the artifact's SHA-256, which
the document's root element also carries. The new --output directory receives
<artifact>.spdx.json for each artifact and summary.json. A native file of the
guest that cannot be attributed fails the run.
"""

import argparse
import datetime
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import urllib.parse

SCRIPTS = Path(__file__).resolve().parent
ROOT = SCRIPTS.parent
SPEC = importlib.util.spec_from_file_location("release_tools", SCRIPTS / "release_tools.py")
TOOLS = importlib.util.module_from_spec(SPEC)
sys.dont_write_bytecode = True
SPEC.loader.exec_module(TOOLS)

NAMESPACE = "https://spdx.org/spdxdocs/agentcapsule"
SLIM_MODULE = "agentcapsule.local/slimbridge"
# Paths that merged-/usr systems may record either way in dpkg's database.
USR_ALIASES = (("/usr/lib/", "/lib/"), ("/usr/sbin/", "/sbin/"), ("/usr/bin/", "/bin/"), ("/usr/lib64/", "/lib64/"))


def sha256(path):
    return TOOLS.sha256(path)


# --- cpio (newc) -------------------------------------------------------------

def cpio_entries(data):
    """Yield (name, mode, content) of a newc cpio archive, as build-product-guest.py writes it."""
    offset = 0
    while True:
        if data[offset:offset + 6] != b"070701":
            raise ValueError(f"not a newc cpio header at offset {offset}")
        fields = [int(data[offset + 6 + 8 * i: offset + 14 + 8 * i], 16) for i in range(13)]
        mode, size, namesize = fields[1], fields[6], fields[11]
        name_start = offset + 110
        name = data[name_start:name_start + namesize - 1].decode()
        content_start = name_start + namesize
        content_start += -content_start % 4
        content = data[content_start:content_start + size]
        offset = content_start + size
        offset += -offset % 4
        if name == "TRAILER!!!":
            return
        yield name, mode, content


def unpack_cpio(data, target):
    """Write directories and regular files of the archive under target; return {name: sha256}."""
    files = {}
    for name, mode, content in cpio_entries(data):
        path = (target / name).resolve()
        if not path.is_relative_to(target.resolve()):
            raise ValueError(f"cpio entry outside the archive root: {name}")
        if stat.S_ISDIR(mode):
            path.mkdir(parents=True, exist_ok=True)
        elif stat.S_ISREG(mode):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
            path.chmod(stat.S_IMODE(mode) | 0o600)
            files[name] = hashlib.sha256(content).hexdigest()
    return files


# --- ELF and Go build information -------------------------------------------

def elf_is_static(path):
    """True when a 64-bit little-endian ELF executable has no program interpreter."""
    with open(path, "rb") as f:
        header = f.read(64)
        if header[:4] != b"\x7fELF" or header[4] != 2 or header[5] != 1:
            raise ValueError(f"{path}: not a 64-bit little-endian ELF file")
        phoff = int.from_bytes(header[32:40], "little")
        phentsize = int.from_bytes(header[54:56], "little")
        phnum = int.from_bytes(header[56:58], "little")
        f.seek(phoff)
        table = f.read(phentsize * phnum)
    return all(int.from_bytes(table[i * phentsize:i * phentsize + 4], "little") != 3 for i in range(phnum))


def go_build_info(go, path):
    out = subprocess.run([str(go), "version", "-m", str(path)], capture_output=True, text=True, check=False)
    info = {"path": "", "version": "", "settings": {}}
    for line in out.stdout.splitlines()[1:]:
        parts = line.strip().split("\t")
        if parts[0] == "path" and len(parts) > 1:
            info["path"] = parts[1]
        elif parts[0] == "mod" and len(parts) > 2:
            info["version"] = parts[2]
        elif parts[0] == "build" and len(parts) > 1 and "=" in parts[1]:
            key, value = parts[1].split("=", 1)
            info["settings"][key] = value
    return info


# --- Debian packages ----------------------------------------------------------

def os_release(path="/etc/os-release"):
    values = {}
    for line in Path(path).read_text().splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            values[key] = value.strip().strip('"')
    return values


def dpkg_fields(package):
    out = subprocess.run(["dpkg-query", "-W", "-f", "${Package}\t${Version}\t${Architecture}\t${source:Package}\t${Conffiles}",
                          package], capture_output=True, text=True, check=False)
    if out.returncode or not out.stdout:
        return None
    name, version, arch, source, conffiles = (out.stdout.split("\t") + [""] * 5)[:5]
    return {"name": name, "version": version, "arch": arch, "source": source or name, "conffiles": conffiles}


def dpkg_owner(path):
    """(package, path as dpkg records it) for a host file, trying the merged-/usr aliases."""
    candidates = [path]
    for usr, legacy in USR_ALIASES:
        if path.startswith(usr):
            candidates.append(legacy + path[len(usr):])
        elif path.startswith(legacy):
            candidates.append(usr + path[len(legacy):])
    for candidate in candidates:
        out = subprocess.run(["dpkg-query", "-S", candidate], capture_output=True, text=True, check=False)
        for line in out.stdout.splitlines():
            owner, _, recorded = line.partition(": ")
            if recorded == candidate and "," not in owner:
                return owner, candidate
    return None, None


def dpkg_md5(package, recorded):
    """The MD5 that dpkg recorded for a file (or a configuration file) of an installed package."""
    control = subprocess.run(["dpkg-query", "--control-path", package, "md5sums"], capture_output=True, text=True,
                             check=False).stdout.strip()
    if control and Path(control).is_file():
        for line in Path(control).read_text().splitlines():
            digest, _, name = line.partition("  ")
            if "/" + name == recorded:
                return digest
    fields = dpkg_fields(package) or {}
    for line in fields.get("conffiles", "").splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0] == recorded:
            return parts[1]
    return None


def deb_index(roots):
    """{absolute file path: (deb fields, sha256)} for the .deb files extracted into each root."""
    index = {}
    for root in roots:
        for deb in sorted((Path(root) / "packages").glob("*.deb")):
            control = subprocess.run(["dpkg-deb", "-f", str(deb), "Package", "Version", "Architecture", "Source"],
                                     capture_output=True, text=True, check=True).stdout
            fields = dict(line.split(": ", 1) for line in control.splitlines() if ": " in line)
            entry = {"name": fields["Package"], "version": fields["Version"], "arch": fields["Architecture"],
                     "source": fields.get("Source", fields["Package"]).split(" ")[0], "deb": deb.name,
                     "deb_sha256": sha256(deb)}
            fsys = subprocess.run(["dpkg-deb", "--fsys-tarfile", str(deb)], capture_output=True, check=True).stdout
            with tarfile.open(fileobj=io.BytesIO(fsys)) as tar:
                for member in tar.getmembers():
                    if member.isfile():
                        digest = hashlib.sha256(tar.extractfile(member).read()).hexdigest()
                        index[str((Path(root) / member.name).resolve())] = (entry, digest)
    return index


def attribute_native(native_files, image_files, debs):
    """Map each native file of the guest to its package; return (packages, unresolved)."""
    packages, unresolved = {}, []
    for dest, record in sorted(native_files.items()):
        source, recorded = record["source"], record["sha256"]
        if image_files.get(dest) != recorded:
            unresolved.append({"file": dest, "reason": "the image's file differs from the build record"})
            continue
        if source in debs:
            entry, digest = debs[source]
            if digest != recorded:
                unresolved.append({"file": dest, "reason": f"differs from {entry['deb']}"})
                continue
            key = (entry["name"], entry["version"])
            packages.setdefault(key, dict(entry, files=[]))["files"].append(dest)
            continue
        owner, path = dpkg_owner(source)
        if owner is None:
            unresolved.append({"file": dest, "reason": f"no installed package owns {source}"})
            continue
        if not Path(source).is_file() or sha256(source) != recorded:
            unresolved.append({"file": dest, "reason": f"{source} changed on this host since the build"})
            continue
        md5 = hashlib.md5(Path(source).read_bytes()).hexdigest()
        if dpkg_md5(owner, path) != md5:
            unresolved.append({"file": dest, "reason": f"{source} is not the file {owner} installed"})
            continue
        fields = dpkg_fields(owner)
        key = (fields["name"], fields["version"])
        packages.setdefault(key, {k: fields[k] for k in ("name", "version", "arch", "source")} | {"files": []})[
            "files"].append(dest)
    return list(packages.values()), unresolved


# --- SPDX ---------------------------------------------------------------------

def deb_purl(package, distro):
    version = urllib.parse.quote(package["version"], safe=".-_~")
    return (f"pkg:deb/{distro['id']}/{package['name']}@{version}?arch={package['arch']}"
            + (f"&upstream={package['source']}" if package.get("source") and package["source"] != package["name"] else "")
            + f"&distro={distro['id']}-{distro['version_id']}")


def spdx_package(spdx_id, name, version, purl, license_declared="NOASSERTION", checksum=None, comment=None):
    package = {"SPDXID": spdx_id, "name": name, "versionInfo": version, "downloadLocation": "NOASSERTION",
               "filesAnalyzed": False, "licenseConcluded": "NOASSERTION", "licenseDeclared": license_declared,
               "copyrightText": "NOASSERTION", "supplier": "NOASSERTION",
               "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
                                 "referenceLocator": purl}]}
    if checksum:
        package["checksums"] = [{"algorithm": "SHA256", "checksumValue": checksum}]
    if comment:
        package["comment"] = comment
    return package


def drop_unversioned_debs(document, natives):
    """Remove the Debian packages that syft read from ELF package notes when dpkg attributed the same.

    Such a note names the source package and its version but not the distribution's release, so
    a scanner cannot use the distribution's own fix data and matches upstream ranges instead.
    """
    attributed = {(n[key], n["version"]) for n in natives for key in ("name", "source")}
    dropped = set()
    for package in document["packages"]:
        purls = [r["referenceLocator"] for r in package.get("externalRefs", []) if r.get("referenceType") == "purl"]
        if any(purl.startswith("pkg:deb/") and not re.search(r"[?&]distro=[^&]+-[0-9]", purl) for purl in purls) \
                and (package["name"], package.get("versionInfo")) in attributed:
            dropped.add(package["SPDXID"])
    document["packages"] = [p for p in document["packages"] if p["SPDXID"] not in dropped]
    document["relationships"] = [r for r in document["relationships"]
                                 if r["spdxElementId"] not in dropped and r["relatedSpdxElement"] not in dropped]
    return len(dropped)


def attribute_host_packages(document, archive, records, platform):
    distro = re.fullmatch(r"(ubuntu)-(\d+\.\d+)-(amd64)", platform)
    if not distro:
        raise ValueError(f"unknown host package platform: {platform}")
    by_file = {p["file"]: p for p in records}
    by_package = {(p["package"], p["version"]): p for p in records}
    if not records or len(by_file) != len(records) or len(by_package) != len(records):
        raise ValueError("empty or duplicate host packages")
    with tarfile.open(archive) as packages:
        for member in packages:
            if not member.name.endswith(".deb"):
                continue
            record = by_file.pop(member.name, None)
            if not member.isfile() or not record:
                raise ValueError(f"unexpected archived host package: {member.name}")
            with packages.extractfile(member) as content:
                digest = hashlib.file_digest(content, "sha256").hexdigest()
            if digest != record["sha256"]:
                raise ValueError(f"host package digest differs: {member.name}")
    root = document_root(document)
    for pkg in document["packages"]:
        if pkg["SPDXID"] == root:
            continue
        record = by_package.pop((pkg["name"], pkg.get("versionInfo")), None)
        refs = [r for r in pkg.get("externalRefs", []) if r["referenceType"] == "purl"]
        if not record or len(refs) != 1 or not refs[0]["referenceLocator"].startswith("pkg:deb/"):
            raise ValueError(f"unexpected host package inventory entry: {pkg['name']}")
        parsed = urllib.parse.urlsplit(refs[0]["referenceLocator"])
        qualifiers = dict(urllib.parse.parse_qsl(parsed.query))
        if qualifiers.get("arch") not in ("all", distro[3]):
            raise ValueError(f"unexpected host package architecture: {pkg['name']}")
        source = re.fullmatch(r"([a-z0-9.+-]+)(?: \(([^()]+)\))?", record["source"])
        if not source:
            raise ValueError(f"invalid Ubuntu source package: {record['source']}")
        upstream = source[1] + ("@" + source[2] if source[2] else "")
        if qualifiers.get("upstream", pkg["name"]) != upstream:
            raise ValueError(f"host source package differs: {pkg['name']}")
        qualifiers["distro"] = f"{distro[1]}-{distro[2]}"
        name = urllib.parse.quote(pkg["name"], safe="")
        version = urllib.parse.quote(record["version"], safe="")
        refs[0]["referenceLocator"] = f"pkg:deb/{distro[1]}/{name}@{version}?" + urllib.parse.urlencode(sorted(qualifiers.items()))
        pkg["checksums"] = [{"algorithm": "SHA256", "checksumValue": record["sha256"]}]
        pkg["comment"] = f"Ubuntu {distro[2]} source package {source[1]}, version {source[2] or record['version']}."
    if by_file or by_package:
        raise ValueError("incomplete host package archive or inventory")


def document_root(document):
    roots = [r["relatedSpdxElement"] for r in document["relationships"]
             if r["spdxElementId"] == "SPDXRef-DOCUMENT" and r["relationshipType"] == "DESCRIBES"]
    if len(roots) != 1:
        raise ValueError("the SBOM does not describe exactly one root element")
    return roots[0]


def add_packages(document, packages):
    root = document_root(document)
    for package in packages:
        document["packages"].append(package)
        document["relationships"].append({"spdxElementId": root, "relatedSpdxElement": package["SPDXID"],
                                          "relationshipType": "CONTAINS"})


def finalize(document, name, version, digest, epoch):
    """Make the document deterministic and bind it to the artifact's digest."""
    created = datetime.datetime.fromtimestamp(epoch, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    document["documentNamespace"] = f"{NAMESPACE}/{name}-{version}-{digest}"
    document["creationInfo"]["created"] = created
    creators = document["creationInfo"].setdefault("creators", [])
    if "Tool: agentcapsule-release-sbom" not in creators:
        creators.append("Tool: agentcapsule-release-sbom")
    root = document_root(document)
    for element in document.get("packages", []):
        if element["SPDXID"] == root:
            element["checksums"] = [c for c in element.get("checksums", []) if c.get("algorithm") != "SHA256"] + \
                [{"algorithm": "SHA256", "checksumValue": digest}]
            element["versionInfo"] = version
    document["packages"].sort(key=lambda p: p["SPDXID"])
    document["relationships"].sort(key=lambda r: (r["spdxElementId"], r["relationshipType"], r["relatedSpdxElement"]))
    return document


def syft_spdx(syft, source, name, version, env):
    out = subprocess.run([str(syft), "scan", source, "--source-name", name, "--source-version", version, "-q",
                          "-o", "spdx-json"], capture_output=True, text=True, env=env, check=False, timeout=1800)
    if out.returncode:
        raise RuntimeError(f"syft {source} failed: {out.stderr[-1000:]}")
    return json.loads(out.stdout)


def static_libc(distro):
    fields = dpkg_fields("libc6-dev") if shutil.which("dpkg-query") else None
    if not fields:
        return None
    return spdx_package("SPDXRef-Package-deb-libc6-dev-static", fields["name"], fields["version"],
                        deb_purl(fields, distro), comment="The C library linked statically into the Go binaries "
                        "built with cgo: the build host's libc6-dev (static archives) when this SBOM was written.")


def slim_package():
    slim = json.loads((ROOT / "runtime/interop/profile.json").read_text())["slim"]
    return spdx_package("SPDXRef-Package-slim-bindings-native", "slim-bindings", slim["native_release"].split("-v")[-1],
                        f"pkg:github/agntcy/slim-bindings@{slim['native_release']}", license_declared="Apache-2.0",
                        checksum=slim["native_library_sha256"],
                        comment=f"Native library {slim['native_library']} linked statically into the SLIM bridge, from "
                        f"{slim['native_url']}. Its own Rust dependencies are not inventoried here.")


def harness_metadata(directory):
    manifest = (directory / "harness.yaml").read_text()
    values = {}
    for key in ("name", "version"):
        match = re.search(rf"^{key}:\s*(\S+)\s*$", manifest, re.M)
        if not match:
            raise ValueError(f"{directory}/harness.yaml has no {key}")
        values[key] = match.group(1).strip("'\"")
    checks = json.loads((directory / "checksums.json").read_text())["files"]
    for name, expected in checks.items():
        if "sha256:" + sha256(directory / name) != expected:
            raise ValueError(f"{directory}/{name} does not match checksums.json")
    return values


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--binary", action="append", default=[], type=Path)
    p.add_argument("--guest-build", type=Path)
    p.add_argument("--host-assets", type=Path)
    p.add_argument("--harness-package", action="append", default=[], type=Path)
    p.add_argument("--extracted-debs", action="append", default=[], type=Path,
                   help="directory holding packages/*.deb extracted into it (as the guest-build tools directory)")
    p.add_argument("--version", help="version of the binaries and the guest image (default: Go's stamp, or 'untagged')")
    p.add_argument("--go", type=Path, default=Path(shutil.which("go") or "go"))
    p.add_argument("--cache", type=Path, default=TOOLS.default_cache())
    p.add_argument("--output", required=True, type=Path, help="new output directory")
    a = p.parse_args(argv)
    if not (a.binary or a.guest_build or a.harness_package or a.host_assets):
        p.error("nothing to describe")

    epoch_text = os.environ.get("SOURCE_DATE_EPOCH") or subprocess.run(
        ["git", "show", "-s", "--format=%ct", "HEAD"], cwd=ROOT, capture_output=True, text=True, check=True).stdout
    epoch = int(epoch_text.strip())
    out = a.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    syft = TOOLS.tool("syft", a.cache)
    try:
        gomodcache = subprocess.run([str(a.go), "env", "GOMODCACHE"], capture_output=True, text=True,
                                    check=False).stdout.strip()
    except OSError:
        gomodcache = ""  # no Go here: harness packages only, or licenses unknown to syft
    if a.binary and not gomodcache:
        p.error("--binary needs Go (--go) to read the build information")
    env = dict(TOOLS.quiet_env(a.cache), SYFT_GOLANG_SEARCH_LOCAL_MOD_CACHE_LICENSES="true")
    if gomodcache:
        env["SYFT_GOLANG_LOCAL_MOD_CACHE_DIR"] = gomodcache
    release = os_release()
    distro = {"id": release.get("ID", "unknown"), "version_id": release.get("VERSION_ID", "unknown")}
    summary = {"source_date_epoch": epoch, "syft": TOOLS.pins()["syft"]["version"], "build_host": distro,
               "sboms": [], "status": "running"}
    failed = False

    def write(name, version, digest, document, extra=None):
        finalize(document, name, version, digest, epoch)
        path = out / f"{name}.spdx.json"
        path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
        summary["sboms"].append({"artifact": name, "version": version, "sha256": digest, "sbom": path.name,
                                 "packages": len(document["packages"]), **(extra or {})})
        print(f"{path.name}: {len(document['packages'])} packages")

    with tempfile.TemporaryDirectory(prefix="sbom-", dir=out) as work:
        work = Path(work)
        if a.host_assets:
            server = a.host_assets / "agentcapsule-server-linux-amd64.tar.gz"
            with tarfile.open(server) as archive:
                manifest = json.load(archive.extractfile("bundle.json"))
                index = archive.extractfile("host-packages.json").read()
            if hashlib.sha256(index).hexdigest() != manifest["sha256"]["host-packages.json"]:
                raise ValueError("host package index differs from the server manifest")
            package_index = json.loads(index)
            records = package_index["packages"] if isinstance(package_index, dict) else package_index
            package_tar = a.host_assets / "agentcapsule-packages-linux-amd64.tar"
            for artifact in (server, package_tar):
                document = syft_spdx(syft, f"file:{artifact.resolve()}", artifact.name, manifest["version"], env)
                if artifact != server:
                    attribute_host_packages(document, artifact, records, manifest["platform"])
                write(artifact.name, manifest["version"], sha256(artifact), document)
            if "userspace" in manifest:
                runtime = a.host_assets / "agentcapsule-userspace-linux-amd64.tar.gz"
                digest = sha256(runtime)
                if manifest["userspace"] != {"file": runtime.name, "sha256": digest}:
                    raise ValueError("private userspace differs from its server manifest")
                document = syft_spdx(syft, f"file:{runtime.resolve()}", runtime.name, manifest["version"], env)
                with tarfile.open(package_tar) as packages:
                    expected = set(json.load(packages.extractfile("roots-userspace.json")))
                installed = {p["name"] + "=" + p["versionInfo"] for p in document["packages"]
                             if any(ref.get("referenceType") == "purl" and ref["referenceLocator"].startswith("pkg:deb/ubuntu/")
                                    for ref in p.get("externalRefs", []))}
                if not expected or installed != expected:
                    raise ValueError(f"private userspace SBOM differs from its package lock: {sorted(installed ^ expected)}")
                write(runtime.name, manifest["version"], digest, document)
        for binary in a.binary:
            info = go_build_info(a.go, binary)
            version = a.version or info["version"] or "untagged"
            document = syft_spdx(syft, f"file:{binary.resolve()}", binary.name, version, env)
            extra = []
            if info["settings"].get("CGO_ENABLED") == "1" and elf_is_static(binary):
                libc = static_libc(distro)
                if libc:
                    extra.append(libc)
            if info["path"] == SLIM_MODULE:
                extra.append(slim_package())
            add_packages(document, extra)
            write(binary.name, version, sha256(binary), document)

        if a.guest_build:
            initrd = a.guest_build / "product.initrd"
            # build-product-guest.py writes artifacts.json; build-release.py copies it as product-guest.json.
            names = [n for n in ("artifacts.json", "product-guest.json") if (a.guest_build / n).is_file()]
            if not names:
                raise SystemExit(f"{a.guest_build} holds neither artifacts.json nor product-guest.json")
            record = json.loads((a.guest_build / names[0]).read_text())
            if record["artifacts"]["product.initrd"] != sha256(initrd):
                raise SystemExit("product.initrd does not match its artifacts.json")
            tree = work / "guest"
            tree.mkdir()
            image_files = unpack_cpio(initrd.read_bytes(), tree)
            document = syft_spdx(syft, f"dir:{tree}", "product.initrd", a.version or "untagged", env)
            natives, unresolved = attribute_native(record["native_files"], image_files, deb_index(a.extracted_debs))
            packages = [spdx_package(f"SPDXRef-Package-deb-{n['name']}-{hashlib.sha256((n['name'] + n['version']).encode()).hexdigest()[:12]}",
                                     n["name"], n["version"], deb_purl(n, distro),
                                     comment="Files in the guest image: " + ", ".join(sorted(n["files"])))
                        for n in sorted(natives, key=lambda n: n["name"])]
            libc = static_libc(distro)
            if libc:
                packages.append(libc)
            drop_unversioned_debs(document, natives)
            add_packages(document, packages)
            write("product.initrd", a.version or "untagged", sha256(initrd), document,
                  {"native_packages": [f"{n['name']} {n['version']}" for n in natives], "unresolved_native_files": unresolved})
            for item in unresolved:
                print(f"UNRESOLVED {item['file']}: {item['reason']}", file=sys.stderr)
            failed |= bool(unresolved)
            shutil.rmtree(tree)

        for directory in a.harness_package:
            meta = harness_metadata(directory)
            tree = work / ("harness-" + meta["name"])
            tree.mkdir()
            dump = subprocess.run(["debugfs", "-R", f"rdump / {tree}", str(directory / "harness.ext4")],
                                  capture_output=True, text=True, check=False)
            # rdump cannot give files to their owners without root: those messages are expected.
            errors = [line for line in dump.stderr.splitlines() if line.strip() and "changing ownership" not in line
                      and not line.startswith("debugfs ")]
            if dump.returncode or errors:
                raise SystemExit(f"debugfs could not unpack {directory}: {' '.join(errors)[:500]}")
            subprocess.run(["chmod", "-R", "u+rwX", str(tree)], check=True)
            name = f"harness-{meta['name']}-{meta['version']}"
            qualification = json.loads((ROOT / "deploy/images/openssl/qualification.json").read_bytes())
            profile = qualification["harness_sboms"].get(name + ".spdx.json")
            if profile:
                for package in qualification["profiles"][profile].values():
                    file = tree / package["path"]
                    if not file.resolve().is_relative_to(tree.resolve()) or file.is_symlink() or sha256(file) != package["sha256"]:
                        raise ValueError("unexpected OpenSSL binary in " + name + ": " + package["path"])
            document = syft_spdx(syft, f"dir:{tree}", name, meta["version"], env)
            write(name, meta["version"], sha256(directory / "harness.ext4"), document)
            shutil.rmtree(tree)

    summary["status"] = "failed" if failed else "passed"
    (out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(f"{summary['status']}: {out / 'summary.json'}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
