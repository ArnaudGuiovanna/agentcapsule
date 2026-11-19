"""Inventory the distributed Docker archives and retain upstream source and notices."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import runpy
import shutil
import subprocess
import tarfile
import tempfile
import zipfile
import tomllib
from urllib.parse import quote
from urllib.request import urlopen

import release_tools

ROOT = Path(__file__).resolve().parents[1]
BUNDLE = runpy.run_path(str(ROOT / "scripts/build-server-bundle.py"))
# The shipped image's build repository for Keycloak differs from its public
# source repository. Use the commit of the corresponding public release tag.
KEYCLOAK_SOURCE = ("26.8.2", "e514445f9dcdabc5bdcf67cab56c1e49655de067")
GITHUB_IMAGES = {"slim": "agntcy/slim", "directory": "agntcy/dir", "init": "agntcy/oasf",
                 "oasf": "agntcy/oasf-server"}


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def is_notice(path):
    name = path.name.lower()
    return (re.fullmatch(r"(license|licence|notice|copying|copyright|third[-_]party[-_]notices?)([._-].*)?", name)
            or "licenses" in [part.lower() for part in path.parts[:-1]])


def safe_relative(name):
    path = PurePosixPath(name)
    return not path.is_absolute() and ".." not in path.parts and bool(path.parts)


def notices(archive, out, prefix, jars=False):
    files = []
    for member in archive:
        name = PurePosixPath(member.name)
        if not member.isfile() or not safe_relative(member.name):
            continue
        if jars and name.suffix.lower() == ".jar":
            with archive.extractfile(member) as stream, tempfile.TemporaryFile() as jar:
                shutil.copyfileobj(stream, jar)
                jar.seek(0)
                with zipfile.ZipFile(jar) as entries:
                    for info in entries.infolist():
                        entry = PurePosixPath(info.filename)
                        if info.is_dir() or not safe_relative(info.filename) or not is_notice(entry):
                            continue
                        target = out / prefix / name / entry
                        target.parent.mkdir(parents=True, exist_ok=True)
                        with entries.open(info) as src, target.open("wb") as dst:
                            shutil.copyfileobj(src, dst)
                        files.append(target.relative_to(out).as_posix())
        if not is_notice(name):
            continue
        target = out / prefix / name
        target.parent.mkdir(parents=True, exist_ok=True)
        with archive.extractfile(member) as stream, target.open("wb") as dst:
            shutil.copyfileobj(stream, dst)
        files.append(target.relative_to(out).as_posix())
    return files


def git_source(repository, revision, work):
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository) or not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise ValueError("invalid upstream Git repository or revision")
    dest = work / f"{repository.replace('/', '-')}-{revision}.tar.gz"
    if dest.exists():
        return dest
    with tempfile.TemporaryDirectory(dir=work) as temp:
        git = ["git", "-C", temp]
        subprocess.run([*git, "init", "--quiet", "--bare"], check=True)
        subprocess.run([*git, "fetch", "--quiet", "--depth=1", "https://github.com/" + repository + ".git", revision], check=True)
        actual = subprocess.check_output([*git, "rev-parse", "FETCH_HEAD^{commit}"], text=True).strip()
        if actual != revision:
            raise ValueError("upstream checkout differs from the pinned commit")
        subprocess.run([*git, "archive", "--format=tar.gz", "--output", dest, revision], check=True)
    return dest


def checked_download(url, dest, expected):
    with urlopen(url, timeout=120) as source, dest.open("wb") as dst:
        shutil.copyfileobj(source, dst)
    if BUNDLE["digest"](dest) != expected:
        raise ValueError("upstream source checksum mismatch for " + dest.name)
    return dest


def native_rust_sources(archive, sources, work, notice_root, syft, sboms):
    with tarfile.open(archive) as tree:
        lock = tree.extractfile("rust/Cargo.lock").read()
    lock_file = work / "Cargo.lock"
    lock_file.write_bytes(lock)
    sbom = sboms / "slim-bindings-Cargo.lock.spdx.json"
    subprocess.run([syft, "scan", "file:" + str(lock_file), "--source-name", "slim-bindings-Cargo.lock",
                    "-o", "spdx-json=" + str(sbom)], env=release_tools.quiet_env(release_tools.default_cache()), check=True)
    packages = tomllib.loads(lock.decode())["package"]

    def collect(pkg):
        if not pkg.get("source"):
            return None
        if pkg["source"] != "registry+https://github.com/rust-lang/crates.io-index":
            raise ValueError("review native source registry for " + pkg["name"])
        name, version = pkg["name"], pkg["version"]
        if not re.fullmatch(r"[a-zA-Z0-9_-]+", name) or not re.fullmatch(r"[a-zA-Z0-9.+_-]+", version):
            raise ValueError("invalid crate identifier")
        filename = f"{name}-{version}.crate"
        dest = checked_download(f"https://static.crates.io/crates/{name}/{filename}", work / filename, pkg["checksum"])
        with tarfile.open(dest) as tree:
            notices(tree, notice_root, "native/crates")
        return dest

    with ThreadPoolExecutor(max_workers=8) as pool:
        for dest in pool.map(collect, packages):
            if dest:
                sources["cargo/" + dest.name] = dest
    return {"lock_sha256": hashlib.sha256(lock).hexdigest(), "sbom": sbom.name,
            "vendored_crates": sum(bool(pkg.get("source")) for pkg in packages)}


def project_source(service, config, work):
    labels = config.get("Labels") or {}
    revision = labels.get("org.opencontainers.image.revision")
    if service in GITHUB_IMAGES:
        repo = GITHUB_IMAGES[service]
        if labels.get("org.opencontainers.image.source") != "https://github.com/" + repo:
            raise ValueError("unexpected source for " + service)
    elif service == "oidc":
        if labels.get("org.opencontainers.image.version") != KEYCLOAK_SOURCE[0]:
            raise ValueError("update the public Keycloak source commit for the new image")
        repo, revision = "keycloak/keycloak", KEYCLOAK_SOURCE[1]
    elif service == "directory-edge":
        env = dict(row.split("=", 1) for row in config["Env"] if "=" in row)
        version = env["HAPROXY_VERSION"]
        if not re.fullmatch(r"\d+\.\d+\.\d+", version):
            raise ValueError("unexpected HAProxy version")
        url = f"https://www.haproxy.org/download/{version.rsplit('.', 1)[0]}/src/haproxy-{version}.tar.gz"
        if env["HAPROXY_URL"] != url:
            raise ValueError("unexpected HAProxy source URL")
        dest = work / url.rsplit("/", 1)[1]
        checked_download(url, dest, env["HAPROXY_SHA256"])
        return dest, url
    else:
        raise ValueError("review source and notices for new image " + service)
    return git_source(repo, revision, work), f"https://github.com/{repo}/tree/{revision}"


def distro_key(package):
    meta = package.get("metadata") or {}
    kind = package["type"]
    if kind == "rpm":
        return "rpm:" + meta["sourceRpm"] + ":"
    if kind == "deb":
        return "deb:" + (meta.get("source") or package["name"]) + ":" + (meta.get("sourceVersion") or package["version"])
    if kind == "apk" and meta.get("gitCommitOfApkPort"):
        version = re.search(r"distro=alpine-(\d+\.\d+)", package["purl"])[1]
        return "apk:" + (meta.get("originPackage") or package["name"]) + ":v" + version + "@" + meta["gitCommitOfApkPort"]
    return None


def mirror_distro(records, sources, work, source_cache):
    lock = json.loads((ROOT / "scripts/release-oci-sources.json").read_bytes())
    required = {pkg["source_package_key"] for image in records for pkg in image["packages"] if pkg.get("source_package_key")}
    if required != lock.keys():
        raise ValueError("review the distro source archives for the updated image inventory")
    members = {}
    for entries in lock.values():
        for file in entries:
            if not re.fullmatch("[0-9a-f]{64}", file["sha256"]) or not safe_relative(file["name"]) or "/" in file["name"]:
                raise ValueError("invalid distro source archive")
            members.setdefault(file["sha256"], file)

    def collect(file):
        name = file["sha256"]
        dest = work / ("distro-" + name)
        cached = source_cache / hashlib.sha256(file["url"].encode()).hexdigest() if source_cache else None
        if cached and cached.is_file() and BUNDLE["digest"](cached) == name:
            shutil.copyfile(cached, dest)
        else:
            checked_download(file["url"], dest, name)
        return name, dest

    with ThreadPoolExecutor(max_workers=5) as pool:
        downloads = dict(pool.map(collect, members.values()))
    for entries in lock.values():
        for file in entries:
            file["member"] = "distro/" + file["sha256"] + "/" + file["name"]
            sources[file["member"]] = downloads[file["sha256"]]
    return lock


def source_record(package):
    kind = package["type"]
    meta = package.get("metadata") or {}
    name, version = package["name"], package["version"]
    record = {"name": name, "version": version, "type": kind, "purl": package.get("purl", ""),
              "licenses": sorted({x["value"] for x in package.get("licenses") or [] if x.get("value")})}
    key = distro_key(package)
    if key:
        record["source_package_key"] = key
    if kind == "deb":
        source = meta.get("source") or name
        version = meta.get("sourceVersion") or version
        record["source"] = f"https://snapshot.debian.org/package/{quote(source, safe='')}/{quote(version, safe='')}/"
    elif kind == "rpm" and meta.get("sourceRpm"):
        record["source_package"] = meta["sourceRpm"]
        record["source_repository"] = "https://cdn-ubi.redhat.com/content/public/ubi/dist/ubi9/9/x86_64/"
    elif kind == "apk" and meta.get("gitCommitOfApkPort"):
        port = quote(meta.get("originPackage") or name, safe="")
        revision = meta["gitCommitOfApkPort"]
        record["source_recipe"] = f"https://gitlab.alpinelinux.org/alpine/aports/-/tree/{revision}"
        record["port"] = port
    elif kind == "go-module" and version not in ("(devel)", "UNKNOWN"):
        escape = lambda text: re.sub("[A-Z]", lambda m: "!" + m[0].lower(), text)
        record["source"] = "https://proxy.golang.org/" + escape(name) + "/@v/" + quote(escape(version)) + ".zip"
    elif kind == "java-archive" and package.get("purl", "").startswith("pkg:maven/"):
        pom = (meta.get("pomProperties") or {})
        if all(pom.get(k) for k in ("groupId", "artifactId", "version")):
            group, artifact, ver = (pom[k] for k in ("groupId", "artifactId", "version"))
            record["source_classifier"] = f"https://repo.maven.apache.org/maven2/{group.replace('.', '/')}/{artifact}/{ver}/{artifact}-{ver}-sources.jar"
    elif kind == "binary" and name == "busybox":
        record["source"] = f"https://busybox.net/downloads/busybox-{version}.tar.bz2"
    return record


def inspect_image(service, source, expected, work, sboms, syft, notice_root, sources):
    all_notices = []
    with tarfile.open(source) as outer:
        manifest, = json.load(outer.extractfile("manifest.json"))
        config = outer.extractfile(manifest["Config"]).read()
        if "sha256:" + hashlib.sha256(config).hexdigest() != expected["config_id"] or expected["tag"] not in manifest["RepoTags"]:
            raise ValueError("OCI identity differs from the server bundle: " + service)
        configuration = json.loads(config)["config"]
        for index, layer in enumerate(manifest["Layers"]):
            with outer.extractfile(layer) as stream, tarfile.open(fileobj=stream, mode="r|*") as contents:
                all_notices += notices(contents, notice_root, f"oci/{service}/layer-{index}", jars=True)
    doc = sboms / f"oci-{service}.spdx.json"
    syft_doc = work / f"oci-{service}.json"
    subprocess.run([syft, "scan", "docker-archive:" + str(source), "--source-name", service,
                    "-o", "spdx-json=" + str(doc), "-o", "syft-json=" + str(syft_doc)],
                   env=release_tools.quiet_env(release_tools.default_cache()), check=True)
    inventory = json.loads(syft_doc.read_bytes())
    packages = [source_record(pkg) for pkg in inventory["artifacts"]]
    if not packages:
        raise ValueError("empty OCI inventory: " + service)
    for package in packages:
        if package["type"] == "binary" and package["name"] == "busybox" and service == "init":
            if package["version"] != "1.37.0":
                raise ValueError("review the BusyBox source version in the schema image")
            filename = "busybox-1.37.0.tar.bz2"
            dest = checked_download(package["source"], work / filename,
                                    "3311dff32e746499f4df0d5df04d7eb396382d7e108bb9250e7b519b837043a4")
            sources[filename] = dest
            with tarfile.open(dest) as tree:
                all_notices += notices(tree, notice_root, "projects/busybox")
    project, origin = project_source(service, configuration, work)
    sources[project.name] = project
    with tarfile.open(project) as tree:
        all_notices += notices(tree, notice_root, "projects/" + service)
    return {**expected, "archive_sha256": BUNDLE["digest"](source), "sbom": doc.name, "sbom_sha256": BUNDLE["digest"](doc),
            "application_source": {"url": origin, "archive": project.name, "sha256": BUNDLE["digest"](project)},
            "image_labels": configuration.get("Labels") or {}, "packages": packages, "notices": sorted(all_notices)}


def audit(assets, sboms, syft, source_cache):
    with tarfile.open(assets / "agentcapsule-server-linux-amd64.tar.gz") as server:
        images = json.load(server.extractfile("offline-images.json"))
        epoch = server.getmember("bundle.json").mtime
    expected = {m["file"]: m for m in images}
    if len(expected) != len(images):
        raise ValueError("duplicate image records")
    sboms.mkdir(exist_ok=True, parents=True)
    with tempfile.TemporaryDirectory() as temp, tarfile.open(assets / "agentcapsule-images-linux-amd64.tar.gz", mode="r|gz") as archive:
        work = Path(temp)
        notice_root = work / "notices"
        sources, records = {}, []
        for image in archive:
            if image.name not in expected or not image.isfile():
                raise ValueError("unexpected offline image archive member")
            item = expected.pop(image.name)
            dest = work / "image.tar"
            with archive.extractfile(image) as stream, dest.open("wb") as target:
                shutil.copyfileobj(stream, target)
            records.append(inspect_image(item["service"], dest, item, work, sboms, syft, notice_root, sources))
            dest.unlink()
        if expected:
            raise ValueError("missing offline images")
        slim = json.loads((ROOT / "runtime/interop/profile.json").read_bytes())["slim"]
        archive = git_source("agntcy/slim-bindings", slim["native_source_commit"], work)
        sources[archive.name] = archive
        with tarfile.open(archive) as tree:
            native_notices = notices(tree, notice_root, "native/slim-bindings")
        rust = native_rust_sources(archive, sources, work, notice_root, syft, sboms)
        distro = mirror_distro(records, sources, work, source_cache)
        write_json(assets / "component-sources.json", {
            "distribution_sources": distro,
            "images": sorted(records, key=lambda rec: rec["service"]),
            "slim_native": {"source": slim["native_source"], "revision": slim["native_source_commit"], "archive": archive.name,
                            "sha256": BUNDLE["digest"](archive), "binary_sha256": slim["native_library_sha256"], "notices": native_notices, "rust": rust}})
        BUNDLE["write_tar"](assets / "component-notices.tar.gz", BUNDLE["tree"](notice_root, "notices"), epoch, True)
        BUNDLE["source_archives"](assets, sources, epoch, prefix="agentcapsule-oci-sources")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--assets", required=True, type=Path)
    parser.add_argument("--sboms", required=True, type=Path)
    parser.add_argument("--source-cache", type=Path, help="reuse locally downloaded distro sources after verifying their pinned SHA-256")
    args = parser.parse_args()
    audit(args.assets.resolve(), args.sboms.resolve(), release_tools.tool("syft"), args.source_cache)
