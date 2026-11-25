#!/usr/bin/env python3
"""Assemble a versioned single-host distribution from qualified release builds.

Run on the release builder with Docker, APT binary and source indices from the
Ubuntu snapshot, and the outputs of the normal guest/kernel/VMM build scripts.
Artifacts, package versions, pinned images, migration names and digests travel
with the bundle. Preserve corresponding third-party sources and rebuild inputs.
"""
import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path
import os
import re
import runpy
import shutil
import subprocess
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[1]
HOST_PROGRAMS = ("agentcapsule-api", "agentcapsule-admin", "agentcapsule-worker", "agentcapsule-authority",
                 "agentcapsule-slim-bridge", "agentcapsule-harness", "capsule-adapter", "agentcapsule-worker-helper")
PACKAGES = ("postgresql-16", "docker.io", "docker-compose-v2", "pgbackrest", "rclone", "curl", "e2fsprogs",
            "libcryptsetup12", "podman", "openssl", "iproute2", "ca-certificates")
# Noble systems upgraded from the installation ISO can still carry the
# original systemd/libsystemd pair. Ship matched updates without asking APT
# to install optional services that the operator has never enabled.
BASE_UPGRADES = ("systemd", "systemd-sysv", "udev", "libnss-systemd", "libpam-systemd",
                 "systemd-resolved", "systemd-timesyncd", "dbus", "dbus-user-session")
SNAPSHOT = "https://snapshot.ubuntu.com/ubuntu/20261113T000000Z"
USERSPACE = "agentcapsule-userspace-linux-amd64.tar.gz"
USERSPACE_PACKAGES = ("systemd-sysv", "dbus", "systemd-container", "libnss-myhostname",
                      "python3", "apt", "ca-certificates", "ubuntu-keyring", "passt", "iproute2")


def run(*args, **kw):
    return subprocess.run([str(a) for a in args],check=True,**kw)


def output(*args, **kw):
    return run(*args,stdout=subprocess.PIPE,text=True,**kw).stdout.strip()


def digest(path):
    with path.open("rb") as f:
        return hashlib.file_digest(f,"sha256").hexdigest()


def write_tar(path, files, epoch, compress=False):
    # Keep only regular files and normalize mode, uid/gid, mtime and order.
    with path.open("xb") as raw:
        stream=gzip.GzipFile(filename="",mode="wb",fileobj=raw,mtime=epoch,compresslevel=3) if compress else raw
        try:
            with tarfile.open(fileobj=stream,mode="w|") as tar:
                for name,file in sorted(files.items()):
                    info=tarfile.TarInfo(name)
                    info.mtime=epoch
                    info.mode=0o755 if isinstance(file,Path) and file.stat().st_mode & 0o111 else 0o644
                    if isinstance(file,bytes):
                        info.size=len(file)
                        tar.addfile(info,io.BytesIO(file))
                    else:
                        info.size=file.stat().st_size
                        with file.open("rb") as src:
                            tar.addfile(info,src)
        finally:
            if compress:
                stream.close()


def tree(directory,prefix):
    return {prefix+"/"+p.relative_to(directory).as_posix():p for p in directory.rglob("*") if p.is_file() and not p.is_symlink()}


def json_bytes(value):
    return (json.dumps(value,indent=2,sort_keys=True)+"\n").encode()


def userspace_packages(archive):
    """Lock every installed binary package, including the base system, for later upgrades."""
    with tarfile.open(archive) as tar:
        member, = (m for m in tar if m.name.removeprefix("./") == "var/lib/dpkg/status")
        if not member.isfile():
            raise ValueError("missing userspace package database")
        status = tar.extractfile(member).read().decode()
    packages = {}
    for paragraph in status.strip().split("\n\n"):
        fields = dict(line.split(": ", 1) for line in paragraph.splitlines()
                      if not line.startswith((" ", "\t")) and ": " in line)
        if fields.get("Status") != "install ok installed":
            raise ValueError(f"incomplete userspace package: {fields.get('Package')}")
        package = fields["Package"]
        version = fields["Version"]
        if (not re.fullmatch(r"[a-z0-9][a-z0-9.+-]*", package) or package in packages or
                not re.fullmatch(r"[0-9][A-Za-z0-9:.+~-]*", version) or fields["Architecture"] not in ("all", "amd64")):
            raise ValueError(f"unexpected userspace package: {package}")
        packages[package] = version
    if set(USERSPACE_PACKAGES) - packages.keys():
        raise ValueError("incomplete private userspace")
    return [name + "=" + packages[name] for name in sorted(packages)]


def userspace_archive(out, work, epoch):
    """Build under a private mount namespace. Keep dpkg ownership, modes and links."""
    mirrors = [f"deb [check-valid-until=no] {SNAPSHOT} {suite} main universe"
               for suite in ("noble", "noble-updates", "noble-security")]
    prefix = ["sudo", "-n"] if os.geteuid() else []
    tar = work / "userspace.tar"
    with tar.open("xb") as raw:
        run(*prefix, "env", f"SOURCE_DATE_EPOCH={epoch}", "mmdebstrap", "--mode=root",
            "--variant=minbase", "--architectures=amd64", "--keyring=/usr/share/keyrings/ubuntu-archive-keyring.gpg",
            "--include=" + ",".join(USERSPACE_PACKAGES), "--skip=output/mknod",
            "--aptopt=Acquire::Retries 4", "--aptopt=APT::Update::Error-Mode any",
            '--setup-hook=set -e; for d in bin sbin lib lib64; do mkdir -p "$1/usr/$d"; ln -s "usr/$d" "$1/$d"; done',
            '--customize-hook=set -e; lib="$1/usr/lib/x86_64-linux-gnu"; for tool in systemd-nspawn pasta; do '
            '"$lib/ld-linux-x86-64.so.2" --library-path "$lib/systemd:$lib" "$1/usr/bin/$tool" --version >&2; done',
            '--customize-hook=chroot "$1" python3 -I -c "import fcntl, hashlib, ssl, tarfile, urllib.request"',
            '--customize-hook=rm -f "$1/etc/hostname" "$1/etc/resolv.conf" "$1/var/lib/dbus/machine-id"; : > "$1/etc/machine-id"',
            '--customize-hook=printf "127.0.0.1 localhost\n::1 localhost\n" > "$1/etc/hosts"',
            "noble", "-", *mirrors, stdout=raw)
    packages = userspace_packages(tar)
    with tar.open("rb") as src, (out / USERSPACE).open("xb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=epoch, compresslevel=3) as gz:
            shutil.copyfileobj(src, gz, 1 << 20)
    tar.unlink()
    return packages


def runtime_files(dist,kernel,vmm):
    files={n:dist/n for n in HOST_PROGRAMS}
    files.update({"product.initrd":dist/"product.initrd","vmlinux":kernel/"vmlinux","firecracker":vmm/"firecracker","jailer":vmm/"jailer"})
    for build,names in ((kernel,["vmlinux"]),(vmm,["firecracker","jailer"])):
        expected=json.loads((build/"artifacts.json").read_bytes())["sha256"]
        for name in names:
            if digest(files[name]) != expected[name]:
                raise ValueError("runtime build digest mismatch: "+name)
    guest=json.loads((dist/"product-guest.json").read_bytes())
    if digest(files["product.initrd"]) != guest["artifacts"]["product.initrd"]:
        raise ValueError("product guest digest mismatch")
    files.update(tree(ROOT/"deploy/interop","interop"))
    files.update(tree(ROOT/"deploy/systemd","systemd"))
    files.update(tree(ROOT/"deploy/backup","backup"))
    files["agentcapsule-archive-ship.py"]=ROOT/"deploy/backup/agentcapsule-archive-ship.py"
    files["config/worker.json"]=ROOT/"runtime/worker/config.example.json"
    files["config/slim-bridge.json"]=ROOT/"runtime/slimbridge/config.example.json"
    for name in ("bootstrap","install","recovery","release","cli-host"):
        files["docs/"+name+".md"]=ROOT/"docs"/(name+".md")
    files["openapi/openapi.yaml"]=ROOT/"openapi/openapi.yaml"
    if (ROOT/"deploy/oidc").is_dir():
        files.update(tree(ROOT/"deploy/oidc","oidc"))
        # The OIDC unit's container helper, for manual installations; the
        # installer embeds the same file (internal/oidclifecycle).
        files["oidc/container.py"]=ROOT/"internal/oidclifecycle/container.py"
    return files


def image_archive(out,work,epoch):
    oidc_image = runpy.run_path(str(Path(__file__).with_name("release_tools.py")))["oidc_image"]
    services=json.loads((ROOT/"runtime/interop/profile.json").read_bytes())["services"]
    sources={name:("docker",ref) for name,ref in services.items()}
    sources["oidc"]=("podman",oidc_image(ROOT))
    metadata=[]
    files={}
    for service,(engine,ref) in sources.items():
        if not re.search(r"@sha256:[a-f0-9]{64}$",ref):
            raise ValueError("image must have a manifest digest")
        tag="localhost/agentcapsule-offline/"+service+":"+ref.split("@sha256:")[1]
        name=service+".tar"
        files[name]=work/name
        pinned=re.sub(r":[^/:@]+@sha256:", "@sha256:",ref)
        run("skopeo","--override-os","linux","--override-arch","amd64","copy","--retry-times","3",
            "docker://"+pinned,"docker-archive:"+str(files[name])+":"+tag)
        with tarfile.open(files[name]) as tar:
            manifest=json.load(tar.extractfile("manifest.json"))
            if len(manifest)!=1 or tag not in manifest[0]["RepoTags"]:
                raise ValueError("wrong image in offline archive")
            config="sha256:"+hashlib.sha256(tar.extractfile(manifest[0]["Config"]).read()).hexdigest()
        metadata.append(dict(service=service,engine=engine,ref=ref,tag=tag,config_id=config,file=name))
    write_tar(out/"agentcapsule-images-linux-amd64.tar.gz",files,epoch,True)
    return metadata


def package_archive(out,src,work,epoch,userspace_roots=()):
    debdir=work/"debs"
    debdir.mkdir()
    (debdir/"partial").mkdir()
    # Resolve everything including dependencies already installed on this
    # runner. The host uses only the downloaded signed release artifacts.
    run("apt-get","-o","Debug::NoLocking=true","-o","Dir::State::status=/dev/null","-o","Dir::Cache::archives="+str(debdir),
        "--yes","--download-only","--no-install-recommends","install",*PACKAGES,*BASE_UPGRADES,*userspace_roots)
    records=[]
    index=[]
    sources=set()
    for deb in sorted(debdir.glob("*.deb")):
        data=output("dpkg-deb","-f",deb,"Package","Version","Source")
        fields=dict(line.split(": ",1) for line in data.splitlines() if ": " in line)
        name,version=fields["Package"],fields["Version"]
        source=fields.get("Source",name)
        match=re.fullmatch(r"([a-z0-9.+-]+)(?: \(([^()]+)\))?",source)
        if not match:
            raise ValueError("invalid Debian package source")
        sources.add(match[1]+"="+(match[2] or version))
        records.append(dict(file=deb.name,package=name,version=version,sha256=digest(deb),source=source))
        control=output("dpkg-deb","-f",deb)
        index.append(control+"\nFilename: ./"+deb.name+"\nSize: "+str(deb.stat().st_size)+"\nSHA256: "+records[-1]["sha256"]+"\n")
    if not {r["package"] for r in records}.issuperset(PACKAGES):
        raise ValueError("incomplete host package closure")
    files={f.name:f for f in debdir.glob("*.deb")}
    files["Packages"]=("\n".join(index)+"\n").encode()
    files["roots.json"]=json_bytes([r["package"]+"="+r["version"] for r in records if r["package"] in PACKAGES])
    if userspace_roots:
        if set(userspace_roots) - {r["package"]+"="+r["version"] for r in records}:
            raise ValueError("offline repository lacks an exact userspace package")
        files["roots-userspace.json"]=json_bytes(userspace_roots)
    write_tar(out/"agentcapsule-packages-linux-amd64.tar",files,epoch)
    # Match ELF files embedded in the guest, and libc linked statically by
    # capsule-adapter, to the exact source versions on the build machine.
    return records,sources


def matching_sources(sources,guest,src):
    owners={"libc6-dev"}
    for f in guest["native_files"].values():
        path=f["source"]
        candidates=[path]
        if path.startswith("/usr/"):
            candidates.append(path[4:])
        if not path.startswith("/usr/"):
            candidates.append("/usr"+path)
        for candidate in candidates:
            result=run_owner(candidate)
            if result:
                owners.add(result)
                break
        else:
            raise ValueError("no corresponding package for "+path)
    for name in owners:
        sources.add(output("dpkg-query","-W","-f=${source:Package}=${source:Version}",name))
    for source in sorted(sources):
        run("apt-get","--download-only","source",source,cwd=src)
    # Source tarballs may exceed GitHub's per-asset limit collectively.
    # Keep packages and original .dsc signatures unmodified.
    return {f.name:f for f in src.iterdir() if f.is_file()}


# One Debian package name, with its architecture if any: never a list
# ("a, b: path") nor a diversion ("diversion by a from: path",
# "local diversion to: path"), which dpkg-query -S prints in the same form.
OWNER=re.compile(r"[a-z0-9][a-z0-9+.-]+(:[a-z0-9-]+)?")


def run_owner(candidate):
    p=subprocess.run(["dpkg-query","-S",candidate],capture_output=True,text=True)
    for line in p.stdout.splitlines():
        package,sep,path=line.partition(": ")
        if sep and path==candidate and OWNER.fullmatch(package):
            return package
    return None


def firecracker_sources(vmm, work):
    # Use the lockfile retained by the --locked build of firecracker and jailer.
    from release_sources import locked_crates
    lock = vmm / "Cargo.lock"
    info = json.loads((vmm / "artifacts.json").read_bytes())
    if "Cargo.lock" in info["sha256"]:
        if digest(lock) != info["sha256"]["Cargo.lock"]:
            raise ValueError("Firecracker build lock checksum mismatch")
    else:
        # Older build records only hashed the executables. Their build used
        # the unmodified upstream lock in the pinned source tarball.
        archive = vmm / "upstream.tgz"
        if digest(archive) != info["upstream"]["source_sha256"]:
            raise ValueError("Firecracker source archive checksum mismatch")
        with tarfile.open(archive) as upstream:
            original = upstream.extractfile("firecracker-" + info["upstream"]["version"] + "/Cargo.lock").read()
        if original != lock.read_bytes():
            raise ValueError("Firecracker lock differs from the pinned upstream release")
    cargo_home = Path(os.environ.get("CARGO_HOME", Path.home() / ".cargo"))
    sources = locked_crates(lock.read_bytes(), work, cargo_home=cargo_home,
                            git_projects=("firecracker-microvm/micro-http",))
    sources["firecracker-Cargo.lock"] = lock
    return sources


def source_archives(out,files,epoch,prefix="agentcapsule-sources"):
    parts=[]
    size=0
    for name,value in sorted(files.items()):
        n=value.stat().st_size if isinstance(value,Path) else len(value)
        if n > 1500 << 20:
            raise ValueError("source package too large for a release asset")
        if not parts or size+n > 1500 << 20:
            parts.append({})
            size=0
        parts[-1][name]=value
        size+=n
    for i,group in enumerate(parts):
        write_tar(out/f"{prefix}-{i+1:02d}.tar",group,epoch)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ("build","kernel","vmm","out","licenses"):
        p.add_argument("--"+name,type=Path,required=True)
    a=p.parse_args()
    build=json.loads((a.build/"build.json").read_bytes())
    if (build["status"]!="passed" or build["reproducible"] is not True or
            build["commit"]!=output("git","rev-parse","HEAD",cwd=ROOT) or not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.]+)?",build["version"])):
        raise ValueError("bundle requires the successful reproducible build of the checked-out release tag")
    epoch=build["source_date_epoch"]
    a.out.mkdir(exist_ok=True,parents=True)
    files=runtime_files(a.build/"dist",a.kernel,a.vmm)
    files["LICENSE"]=ROOT/"LICENSE"
    files["third-party-licenses.txt"]=a.licenses
    with tempfile.TemporaryDirectory() as tmp:
        work=Path(tmp)
        src=work/"source"
        src.mkdir()
        userspace_roots=userspace_archive(a.out,work,epoch)
        records,sources=package_archive(a.out,src,work,epoch,userspace_roots)
        images=image_archive(a.out,work,epoch)
        files["offline-images.json"]=json_bytes(images)
        files["host-packages.json"]=json_bytes(dict(snapshot=SNAPSHOT,packages=records))
        manifest={"schema":"agentcapsule.bundle/v1","version":build["version"],"commit":build["commit"],
                  "platform":"ubuntu-24.04-amd64","protocol":"v1","migration_mode":"offline-exact-history","rolling_schema":1,
                  "userspace":{"file":USERSPACE,"sha256":digest(a.out/USERSPACE)},
                  "binary_rollback_epoch":"agentcapsule-state/v1",
                  "migration_ledger":json.loads(output(files["agentcapsule-admin"],"migration-manifest")),
                  "migrations":[p.name for p in sorted((ROOT/"internal/controlplane/migrations").glob("*.sql"))],
                  "sha256":{n:digest(f) if isinstance(f,Path) else hashlib.sha256(f).hexdigest() for n,f in files.items()}}
        files["bundle.json"]=json_bytes(manifest)
        write_tar(a.out/"agentcapsule-server-linux-amd64.tar.gz",files,epoch,True)
        guest=json.loads((a.build/"dist/product-guest.json").read_bytes())
        src_files=matching_sources(sources,guest,src)
        src_files.update({"linux.tar.xz":a.kernel/"linux.tar.xz","kernel.config":a.kernel/"config",
                          "firecracker-upstream.tgz":a.vmm/"upstream.tgz","volume-lock.patch":a.vmm/"volume-lock.patch"})
        src_files.update(firecracker_sources(a.vmm,work))
        source=work/"platform-source.tar"
        run("git","archive","--format=tar","-o",source,build["commit"],cwd=ROOT)
        src_files[source.name]=source
        # The Go archives retain embedded C sources and license files (notably
        # SQLite); vendoring alone would omit some of the original contents.
        for mod in (ROOT,ROOT/"runtime/slimbridge"):
            data=output("go","mod","download","-json","all",cwd=mod)
            while data.strip():
                obj,end=json.JSONDecoder().raw_decode(data.lstrip())
                data=data.lstrip()[end:]
                if obj.get("Zip"):
                    src_files["go/"+obj["Path"]+"@"+obj["Version"]+".zip"]=Path(obj["Zip"])
        source_archives(a.out,src_files,epoch)
        (a.out/"agentcapsule-bundle.json").write_bytes(files["bundle.json"])


if __name__=="__main__":
    main()
