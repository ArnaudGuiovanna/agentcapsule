# Production host setup. This file is embedded ahead of host.py in the helper.
import base64
import configparser
import ctypes
import errno
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import shutil
import socket
import stat
import subprocess
import tempfile
import time
import urllib.parse


def normalize_profile(raw):
    defaults = dict(schema="agentcapsule.install/v1", api_name=socket.getfqdn(), api_port=9443,
                    platform_account="sysadmin", host_id="local", storage_mib=8192, max_active=2,
                    first_uid=62100, last_uid=63123, allow_internal_providers=[], database_url_file=None,
                    api_database_url_file=None, worker_database_url_file=None,
                    tls_certificate=None, tls_key=None, tls_ca=None, interop_certs=None, pgbackrest_config=None,
                    registry_rules=None, oidc_port=9444, oidc_name=None, oidc_cert=None, oidc_key=None,
                    oidc_ca=None, monapp_redirect_uri=None, rclone_config=None)
    if not isinstance(raw, dict) or set(raw) - set(defaults):
        raise ValueError("unknown installation profile field")
    p = dict(defaults, **raw)
    p["oidc_name"]=p["oidc_name"] or p["api_name"]
    p["monapp_redirect_uri"]=p["monapp_redirect_uri"] or "https://"+p["api_name"]+"/monapp/callback"
    redirect=urllib.parse.urlsplit(p["monapp_redirect_uri"])
    if redirect.scheme!="https" or not redirect.hostname or redirect.username or redirect.password or redirect.fragment:
        raise ValueError("MonApp needs an exact HTTPS callback URI")
    if p["schema"] != defaults["schema"]:
        raise ValueError("unknown profile schema")
    for field in ("api_name","oidc_name","host_id","platform_account"):
        if not isinstance(p[field],str) or not re.fullmatch(r"[A-Za-z0-9][a-zA-Z0-9_.-]{0,126}", p[field]):
            raise ValueError("invalid "+field)
    if any(type(p[k]) != int for k in ("api_port","oidc_port","storage_mib","max_active","first_uid","last_uid")):
        raise ValueError("expected integer capacity and port settings")
    if p["oidc_port"] == p["api_port"] or not 1 <= p["oidc_port"] <= 65535 or p["oidc_port"] in (8443,9445,9464,9465,9466,46357,55432):
        raise ValueError("invalid OIDC port")
    if (p["api_port"] in (8443,9445,9464,9465,9466,46357,55432) or not 1 <= p["api_port"] <= 65535
            or min(p["storage_mib"],p["max_active"]) < 1 or not 10000 <= p["first_uid"] <= p["last_uid"] < 2147483647
            or p["last_uid"]-p["first_uid"] > 1 << 20):
        raise ValueError("invalid profile capacity or listen port")
    for key in ("database_url_file","api_database_url_file","worker_database_url_file","tls_certificate","tls_key","tls_ca","interop_certs","pgbackrest_config","oidc_cert","oidc_key","oidc_ca","rclone_config"):
        if p[key] is not None and (not isinstance(p[key],str) or not Path(p[key]).is_absolute()):
            raise ValueError("expected absolute host path for "+key)
    if (p["api_database_url_file"] or p["worker_database_url_file"]) and not p["database_url_file"]:
        raise ValueError("a service's database URL file needs database_url_file")
    if bool(p["oidc_cert"]) != bool(p["oidc_key"]):
        raise ValueError("provide both OIDC TLS certificate and key")
    if bool(p["tls_key"]) != bool(p["tls_certificate"]):
        raise ValueError("provide both TLS certificate and private key")
    # A production worker imports through a rule that trusts publisher keys,
    # or that opts out explicitly (L-16, docs/registry.md).
    if p["registry_rules"] is not None and (not isinstance(p["registry_rules"],list) or not all(
            isinstance(r,dict) and (bool(r.get("publisher_keys")) or r.get("allow_unsigned") is True) for r in p["registry_rules"])):
        raise ValueError("each registry rule needs publisher_keys or allow_unsigned")
    return p


def opt_out_unsigned_registry_rules(path):
    """Write "allow_unsigned": true in each registry rule of the worker
    configuration at path that trusts no publisher key and says nothing: a
    worker before L-16 imported unsigned packages through it, and a
    production worker now refuses it. Return the rules' hosts."""
    cfg=read(path)
    opted=[]
    for rule in (cfg.get("registry") or {}).get("rules") or []:
        if not rule.get("publisher_keys") and "allow_unsigned" not in rule:
            rule["allow_unsigned"]=True
            opted.append(rule.get("host"))
    if opted:
        write_file(path,(json.dumps(cfg,sort_keys=True,indent=2)+"\n").encode(),path.stat().st_mode&0o777)
    return opted


def user_id(name):
    return pwd.getpwnam(name).pw_uid


def install_file(src, dst, mode=0o644, owner=0):
    write_file(dst, src.read_bytes(),mode)
    os.chown(dst,owner,-1)


def unit_drop(unit,name,body):
    write_file(UNIT_DIR/(unit+".service.d")/(name+".conf"),body.encode(),0o644)


def run_user(user,*cmd,env=None, capture=False):
    args = ["runuser","--preserve-environment","-u",user,"--",*cmd]
    if capture:
        return output(*args,env=env)
    run(*args,env=env)


def install_dependencies(dist,release):
    # The signed archive holds the exact .deb closure from the release build.
    # Never let APT substitute an unverified network package.
    with tempfile.TemporaryDirectory(dir=STATE) as tmp:
        root = Path(tmp)/"packages"
        unpack(dist/DEBS,root)
        roots=read(root/"roots.json")
        if Path("/etc/agentcapsule-private-userspace").is_file() and (root/"roots-userspace.json").is_file():
            roots = sorted(set(roots + read(root/"roots-userspace.json")))
        if not roots or not all(re.fullmatch(r"[a-z0-9.+-]+=[A-Za-z0-9:.+~_-]+",p) for p in roots):
            raise ValueError("invalid version-locked packages")
        lists=Path(tmp)/"lists"
        (lists/"partial").mkdir(parents=True)
        sources=Path(tmp)/"local.list"
        write_file(sources,("deb [trusted=yes] file:"+str(root)+" ./\n").encode())
        # The entire local repository was verified before extraction. Isolate
        # the indices and sources so APT can acquire only those local files.
        apt=["apt-get","-o","Dir::Etc::sourcelist="+str(sources),"-o","Dir::Etc::sourceparts=-",
             "-o","Dir::State::lists="+str(lists),"-o","Acquire::Languages=none"]
        run(*apt,"update")
        env=dict(os.environ,DEBIAN_FRONTEND="noninteractive")
        if output("dpkg","--audit"):
            # A power loss can leave dpkg's status journal uncommitted. An
            # unconfigured dependency is repaired by the same signed APT set.
            subprocess.run(["dpkg","--configure","--pending"],env=env,check=False)
        run(*apt,"install","--fix-broken","--no-remove","-y","--no-install-recommends",*roots,env=env)
        if output("dpkg","--audit"):
            raise ValueError("dpkg still reports incomplete package configuration")
    run("systemctl","enable","--now","docker.service")
    with tempfile.TemporaryDirectory(dir=STATE) as tmp:
        root=Path(tmp)/"images"
        unpack(dist/IMAGES,root)
        for image in read(release/"offline-images.json"):
            engine=image["engine"]
            if engine not in ("docker","podman"):
                raise ValueError("unknown OCI image engine")
            run(engine,"load","--input",root/image["file"])
            actual=output(engine,"inspect","--type=image","--format","{{.Id}}",image["tag"])
            expected=image["config_id"].removeprefix("sha256:")
            if actual.removeprefix("sha256:") != expected:
                # Docker's containerd image store exposes a manifest digest
                # in .Id. Ask that store for the selected manifest's config.
                if engine!="docker" or not saved_config(image["tag"],expected,root):
                    raise ValueError("offline image differs from signed image index: "+image["service"])


def saved_config(reference,expected,root):
    path=root/"loaded-image.tar"
    try:
        run("docker","image","save","--output",path,reference)
        with tarfile.open(path) as tar:
            manifests=json.load(tar.extractfile("manifest.json"))
            if len(manifests)!=1:
                return False
            # A save by immutable image ID can have no tags. A save by
            # the release tag must still identify that exact tag.
            if not re.fullmatch("sha256:[a-f0-9]{64}",reference) and reference not in (manifests[0].get("RepoTags") or []):
                return False
            config=tar.getmember(manifests[0]["Config"])
            if not config.isfile() or config.size>4<<20:
                return False
            return hashlib.sha256(tar.extractfile(config).read()).hexdigest()==expected
    finally:
        path.unlink(missing_ok=True)


def configure_system():
    for file in (ACTIVE/"systemd").iterdir():
        if file.suffix == ".sysusers":
            install_file(file,Path("/usr/lib/sysusers.d")/(file.stem+".conf"))
        elif file.suffix == ".tmpfiles":
            install_file(file,Path("/usr/lib/tmpfiles.d")/(file.stem+".conf"))
        elif file.suffix == ".service":
            install_file(file,UNIT_DIR/file.name)
    run("systemd-sysusers")
    run("systemd-tmpfiles","--create", *(str(p) for p in Path("/usr/lib/tmpfiles.d").glob("agentcapsule-*.conf")))
    ETC.mkdir(mode=0o755,exist_ok=True)
    # Unprivileged services traverse /etc/agentcapsule, keys remain 0600.
    ETC.chmod(0o755)


def database_url(path):
    f=Path(path)
    if f.stat().st_uid != 0 or f.stat().st_mode & 0o077:
        raise ValueError("the database URL must be in a root-owned private file")
    dsn=f.read_text().strip()
    if not dsn or any(ord(c)<32 for c in dsn):
        raise ValueError("invalid database URL file")
    return dsn


# The bundled cluster's roles (ADR 001, "Changes after the v0.1.0 audit"):
# agentcapsule owns the database and every object and runs the migrations
# (agentcapsule-admin, as root); the API and the worker connect as roles that
# own nothing and write only what they write.
LOCAL_DSN="host=/run/postgresql port=55432 dbname=agentcapsule user="
SERVICE_ROLES=("agentcapsule_api","agentcapsule_worker")


def db_env(profile):
    # The owner's connection: migrations and agentcapsule-admin.
    path = profile["database_url_file"]
    dsn = database_url(path) if path else LOCAL_DSN+"agentcapsule"
    return dict(os.environ,AGENTCAPSULE_DATABASE_URL=dsn)


def service_dsns(profile):
    # The API's and the worker's connections, each as its own role.
    if not profile.get("database_url_file"):
        return {"api":LOCAL_DSN+"agentcapsule_api","worker":LOCAL_DSN+"agentcapsule_worker"}
    files={"api":profile.get("api_database_url_file"),"worker":profile.get("worker_database_url_file")}
    if not all(files.values()):
        raise ValueError("an external database needs api_database_url_file and worker_database_url_file: "
                         "the API and the worker connect as roles that do not own the schema")
    return {name:database_url(path) for name,path in files.items()}


def worker_env(profile):
    return dict(os.environ,AGENTCAPSULE_DATABASE_URL=service_dsns(profile)["worker"])


# The worker runs as its own account, with no capability; its helper keeps
# root (ADR 024). Both read /etc/agentcapsule/worker.json.
WORKER_USER="agentcapsule-worker"
HELPER_SOCKET="/run/agentcapsule-worker-helper/worker.sock"
RESTORE_TESTS=Path("/var/lib/agentcapsule-restore-tests")


def worker_ids():
    account=pwd.getpwnam(WORKER_USER)
    return account.pw_uid,account.pw_gid


def worker_output(*args,profile):
    # The worker's operator modes run as its account, so that what they
    # write stays the worker's, with the worker's database role.
    return run_user(WORKER_USER,*args,env=worker_env(profile),capture=True)


def give_worker_trees(cfg):
    # The worker's trees: the runtime root, the archive root, the restore
    # tests' scratch and the caches. Each entry root owns goes to the worker,
    # but <root>/jails, where runs a root worker started keep their jails;
    # the VMs' volumes and drives keep their UIDs. No link is followed.
    # Directories that do not exist yet are created, 0700.
    uid,gid=worker_ids()
    root=Path(cfg["root"])
    trees=[root,RESTORE_TESTS]
    for section,key in (("archives","root"),("registry","cache"),("corpus","cache"),("corpus","staging")):
        value=(cfg.get(section) or {}).get(key)
        if value:
            trees.append(Path(value))
    system={Path(p) for p in ("/var/lib","/var/cache","/var/lib/agentcapsule","/srv","/opt","/home","/etc","/usr")}
    given=0
    for top in trees:
        if not top.is_absolute() or len(top.parts)<3 or top in system or top.is_symlink():
            raise ValueError("the worker's directories must be its own: "+str(top))
        if not top.exists():
            top.mkdir(mode=0o700,parents=True)
        for directory,subdirectories,files in os.walk(top):
            if Path(directory)==root:
                subdirectories[:]=[d for d in subdirectories if d!="jails"]
            paths=[Path(directory)/name for name in subdirectories+files]
            for path in ([top] if Path(directory)==top else [])+paths:
                st=os.lstat(path)
                if st.st_uid==0 and not stat.S_ISLNK(st.st_mode):
                    os.lchown(path,uid,gid)
                    given+=1
    return given


def worker_private_files(cfg):
    # The private files the worker reads (operatorconfig: 0600, its own or
    # root's): they become its own. An operator's interop certificates
    # (a link) stay the operator's to give.
    files=[(cfg.get("llm") or {}).get("receipt_key"),(cfg.get("directory") or {}).get("key")]
    files+=list(((cfg.get("transit") or {}).get("keys") or {}).values())
    files+=[rule.get("credentials_file") for rule in (cfg.get("registry") or {}).get("rules") or []]
    uid,gid=worker_ids()
    # make-certs.sh writes the client CA and certificate under umask 0077.
    # Let the worker traverse its certificate directory and read these two
    # public files. The operator retains control over an external PKI.
    client=ETC/"interop/control-plane"
    if (cfg.get("directory") or {}).get("key")==str(client/"directory.key") and (
            client.is_dir() and not any(p.is_symlink() for p in [client,*client.parents])):
        os.chown(client,0,gid)
        client.chmod(0o750)
        for name in ("directory-ca.pem","directory.crt"):
            path=client/name
            if not stat.S_ISREG(os.lstat(path).st_mode):
                raise ValueError("expected a regular Directory certificate")
            os.chown(path,0,gid)
            path.chmod(0o640)
    for name in filter(None,files):
        path=Path(name)
        if any(p.is_symlink() for p in [path,*path.parents]):
            continue
        try:
            st=os.lstat(path)
        except FileNotFoundError:
            continue
        if stat.S_ISREG(st.st_mode) and st.st_uid==0:
            os.chown(path,uid,-1)


def worker_configuration(path=None):
    # worker.json: root's, readable by the worker's group (0640), with the
    # helper's socket; an earlier release's gets the section.
    path=path or ETC/"worker.json"
    cfg=read(path)
    if "helper" not in cfg:
        cfg["helper"]=dict(socket=HELPER_SOCKET)
        save(path,cfg)
    _,gid=worker_ids()
    os.chown(path,0,gid)
    path.chmod(0o640)
    return cfg


def worker_accounts():
    # authority.json names the worker's account, which its worker socket
    # then admits; slim-bridge.json names it as the bridge's peer.
    uid,_=worker_ids()
    for path in (ETC/"authority.json",ETC/"slim-bridge.json"):
        if not path.is_file():
            continue
        cfg=read(path)
        key="worker_uid"
        if path.name=="authority.json" and cfg.get("role")!="primary":
            continue
        if cfg.get(key)!=uid:
            cfg[key]=uid
            write_file(path,json.dumps(cfg).encode(),0o644)


def separate_worker():
    # ADR 024: the worker's account owns its trees and the private files it
    # reads, and the services name it. Idempotent: install and every update.
    cfg=worker_configuration()
    given=give_worker_trees(cfg)
    worker_private_files(cfg)
    worker_accounts()
    return given


# pg_ident.conf: root runs agentcapsule-admin as the owner; the worker's
# account reaches only the worker's role (ADR 024), the API's account only
# the API's. pg_hba.conf admits those three roles by peer authentication on
# the socket.
PEER_MAP=("agentcapsule root agentcapsule\nagentcapsule agentcapsule-worker agentcapsule_worker\n"
          "agentcapsule agentcapsule-api agentcapsule_api\n")
PEER_HBA=("local agentcapsule agentcapsule,agentcapsule_api,agentcapsule_worker peer map=agentcapsule\n"
          "host all all 127.0.0.1/32 scram-sha-256\nhost all all ::1/128 scram-sha-256\n")
# What an earlier release wrote, which mapped the API's account to the owner.
OLD_PEER_HBA=("local agentcapsule agentcapsule peer map=agentcapsule",)


def peer_entries(text, entries, ours):
    # Our block first, once; every line it replaces removed.
    kept=[line for line in text.splitlines(keepends=True) if not ours(line.strip())]
    return entries+"".join(kept)


def database_roles(folder=Path("/etc/postgresql/16/agentcapsule")):
    hba = folder/"pg_hba.conf"
    ident = folder/"pg_ident.conf"
    block=set(PEER_HBA.splitlines())|set(OLD_PEER_HBA)
    for file,entries,ours in [(ident,PEER_MAP,lambda line:line.split()[:1]==["agentcapsule"]),
                              (hba,PEER_HBA,lambda line:line in block)]:
        text=file.read_text()
        updated=peer_entries(text,entries,ours)
        if updated!=text:
            write_file(file,updated.encode(),0o640)
            os.chown(file,user_id("postgres"),pwd.getpwnam("postgres").pw_gid)
    cmd=["psql","-XAt","-v","ON_ERROR_STOP=1","-h","/run/postgresql","-p","55432","-d","postgres","-c"]
    for role in ("agentcapsule",*SERVICE_ROLES):
        if not run_user("postgres",*cmd,"SELECT 1 FROM pg_roles WHERE rolname='"+role+"'",capture=True):
            run_user("postgres",*cmd,"CREATE ROLE "+role+" LOGIN")
        run_user("postgres",*cmd,"ALTER ROLE "+role+" NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS")
    run("pg_ctlcluster","16","agentcapsule","reload")


def database():
    # A dedicated cluster avoids modifying pg_hba.conf or WAL retention on an
    # operator's other databases. The services' roles have no cluster privileges.
    folder=Path("/etc/postgresql/16/agentcapsule")
    if not folder.exists():
        run("pg_createcluster","16","agentcapsule","--port","55432","--","--auth-local=peer","--auth-host=scram-sha-256")
    write_file(folder/"conf.d"/"agentcapsule.conf",b"listen_addresses = '127.0.0.1'\n",0o644)
    run("systemctl","enable","--now","postgresql@16-agentcapsule.service")
    database_roles(folder)
    cmd=["psql","-XAt","-v","ON_ERROR_STOP=1","-h","/run/postgresql","-p","55432","-d","postgres","-c"]
    if not run_user("postgres",*cmd,"SELECT 1 FROM pg_database WHERE datname='agentcapsule'",capture=True):
        run_user("postgres",*cmd,"CREATE DATABASE agentcapsule OWNER agentcapsule")


def create_key(path,data):
    if path.exists():
        return
    write_file(path,data)


def export_login_file(name, mode):
    # Only the CA/certificate and the initial operator enrollment cross the
    # userspace boundary. Service-owned keys stay beneath the
    # root-only runtime directory on the host.
    export = Path("/run/agentcapsule-login")
    if Path("/etc/agentcapsule-private-userspace").is_file() and export.is_dir():
        write_file(export/name, (ETC/name).read_bytes(), mode)


def api_tls(p):
    cert=ETC/"api.crt"
    key=ETC/"api.key"
    if p["tls_certificate"]:
        install_file(Path(p["tls_certificate"]),cert)
        install_file(Path(p["tls_key"]),key,0o600,user_id("agentcapsule-api"))
    elif not cert.exists():
        if not key.exists():
            with tempfile.TemporaryDirectory(dir=STATE) as tmp:
                tmpkey=Path(tmp)/"api.key"
                run("openssl","genpkey","-algorithm","EC","-pkeyopt","ec_paramgen_curve:P-256","-out",tmpkey)
                install_file(tmpkey,key,0o600,user_id("agentcapsule-api"))
        issue_api_certificate(p)
    export_login_file("api.crt", 0o644)


def issue_api_certificate(p):
    with tempfile.TemporaryDirectory(dir=STATE) as tmp:
        generated=Path(tmp)/"api.crt"
        run("openssl","req","-new","-x509","-key",ETC/"api.key","-days","365","-subj","/CN="+p["api_name"],
            "-addext","subjectAltName=DNS:"+p["api_name"],"-addext","extendedKeyUsage=serverAuth",
            "-addext","basicConstraints=critical,CA:FALSE","-out",generated)
        install_file(generated,ETC/"api.crt")
    export_login_file("api.crt", 0o644)


# The certificates the installer generates last 365 days (L-14). Each update
# renews those that expire within RENEW_BEFORE_DAYS, with the same keys for the
# API and the identity provider, and new authorities for the private services.
# An operator's certificates are the operator's to renew. `host diagnose
# certificates` reports every one.
RENEW_BEFORE_DAYS=30
INTEROP_CERTIFICATES=("ca/directory-ca.pem","ca/slim-ca.pem","directory-edge/edge.pem","control-plane/directory.crt",
                      "slim/server.pem","slim-bridge/client.crt")


def host_certificates(p):
    # (name, certificate, generated by the installer)
    found=[("api",ETC/"api.crt",not p["tls_certificate"]),("oidc",ETC/"oidc-tls"/"tls.crt",not p["oidc_cert"])]
    found+=[("interop/"+name,ETC/"interop"/name,not p["interop_certs"]) for name in INTEROP_CERTIFICATES]
    return [entry for entry in found if entry[1].is_file()]


def expires_within(path,days):
    return subprocess.run(["openssl","x509","-noout","-checkend",str(days*86400),"-in",str(path)],
                          stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode!=0


def renew_certificates(p):
    due={name for name,path,generated in host_certificates(p) if generated and expires_within(path,RENEW_BEFORE_DAYS)}
    if "api" in due:
        issue_api_certificate(p)
    if "oidc" in due:
        issue_oidc_certificate(p,ETC/"oidc-tls")
    if any(name.startswith("interop/") for name in due):
        links=ETC/"interop"
        if links.is_symlink():
            raise ValueError("the private services' certificates are the operator's: renew them")
        old=ETC/(".interop-expiring-"+secrets.token_hex(8))
        links.rename(old)
        try:
            setup_interop(p)
        except Exception:
            if not links.exists():
                old.rename(links)
            raise
        shutil.rmtree(old)
    return sorted(due)


def setup_interop(profile):
    links=ETC/"interop"
    if not links.exists():
        if profile["interop_certs"]:
            # Keep operator-managed key ownership and renewal paths.
            links.symlink_to(profile["interop_certs"])
        else:
            with tempfile.TemporaryDirectory(dir=ETC) as tmp:
                new=Path(tmp)/"certs"
                run("/bin/sh", ACTIVE/"interop/make-certs.sh", new, env=dict(os.environ,DAYS="365"))
                for part,uid in [("directory-edge",99),("slim",65532)]:
                    for key in (new/part).glob("*"):
                        os.chown(key,uid,-1)
                        key.chmod(0o400)
                new.rename(links)
    uid=user_id("agentcapsule-slim")
    slimdir=ETC/"slim-bridge"
    slimdir.mkdir(mode=0o700,exist_ok=True)
    os.chown(slimdir,uid,-1)
    for name in ("slim-ca.pem","client.crt","client.key"):
        install_file(links/"slim-bridge"/name,slimdir/name,0o600,uid)
    secret=slimdir/"secret"
    create_key(secret,secrets.token_hex(32).encode())
    os.chown(secret,uid,-1)
    cfg=read(ACTIVE/"config/slim-bridge.json")
    cfg["name"]="agentcapsule/platform/"+profile["host_id"]
    write_file(ETC/"slim-bridge.json",json.dumps(cfg).encode(),0o644)
    setup_interop_images()


def setup_interop_images():
    # Offline tags are generated from the pinned OCI manifests at build time.
    override={"services":{i["service"]:{"image":i["tag"]} for i in read(ACTIVE/"offline-images.json") if i["engine"]=="docker"}}
    save(ETC/"interop-images.json",override)
    compose="/usr/bin/docker compose -f compose.yml -f /etc/agentcapsule/interop-images.json"
    unit_drop("agentcapsule-interop","offline","[Service]\nExecStart=\nExecStart="+compose+" up -d --wait --pull never --remove-orphans\nExecStop=\nExecStop="+compose+" stop\n")


def authority():
    path=ETC/"authority.json"
    if path.exists():
        return read(path)
    user="agentcapsule-authority"
    key="/var/lib/agentcapsule-key-authority"
    restore="/var/lib/agentcapsule-restore-authority"
    run("install","-d","-o",user,"-g",user,"-m","0700",key,restore)
    # The runtime root's parent: the authority's account may traverse it,
    # never list it (searchable_parent).
    run("install","-d","-m","0711","/var/lib/agentcapsule")
    admin=ACTIVE/"agentcapsule-admin"
    keyid=json.loads(run_user(user,admin,"init-key-authority","-root",key,capture=True))["authority_id"]
    restid=json.loads(run_user(user,admin,"init-restore-authority","-root",restore,"-key-authority-root",key,
                               "-key-authority-id",keyid,"-data-root","/var/lib/agentcapsule/host",capture=True))["authority_id"]
    config=dict(version=2,role="primary",key_authority=dict(root=key,identity=keyid),restore_authority=dict(root=restore,identity=restid),
                api_uid=user_id("agentcapsule-api"),worker_socket="/run/agentcapsule-authority/worker.sock",
                api_socket="/run/agentcapsule-authority/api.sock",metrics_listen="127.0.0.1:9466")
    write_file(path,json.dumps(config).encode(),0o644)
    return config


def searchable_parent(root):
    # init-restore-authority runs as agentcapsule-authority and resolves the
    # worker's runtime root, which needs search permission on its parent.
    # The worker's state directory is now the runtime root itself, so its
    # unit leaves that parent alone; a v0.1.0 unit, whose state directory it
    # was, left it 0700. Add o+x, nothing else, to a real directory that
    # lacks it.
    parent=Path(root).parent
    try:
        st=os.lstat(parent)
    except FileNotFoundError:
        return False
    if not stat.S_ISDIR(st.st_mode) or st.st_mode & stat.S_IXOTH:
        return False
    os.chmod(parent,stat.S_IMODE(st.st_mode)|stat.S_IXOTH)
    return True


def environment_quote(s):
    if any(ord(c)<32 for c in s):
        raise ValueError("unsupported environment value")
    return '"'+s.replace("\\","\\\\").replace('"','\\"')+'"'


def environment_file(path, settings):
    write_file(path,"".join(k+"="+environment_quote(v)+"\n" for k,v in settings.items()).encode())


def service_environment(p):
    # Each unit's own connection string, also on an installation whose
    # files still name the owner for every service; the other settings stay.
    dsns=service_dsns(p)
    for unit in ("api","worker"):
        path=ETC/(unit+".env")
        lines=path.read_text().splitlines() if path.exists() else []
        lines=[l for l in lines if not l.startswith("AGENTCAPSULE_DATABASE_URL=")]
        lines.insert(0,"AGENTCAPSULE_DATABASE_URL="+environment_quote(dsns[unit]))
        write_file(path,("\n".join(lines)+"\n").encode())
    environment_file(ETC/"admin.env",dict(AGENTCAPSULE_DATABASE_URL=db_env(p)["AGENTCAPSULE_DATABASE_URL"]))


def configure(p,version,initial):
    service_dsns(p)  # an external database names each service's role, or nothing changes
    configure_system()
    if not initial:
        # A release transition preserves the operator's current credentials,
        # transit key ring, storage and PKI configuration. Offline migrations
        # run with the authorities stopped and must retain their identities.
        cfg=read(ETC/"authority.json")
        admin=ACTIVE/"agentcapsule-admin"
        env=db_env(p)
        if not p["database_url_file"]:
            run("systemctl", "start", "postgresql@16-agentcapsule.service")
            database_roles()
        run(admin,"migrate",env=env)
        service_environment(p)
        searchable_parent(read(ETC/"worker.json")["root"])
        upgrade=json.loads(run_user("agentcapsule-authority",admin,"init-restore-authority",
                           "-root",cfg["restore_authority"]["root"],"-data-root",read(ETC/"worker.json")["root"],
                           "-key-authority-root",cfg["key_authority"]["root"],"-key-authority-id",cfg["key_authority"]["identity"],capture=True))
        if upgrade["authority_id"]!=cfg["restore_authority"]["identity"]:
            raise ValueError("authority identity changed during upgrade")
        renewed=renew_certificates(p)
        if (ETC/"oidc.env").is_file():
            oidc_listeners(p)
        setup_oidc_unit()
        setup_interop_images()
        run("systemctl","daemon-reload")
        opted=opt_out_unsigned_registry_rules(ETC/"worker.json")
        result={"renewed_certificates":renewed}
        if opted:
            result["registry_rules_allowing_unsigned"]=opted
        # An update from a root worker: its trees, its keys and the services'
        # configurations go to its own account (ADR 024 §9).
        given=separate_worker()
        if given:
            result["worker_files_given"]=given
        return result
    database()  # Dedicated local cluster also owns the bundled OIDC realm.
    api_tls(p)
    setup_interop(p)
    setup_oidc(p)
    auth=authority()
    admin=ACTIVE/"agentcapsule-admin"
    env=db_env(p)
    run(admin,"migrate",env=env)
    if initial:
        run(admin,"bootstrap-platform","-receipt-key-file",ETC/"receipt.key","-token-file",ETC/"platform.token",env=env)
    create_key(ETC/"transit.key",secrets.token_bytes(32))
    for name in ("receipt","transit"):
        install_file(ETC/(name+".key"),ETC/("api-"+name+".key"),0o600,user_id("agentcapsule-api"))
    run(admin,"activate-transit-keys","-active-key","initial","-key","initial="+str(ETC/"transit.key"),env=env)
    pins=dict(restore_authority_id=auth["restore_authority"]["identity"],key_authority_id=auth["key_authority"]["identity"])
    environment_file(ETC/"api.env",dict(API_LISTEN="0.0.0.0:"+str(p["api_port"]),API_NAME=p["api_name"],
                                        HOST_ID=p["host_id"],RESTORE_AUTHORITY=pins["restore_authority_id"],KEY_AUTHORITY=pins["key_authority_id"]))
    service_environment(p)
    config_path=ETC/"worker.json"
    if initial and not config_path.exists():
        cfg=read(ACTIVE/"config/worker.json")
        artifact=ACTIVE.resolve()
        for name,file in [("initrd","product.initrd"),("firecracker","firecracker"),("jailer","jailer"),("kernel","vmlinux")]:
            cfg[name]={"path":str(artifact/file),"sha256":read(artifact/"bundle.json")["sha256"][file]}
        cfg.update(host_id=p["host_id"],max_active=p["max_active"],metrics_listen="127.0.0.1:9465",
                   provisioning=dict(first_uid=p["first_uid"],last_uid=p["last_uid"]),
                   authority=dict(pins,socket="/run/agentcapsule-authority/worker.sock"),
                   archives=dict(root="/var/lib/agentcapsule-archives"),
                   llm=dict(receipt_key=str(ETC/"receipt.key"),allowed_internal_providers=p["allow_internal_providers"]),
                   slim=dict(bridge_socket="/run/agentcapsule-slim/bridge.sock",worker_socket="/run/agentcapsule-worker/slim.sock",bridge_uid=user_id("agentcapsule-slim")),
                   transit=dict(active_key="initial",keys=dict(initial=str(ETC/"transit.key"))))
        if p["registry_rules"] is not None:
            cfg["registry"]["rules"]=p["registry_rules"]
        else:
            cfg["registry"]["rules"][0]["repositories"]=["arnaudguiovanna/"]
        cfg["helper"]=dict(socket=HELPER_SOCKET)
        save(config_path,cfg)
    separate_worker()
    if initial:
        run(admin,"configure-host","-host-id",p["host_id"],"-storage-mib",p["storage_mib"],env=env)
        run(admin,"approve-local-harness","-name","starter","-version","1.0.0","-artifact",read(config_path)["initrd"]["path"],env=env)
    run("systemctl","daemon-reload")


def issue_enrollment(p):
    path=ETC/"first-enrollment.token"
    run(ACTIVE/"agentcapsule-admin","issue-enrollment","-platform-account",p["platform_account"],"-token-file",path,env=db_env(p))
    export_login_file("first-enrollment.token", 0o600)
    return {"enrollment_file":str(path)}


# Keep these drop-ins on the host across release swaps. Older bundled units
# gate both the worker and the API on "maintenance", or lack a gate entirely.
SUSPENDED_SERVICES = ("agentcapsule-oidc", "agentcapsule-interop", "agentcapsule-authority",
                      "agentcapsule-worker-helper", "agentcapsule-worker", "agentcapsule-slim-bridge")


def installed(units):
    # The units installed on this host: an update from a release before the
    # worker helper (ADR 024) stops and drains without it.
    return tuple(u for u in units if (UNIT_DIR/(u+".service")).is_file())


def install_maintenance_gates():
    if (UNIT_DIR/"agentcapsule-oidc.service").is_file():
        setup_oidc_unit()
    for unit in (*SUSPENDED_SERVICES, *oidc_edge(), "agentcapsule-api"):
        gates = [STATE / "maintenance"]
        if unit == "agentcapsule-api":
            gates.append(STATE / "admissions-paused")
        unit_drop(unit, "agentcapsule-update", "[Unit]\n" + "".join(f"ConditionPathExists=!{gate}\n" for gate in gates))
    run("systemctl", "daemon-reload")


def clear_gate(name):
    marker = STATE / name
    if marker.exists():
        marker.unlink()
        fd = os.open(STATE, os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def pause_admissions():
    write_file(STATE / "admissions-paused", b"platform update\n")
    run("systemctl", "stop", "agentcapsule-api")


def suspend_services():
    write_file(STATE / "maintenance", b"services suspended\n")
    run("systemctl", "stop", *oidc_edge(), *installed(SUSPENDED_SERVICES))


def start_services(p):
    # A reboot can start these enabled units independently. Hold admissions
    # until the migrated worker, authorities and identity provider are ready.
    install_maintenance_gates()
    pause_admissions()
    clear_gate("maintenance")
    for service in SUSPENDED_SERVICES:
        if service=="agentcapsule-oidc" and output("systemctl","show","--value","-p","ActiveState",service+".service")=="failed":
            run("python3","-I","/usr/local/lib/agentcapsule-host/oidc-container.py","prepare")
            run("systemctl","reset-failed",service+".service")
        run("systemctl", "enable", "--now", service+".service")
    for service in oidc_edge():
        run("systemctl", "enable", "--now", service+".service")
    port=str(p["oidc_port"])
    realm=f"https://{p['oidc_name']}:{port}/realms/agentcapsule"
    cmd=["curl","-fsS","--max-time","5","--noproxy","*","--resolve",p["oidc_name"]+":"+port+":127.0.0.1"]
    if p["oidc_ca"] or not p["oidc_cert"]:
        cmd+=["--cacert",p["oidc_ca"] or ETC/"oidc-tls/tls.crt"]
    for _ in range(120):
        try:
            if json.loads(output(*cmd,realm+"/.well-known/openid-configuration"))["issuer"] == realm:
                break
        except (subprocess.CalledProcessError,ValueError,KeyError):
            pass
        time.sleep(2)
    else:
        raise ValueError("OIDC issuer discovery did not pass")
    for service in (*SUSPENDED_SERVICES, *oidc_edge()):
        run("systemctl", "is-active", "--quiet", service)
    bootstrap_admin=harden_oidc() if (ETC/"oidc.env").is_file() else None
    clear_gate("admissions-paused")
    try:
        run("systemctl", "enable", "--now", "agentcapsule-api.service")
        for _ in range(60):
            try:
                request_api(p,"GET","/v1/health/ready")
                break
            except (ValueError,subprocess.CalledProcessError):
                time.sleep(1)
        else:
            raise ValueError("HTTPS readiness did not pass")
        run("systemctl", "is-active", "--quiet", "agentcapsule-api")
    except Exception:
        pause_admissions()
        raise
    return {"services_started":True, "url":f"https://{p['api_name']}:{p['api_port']}", "oidc_issuer":realm,
            **({"oidc_bootstrap_admin":bootstrap_admin} if bootstrap_admin else {})}


def worker_exclusive(args, profile, checkpoint):
    # The worker's operator modes acquire the host listeners. Preserve a
    # maintenance service that was already stopped, also on operation replay.
    if not checkpoint.exists():
        status=subprocess.run(["systemctl","is-active","--quiet","agentcapsule-worker"])
        if status.returncode not in (0,3):
            raise ValueError("cannot determine maintenance worker state")
        save(checkpoint,{"restart":status.returncode==0})
    restart=read(checkpoint)["restart"]
    run("systemctl","stop","agentcapsule-worker")
    try:
        # As the worker's account; the helper keeps running (ADR 024).
        return worker_output(*args,profile=profile)
    finally:
        if restart:
            run("systemctl","start","agentcapsule-worker")


def install_backup_config(source, directory=Path("/etc/pgbackrest")):
    # The installer uses UMask=0077. PostgreSQL must traverse this directory
    # when PostgreSQL's archive_command independently starts pgBackRest.
    pg=pwd.getpwnam("postgres")
    directory.mkdir(exist_ok=True)
    if subprocess.run(["runuser","-u","postgres","--","test","-x",directory]).returncode:
        os.chown(directory,0,pg.pw_gid)
        directory.chmod(0o750)
    conf=directory/"pgbackrest.conf"
    install_file(source,conf,0o600,pg.pw_uid)
    run_user("postgres","test","-r",conf)


def backup_peer_addresses(address):
    host=urllib.parse.urlsplit(address if "://" in address else "//"+address).hostname
    if not host:
        return set()
    peers=socket.getaddrinfo(host,None,type=socket.SOCK_STREAM)
    for family,kind,protocol,_,peer in peers:
        with socket.socket(family,kind,protocol) as probe:
            try:
                probe.bind(peer)
            except OSError as err:
                # This address is not assigned to the current host.
                if err.errno==errno.EADDRNOTAVAIL:
                    continue
                raise
            return set()
    return {peer[4][0] for peer in peers}


def backup_destinations(config, includes=()):
    cfg=configparser.ConfigParser(interpolation=None)
    cfg.read([config,*includes])
    # A command/stanza override can redirect the periodic backup or its readback.
    # Require consistent destinations across every operation before attesting them.
    def setting(key):
        values={s[key] for s in cfg.values() if s.name.split(":",1)[0] in ("global","agentcapsule") and key in s}
        if len(values)>1:
            raise ValueError("conflicting pgBackRest destinations or encryption settings")
        return next(iter(values),"")
    stores={}
    for n in (1,2):
        prefix=f"repo{n}-"
        kind=setting(prefix+"type")
        if kind not in ("s3","sftp"):
            return {}
        if setting(prefix+"cipher-type")!="aes-256-cbc":
            raise ValueError("both remote pgBackRest repositories must be encrypted")
        if kind=="s3":
            # The transport host may differ from the endpoint used for the
            # S3 signature (e.g. a local forwarder).
            stores[kind]=setting(prefix+"storage-host") or setting(prefix+"s3-host") or setting(prefix+"s3-endpoint")
        else:
            stores[kind]=setting(prefix+"sftp-host")
    if set(stores)!={"s3","sftp"} or not all(stores.values()):
        raise ValueError("configure independent S3 and SFTP pgBackRest repositories")
    return stores


def volume_destinations(config):
    cfg=configparser.ConfigParser(interpolation=None)
    cfg.read(config)
    hosts={}
    for name,kind in (("s3","s3"),("standby","sftp")):
        crypt=cfg[name] if name in cfg else {}
        remote,sep,_=crypt.get("remote","").partition(":")
        if (crypt.get("type")!="crypt" or not sep or remote not in cfg or cfg[remote].get("type")!=kind
                or not crypt.get("password") or not crypt.get("password2")
                or crypt.get("filename_encryption","standard")!="standard"
                or crypt.get("directory_name_encryption","true").lower() not in ("1","t","true")):
            raise ValueError("configure encrypted rclone remotes s3 and standby backed by S3 and SFTP")
        backend=cfg[remote]
        hosts[kind]=backend.get("endpoint","s3.amazonaws.com") if kind=="s3" else backend.get("host","")
        if not hosts[kind]:
            raise ValueError("missing rclone store endpoint")
    return hosts


def off_host_destinations(stores):
    if not stores:
        return False
    s3=backup_peer_addresses(stores["s3"])
    sftp=backup_peer_addresses(stores["sftp"])
    return bool(s3 and sftp) and s3.isdisjoint(sftp)


def verify_volume_copies(profile, agent, archive, directory, conf):
    evidence={}
    uid,gid=worker_ids()
    for store in ("s3","standby"):
        # The worker's own scratch: the restore test runs as its account,
        # and the shipper writes the copy as that account (ADR 024).
        with tempfile.TemporaryDirectory(dir=RESTORE_TESTS) as tmp:
            os.chown(tmp,uid,gid)
            root=Path(tmp)/"copies"
            scratch=Path(tmp)/"scratch"
            scratch.mkdir(mode=0o700)
            os.chown(scratch,uid,gid)
            run("python3","-I",ACTIVE/"agentcapsule-archive-ship.py","--rclone-config",conf,
                "--archive-root",root,"fetch","--store",store,"--archive",archive,"--owner",WORKER_USER)
            result=json.loads(worker_output(ACTIVE/"agentcapsule-worker","-config",ETC/"worker.json","-test-restore",agent,
                                            "-archive-id",archive,"-archive-root",root,"-scratch",scratch,profile=profile))
            if (result.get("archive_id")!=archive or result.get("agent_id")!=agent or result.get("archive_store")!="local"
                    or not {"manifest","digest","volume","copy","key"}<=set(result.get("checked",[]))):
                raise ValueError("restore test did not confirm the fetched probe archive")
            evidence[store]={"archive_id":archive,"bytes":result["size"],"checked":result["checked"]}
    return evidence


def backup(profile,mandatory,directory):
    config=profile["pgbackrest_config"]
    if not config:
        if mandatory:
            raise ValueError("configure off-host pgBackRest repositories before updating")
        return {"off_host_backup_verified":False,"database_backups_verified":False,"volume_shipping_verified":False,
                "backup_status":"awaiting_off_host_configuration"}
    stores=backup_destinations(config,sorted(Path("/etc/pgbackrest/conf.d").glob("*.conf")))
    destinations=volume_destinations(profile["rclone_config"]) if profile.get("rclone_config") else {}
    remote=off_host_destinations(stores)
    remote_volumes=off_host_destinations(destinations)
    strict=mandatory and "-dev." not in (current() or "")
    if strict and not (remote and remote_volumes):
        raise ValueError("update requires verified off-host repositories")
    if not profile["database_url_file"]:
        folder=Path("/etc/postgresql/16/agentcapsule/conf.d")
        config_file=folder/"backup.conf"
        source=ACTIVE/"backup/postgresql.conf"
        if not config_file.exists() or config_file.read_bytes()!=source.read_bytes():
            install_file(source,config_file)
            run("systemctl","restart","postgresql@16-agentcapsule.service")
    install_backup_config(Path(config))
    pg=["pgbackrest","--stanza=agentcapsule"]
    run_user("postgres",*pg,"stanza-create")
    run_user("postgres",*pg,"check")
    for repo in (1,2):
        run_user("postgres",*pg,"--repo="+str(repo),"--type=full","backup")
    info=json.loads(run_user("postgres",*pg,"--output=json","info",capture=True))
    stanza,=info
    labels={}
    for repo in (1,2):
        status=next((r for r in stanza["repo"] if r["key"]==repo),{})
        full=[b for b in stanza.get("backup",[]) if b["database"]["repo-key"]==repo and b["type"]=="full" and not b.get("error")]
        if (not full or status.get("status",{}).get("code")!=0 or (stores and status.get("cipher")!="aes-256-cbc")):
            raise ValueError("missing healthy full backup in at least one repository")
        labels[str(repo)]=max(full,key=lambda b:b["timestamp"]["stop"])["label"]
        # Noble ships pgBackRest 2.50. Its verify command checks the whole
        # selected repository, including this full backup and its WAL.
        run_user("postgres",*pg,"--repo="+str(repo),"verify")
    for timer in (ACTIVE/"backup").glob("agentcapsule-pg-*"):
        install_file(timer,UNIT_DIR/timer.name)
    if not profile["database_url_file"]:
        unit_drop("agentcapsule-pg-heartbeat","port","[Service]\nEnvironment=PGPORT=55432\n")
    run("systemctl","daemon-reload")
    for timer in ("pg-backup-full","pg-backup-diff","pg-heartbeat"):
        run("systemctl","enable","--now","agentcapsule-"+timer+".timer")
    copies={}
    if profile.get("rclone_config"):
        conf=Path("/etc/agentcapsule-archive-ship/rclone.conf")
        install_file(ACTIVE/"backup/agentcapsule-archive-ship.sysusers",Path("/usr/lib/sysusers.d/agentcapsule-archive-ship.conf"))
        run("systemd-sysusers","/usr/lib/sysusers.d/agentcapsule-archive-ship.conf")
        conf.parent.mkdir(exist_ok=True)
        os.chmod(conf.parent,0o755)
        install_file(Path(profile["rclone_config"]),conf,0o640)
        os.chown(conf,0,pwd.getpwnam("agentcapsule-ship").pw_gid)
        for suffix in ("service","timer"):
            name="agentcapsule-archive-ship."+suffix
            install_file(ACTIVE/"backup"/name,UNIT_DIR/name)
        Path("/var/lib/prometheus/node-exporter").mkdir(parents=True,exist_ok=True)
        # Exercise the physical storage path on the probe volume.
        probe=read(STATE/"smoke.json")
        archive="arc_"+secrets.token_hex(16)
        worker_exclusive([ACTIVE/"agentcapsule-worker","-config",ETC/"worker.json","-archive-agent",probe["agent"],
                         "-archive-root","/var/lib/agentcapsule-archives","-archive-id",archive],profile,directory/"backup-worker.json")
        run("systemctl","daemon-reload")
        run("systemctl","start","agentcapsule-archive-ship.service")
        run("systemctl","enable","--now","agentcapsule-archive-ship.timer")
        copies=verify_volume_copies(profile,probe["agent"],archive,directory,conf)
    if mandatory and remote and not copies:
        raise ValueError("configure and verify off-host volume shipping before updating")
    off_host=remote and bool(copies) and remote_volumes
    status="local_repositories_verified"
    if stores:
        status="two_remote_repositories_verified" if off_host else "repository_separation_unverified"
        if remote and not copies:
            status="awaiting_volume_shipping"
    return {"off_host_backup_verified":off_host,"database_backups_verified":True,"database_backup_sets":labels,
            "volume_shipping_verified":bool(copies),"volume_copy_checks":copies,"backup_status":status}


# RUNNING includes invocations that have acknowledged work and await a result.
# Unreleased future schedules are durable and can stay queued across migration.
DRAIN_QUERY = """SELECT count(*) FROM platform_operations o
    WHERE o.status='RUNNING' OR (o.status='PENDING' AND NOT EXISTS (
        SELECT 1 FROM owner_instructions i WHERE i.operation_id=o.id AND o.kind='instruction'
        AND i.run_at>CURRENT_TIMESTAMP AND i.released_at IS NULL))"""


def postgres_scalar(profile, query):
    # Use the same private libpq connection string as the API. PGDATABASE in
    # psql's environment treats a connection string as a literal database name.
    # Putting it in psql's arguments would expose operator-supplied credentials.
    pq = ctypes.CDLL("libpq.so.5")
    ptr, string, integer = ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int
    connect = ctypes.CFUNCTYPE(ptr, string)(("PQconnectdb", pq))
    status = ctypes.CFUNCTYPE(integer, ptr)(("PQstatus", pq))
    execute = ctypes.CFUNCTYPE(ptr, ptr, string)(("PQexec", pq))
    result_status = ctypes.CFUNCTYPE(integer, ptr)(("PQresultStatus", pq))
    value = ctypes.CFUNCTYPE(string, ptr, integer, integer)(("PQgetvalue", pq))
    clear = ctypes.CFUNCTYPE(None, ptr)(("PQclear", pq))
    finish = ctypes.CFUNCTYPE(None, ptr)(("PQfinish", pq))
    conn = connect(db_env(profile)["AGENTCAPSULE_DATABASE_URL"].encode())
    if not conn:
        raise ValueError("could not allocate a PostgreSQL connection")
    try:
        if status(conn) != 0:  # CONNECTION_OK
            raise ValueError("could not connect to the configured PostgreSQL database")
        result = execute(conn, query.encode())
        try:
            if not result or result_status(result) != 2:  # PGRES_TUPLES_OK
                raise ValueError("PostgreSQL could not read the requested host operation state")
            return value(result, 0, 0)
        finally:
            clear(result)
    finally:
        finish(conn)


def pending_operations(profile):
    return int(postgres_scalar(profile, DRAIN_QUERY))


def drain(profile):
    install_maintenance_gates()
    pause_admissions()
    if not profile["database_url_file"]:
        run("systemctl", "start", "postgresql@16-agentcapsule.service")
    while True:
        if pending_operations(profile):
            # Also recover an interrupted older drain whose single marker
            # stopped the worker on reboot. The API retains its separate gate.
            clear_gate("maintenance")
            run("systemctl", "start", *installed(SUSPENDED_SERVICES), *oidc_edge())
            while pending_operations(profile):
                time.sleep(2)
        suspend_services()
        # Close the race with delivery becoming eligible just before stop.
        # No worker can start more work after this final observation.
        if not pending_operations(profile):
            return


def run_storage(request,directory):
    worker=ACTIVE/"agentcapsule-worker"
    profile=read(STATE/"profile.json")
    action=request["action"]
    flag={"restore-test":"-test-restore","restore-apply":"-restore-agent","archive":"-archive-agent"}[action]
    args=[worker,"-config",ETC/"worker.json",flag,request["agent"],"-archive-root","/var/lib/agentcapsule-archives","-archive-id",request["archive"]]
    if action=="restore-apply":
        args+=["-restore-id",request["restore"]]
    elif action=="restore-test":
        scratch=RESTORE_TESTS/directory.name
        scratch.mkdir(mode=0o700,parents=True,exist_ok=True)
        os.chown(scratch,*worker_ids())
        args+=["-scratch",scratch]
    if action=="restore-test":
        result=worker_output(*args,profile=profile)
    else:
        result=worker_exclusive(args,profile,directory/"worker-state.json")
    return {"storage_result":json.loads(result.splitlines()[-1])}


def request_api(p,method,path,body=None,token=None,idempotency=None):
    # Resolve to loopback and validate the actual certificate and server name.
    # A private header file keeps credentials out of process listings and logs.
    with tempfile.TemporaryDirectory(dir=STATE) as tmp:
        headers=Path(tmp)/"headers"
        rows=["Content-Type: application/json"]
        if token:
            if "\n" in token or "\r" in token:
                raise ValueError("invalid bearer token")
            rows.append("Authorization: Bearer "+token)
        if idempotency:
            rows.append("Idempotency-Key: "+idempotency)
        write_file(headers,("\n".join(rows)+"\n").encode())
        port=str(p["api_port"])
        cmd=["curl","--silent","--show-error","--fail","--max-time","20","--noproxy","*",
             "--resolve",p["api_name"]+":"+port+":127.0.0.1","--header","@"+str(headers),"-X",method]
        if p["tls_ca"] or not p["tls_certificate"]:
            cmd+=["--cacert",p["tls_ca"] or ETC/"api.crt"]
        if body is not None:
            cmd+=["--data-binary","@-"]
        url="https://"+p["api_name"]+":"+port+path
        return json.loads(output(*cmd,url,input=json.dumps(body) if body is not None else None))


def token_smoke(issuer,audience,scopes,key):
    def b64(data):
        return base64.urlsafe_b64encode(data).decode().rstrip("=")
    moment=int(time.time())
    claims={"iss":issuer,"aud":audience,"sub":"probe","iat":moment,"exp":moment+120,"jti":secrets.token_hex(16),
            "trust_generation":1,"scope":" ".join(scopes)}
    signing=".".join(b64(json.dumps(part,separators=(",",":")).encode()) for part in
                     ({"alg":"EdDSA","typ":"JWT","kid":"probe"},claims))
    with tempfile.NamedTemporaryFile(dir=STATE) as f:
        f.write(signing.encode())
        f.flush()
        sig=run("openssl","pkeyutl","-sign","-inkey",key,"-rawin","-in",f.name,stdout=subprocess.PIPE).stdout
    return signing+"."+b64(sig)


def smoke(p,directory):
    path=STATE/"smoke.json"
    data=read(path) if path.exists() else {}
    issuer="https://agentcapsule-install.invalid"
    audience="agentcapsule-installation"
    scopes=["agent:assign","agent:create","agent:invoke","agent:content:read","agent:operate","agent:read"]
    key=STATE/"smoke.key"
    if not key.is_file():
        with tempfile.TemporaryDirectory(dir=STATE) as tmp:
            generated=Path(tmp)/"smoke.key"
            run("openssl","genpkey","-algorithm","ed25519","-out",generated)
            install_file(generated,key,0o600)
    if "organization" not in data:
        org=request_api(p,"POST","/v1/organizations",
                        {"name":"Installation health","initial_owner":{"issuer":issuer,"subject":"probe","display_name":"Installation probe"}},
                        (ETC/"platform.token").read_text().strip(),"installation-health-org")
        data.update(organization=org["id"],principal=org["owner_principal_id"])
        save(path,data)
    if "trust" not in data:
        public=run("openssl","pkey","-in",key,"-pubout","-outform","DER",stdout=subprocess.PIPE).stdout[-32:]
        trust=dict(version=1,trusts=[dict(tenant_id=data["organization"],issuer=issuer,audience=audience,allowed_scopes=scopes,
                                         max_ttl_seconds=300,keys=[dict(kid="probe",public_key=base64.b64encode(public).decode())])])
        save(STATE/"probe-trust.json",trust)
        result=output(ACTIVE/"agentcapsule-admin","configure-delegation","-action","install","-operation-id","installation-health",
                      "-tenant-id",data["organization"],"-issuer",issuer,"-audience",audience,"-trust-file",STATE/"probe-trust.json",env=db_env(p))
        data["trust"]=json.loads(result)["minimum_iat"]
        save(path,data)
    minimum=datetime.datetime.fromisoformat(data["trust"]).timestamp()
    while int(time.time()) < minimum:
        time.sleep(0.2)
    def call(method,path,body=None,idem=None):
        return request_api(p,method,path,body,token_smoke(issuer,audience,scopes,key),idem)
    if "agent" not in data:
        result=call("POST","/v1/agents",dict(name="Installation health",harness=dict(name="starter",version="1.0.0"),
                    resources=dict(vcpus=1,memory_mib=256,data_volume_mib=128)),"installation-health-agent")
        data.update(agent=result["agent_id"],provision=result["operation_id"])
        save(path,data)
    def wait(path,field,expected):
        for _ in range(180):
            value=call("GET",path)[field]
            if value==expected:
                return
            if value.upper() in ("FAILED","CANCELED","LOST"):
                raise ValueError("installation probe failed at "+path)
            time.sleep(2)
        raise ValueError("installation probe timed out at "+path)
    wait("/v1/operations/"+data["provision"],"status","SUCCEEDED")
    prefix="/v1/agents/"+data["agent"]
    if "assignment" not in data:
        call("POST",prefix+"/assignments",dict(principal_id=data["principal"],permissions=["read_metadata","invoke","read_content"]),
             "installation-health-assignment")
        data["assignment"]=True
        save(path,data)
    marker=directory.name
    content=[{"type":"text","text":marker}]
    invocation=call("POST",prefix+"/invocations",dict(content=content),marker+"-invoke")
    target="/v1/invocations/"+invocation["id"]
    wait(target,"state","completed")
    if call("GET",target+"/result").get("content") != content:
        raise ValueError("starter harness did not echo the installation probe")
    sleep=call("POST",prefix+"/sleep",{},marker+"-sleep")
    wait("/v1/operations/"+sleep["operation_id"],"status","SUCCEEDED")
    return {"invocation_verified":True,"probe_agent":data["agent"],"probe_invocation":invocation["id"]}


def setup_oidc(p):
    env=ETC/"oidc.env"
    certs=ETC/"oidc-tls"
    certs.mkdir(exist_ok=True)
    certs.chmod(0o755)
    if p["oidc_cert"]:
        install_file(Path(p["oidc_cert"]),certs/"tls.crt")
        install_file(Path(p["oidc_key"]),certs/"tls.key",0o600,1000)
    elif not (certs/"tls.crt").exists():
        issue_oidc_certificate(p,certs)
    # Keep the password in root-only files and stdin, out of psql arguments.
    secret=STATE/"oidc-db.password"
    create_key(secret,secrets.token_hex(32).encode())
    dbpass=secret.read_text()
    sql=["psql","-XAt","-v","ON_ERROR_STOP=1","-h","/run/postgresql","-p","55432","-d","postgres"]
    if not run_user("postgres",*sql,"-c","SELECT 1 FROM pg_roles WHERE rolname='keycloak'",capture=True):
        run("runuser","-u","postgres","--",*sql,input="CREATE ROLE keycloak LOGIN PASSWORD '"+dbpass+"';",text=True)
    if not run_user("postgres",*sql,"-c","SELECT 1 FROM pg_database WHERE datname='keycloak'",capture=True):
        run_user("postgres",*sql,"-c","CREATE DATABASE keycloak OWNER keycloak")
    if not env.exists():
        data=dict(KC_DB="postgres",KC_DB_URL="jdbc:postgresql://127.0.0.1:55432/keycloak",KC_DB_USERNAME="keycloak",
                  KC_DB_PASSWORD=dbpass,KC_HOSTNAME="https://"+p["oidc_name"]+":"+str(p["oidc_port"]),
                  KC_BOOTSTRAP_ADMIN_USERNAME="operator",
                  KC_BOOTSTRAP_ADMIN_PASSWORD=secrets.token_hex(32),MONAPP_REDIRECT_URI=p["monapp_redirect_uri"])
        if any("\n" in v or "\r" in v for v in data.values()):
            raise ValueError("invalid OIDC environment")
        write_file(env,"".join(k+"="+v+"\n" for k,v in data.items()).encode())
    (ETC/"oidc").mkdir(exist_ok=True)
    (ETC/"oidc").chmod(0o755)
    install_file(ACTIVE/"oidc/realm.json",ETC/"oidc/realm.json")
    oidc_listeners(p)
    setup_oidc_unit()


def issue_oidc_certificate(p,certs):
    # A new key on the first install; a renewal keeps it.
    with tempfile.TemporaryDirectory(dir=STATE) as tmp:
        crt=Path(tmp)/"tls.crt"
        if (certs/"tls.key").is_file():
            key=["-key",certs/"tls.key"]
        else:
            key=["-nodes","-newkey","ec","-pkeyopt","ec_paramgen_curve:P-256","-keyout",Path(tmp)/"tls.key"]
        run("openssl","req","-new","-x509",*key,"-days","365",
            "-subj","/CN="+p["oidc_name"],"-addext","subjectAltName=DNS:"+p["oidc_name"],
            "-addext","extendedKeyUsage=serverAuth","-out",crt)
        if (Path(tmp)/"tls.key").is_file():
            install_file(Path(tmp)/"tls.key",certs/"tls.key",0o600,1000)
        install_file(crt,certs/"tls.crt")


def setup_oidc_unit():
    image=next(i for i in read(ACTIVE/"offline-images.json") if i["service"]=="oidc")
    template=(ACTIVE/"oidc/agentcapsule-oidc.service").read_text()
    if image["ref"] not in template:
        raise ValueError("OIDC unit image differs from signed image index")
    helper=Path("/usr/local/lib/agentcapsule-host/oidc-container.py")
    write_file(helper,OIDC_LIFECYCLE,0o700)
    launch="/usr/bin/python3 -I "+str(helper)
    if "--cidfile=" not in template:
        legacy_stop="ExecStop=/usr/bin/podman stop --time 30 agentcapsule-oidc"
        legacy_run="/usr/bin/podman run --rm --name agentcapsule-oidc "
        if legacy_run not in template or legacy_stop not in template:
            raise ValueError("unrecognized OIDC unit lifecycle")
        template=template.replace("Type=simple\n","Type=simple\nStateDirectory=agentcapsule-oidc\nStateDirectoryMode=0700\nExecStartPre="+launch+" prepare\n")
        template=template.replace(legacy_run,"/usr/bin/podman run --rm --cidfile=/var/lib/agentcapsule-oidc/container-id --name agentcapsule-oidc ")
        template=template.replace(legacy_stop,"ExecStop="+launch+" stop\nExecStopPost="+launch+" cleanup")
    write_file(UNIT_DIR/"agentcapsule-oidc.service",template.replace(image["ref"],image["tag"]).encode(),0o644)
    edge=ACTIVE/"oidc"/(OIDC_EDGE+".service")
    if edge.is_file():
        install_file(edge,UNIT_DIR/edge.name)


# The identity provider's listeners (S-19): Keycloak on loopback only, its
# administration and management with it, one node (no JGroups port); the
# edge (agentcapsule-oidc-edge, internal/oidcedge) on the public port, with
# the identity provider's certificate, forwards only the realms' pages and
# endpoints and the static files. Brute-force detection guards the master
# realm and the platform's; the bootstrap administrator is deleted once a
# permanent one exists.
OIDC_EDGE="agentcapsule-oidc-edge"
OIDC_LOOPBACK_PORT=9445
OIDC_LOOPBACK="http://127.0.0.1:"+str(OIDC_LOOPBACK_PORT)
OIDC_LISTENERS=dict(KC_HTTP_ENABLED="true",KC_HTTP_HOST="127.0.0.1",KC_HTTP_PORT=str(OIDC_LOOPBACK_PORT),
                    KC_HOSTNAME_ADMIN="http://localhost:"+str(OIDC_LOOPBACK_PORT),KC_PROXY_HEADERS="xforwarded",
                    KC_PROXY_TRUSTED_ADDRESSES="127.0.0.1/32",KC_CACHE="local",KC_HEALTH_ENABLED="false",
                    KC_METRICS_ENABLED="false")
# What an earlier release wrote: Keycloak served TLS on the public port.
OIDC_RETIRED_KEYS=("KC_HTTPS_PORT","KC_HTTPS_CERTIFICATE_FILE","KC_HTTPS_CERTIFICATE_KEY_FILE","KC_HTTPS_HOST")
BRUTE_FORCE=dict(bruteForceProtected=True,permanentLockout=False,failureFactor=5,waitIncrementSeconds=60,
                 maxFailureWaitSeconds=900,maxDeltaTimeSeconds=43200,quickLoginCheckMilliSeconds=1000,
                 minimumQuickLoginWaitSeconds=60)
BOOTSTRAP_KEYS=("KC_BOOTSTRAP_ADMIN_USERNAME","KC_BOOTSTRAP_ADMIN_PASSWORD")


def oidc_edge():
    # The edge's unit, once installed (a release before it has none).
    return (OIDC_EDGE,) if (UNIT_DIR/(OIDC_EDGE+".service")).is_file() else ()


def read_oidc_env():
    return dict(line.split("=",1) for line in (ETC/"oidc.env").read_text().splitlines() if "=" in line)


def write_oidc_env(values):
    # podman --env-file: one KEY=value per line, no quoting.
    if any("\n" in v or "\r" in v for v in values.values()):
        raise ValueError("invalid OIDC environment")
    write_file(ETC/"oidc.env","".join(k+"="+v+"\n" for k,v in values.items()).encode())


def oidc_listeners(p):
    values={k:v for k,v in read_oidc_env().items() if k not in OIDC_RETIRED_KEYS}
    values.update(OIDC_LISTENERS,KC_HOSTNAME="https://"+p["oidc_name"]+":"+str(p["oidc_port"]))
    write_oidc_env(values)
    environment_file(ETC/"oidc-edge.env",dict(OIDC_LISTEN="0.0.0.0:"+str(p["oidc_port"]),OIDC_NAME=p["oidc_name"]))


def keycloak(method,path,token=None,form=None,body=None):
    # Keycloak's loopback listener, never through a proxy.
    import urllib.error
    import urllib.request
    headers={}
    data=None
    if form is not None:
        data=urllib.parse.urlencode(form).encode()
        headers["Content-Type"]="application/x-www-form-urlencoded"
    elif body is not None:
        data=json.dumps(body).encode()
        headers["Content-Type"]="application/json"
    if token:
        headers["Authorization"]="Bearer "+token
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
    request=urllib.request.Request(OIDC_LOOPBACK+path,data=data,method=method,headers=headers)
    try:
        with opener.open(request,timeout=20) as reply:
            raw=reply.read(4<<20)
            return reply.status,(json.loads(raw) if raw else None)
    except urllib.error.HTTPError as error:
        error.close()
        return error.code,None


def harden_oidc(required=False):
    # Brute-force protection on both realms, then the bootstrap administrator
    # retired when another administrator exists. Returns "retired", "kept"
    # (no other administrator yet) or "credentials_refused".
    values=read_oidc_env()
    user,password=values.get(BOOTSTRAP_KEYS[0]),values.get(BOOTSTRAP_KEYS[1])
    if not user or not password:
        return "retired"
    status,grant=keycloak("POST","/realms/master/protocol/openid-connect/token",
                          form=dict(grant_type="password",client_id="admin-cli",username=user,password=password))
    if status in (400,401):
        # Deleted or changed by hand, or locked out: keep the entries, which
        # the operator removes after checking (deploy/oidc/README.md).
        if required:
            raise ValueError("the identity provider refused the bootstrap administrator's credentials")
        return "credentials_refused"
    if status!=200 or not isinstance(grant,dict) or not grant.get("access_token"):
        raise ValueError("the identity provider's administration did not answer on loopback")
    token=grant["access_token"]
    for realm in ("master","agentcapsule"):
        status,_=keycloak("PUT","/admin/realms/"+realm,token,body=BRUTE_FORCE)
        if status not in (200,204):
            raise ValueError("could not turn on brute-force protection for realm "+realm)
    status,admins=keycloak("GET","/admin/realms/master/roles/admin/users?first=0&max=1000",token)
    if status!=200 or not isinstance(admins,list):
        raise ValueError("could not list the identity provider's administrators")
    if not any(a.get("username")!=user and a.get("enabled") for a in admins):
        if required:
            raise ValueError("create a permanent administrator in the master realm, with its admin role, first")
        return "kept"
    status,found=keycloak("GET","/admin/realms/master/users?exact=true&username="+urllib.parse.quote(user),token)
    for account in found if status==200 and isinstance(found,list) else []:
        if account.get("username")==user:
            status,_=keycloak("DELETE","/admin/realms/master/users/"+urllib.parse.quote(account["id"],safe=""),token)
            if status not in (200,204):
                raise ValueError("could not delete the bootstrap administrator")
    write_oidc_env({k:v for k,v in values.items() if k not in BOOTSTRAP_KEYS})
    return "retired"
