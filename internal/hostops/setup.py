# Production host setup. This file is embedded ahead of host.py in the helper.
import base64
import configparser
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.parse


def normalize_profile(raw):
    defaults = dict(schema="agentcapsule.install/v1", api_name=socket.getfqdn(), api_port=9443,
                    platform_account="sysadmin", host_id="local", storage_mib=8192, max_active=2,
                    first_uid=62100, last_uid=63123, allow_internal_providers=[], database_url_file=None,
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
    if p["oidc_port"] == p["api_port"] or not 1 <= p["oidc_port"] <= 65535 or p["oidc_port"] in (8443,9464,9465,9466,46357,55432):
        raise ValueError("invalid OIDC port")
    if (p["api_port"] in (8443,9464,9465,9466,46357,55432) or not 1 <= p["api_port"] <= 65535
            or min(p["storage_mib"],p["max_active"]) < 1 or not 10000 <= p["first_uid"] <= p["last_uid"] < 2147483647
            or p["last_uid"]-p["first_uid"] > 1 << 20):
        raise ValueError("invalid profile capacity or listen port")
    for key in ("database_url_file","tls_certificate","tls_key","tls_ca","interop_certs","pgbackrest_config","oidc_cert","oidc_key","oidc_ca","rclone_config"):
        if p[key] is not None and (not isinstance(p[key],str) or not Path(p[key]).is_absolute()):
            raise ValueError("expected absolute host path for "+key)
    if bool(p["oidc_cert"]) != bool(p["oidc_key"]):
        raise ValueError("provide both OIDC TLS certificate and key")
    if bool(p["tls_key"]) != bool(p["tls_certificate"]):
        raise ValueError("provide both TLS certificate and private key")
    return p


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


def saved_config(tag,expected,root):
    path=root/"loaded-image.tar"
    try:
        run("docker","image","save","--output",path,tag)
        with tarfile.open(path) as tar:
            manifests=json.load(tar.extractfile("manifest.json"))
            if len(manifests)!=1 or tag not in manifests[0]["RepoTags"]:
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


def db_env(profile):
    path = profile["database_url_file"]
    if path:
        f=Path(path)
        if f.stat().st_uid != 0 or f.stat().st_mode & 0o077:
            raise ValueError("the database URL must be in a root-owned private file")
        dsn=f.read_text().strip()
    else:
        dsn="host=/run/postgresql port=55432 dbname=agentcapsule user=agentcapsule"
    if not dsn or any(ord(c)<32 for c in dsn):
        raise ValueError("invalid database URL file")
    return dict(os.environ,AGENTCAPSULE_DATABASE_URL=dsn,PGDATABASE=dsn)


def database():
    # A dedicated cluster avoids modifying pg_hba.conf or WAL retention on an
    # operator's other databases. The API's role has no cluster privileges.
    folder=Path("/etc/postgresql/16/agentcapsule")
    if not folder.exists():
        run("pg_createcluster","16","agentcapsule","--port","55432","--","--auth-local=peer","--auth-host=scram-sha-256")
    hba = folder/"pg_hba.conf"
    ident = folder/"pg_ident.conf"
    for file,entries in [(ident,"agentcapsule root agentcapsule\nagentcapsule agentcapsule-api agentcapsule\n"),
                         (hba,"local agentcapsule agentcapsule peer map=agentcapsule\n"
                              "host all all 127.0.0.1/32 scram-sha-256\nhost all all ::1/128 scram-sha-256\n")]:
        if not file.read_text().startswith(entries):
            write_file(file,(entries+file.read_text()).encode(),0o640)
            os.chown(file,user_id("postgres"),pwd.getpwnam("postgres").pw_gid)
    write_file(folder/"conf.d"/"agentcapsule.conf",b"listen_addresses = '127.0.0.1'\n",0o644)
    run("systemctl","enable","--now","postgresql@16-agentcapsule.service")
    run("pg_ctlcluster","16","agentcapsule","reload")
    cmd=["psql","-XAt","-v","ON_ERROR_STOP=1","-h","/run/postgresql","-p","55432","-d","postgres","-c"]
    for query,statement in [("SELECT 1 FROM pg_roles WHERE rolname='agentcapsule'","CREATE ROLE agentcapsule LOGIN"),
                            ("SELECT 1 FROM pg_database WHERE datname='agentcapsule'","CREATE DATABASE agentcapsule OWNER agentcapsule")]:
        if not run_user("postgres",*cmd,query,capture=True):
            run_user("postgres",*cmd,statement)


def create_key(path,data):
    if path.exists():
        return
    write_file(path,data)


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
        with tempfile.TemporaryDirectory(dir=STATE) as tmp:
            generated=Path(tmp)/"api.crt"
            run("openssl","req","-new","-x509","-key",key,"-days","365","-subj","/CN="+p["api_name"],
                "-addext","subjectAltName=DNS:"+p["api_name"],"-addext","extendedKeyUsage=serverAuth",
                "-addext","basicConstraints=critical,CA:FALSE","-out",generated)
            install_file(generated,cert)


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
    admin=ACTIVE/"agentcapsule-admin"
    keyid=json.loads(run_user(user,admin,"init-key-authority","-root",key,capture=True))["authority_id"]
    restid=json.loads(run_user(user,admin,"init-restore-authority","-root",restore,"-key-authority-root",key,
                               "-key-authority-id",keyid,"-data-root","/var/lib/agentcapsule/host",capture=True))["authority_id"]
    config=dict(version=2,role="primary",key_authority=dict(root=key,identity=keyid),restore_authority=dict(root=restore,identity=restid),
                api_uid=user_id("agentcapsule-api"),worker_socket="/run/agentcapsule-authority/worker.sock",
                api_socket="/run/agentcapsule-authority/api.sock",metrics_listen="127.0.0.1:9466")
    write_file(path,json.dumps(config).encode(),0o644)
    return config


def environment_file(path, settings):
    def quote(s):
        if any(ord(c)<32 for c in s):
            raise ValueError("unsupported environment value")
        return '"'+s.replace("\\","\\\\").replace('"','\\"')+'"'
    write_file(path,"".join(k+"="+quote(v)+"\n" for k,v in settings.items()).encode())


def configure(p,version,initial):
    configure_system()
    if not initial:
        # A release transition preserves the operator's current credentials,
        # transit key ring, storage and PKI configuration. Offline migrations
        # run with the authorities stopped and must retain their identities.
        cfg=read(ETC/"authority.json")
        admin=ACTIVE/"agentcapsule-admin"
        env=db_env(p)
        run(admin,"migrate",env=env)
        upgrade=json.loads(run_user("agentcapsule-authority",admin,"init-restore-authority",
                           "-root",cfg["restore_authority"]["root"],"-data-root",read(ETC/"worker.json")["root"],
                           "-key-authority-root",cfg["key_authority"]["root"],"-key-authority-id",cfg["key_authority"]["identity"],capture=True))
        if upgrade["authority_id"]!=cfg["restore_authority"]["identity"]:
            raise ValueError("authority identity changed during upgrade")
        setup_oidc_unit()
        setup_interop_images()
        run("systemctl","daemon-reload")
        return
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
    values=dict(AGENTCAPSULE_DATABASE_URL=env["AGENTCAPSULE_DATABASE_URL"])
    environment_file(ETC/"worker.env",values)
    environment_file(ETC/"api.env",dict(values,API_LISTEN="0.0.0.0:"+str(p["api_port"]),API_NAME=p["api_name"],
                                        HOST_ID=p["host_id"],RESTORE_AUTHORITY=pins["restore_authority_id"],KEY_AUTHORITY=pins["key_authority_id"]))
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
        save(config_path,cfg)
    if initial:
        run(admin,"configure-host","-host-id",p["host_id"],"-storage-mib",p["storage_mib"],env=env)
        run(admin,"approve-local-harness","-name","starter","-version","1.0.0","-artifact",read(config_path)["initrd"]["path"],env=env)
    run("systemctl","daemon-reload")


def issue_enrollment(p):
    path=ETC/"first-enrollment.token"
    run(ACTIVE/"agentcapsule-admin","issue-enrollment","-platform-account",p["platform_account"],"-token-file",path,env=db_env(p))
    return {"enrollment_file":str(path)}


def start_services(p):
    # The authority and private transports retain their state across reboot.
    (STATE/"maintenance").unlink(missing_ok=True)
    run("systemctl","enable","--now","agentcapsule-oidc.service")
    for service in ("agentcapsule-interop","agentcapsule-authority","agentcapsule-worker","agentcapsule-slim-bridge","agentcapsule-api"):
        run("systemctl","enable","--now",service+".service")
    for _ in range(60):
        try:
            request_api(p,"GET","/v1/health/ready")
            break
        except (ValueError,subprocess.CalledProcessError):
            time.sleep(1)
    else:
        raise ValueError("HTTPS readiness did not pass")
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
    for service in ("agentcapsule-oidc","agentcapsule-interop","agentcapsule-authority","agentcapsule-worker","agentcapsule-slim-bridge","agentcapsule-api"):
        run("systemctl","is-active","--quiet",service)
    return {"services_started":True, "url":f"https://{p['api_name']}:{p['api_port']}", "oidc_issuer":realm}


def backup(profile,mandatory):
    config=profile["pgbackrest_config"]
    if not config:
        if mandatory:
            raise ValueError("configure off-host pgBackRest repositories before updating")
        return {"off_host_backup_verified":False,"backup_status":"awaiting_off_host_configuration"}
    cfg=configparser.ConfigParser(interpolation=None, strict=False)
    cfg.read(config)
    remote={cfg.get("global","repo1-type",fallback="posix"),cfg.get("global","repo2-type",fallback="posix")}=={"s3","sftp"}
    if mandatory and not remote and "-dev." not in (current() or ""):
        raise ValueError("update requires verified off-host repositories")
    if not profile["database_url_file"]:
        folder=Path("/etc/postgresql/16/agentcapsule/conf.d")
        config_file=folder/"backup.conf"
        source=ACTIVE/"backup/postgresql.conf"
        if not config_file.exists() or config_file.read_bytes()!=source.read_bytes():
            install_file(source,config_file)
            run("systemctl","restart","postgresql@16-agentcapsule.service")
    conf=Path("/etc/pgbackrest/pgbackrest.conf")
    install_file(Path(config),conf,0o600,user_id("postgres"))
    pg=["pgbackrest","--stanza=agentcapsule"]
    run_user("postgres",*pg,"stanza-create")
    run_user("postgres",*pg,"check")
    for repo in (1,2):
        run_user("postgres",*pg,"--repo="+str(repo),"--type=full","backup")
    info=json.loads(run_user("postgres",*pg,"--output=json","info",capture=True))
    if not info or {b["database"]["repo-key"] for b in info[0].get("backup",[]) if b["type"]=="full" and not b.get("error")} != {1,2}:
        raise ValueError("missing full backup in at least one repository")
    for timer in (ACTIVE/"backup").glob("agentcapsule-pg-*"):
        install_file(timer,UNIT_DIR/timer.name)
    if not profile["database_url_file"]:
        unit_drop("agentcapsule-pg-heartbeat","port","[Service]\nEnvironment=PGPORT=55432\n")
    run("systemctl","daemon-reload")
    for timer in ("pg-backup-full","pg-backup-diff","pg-heartbeat"):
        run("systemctl","enable","--now","agentcapsule-"+timer+".timer")
    volumes=False
    if profile.get("rclone_config"):
        conf=Path("/etc/agentcapsule-archive-ship/rclone.conf")
        install_file(ACTIVE/"backup/agentcapsule-archive-ship.sysusers",Path("/usr/lib/sysusers.d/agentcapsule-archive-ship.conf"))
        run("systemd-sysusers","/usr/lib/sysusers.d/agentcapsule-archive-ship.conf")
        conf.parent.mkdir(exist_ok=True)
        os.chmod(conf.parent,0o755)
        install_file(Path(profile["rclone_config"]),conf,0o600,user_id("agentcapsule-ship"))
        for suffix in ("service","timer"):
            name="agentcapsule-archive-ship."+suffix
            install_file(ACTIVE/"backup"/name,UNIT_DIR/name)
        Path("/var/lib/prometheus/node-exporter").mkdir(parents=True,exist_ok=True)
        # Exercise the physical storage path on the probe volume.
        probe=read(STATE/"smoke.json")
        archive="arc_"+secrets.token_hex(16)
        run(ACTIVE/"agentcapsule-worker","-config",ETC/"worker.json","-archive-agent",probe["agent"],
            "-archive-root","/var/lib/agentcapsule-archives","-archive-id",archive,env=db_env(profile))
        run("systemctl","daemon-reload")
        run("systemctl","start","agentcapsule-archive-ship.service")
        run("systemctl","enable","--now","agentcapsule-archive-ship.timer")
        volumes=True
    if mandatory and remote and not volumes:
        raise ValueError("configure and verify off-host volume shipping before updating")
    return {"off_host_backup_verified":remote and volumes, "database_backups_verified":True,
            "volume_shipping_verified":volumes, "backup_status":"two_remote_repositories_verified" if remote else "local_repositories_verified"}


def drain(profile):
    # The durable marker also suppresses admissions after a reboot mid-update.
    write_file(STATE/"maintenance",b"platform update\n")
    run("systemctl","stop","agentcapsule-api")
    for _ in range(120):
        remaining=output("psql","-XAt","-v","ON_ERROR_STOP=1","-c",
                         "SELECT count(*) FROM platform_operations WHERE status IN ('PENDING','RUNNING')",env=db_env(profile))
        if remaining=="0":
            break
        time.sleep(2)
    else:
        raise ValueError("admissions paused; pending operations still draining")
    run("systemctl","stop","agentcapsule-worker","agentcapsule-slim-bridge","agentcapsule-authority","agentcapsule-interop","agentcapsule-oidc")


def run_storage(request,directory):
    worker=ACTIVE/"agentcapsule-worker"
    profile=read(STATE/"profile.json")
    action=request["action"]
    flag={"restore-test":"-test-restore","restore-apply":"-restore-agent","archive":"-archive-agent"}[action]
    args=[worker,"-config",ETC/"worker.json",flag,request["agent"],"-archive-root","/var/lib/agentcapsule-archives","-archive-id",request["archive"]]
    if action=="restore-apply":
        args+=["-restore-id",request["restore"]]
    elif action=="restore-test":
        scratch=Path("/var/lib/agentcapsule-restore-tests")/directory.name
        scratch.mkdir(parents=True,exist_ok=True)
        args+=["-scratch",scratch]
    result=json.loads(output(*args,env=db_env(profile)))
    return {"storage_result":result}


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
        with tempfile.TemporaryDirectory(dir=STATE) as tmp:
            key=Path(tmp)/"tls.key"
            crt=Path(tmp)/"tls.crt"
            run("openssl","req","-new","-x509","-nodes","-newkey","ec","-pkeyopt","ec_paramgen_curve:P-256","-days","365",
                "-subj","/CN="+p["oidc_name"],"-addext","subjectAltName=DNS:"+p["oidc_name"],
                "-addext","extendedKeyUsage=serverAuth","-keyout",key,"-out",crt)
            install_file(key,certs/"tls.key",0o600,1000)
            install_file(crt,certs/"tls.crt")
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
                  KC_HTTPS_PORT=str(p["oidc_port"]),KC_HTTPS_CERTIFICATE_FILE="/keycloak-tls/tls.crt",
                  KC_HTTPS_CERTIFICATE_KEY_FILE="/keycloak-tls/tls.key",KC_BOOTSTRAP_ADMIN_USERNAME="operator",
                  KC_BOOTSTRAP_ADMIN_PASSWORD=secrets.token_hex(32),MONAPP_REDIRECT_URI=p["monapp_redirect_uri"])
        if any("\n" in v or "\r" in v for v in data.values()):
            raise ValueError("invalid OIDC environment")
        write_file(env,"".join(k+"="+v+"\n" for k,v in data.items()).encode())
    (ETC/"oidc").mkdir(exist_ok=True)
    (ETC/"oidc").chmod(0o755)
    install_file(ACTIVE/"oidc/realm.json",ETC/"oidc/realm.json")
    setup_oidc_unit()


def setup_oidc_unit():
    image=next(i for i in read(ACTIVE/"offline-images.json") if i["service"]=="oidc")
    template=(ACTIVE/"oidc/agentcapsule-oidc.service").read_text()
    if image["ref"] not in template:
        raise ValueError("OIDC unit image differs from signed image index")
    write_file(UNIT_DIR/"agentcapsule-oidc.service",template.replace(image["ref"],image["tag"]).encode(),0o644)
