"""Bootstrap the signed private Linux userspace and dispatch host operations into it.

Only the initial bootstrap runs in the operator's Linux distribution. Package
installation and the service manager used by the PaaS run inside its own root.
"""
import contextlib

PRIVATE_OS = Path("/var/lib/agentcapsule-userspace")
OS_UNIT = "agentcapsule-userspace.service"
NET_UNIT = "agentcapsule-userspace-network.service"
NET_PID = Path("/run/agentcapsule-userspace-network/pasta.pid")
OS_MEDIA = "agentcapsule-userspace-linux-amd64.tar.gz"
PROFILE_FILES = ("database_url_file", "api_database_url_file", "worker_database_url_file",
                 "tls_certificate", "tls_key", "tls_ca", "oidc_cert", "oidc_key", "oidc_ca",
                 "rclone_config", "pgbackrest_config", "interop_certs")


def seed_for_boot():
    # Only the outer installer writes this mapping, after verifying the release.
    # A failed/interrupted database transition keeps its previous launcher.
    previous = PRIVATE_OS / "boot-seed.json"
    digest = read(previous) if previous.exists() else None
    activation = STATE / "active-release.json"
    if activation.is_file():
        active = read(activation)
        if re.fullmatch(VERSION, active["version"]):
            record = PRIVATE_OS / "versions" / active["version"]
            status = opdir(active["operation_id"]) / "status.json"
            if record.is_file() and status.is_file() and read(status)["state"] == "succeeded":
                digest = read(record)
    if digest is not None and not re.fullmatch("[a-f0-9]{64}",digest):
        raise ValueError("invalid private userspace digest")
    save(previous,digest)
    return digest


def portable_program(name):
    stamp = PRIVATE_OS / "boot-seed.json"
    digest = read(stamp) if stamp.is_file() else None
    if digest is not None and not re.fullmatch("[a-f0-9]{64}",digest):
        raise ValueError("invalid private userspace digest")
    seed = PRIVATE_OS / "seeds" / digest if digest else PRIVATE_OS / "system" / "seed"
    libs = seed / "usr/lib/x86_64-linux-gnu"
    return [str(libs / "ld-linux-x86-64.so.2"), "--library-path", f"{libs}/systemd:{libs}",
            str(seed / "usr/bin" / name)]


def container_leader():
    # Match both the root inode and PID 1 in a nested namespace. Hold /proc/pid
    # open while opening namespace fds so PID recycling cannot redirect nsenter.
    root = PRIVATE_OS / "system/guest"
    for entry in Path("/proc").iterdir():
        if not entry.name.isdecimal():
            continue
        try:
            fd = os.open(entry, os.O_DIRECTORY | os.O_CLOEXEC)
        except FileNotFoundError:
            continue
        try:
            proc = Path(f"/proc/self/fd/{fd}")
            if ((proc/"root").samefile(root) and
                    re.search(r"^NSpid:\s*\d+(?:\s+\d+)*[\t ]1$", (proc/"status").read_text(), re.M)):
                return fd
        except (FileNotFoundError, ProcessLookupError, PermissionError):
            pass
        except BaseException:
            os.close(fd)
            raise
        os.close(fd)
    raise ValueError(f"private service manager is unavailable; inspect journalctl -u {OS_UNIT}")


def userspace_service(action):
    settings = read(PRIVATE_OS / "system/boot.json")
    if action == "network-ready":
        # pasta writes its PID after configuring the guest and installing its
        # sandbox. Type=exec alone would mark the helper ready before then.
        expected = str(int(os.environ["MAINPID"]))
        until = time.monotonic() + 25
        while time.monotonic() < until:
            if NET_PID.is_file() and NET_PID.read_text().strip() == expected:
                return
            time.sleep(.1)
        raise ValueError("private network did not become ready; inspect journalctl -u " + NET_UNIT)
    if action == "boot":
        seed_for_boot()
        cmd = portable_program("systemd-nspawn") + [
            "--directory=" + str(PRIVATE_OS / "system/guest"), "--settings=no", "--boot",
            # Attach pasta as soon as init owns the guest namespaces. Guest
            # boot jobs can themselves need the network (off-host backups).
            "--notify-ready=no", "--machine=agentcapsule-paas", "--hostname=" + settings["hostname"],
            "--register=no", "--keep-unit", "--link-journal=no", "--private-users=no",
            "--private-network", "--console=read-only",
            "--resolv-conf=" + ("copy-uplink" if Path("/run/systemd/resolve/resolv.conf").is_file() else "copy-host"),
            # OCI runtimes create a session keyring and query their cgroup device program.
            "--system-call-filter=keyctl bpf", "--capability=CAP_NET_ADMIN,CAP_SYS_PTRACE", "--bind=/dev/kvm", "--bind=/dev/net/tun",
            "--bind=" + str(STATE), "--bind=" + str(ETC) + ":/run/agentcapsule-login"]
        if settings.get("interop_certs"):
            source = settings["interop_certs"].replace("\\","\\\\").replace(":","\\:")
            cmd.append("--bind-ro="+source+":/run/agentcapsule-pki")
        if Path("/dev/userfaultfd").is_char_device():
            cmd.append("--bind=/dev/userfaultfd")
    elif action == "network":
        procfd = container_leader()
        # Open the target while privileged. pasta switches to nobody before
        # opening --netns and cannot traverse another user's /proc/PID.
        try:
            netfd = os.open("ns/net", os.O_RDONLY, dir_fd=procfd)
        finally:
            os.close(procfd)
        os.set_inheritable(netfd, True)
        # Root owns the 0700 runtime directory. Only the inherited fd grants
        # pasta access to this file once it has switched to nobody.
        pidfd = os.open(NET_PID, os.O_CREAT | os.O_RDWR | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        os.fchmod(pidfd, 0o622)
        os.set_inheritable(pidfd, True)
        ports = ",".join(map(str, settings["ports"]))
        cmd = portable_program("pasta") + ["--foreground", "--config-net", "-t", ports,
                 "-t", "127.0.0.1/9445", "-u", "none", "-T", "none", "-U", "none",
                 "--pid", f"/proc/self/fd/{pidfd}", "--netns", f"/proc/self/fd/{netfd}"]
    else:
        raise ValueError("unknown userspace service")
    os.execv(cmd[0],cmd)


def boot_private_os():
    helper = PRIVATE_OS / "launcher.py"
    if not helper.is_file() or helper.read_bytes() != HELPER_SOURCE:
        write_file(helper, HELPER_SOURCE)
    interpreter = "/usr/bin/python3" if Path(sys.executable).resolve() == Path("/usr/bin/python3").resolve() else str(PRIVATE_OS/"python/bin/python3")
    boot = f"""[Unit]
Description=Agent Capsule private Linux userspace
After=local-fs.target network-online.target
Wants=network-online.target {NET_UNIT}
[Service]
Type=notify
NotifyAccess=all
Delegate=yes
TasksMax=infinity
KillMode=mixed
ExecStart={interpreter} -I {helper} --userspace-service boot
Restart=on-failure
RestartSec=5
TimeoutStartSec=180
[Install]
WantedBy=multi-user.target
"""
    network = f"""[Unit]
Description=Agent Capsule private network
After={OS_UNIT} network-online.target
BindsTo={OS_UNIT}
PartOf={OS_UNIT}
[Service]
Type=exec
RuntimeDirectory=agentcapsule-userspace-network
RuntimeDirectoryMode=0700
SecureBits=no-setuid-fixup
NoNewPrivileges=yes
CapabilityBoundingSet=CAP_SYS_ADMIN CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_SETUID CAP_SETGID CAP_SETPCAP CAP_SYS_PTRACE CAP_DAC_READ_SEARCH
ExecStart={interpreter} -I {helper} --userspace-service network
ExecStartPost={interpreter} -I {helper} --userspace-service network-ready
TimeoutStartSec=30
Restart=on-failure
RestartSec=3
"""
    changed = False
    for name, content in [(OS_UNIT,boot),(NET_UNIT,network)]:
        path = UNIT_DIR / name
        if path.exists() and path.read_bytes() != content.encode() and not path.read_text().startswith(
                "[Unit]\nDescription=Agent Capsule private "):
            raise ValueError(f"conflicting host unit: {path}")
        if not path.exists() or path.read_bytes() != content.encode():
            write_file(path,content.encode(),0o644)
            changed = True
    if changed:
        run("systemctl","daemon-reload")
    run("systemctl","enable","--now",OS_UNIT)
    run("systemctl","start",NET_UNIT)


def enter_userspace(argv, version):
    payload = base64.urlsafe_b64encode(json.dumps([version,*argv]).encode()).decode().rstrip("=")
    source = (b"import base64\nHELPER_SOURCE=base64.b64decode('" + base64.b64encode(HELPER_SOURCE)
              + b"')\nexec(compile(HELPER_SOURCE, 'agentcapsule-host', 'exec'))\n")
    with contextlib.ExitStack() as stack:
        leader = container_leader()
        stack.callback(os.close,leader)
        # Early nspawn readiness guarantees the namespace exists. The CLI
        # also needs its service manager's socket, regardless of which
        # application units are still starting inside the guest.
        manager = Path(f"/proc/self/fd/{leader}/root/run/systemd/private")
        deadline = time.monotonic() + 30
        while not manager.is_socket():
            if time.monotonic() >= deadline:
                raise ValueError(f"private systemd socket unavailable; inspect journalctl -u {OS_UNIT}")
            time.sleep(.1)
        fds = []
        def pinned(name):
            fd = os.open(name, os.O_RDONLY, dir_fd=leader)
            stack.callback(os.close,fd)
            fds.append(fd)
            return f"/proc/self/fd/{fd}"
        cmd = ["/usr/bin/nsenter"]
        for arg, ns in (("mount","mnt"),("pid","pid"),("net","net"),("uts","uts"),("ipc","ipc"),("cgroup","cgroup")):
            cmd.append(f"--{arg}="+pinned("ns/"+ns))
        root = pinned("root")
        cmd += ["--root="+root, "--wd="+root, "/usr/bin/python3", "-I", "-", payload, "--inside-userspace"]
        child = subprocess.run(cmd, input=source, pass_fds=fds)
        raise SystemExit(child.returncode if child.returncode >= 0 else 128-child.returncode)


def snapshot_input(src):
    src = Path(src).resolve(strict=True)
    store = STATE / "inputs"
    store.mkdir(mode=0o700, exist_ok=True)
    if not src.is_file() or src.stat().st_size > 64 << 20:
        raise ValueError(f"expected a regular input file of at most 64 MiB: {src}")
    if store in src.parents:
        return str(src)
    with tempfile.TemporaryDirectory(dir=store) as tmp:
        staged = Path(tmp) / "data"
        with staged.open("xb") as f:
            copy_local_file(src, f, 64 << 20)
            os.fchmod(f.fileno(), 0o600)
        target = store / ("file-" + sha(staged))
        if not target.exists():
            os.rename(staged,target)
        return str(target)


def snapshot_offline(src, plan_only):
    # Keep the plan's paths stable when full media are collected on apply.
    # Each artifact is checked again by verify_assets before it is consumed.
    src = Path(src).resolve(strict=True)
    sums = src / "SHA256SUMS"
    if not sums.is_file() or sums.stat().st_size > 8 << 20:
        raise ValueError("invalid offline checksum index")
    target = STATE / "inputs" / ("offline-" + sha(sums))
    target.mkdir(mode=0o700, parents=True, exist_ok=True)
    names = ["agentcapsule-bundle.json", "cosign-linux-amd64", "SHA256SUMS",
             "SHA256SUMS.sigstore.json", "SHA256SUMS.dev.sig"]
    if not plan_only:
        names += [SERVER, DEBS, IMAGES, OS_MEDIA]
    digests = checksums(sums)
    for name in names:
        item = src / name
        if not item.exists():
            continue
        if not item.is_file() or item.stat().st_size > 2 << 30:
            raise ValueError("invalid offline asset: "+name)
        dst = target/name
        if name in digests and dst.is_file() and sha(dst) == digests[name]:
            continue
        limit = (8 << 20) if name == "agentcapsule-bundle.json" or name.startswith("SHA256SUMS") else (2 << 30)
        with tempfile.NamedTemporaryFile(dir=target, delete=False) as f:
            tmp = Path(f.name)
            try:
                copy_local_file(item, f, limit)
                f.flush()
                os.replace(tmp,dst)
            finally:
                tmp.unlink(missing_ok=True)
    return str(target)


def interop_source(args):
    if not getattr(args,"profile",None):
        return None
    path = read(Path(args.profile)).get("interop_certs")
    if not path:
        return None
    root = Path(path).resolve(strict=True)
    for name in ("ca/directory-ca.pem","ca/slim-ca.pem","directory-edge/edge.pem",
                 "control-plane/directory.crt","slim/server.pem","slim-bridge/client.crt"):
        cert = root/name
        if not cert.is_file() or not cert.resolve().is_relative_to(root):
            raise ValueError("expected a dedicated service PKI directory containing "+name)
    return str(root)


def portable_inputs(args, argv, initial=False):
    replacements = {}
    for opt in ("offline","development_key","trusted_root","profile"):
        value = getattr(args,opt,None)
        if not value and not (opt == "profile" and initial):
            continue
        if opt == "profile":
            # Resolve hostname-dependent defaults on the operator's host both
            # for the plan and for apply, even when no profile was supplied.
            profile = normalize_profile(read(Path(value)) if value else {})
            for field in PROFILE_FILES:
                if not profile.get(field):
                    continue
                if field == "interop_certs":
                    profile[field] = "/run/agentcapsule-pki"
                    continue
                if field.endswith("database_url_file"):
                    database_url(profile[field])
                profile[field] = snapshot_input(profile[field])
            path = STATE / "inputs" / ("profile-"+hashlib.sha256(json.dumps(profile,sort_keys=True).encode()).hexdigest()+".json")
            save(path,profile)
            new = str(path)
            if not value:
                argv = [*argv, "--profile", new]
        elif opt == "offline":
            new = snapshot_offline(value, getattr(args,"plan_only",False))
        else:
            new = snapshot_input(value)
        replacements["--"+opt.replace("_","-")] = new
        setattr(args,opt,new)
    result = []
    i = 0
    while i < len(argv):
        key, sep, _ = argv[i].partition("=")
        matches = [name for name in replacements if key.startswith("--") and name.startswith(key)]
        if len(matches) == 1:
            key = matches[0]
        if key in replacements:
            result.extend((key,replacements[key]))
            i += 1 if sep else 2
        else:
            result.append(argv[i])
            i += 1
    return result


def extract_seed(media, seed):
    # The signed filesystem image retains owners, modes, capabilities
    # and symlinks. Extract only inside a fresh, root-owned directory.
    run("tar","--numeric-owner","--xattrs","--xattrs-include=security.capability",
        "-xpf",media,"-C",seed)
    for name in ("usr/bin/systemd-nspawn","usr/bin/pasta","usr/bin/python3","usr/lib/systemd/systemd"):
        if not (seed/name).is_file():
            raise ValueError("incomplete signed userspace: "+name)


def stage_next_seed(args, release):
    media = stage({"version":release,"action":"update","offline":args.offline,
                   "trusted_root":args.trusted_root,"development_key":args.development_key},
                  manifest_only="userspace")
    if media is None:
        return
    digest = sha(media)
    initial = read(PRIVATE_OS / "system/boot.json")["sha256"]
    if digest != initial:
        seeds = PRIVATE_OS / "seeds"
        seeds.mkdir(mode=0o700,exist_ok=True)
        if not (seeds/digest).is_dir():
            with tempfile.TemporaryDirectory(dir=seeds) as tmp:
                seed = Path(tmp)/"seed"
                seed.mkdir()
                extract_seed(media,seed)
                seed.rename(seeds/digest)
    save(PRIVATE_OS/"versions"/release,digest if digest!=initial else None)


def create_private_os(media, profile, version, install_argv, interop_certs):
    system = PRIVATE_OS / "system"
    with tempfile.TemporaryDirectory(dir=PRIVATE_OS) as tmp:
        build = Path(tmp) / "system"
        seed = build / "seed"
        seed.mkdir(parents=True)
        extract_seed(media,seed)
        run("cp","-a","--reflink=auto",seed,build/"guest")
        write_file(build/"guest/etc/agentcapsule-private-userspace", b"1\n", 0o644)
        host = socket.gethostname()
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.\-]{0,63}",host):
            raise ValueError("the host needs a valid Linux hostname")
        # Default API and issuer names resolve inside this private network as
        # they did on the host. Custom DNS records remain the operator's choice.
        with (build/"guest/etc/hosts").open("a") as hosts:
            hosts.write(f"\n127.0.1.1 {host} {socket.getfqdn()}\n")
        save(build/"boot.json",{"hostname":host,"install_argv":install_argv,"interop_certs":interop_certs, "ports":[profile["api_port"],profile["oidc_port"]],
                                "bootstrap_version":version, "sha256":sha(media)})
        run("sync","-f",build)
        build.rename(system)
        parent = os.open(PRIVATE_OS, os.O_DIRECTORY)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
        save(PRIVATE_OS/"versions"/version,None)


def native_install_pending():
    # A pre-portability helper can already have started installing host packages
    # before /opt/agentcapsule becomes active. Resume in its original layout.
    for filename in OPERATIONS.glob("host_*/status.json"):
        record = read(filename)
        if (record.get("action") == "install" and "userspace_sha256" not in record and
                record.get("state") in ("queued", "running", "failed")):
            return True
    return False


def portable_command(args, argv, version):
    system = PRIVATE_OS / "system"
    if args.command == "host" and args.group == "operation" and args.sub in ("show", "wait"):
        return False,None
    if not system.is_dir() and (args.command != "install" or ACTIVE.exists() or native_install_pending()):
        return False,None
    if os.geteuid() != 0:
        raise ValueError("local host operation requires root; run with sudo")
    if getattr(args,"offline",None) and not getattr(args,"to",None) and (
            args.command != "install" or not re.fullmatch(VERSION, version)):
        raise ValueError("--offline requires an explicit release tag")
    follow = getattr(args,"follow_install",False)
    if not system.is_dir():
        if follow:
            print("Checking KVM, systemd, cgroups and persistent storage.", file=sys.stderr, flush=True)
        portable_host_preflight(PRIVATE_OS)
    STATE.mkdir(mode=0o700,exist_ok=True)
    PRIVATE_OS.mkdir(mode=0o700,exist_ok=True)
    with (PRIVATE_OS/"bootstrap.lock").open("a+b") as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        if not system.is_dir():
            release = args.to or (version if re.fullmatch(VERSION,version) else latest())
            if not re.fullmatch(VERSION,release):
                raise ValueError("invalid release tag")
            if re.fullmatch(VERSION,version) and version_order(release)<version_order(version) and not args.allow_older:
                raise ValueError("older release requires --allow-older")
            request = {"version":release,"action":"install","offline":args.offline,
                       "trusted_root":args.trusted_root,"development_key":args.development_key}
            request["allow_older"] = args.allow_older
            validate_release_floor(request)
            details = stage(request, manifest_only=True)
            if not details.get("userspace_sha256"):
                distro = platform.freedesktop_os_release()
                if (distro.get("ID"),distro.get("VERSION_ID")) != ("ubuntu","24.04"):
                    raise ValueError(f"{release} contains only the Ubuntu 24.04 server bundle; select a release with the portable Linux userspace")
                return False,None
            pki = interop_source(args)
            argv = portable_inputs(args,argv,initial=True)
            # Pin latest to the version just verified across the second stage.
            if not args.to:
                argv += ["--to",release]
            if args.plan_only:
                return True,main(argv,version,planned_portable=True)
            profile = normalize_profile(read(Path(args.profile)) if args.profile else {})
            if follow:
                print(f"Preparing the signed Linux userspace for {release}.", file=sys.stderr, flush=True)
            media = stage(request, manifest_only="userspace")
            create_private_os(media,profile,release,[v for v in argv if v!="--follow-install"], pki)
        else:
            if argv == ["install","--follow-install"] and not (STATE/"profile.json").is_file():
                argv = read(system/"boot.json")["install_argv"] + ["--follow-install"]
            else:
                pki = interop_source(args)
                if pki and pki != read(system/"boot.json").get("interop_certs"):
                    raise ValueError("use the installed host profile's service PKI directory")
                argv = portable_inputs(args,argv)
                if args.command == "update" and args.sub == "plan":
                    target = args.to or latest()
                    if not re.fullmatch(VERSION,target):
                        raise ValueError("invalid release tag")
                    stage_next_seed(args,target)
                    if not args.to:
                        argv += ["--to",target]
        if not ETC.is_dir():
            ETC.mkdir(mode=0o755)
            ETC.chmod(0o755)
        if follow:
            print("Starting the private service manager and network.", file=sys.stderr, flush=True)
        boot_private_os()
    enter_userspace(argv,version)
