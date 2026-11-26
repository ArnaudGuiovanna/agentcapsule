# Optional Pi and corpus support, using the catalog in the verified host bundle.
PI_REPOSITORY = "ghcr.io/arnaudguiovanna/agentcapsule/runtime"
PI_PACKAGES = ("pi-agent", "agentcapsule-corpus-builder")


def pi_worker_settings(cfg, catalog, keypath, repository):
    if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9._-]{0,99}/[A-Za-z0-9_][A-Za-z0-9._-]{0,99}", repository) or repository.lower().endswith(".git"):
        raise ValueError("provide one GitHub OWNER/REPOSITORY for --corpus-repo")
    version = catalog["release"]
    packages = catalog["packages"]
    if (catalog["schema"] != "agentcapsule.pi/v1" or not re.fullmatch(VERSION, version)
            or set(packages) != set(PI_PACKAGES) or len(set(packages.values())) != len(PI_PACKAGES)):
        raise ValueError("invalid Pi release catalog")
    if cfg.get("registry") is None:
        cfg["registry"] = {"inspection_uid": 61999, "rules": []}
    pins = cfg["registry"].setdefault("release_packages", {})
    for ref in packages.values():
        if not re.fullmatch(re.escape(PI_REPOSITORY) + r"@sha256:[a-f0-9]{64}", ref):
            raise ValueError("invalid Pi package reference")
        pins[ref] = str(keypath)
    if cfg.get("corpus") is None:
        cfg["corpus"] = {"max_image_mib": 1024}
    corpus = cfg["corpus"]
    rules = corpus.setdefault("sources", {}).setdefault("rules", [])
    rule = next((r for r in rules if r["host"] == "github.com"), None)
    if rule is None:
        rule = {"kind":"github", "host":"github.com", "repositories":[], "archive_hosts":["codeload.github.com"]}
        rules.append(rule)
    if rule["kind"] != "github" or rule.get("api_host", "api.github.com") != "api.github.com" or rule.get("local"):
        raise ValueError("the existing github.com source rule is incompatible with the public GitHub service")
    if "codeload.github.com" not in rule.setdefault("archive_hosts", []):
        rule["archive_hosts"].append("codeload.github.com")
    repos = [r.lower() for r in rule["repositories"]]
    if not any(repository.lower() == r or (r.endswith("/") and repository.lower().startswith(r)) for r in repos):
        if len(repos) >= 100:
            raise ValueError("the github.com source rule already contains 100 repository entries")
        rule["repositories"].append(repository)
    if corpus.get("builder") is None:
        corpus["builder"] = {"vcpus": 1, "memory_mib": 2048, "volume_mib": 512}
    builder = corpus["builder"]
    harness = builder.get("harness") or {}
    if harness.get("name", PI_PACKAGES[1]) == PI_PACKAGES[1]:
        builder["harness"] = {"name":PI_PACKAGES[1], "version":version[1:]}
    return builder["harness"]


def enable_pi(repository):
    with (STATE / "operation.lock").open("a+b") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if (STATE/"maintenance").exists():
            raise ValueError("finish the host maintenance operation before enabling Pi")
        dist = ACTIVE.resolve(strict=True)
        bundle = read(dist/"bundle.json")
        file = dist/"config/pi-catalog.json"
        if not file.is_file() or bundle["sha256"].get("config/pi-catalog.json") != sha(file):
            raise ValueError("the installed release needs a signed Pi catalog")
        catalog = read(file)
        if catalog["release"] != bundle["version"]:
            raise ValueError("the Pi catalog is for a different version")
        pem = catalog["publisher_key"].encode("ascii")
        if not re.fullmatch(rb"-----BEGIN PUBLIC KEY-----\n[A-Za-z0-9+/=\n]+\n-----END PUBLIC KEY-----\n", pem) or len(pem) > 16384:
            raise ValueError("invalid publisher key in Pi catalog")
        der = base64.b64decode(b"".join(pem.splitlines()[1:-1]), validate=True)
        signer = "sha256:" + hashlib.sha256(der).hexdigest()
        keypath = ETC/("pi-publisher-" + hashlib.sha256(pem).hexdigest() + ".pub")
        cfgpath = ETC/"worker.json"
        old = cfgpath.read_bytes()
        cfg = json.loads(old)
        builder = pi_worker_settings(cfg, catalog, keypath, repository)
        image = {"reference":"pi-linux@" + catalog["release"][1:],
                 "kernel_digest":"sha256:" + cfg["kernel"]["sha256"],
                 "initrd_digest":"sha256:" + cfg["initrd"]["sha256"], "features":["corpus.mount"]}
        if not keypath.exists() or keypath.read_bytes() != pem:
            write_file(keypath, pem, 0o644)
        if json.loads(old) != cfg:
            new = (json.dumps(cfg, sort_keys=True, indent=2) + "\n").encode()
        else:
            new = old
        st = cfgpath.stat()
        stamp = STATE/"pi-worker-settings.json"
        digest = hashlib.sha256(new).hexdigest()
        if old != new or not stamp.exists() or read(stamp) != digest:
            def replace(raw):
                write_file(cfgpath, raw, stat.S_IMODE(st.st_mode), owner=(st.st_uid,st.st_gid))
            if old != new:
                replace(new)
            try:
                run("systemctl", "restart", "agentcapsule-worker.service")
                run("systemctl", "is-active", "--quiet", "agentcapsule-worker.service")
                save(stamp, digest)
            except Exception:
                if old != new:
                    replace(old)
                    run("systemctl", "restart", "agentcapsule-worker.service")
                raise
        return {"schema":"agentcapsule.pi-host/v1","release":catalog["release"],"packages":catalog["packages"],
                "system_image":image, "signer":signer, "builder":builder, "corpus_repository":repository}
