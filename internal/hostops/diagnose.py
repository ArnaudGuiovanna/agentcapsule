# Embedded in the Linux host helper alongside setup.py and host.py.
import datetime
import http.client
import json
from pathlib import Path
import re

DIAG_SERVICES = ("api", "worker", "authority", "interop", "slim-bridge", "oidc")
METRIC_PORTS = {"api": 9464, "worker": 9465, "authority": 9466}


def add_diagnostics(host):
    group = host.add_parser("diagnose").add_subparsers(dest="sub", required=True)
    p = group.add_parser("metrics")
    p.add_argument("--service", choices=METRIC_PORTS, required=True)
    p = group.add_parser("journal")
    p.add_argument("--service", choices=DIAG_SERVICES, required=True)
    p.add_argument("--limit", type=int, default=50)
    p.add_argument("--request-id")
    group.add_parser("alerts")
    group.add_parser("backups")
    group.add_parser("images")
    p = group.add_parser("llm")
    p.add_argument("--organization", required=True)
    p.add_argument("--alias", required=True)


def service_observations():
    result = []
    for name in DIAG_SERVICES:
        properties = output("systemctl", "show", "agentcapsule-" + name + ".service",
                            "-p", "ActiveState", "-p", "SubState", "-p", "LoadState",
                            "-p", "StateChangeTimestamp", timeout=10)
        entry = {"service": name}
        entry.update(line.split("=", 1) for line in properties.splitlines() if "=" in line)
        if entry.get("LoadState") == "not-found" and name == "oidc":
            continue
        if entry.get("ActiveState") != "active":
            entry["next_check"] = "inspect_service_journal"
        result.append(entry)
    return result


def runtime_image(image, directory):
    engine, service = image["engine"], image["service"]
    expected = "sha256:" + image["config_id"].removeprefix("sha256:")
    if not re.fullmatch("sha256:[a-f0-9]{64}", expected):
        raise ValueError("invalid release image configuration")
    result = dict(service=service, engine=engine, reference=image["ref"], expected_config_id=expected)
    if engine == "docker":
        filters = ["--filter", "label=com.docker.compose.project=agentcapsule-interop",
                   "--filter", "label=com.docker.compose.service=" + service]
    elif engine == "podman" and service == "oidc":
        filters = ["--filter", "name=^agentcapsule-oidc$"]
    else:
        raise ValueError("unsupported service image engine")
    ids = output(engine, "ps", "--all", "--no-trunc", "--quiet", *filters).split()
    if len(ids) != 1:
        return dict(result, verified=False, reason="container_count", container_count=len(ids))
    ident = ids[0]
    if not re.fullmatch("[a-f0-9]{64}", ident):
        raise ValueError("invalid container identity")
    # Inspect only public identity and lifecycle fields. The full inspection
    # also carries the service environment and credentials.
    image_id, state, exit_code = output(engine, "container", "inspect", "--format",
                                        "{{.Image}} {{.State.Status}} {{.State.ExitCode}}", ident).split()
    actual = "sha256:" + image_id.removeprefix("sha256:")
    if not re.fullmatch("sha256:[a-f0-9]{64}", actual):
        raise ValueError("invalid container image identity")
    result.update(container_id=ident, image_id=actual, state=state, exit_code=int(exit_code))
    healthy = (state == "exited" and exit_code == "0") if service == "init" else state == "running"
    if not healthy:
        return dict(result, verified=False, reason="container_state")
    if actual == expected:
        return dict(result, verified=True, method="container_config_id")
    # Docker's containerd store reports the manifest ID. Export precisely
    # the image attached to the container, including when its tag has moved.
    if engine == "docker" and saved_config(actual, expected.removeprefix("sha256:"), directory):
        return dict(result, verified=True, method="container_image_export")
    return dict(result, verified=False, reason="configuration_mismatch")


def runtime_images():
    # Resolve the activation symlink once to keep the inventory and its
    # release identity together if a concurrent upgrade switches releases.
    release = ACTIVE.resolve(strict=True)
    manifest = (release / "bundle.json").read_bytes()
    bundle = json.loads(manifest)
    version = bundle["version"]
    if not re.fullmatch(VERSION, version) or release != (RELEASES / version).resolve(strict=True):
        raise ValueError("active directory differs from its release version")
    dist = STATE / "downloads" / version
    signed = checksums(dist / "SHA256SUMS", (dist / "verified-manifest.sha256").read_text())
    if signed.get("agentcapsule-bundle.json") != hashlib.sha256(manifest).hexdigest():
        raise ValueError("installed manifest differs from the signed release")
    index = release / "offline-images.json"
    index_data = index.read_bytes()
    if hashlib.sha256(index_data).hexdigest() != bundle["sha256"].get(index.name):
        raise ValueError("installed image inventory differs from the release manifest")
    inventory = json.loads(index_data)
    services = {"init", "oasf", "directory", "directory-edge", "slim"}
    if "oidc/agentcapsule-oidc.service" in bundle["sha256"]:
        services.add("oidc")
    if len(inventory) != len(services) or {image["service"] for image in inventory} != services:
        raise ValueError("incomplete or duplicate service image inventory")
    with tempfile.TemporaryDirectory(dir=STATE) as tmp:
        images = [runtime_image(image, Path(tmp)) for image in inventory]
    if ACTIVE.resolve(strict=True) != release:
        raise ValueError("active release changed during image verification")
    return dict(installed=bundle["version"], verified=all(image["verified"] for image in images), images=images)


def diagnose(args):
    report = {"schema": "agentcapsule.host/v1", "observed_at": datetime.datetime.now(datetime.timezone.utc).isoformat()}
    if args.sub == "alerts":
        report["boot_id"] = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        report["services"] = service_observations()
    elif args.sub == "images":
        report.update(runtime_images())
    elif args.sub == "metrics":
        conn = http.client.HTTPConnection("127.0.0.1", METRIC_PORTS[args.service], timeout=5)
        try:
            conn.request("GET", "/metrics")
            response = conn.getresponse()
            raw = response.read(4 * 1024 * 1024 + 1)
            if response.status != 200 or len(raw) > 4 * 1024 * 1024:
                raise ValueError("invalid metrics response")
            report["service"] = args.service
            report["samples"] = [s for s in raw.decode().splitlines() if s.startswith("agentcapsule_")]
        finally:
            conn.close()
    elif args.sub == "journal":
        if not 1 <= args.limit <= 500 or args.request_id and not re.fullmatch("[0-9a-f]{32}", args.request_id):
            raise ValueError("invalid journal filter")
        lines = output("journalctl", "-q", "--no-pager", "-u", "agentcapsule-" + args.service + ".service",
                       "--output=json", "--output-fields=MESSAGE,__REALTIME_TIMESTAMP", "-n", "2000", timeout=10)
        events = []
        for line in lines.splitlines():
            row = json.loads(line)
            try:
                msg = json.loads(row.get("MESSAGE", ""))
            except (TypeError, ValueError):
                continue
            if not isinstance(msg, dict) or not isinstance(msg.get("event"), str):
                continue
            if args.request_id and msg.get("request_id") != args.request_id:
                continue
            if not re.fullmatch("[a-z][a-z_0-9]{0,80}", msg["event"]):
                continue
            event = {"timestamp_us": row.get("__REALTIME_TIMESTAMP"), "event": msg["event"]}
            if re.fullmatch("[0-9a-f]{32}", str(msg.get("request_id", ""))):
                event["request_id"] = msg["request_id"]
            events.append(event)
        report.update(service=args.service, events=events[-args.limit:], scanned_window=2000)
    elif args.sub == "backups":
        raw = run_user("postgres", "pgbackrest", "--stanza=agentcapsule", "--output=json", "info", capture=True)
        report["repositories"] = []
        for stanza in json.loads(raw):
            for repo in stanza.get("repo", []):
                backups = [b for b in stanza.get("backup", []) if b["database"]["repo-key"] == repo["key"] and not b.get("error")]
                report["repositories"].append(dict(repository=repo["key"], status=repo["status"]["code"],
                                                   latest_success=max((b["timestamp"]["stop"] for b in backups), default=None)))
    elif args.sub == "llm":
        if not re.fullmatch(r"org_[0-9a-f]{32}", args.organization) or not 1 <= len(args.alias) <= 100:
            raise ValueError("invalid organization or alias")
        raw = output(ACTIVE / "agentcapsule-worker", "-config", ETC / "worker.json",
                     "-probe-organization", args.organization, "-probe-llm-alias", args.alias,
                     env=db_env(read(STATE / "profile.json")), timeout=20)
        report["provider"] = json.loads(raw)
    return report
