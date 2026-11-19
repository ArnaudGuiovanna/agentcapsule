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


def diagnose(args):
    report = {"schema": "agentcapsule.host/v1", "observed_at": datetime.datetime.now(datetime.timezone.utc).isoformat()}
    if args.sub == "alerts":
        report["boot_id"] = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        report["services"] = service_observations()
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
