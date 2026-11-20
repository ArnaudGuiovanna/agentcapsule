"""Systemd stop and cleanup for the single AgentCapsule Podman container."""
import json
from pathlib import Path
import re
import subprocess
import sys

NAME = "agentcapsule-oidc"
UNIT = NAME + ".service"
CID = Path("/var/lib/agentcapsule-oidc/container-id")
PODMAN = "/usr/bin/podman"


def run(*args, **kwargs):
    return subprocess.run(args, check=True, text=True, **kwargs)


def created_by_unit(ident):
    # An existing installation predates the private cidfile. Podman's
    # structured creation record must originate inside this specific unit.
    fields = {
        "_EXE": PODMAN, "_SYSTEMD_UNIT": UNIT, "PODMAN_TYPE": "container",
        "PODMAN_EVENT": "create", "PODMAN_ID": ident,
    }
    journal = run("journalctl", "--no-pager", "-n", "1", "-o", "json",
                  "--output-fields=" + ",".join(fields),
                  *(f"{key}={value}" for key, value in fields.items()),
                  capture_output=True).stdout.strip()
    if not journal:
        return False
    record = json.loads(journal)
    return all(record.get(key) == value for key, value in fields.items())


def occupant():
    result = subprocess.run([PODMAN,"container","exists",NAME])
    if result.returncode == 1:
        return None
    result.check_returncode()
    ident = run(PODMAN, "container", "inspect", "--format", "{{.Id}}", NAME, capture_output=True).stdout.strip()
    if not re.fullmatch("[0-9a-f]{64}",ident):
        raise ValueError("invalid container ID")
    recorded = CID.read_text().strip() if CID.is_file() else ""
    if ident != recorded and not created_by_unit(ident):
        raise ValueError("OIDC container name belongs to an unrecognized container")
    return ident


def lifecycle(action):
    if action not in ("prepare", "stop", "cleanup"):
        raise ValueError("unknown OIDC lifecycle operation")
    ident = occupant()
    if ident and action == "stop":
        run(PODMAN, "stop", "--ignore", "--time", "30", ident)
    elif ident:
        # A --rm container can disappear between inspect and removal. By
        # using only its full ID a newly created namesake is never targeted.
        run(PODMAN, "rm", "--ignore", "--force", "--time", "30", ident)
    if action != "stop":
        CID.unlink(missing_ok=True)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("one OIDC lifecycle action is required")
    try:
        lifecycle(sys.argv[1])
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        sys.exit(str(error))
