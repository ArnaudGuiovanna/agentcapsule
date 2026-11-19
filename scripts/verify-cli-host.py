#!/usr/bin/env python3
"""Qualify two signed builds and a volume restore on a dedicated KVM instance.

The CLI and report live on this station. Asset directories, profile and trust
paths belong to the target. Use the WSL namespace or SSH to a test host.
The supplied restart command must restart only that dedicated instance.
"""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import time
import uuid


def verify_reboot(command, before, diagnostics, required_services=()):
    subprocess.run(command, timeout=300, check=True)
    deadline = time.monotonic() + 300
    while time.monotonic() < deadline:
        try:
            health = diagnostics()
            after = uuid.UUID(health["boot_id"])
            active = {s["service"] for s in health["services"] if s.get("ActiveState") == "active"}
            if before != after and active.issuperset(required_services):
                return {"boot_before": str(before), "boot_after": str(after)}
        except (subprocess.CalledProcessError, ValueError):
            pass
        time.sleep(2)
    raise ValueError("target did not report a new boot with the required services")


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--cli",nargs="+",required=True,help="CLI command or wrapper that enters the target namespace")
    p.add_argument("--ssh")
    p.add_argument("--profile",required=True,help="host profile with verified backup repositories")
    p.add_argument("--offline",required=True)
    p.add_argument("--upgrade-offline",required=True)
    p.add_argument("--version",required=True)
    p.add_argument("--upgrade-version",required=True)
    p.add_argument("--restart-command",nargs="+",required=True,help="argv for explicitly restarting the dedicated test instance")
    p.add_argument("--development-key")
    p.add_argument("--trusted-root")
    p.add_argument("--output",type=Path,required=True)
    a=p.parse_args()
    if a.version==a.upgrade_version:
        p.error("the upgrade requires two different builds")
    if a.output.exists():
        p.error("--output must be new")
    report={"schema":"agentcapsule.qualification/v1","steps":[],"status":"running","versions":[a.version,a.upgrade_version]}
    def save():
        tmp=a.output.with_name("."+a.output.name+".tmp")
        tmp.write_text(json.dumps(report,indent=2)+"\n")
        os.replace(tmp,a.output)
    def call(cmd,args):
        argv=[*a.cli,*cmd,*args]
        if a.ssh:
            argv+=["--ssh",a.ssh]
        result=subprocess.run(argv,stdout=subprocess.PIPE,text=True,timeout=8*3600,check=True)
        data=json.loads(result.stdout)
        if data.get("schema")!="agentcapsule.host/v1":
            raise ValueError("invalid host response")
        return data
    def record(name,data):
        # Keep only operation state and public IDs, never the host's profile.
        step=dict(name=name,**{k:v for k,v in data.items() if k in {
            "state","phase","operation_id","completed","target","installed","services_started","invocation_verified",
            "off_host_backup_verified","volume_shipping_verified","database_backups_verified","backup_status","probe_agent","probe_invocation","reason",
            "boot_before","boot_after"}})
        if "storage_result" in data:
            step["storage_result"]={k:v for k,v in data["storage_result"].items() if k in {
                "id","size","agent_id","restore_id","archive_id","archive_store","archive_incarnation","incarnation","checked","losses",
                "digest","harness_digest"}}
        report["steps"].append(step)
        save()
    def diagnostics():
        return call(["host", "diagnose", "alerts"], [])
    def wait(data):
        try:
            result=call(["host","operation","wait"],[data["operation_id"]])
        except subprocess.CalledProcessError:
            record("failed-operation",call(["host","operation","show"],[data["operation_id"]]))
            raise
        if result["state"]!="succeeded":
            raise ValueError("operation did not succeed")
        return result
    trust=(["--development-key",a.development_key] if a.development_key else
           ["--trusted-root",a.trusted_root] if a.trusted_root else [])
    install=["--offline",a.offline,"--profile",a.profile,"--to",a.version,*trust]
    save()
    try:
        plan=call(["install"],["--plan-only",*install])
        record("install-plan",plan)
        install_boot = uuid.UUID(diagnostics()["boot_id"])
        started=call(["install"],install)
        if plan["operation_id"]!=started["operation_id"]:
            raise ValueError("plan and install operation mismatch")
        record("submitted",started)
        # Capture a real completed checkpoint before restart. A subsequent
        # show must expose the same durable request and completed phases.
        deadline=time.monotonic()+900
        while time.monotonic()<deadline:
            before=call(["host","operation","show"],[started["operation_id"]])
            if before["state"]=="failed":
                raise ValueError("installation failed before interruption")
            if before["completed"]:
                break
            time.sleep(1)
        if not before["completed"] or before["state"]=="succeeded":
            raise ValueError("installation did not reach an interruptible checkpoint")
        record("before-restart",before)
        record("installation reboot", verify_reboot(a.restart_command, install_boot, diagnostics))
        for i in range(120):
            try:
                after=call(["host","operation","show"],[started["operation_id"]])
                break
            except (subprocess.CalledProcessError,ValueError):
                if i==119: raise
                time.sleep(2)
        if not set(before["completed"]).issubset(after["completed"]):
            raise ValueError("checkpoints were lost across restart")
        installed=wait(started)
        record("installed",installed)
        if not installed["services_started"] or not installed["invocation_verified"]:
            raise ValueError("installation did not start services and return the starter echo")
        update=call(["update","plan"],["--offline",a.upgrade_offline,"--profile",a.profile,"--to",a.upgrade_version,*trust])
        if update.get("installed")!=a.version or update.get("target")!=a.upgrade_version:
            raise ValueError("update plan did not select the installed and candidate builds")
        record("update-plan",update)
        upgraded=wait(call(["update","apply"],["--plan",update["operation_id"]]))
        record("upgraded",upgraded)
        if (not upgraded["invocation_verified"] or upgraded["probe_agent"]!=installed["probe_agent"]
                or upgraded["probe_invocation"]==installed["probe_invocation"]):
            raise ValueError("starter agent identity or invocation changed unexpectedly")
        if not a.development_key and not upgraded["off_host_backup_verified"]:
            raise ValueError("release qualification needs verified off-host backups")
        agent=upgraded["probe_agent"]
        if not re.fullmatch("agt_[a-f0-9]{32}",agent):
            raise ValueError("invalid starter agent")
        upgrade_boot = uuid.UUID(diagnostics()["boot_id"])
        record("upgraded reboot", verify_reboot(a.restart_command, upgrade_boot, diagnostics, ("api", "worker", "authority")))
        archive_id="arc_"+uuid.uuid4().hex
        restore_id="rst_"+uuid.uuid4().hex
        archive=["--agent",agent,"--archive-id",archive_id]
        captured=wait(call(["archive"],archive))
        record("archive",captured)
        if captured["storage_result"]["id"]!=archive_id or captured["storage_result"]["size"]<=0:
            raise ValueError("capture receipt does not identify the requested archive")
        tested=wait(call(["restore","test"],archive))
        record("restore test",tested)
        test=tested["storage_result"]
        if (test["agent_id"] != agent or test["archive_id"] != archive_id or
                test["size"] != captured["storage_result"]["size"] or
                not {"manifest", "digest", "volume", "copy", "key"}.issubset(test["checked"])):
            raise ValueError("restore test did not verify the requested agent and full archive")
        applied=wait(call(["restore","apply"],[*archive,"--restore-id",restore_id,"--verify-starter"]))
        record("restore apply",applied)
        receipt=applied["storage_result"]
        if (receipt["restore_id"]!=restore_id or receipt["archive_id"]!=archive_id or receipt["losses"] != 0
                or receipt["agent_id"]!=agent or receipt["incarnation"]<=test["incarnation"]):
            raise ValueError("restore receipt does not confirm a loss-free new incarnation of the starter")
        if (not applied["invocation_verified"] or applied["probe_agent"] != agent or
                applied["probe_invocation"] in (installed["probe_invocation"], upgraded["probe_invocation"])):
            raise ValueError("restored installation agent did not return a new echo")
        report["status"]="passed"
    finally:
        if report["status"]=="running":
            report["status"]="failed"
        save()


if __name__=="__main__":
    main()
