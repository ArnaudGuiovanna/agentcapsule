"""Verify stop/restart ownership against Podman's full immutable IDs."""
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SOURCE=Path(__file__).resolve().parents[1]/"deploy/oidc/container.py"
spec=importlib.util.spec_from_file_location("oidc_lifecycle",SOURCE)
oidc=importlib.util.module_from_spec(spec)
spec.loader.exec_module(oidc)


class LifecycleTest(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.record=Path(self.temp.name)/"container-id"
        self.ident="e"*64
        patched=patch.object(oidc,"CID",self.record)
        patched.start()
        self.addCleanup(patched.stop)
        self.commands=[]
        self.events=""
        self.exists=True
        def command(args,check=False,**kwargs):
            args=list(args)
            self.commands.append(args)
            if args[0]=="journalctl":
                result=subprocess.CompletedProcess(args,0,self.events,"")
            elif args[1:3]==["container","inspect"]:
                result=subprocess.CompletedProcess(args,0,self.ident+"\n","")
            elif args[1:3]==["container","exists"]:
                result=subprocess.CompletedProcess(args,0 if self.exists else 1)
            else:
                if args[1]=="rm":
                    self.exists=False
                result=subprocess.CompletedProcess(args,0,"","")
            if check: result.check_returncode()
            return result
        patched=patch.object(oidc.subprocess,"run",side_effect=command)
        patched.start()
        self.addCleanup(patched.stop)

    def test_stop_and_cleanup_recorded_id(self):
        self.record.write_text(self.ident+"\n")
        oidc.lifecycle("stop")
        oidc.lifecycle("cleanup")
        self.assertIn([oidc.PODMAN,"stop","--ignore","--time","30",self.ident],self.commands)
        self.assertIn([oidc.PODMAN,"rm","--ignore","--force","--time","30",self.ident],self.commands)
        self.assertFalse(self.record.exists())

    def test_stale_private_id_on_restart(self):
        self.exists=False
        self.record.write_text(self.ident)
        oidc.lifecycle("prepare")
        self.assertFalse(self.record.exists())
        self.assertFalse(any(c[1] in ("stop","rm") for c in self.commands))

    def test_legacy_container_needs_podmans_creation_event_from_this_unit(self):
        import json
        self.events=json.dumps({"_EXE":oidc.PODMAN,"_SYSTEMD_UNIT":oidc.UNIT,"PODMAN_TYPE":"container","PODMAN_EVENT":"create","PODMAN_ID":self.ident})
        oidc.lifecycle("prepare")
        self.assertFalse(self.exists)
        self.assertTrue(any("_EXE=/usr/bin/podman" in c and "_SYSTEMD_UNIT="+oidc.UNIT in c for c in self.commands))

    def test_unrelated_container_occupant_survives_every_operation(self):
        import json
        self.record.write_text("f"*64)
        self.events=json.dumps({"_EXE":oidc.PODMAN,"_SYSTEMD_UNIT":"other.service","PODMAN_TYPE":"container","PODMAN_EVENT":"create","PODMAN_ID":self.ident})
        for action in ("prepare","stop","cleanup"):
            with self.assertRaisesRegex(ValueError,"unrecognized container"):
                oidc.lifecycle(action)
        self.assertTrue(self.exists)
        self.assertFalse(any(c[1] in ("stop","rm") for c in self.commands))
