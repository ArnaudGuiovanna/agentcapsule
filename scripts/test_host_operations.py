"""Exercise the embedded Linux helper with real signatures and archives."""
import hashlib
import io
import json
from pathlib import Path
import runpy
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
HELPERS=ROOT/"internal/hostops"


class HostOperationTests(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root=Path(temporary.name)
        self.api={"__name__":"host_test"}
        for file in ("setup.py","diagnose.py","host.py"):
            exec(compile((HELPERS/file).read_bytes(),file,"exec"),self.api)
        self.state=self.root/"state"
        self.state.mkdir()
        self.api.update(STATE=self.state,ACTIVE=self.root/"active",RELEASES=self.root/"releases",OPERATIONS=self.state/"operations")
        self.assets=self.root/"offline"
        self.assets.mkdir()
        self.version="v0.1.0-dev.1"
        self.key=self.root/"dev.key"
        self.public=self.root/"dev.pub"
        self.request=dict(offline=str(self.assets),version=self.version,development_key=str(self.public))
        subprocess.run(["openssl","genpkey","-algorithm","ed25519","-out",self.key],check=True)
        subprocess.run(["openssl","pkey","-pubout","-in",self.key,"-out",self.public],check=True)
        for name in ("SERVER","DEBS","IMAGES"):
            (self.assets/self.api[name]).write_bytes(b"sample")
        self.bundle=dict(schema="agentcapsule.bundle/v1",version=self.version,platform="ubuntu-24.04-amd64",migrations=["0002.sql"],commit="sample")
        self.sign()

    def sign(self):
        manifest=self.assets/"agentcapsule-bundle.json"
        manifest.write_text(json.dumps(self.bundle))
        files=[p for p in self.assets.iterdir() if not p.name.startswith("SHA256SUMS")]
        sums=self.assets/"SHA256SUMS"
        sums.write_text("".join(hashlib.sha256(p.read_bytes()).hexdigest()+"  "+p.name+"\n" for p in sorted(files)))
        subprocess.run(["openssl","pkeyutl","-sign","-inkey",self.key,"-rawin","-in",sums,"-out",self.assets/"SHA256SUMS.dev.sig"],check=True)

    def test_plan_verifies_before_fetching_large_archives(self):
        plan=self.api["stage"](self.request,True)
        self.assertEqual(plan["added_migrations"],["0002.sql"])
        self.assertFalse((self.state/"downloads"/self.version/self.api["SERVER"]).exists())
        self.api["stage"](self.request)
        self.assertTrue((self.state/"downloads"/self.version/self.api["SERVER"]).is_file())

    def test_changed_payload_refused_before_activation(self):
        (self.assets/self.api["SERVER"]).write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError,"digest mismatch"):
            self.api["stage"](self.request)
        self.assertFalse(self.api["ACTIVE"].exists())

    def test_invalid_signature_refused_and_tag_immutable(self):
        sig=self.assets/"SHA256SUMS.dev.sig"
        sig.write_bytes(b"x"*64)
        with self.assertRaises(subprocess.CalledProcessError):
            self.api["stage"](self.request,True)
        self.sign()
        self.api["stage"](self.request,True)
        self.bundle["commit"]="retagged"
        self.sign()
        with self.assertRaisesRegex(ValueError,"tag changed"):
            self.api["stage"](self.request,True)

    def test_reject_binary_downgrade_after_migration(self):
        self.api["stage"](self.request,True)
        self.api["ACTIVE"].mkdir()
        (self.api["ACTIVE"]/"bundle.json").write_text(json.dumps(dict(version="v0.1.0-dev.2",migrations=["0002.sql","0003.sql"])))
        with self.assertRaisesRegex(ValueError,"restore"):
            self.api["stage"](self.request,True)

    def test_reject_archive_traversal_and_links(self):
        for i,(name,kind) in enumerate((("../outside",tarfile.REGTYPE),("/root/a",tarfile.REGTYPE),("link",tarfile.SYMTYPE))):
            archive=self.root/f"bad{i}.tar"
            with tarfile.open(archive,"w") as tar:
                info=tarfile.TarInfo(name)
                info.type=kind
                info.linkname="../outside" if kind==tarfile.SYMTYPE else ""
                tar.addfile(info,io.BytesIO(b""))
            with self.assertRaisesRegex(ValueError,"archive entry"):
                self.api["unpack"](archive,self.root/f"extraction{i}")

    def test_backup_configuration_traversable_under_installer_umask(self):
        from unittest.mock import Mock
        src=self.root/"config"
        src.write_bytes(b"[global]\n")
        target=self.root/"pgbackrest"
        target.mkdir(mode=0o700)
        with patch("subprocess.run",return_value=Mock(returncode=1)), patch("os.chown") as chown, patch("pwd.getpwnam",return_value=Mock(pw_uid=31,pw_gid=32)):
            self.api["run_user"]=Mock()
            self.api["install_backup_config"](src,target)
            self.assertEqual(target.stat().st_mode&0o777,0o750)
            self.assertEqual((target/"pgbackrest.conf").stat().st_mode&0o777,0o600)
            chown.assert_any_call(target,0,32)
            self.api["run_user"].assert_called_once_with("postgres","test","-r",target/"pgbackrest.conf")

    def test_restore_restarts_the_worker_even_after_failure(self):
        from unittest.mock import Mock
        for previously_active in (True,False):
            marker=self.root/("worker-"+str(previously_active))
            running=Mock(returncode=0 if previously_active else 3)
            self.api["run"]=Mock()
            self.api["output"]=Mock(side_effect=ValueError("restore interrupted"))
            self.api["db_env"]=lambda profile:{}
            with patch("subprocess.run",return_value=running) as query:
                for _ in range(2):
                    with self.assertRaisesRegex(ValueError,"restore interrupted"):
                        self.api["worker_exclusive"](["worker"],{},marker)
                query.assert_called_once()
            commands=[call.args for call in self.api["run"].call_args_list]
            self.assertEqual(commands.count(("systemctl","stop","agentcapsule-worker")),2)
            self.assertEqual(commands.count(("systemctl","start","agentcapsule-worker")),2 if previously_active else 0)

    def test_resume_preserves_completed_storage_operation(self):
        op=self.state/("host_"+"a"*32)
        op.mkdir()
        request=dict(action="restore-apply")
        self.api["save"](op/"request.json",request)
        self.api["state"](op,state="queued")
        self.api["preflight"]=lambda:None
        calls=[]
        def fail_then_succeed(*_):
            calls.append(1)
            if len(calls)==1:
                raise ValueError("retry")
        self.api["run_storage"]=fail_then_succeed
        with self.assertRaisesRegex(ValueError,"retry"):
            self.api["execute"](op)
        self.assertEqual(self.api["read"](op/"status.json")["state"],"failed")
        self.api["execute"](op)
        self.api["execute"](op)
        self.assertEqual(len(calls),2)
        self.assertEqual(self.api["read"](op/"status.json")["completed"],["restore-apply"])


if __name__=="__main__":
    unittest.main()
