"""The optional host profile preserves existing policy and applies config atomically."""
import base64
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


class PiHostTests(unittest.TestCase):
    def setUp(self):
        root = Path(__file__).resolve().parents[1]/"internal/hostops"
        env = {"__name__":"pi_host_tests"}
        for name in ("setup.py", "pi.py", "host.py"):
            exec(compile((root/name).read_bytes(), name, "exec"), env)
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = Path(tmp.name)
        env.update(STATE=path/"state", ACTIVE=path/"active", ETC=path/"etc")
        for directory in (env["STATE"], env["ACTIVE"]/"config", env["ETC"]):
            directory.mkdir(parents=True)
        self.calls = []
        env["run"] = lambda *args: self.calls.append(tuple(args))
        self.env = env
        self.catalog = {"schema":"agentcapsule.pi/v1","release":"v0.1.6",
                        "publisher_key":"-----BEGIN PUBLIC KEY-----\n"+base64.b64encode(b"test").decode()+"\n-----END PUBLIC KEY-----\n",
                        "packages":{n:env["PI_REPOSITORY"]+"@sha256:"+h*64 for n,h in zip(env["PI_PACKAGES"],"ab")}}
        self.file = env["ACTIVE"]/"config/pi-catalog.json"
        self.file.write_text(json.dumps(self.catalog))
        self.manifest = env["ACTIVE"]/"bundle.json"
        self.manifest.write_text(json.dumps({"version":"v0.1.6","sha256":{"config/pi-catalog.json":env["sha"](self.file)}}))
        self.config = env["ETC"]/"worker.json"
        self.settings = {"registry":{"rules":[{"host":"ghcr.io","repositories":["acme/"],"allow_unsigned":True}],"max_harness_mib":512},
                         "kernel":{"sha256":"e"*64}, "initrd":{"sha256":"f"*64},"worker":{"another":"value"}}
        self.config.write_text(json.dumps(self.settings))
        self.config.chmod(0o640)

    def test_enable_scopes_trust_and_preserves_other_sources_and_builder(self):
        self.settings["corpus"] = {"builder":{"harness":{"name":"custom","version":"5"}},"sources":{"rules":[
            {"kind":"github","host":"github.com","repositories":["training/old"]}]}}
        self.config.write_text(json.dumps(self.settings))
        result = self.env["enable_pi"]("training/French")
        cfg = json.loads(self.config.read_bytes())
        self.assertEqual(cfg["registry"]["rules"], self.settings["registry"]["rules"])
        self.assertEqual(cfg["registry"]["max_harness_mib"], 512)
        self.assertEqual(set(cfg["registry"]["release_packages"]),set(self.catalog["packages"].values()))
        self.assertEqual(cfg["corpus"]["builder"], self.settings["corpus"]["builder"])
        self.assertEqual(cfg["corpus"]["sources"]["rules"][0]["repositories"],["training/old","training/French"])
        self.assertEqual(result["signer"],"sha256:"+hashlib.sha256(b"test").hexdigest())
        self.assertEqual(result["system_image"]["features"],["corpus.mount"])
        self.assertEqual(result["system_image"]["kernel_digest"],"sha256:"+"e"*64)
        self.assertEqual(self.config.stat().st_mode&0o777,0o640)
        self.calls.clear()
        self.env["enable_pi"]("Training/french")
        self.assertFalse(any("restart" in c for c in self.calls))

    def test_rejects_modified_catalog_bad_repo_and_rolls_back_failed_restart(self):
        original = self.config.read_bytes()
        for repo in ("a/", "a/b.git", "a/../b", "https://github.com/a/b"):
            with self.assertRaisesRegex(ValueError,"OWNER/REPOSITORY"):
                self.env["enable_pi"](repo)
        def fail_once(*args):
            if not self.calls:
                self.calls.append(args)
                raise RuntimeError("service did not start")
        with patch.dict(self.env,run=fail_once):
            with self.assertRaisesRegex(RuntimeError,"did not start"):
                self.env["enable_pi"]("acme/course")
        self.assertEqual(self.config.read_bytes(), original)
        self.assertFalse((self.env["STATE"]/"pi-worker-settings.json").exists())
        self.env["enable_pi"]("acme/course")
        self.assertEqual(json.loads(self.config.read_bytes())["corpus"]["builder"]["harness"]["version"],"0.1.6")
        self.file.write_text("{}")
        with self.assertRaisesRegex(ValueError,"signed Pi catalog"):
            self.env["enable_pi"]("acme/other")
