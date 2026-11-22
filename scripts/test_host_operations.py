"""Exercise the embedded Linux helper with real signatures and archives."""
import hashlib
import io
import json
import os
from pathlib import Path
import runpy
import sqlite3
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

    def test_prepared_release_matches_the_signed_plan_and_all_files_on_reuse(self):
        required = ("firecracker", "jailer", "vmlinux", "product.initrd", "agentcapsule-api", "agentcapsule-worker")
        files = {name: name.encode() for name in (*required, "systemd/agentcapsule-api.service")}
        self.bundle["sha256"] = {name: hashlib.sha256(data).hexdigest() for name, data in files.items()}
        files["bundle.json"] = json.dumps(self.bundle).encode()
        with tarfile.open(self.assets / self.api["SERVER"], "w:gz") as tar:
            for name, data in files.items():
                info = tarfile.TarInfo(name)
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
        self.sign()
        staged = self.api["stage"](self.request)
        release = self.api["RELEASES"] / self.version
        prepare = self.api["prepare_release"]
        prepare(release, staged, self.version)
        prepare(release, staged, self.version)
        unit = release / "systemd/agentcapsule-api.service"
        unit.write_bytes(b"interrupted write")
        with self.assertRaisesRegex(ValueError, "differs from manifest"):
            prepare(release, staged, self.version)
        # Replacing the inner inventory along with that unit cannot change
        # which files the independently signed installation plan selected.
        self.bundle["sha256"]["systemd/agentcapsule-api.service"] = hashlib.sha256(unit.read_bytes()).hexdigest()
        (release / "bundle.json").write_text(json.dumps(self.bundle))
        with self.assertRaisesRegex(ValueError, "verified bundle manifest"):
            prepare(release, staged, self.version)

    def test_signed_update_plan_checks_the_database_ledger_before_downloading(self):
        from unittest.mock import Mock
        ledger = [dict(version=i, name=n, sha256=hashlib.sha256(n.encode()).hexdigest())
                  for i, n in enumerate(("control-plane-baseline", "organization-identity"), 1)]
        self.bundle["migration_ledger"] = ledger
        self.sign()
        self.assertEqual(self.api["stage"](self.request, True)["migration_check"], "initial_install")
        self.api["ACTIVE"].mkdir()
        self.api["save"](self.api["ACTIVE"] / "bundle.json", dict(version="v0.0.1-dev.1", migrations=[]))
        self.api["save"](self.state / "profile.json", {})
        query = Mock(return_value=json.dumps(ledger[:1]).encode())
        with patch.dict(self.api, postgres_scalar=query):
            self.assertEqual(self.api["stage"](self.request, True)["migration_check"], "database_ledger_verified")
            wrong = dict(ledger[0], sha256="f" * 64)
            query.return_value = json.dumps([wrong]).encode()
            with self.assertRaisesRegex(ValueError, "database migration history"):
                self.api["stage"](self.request, True)
        self.assertFalse((self.state / "downloads" / self.version / self.api["SERVER"]).exists())
        self.bundle["protocol"] = "v2"
        with self.assertRaisesRegex(ValueError, "protocol"):
            self.api["check_migration_plan"]({}, self.bundle)

    def test_second_host_accepts_only_the_signed_expand_suffix(self):
        base = dict(version=1, name="baseline", sha256="a"*64)
        expand = dict(version=2, name="more", sha256="b"*64, compatible_with_previous=True)
        installed = dict(migrations=[], migration_ledger=[base], rolling_schema=1)
        candidate = dict(migrations=["0002_more.sql"], migration_ledger=[base, expand])
        self.api["save"](self.state / "profile.json", {})
        plan = self.api["check_migration_plan"]
        def check(actual):
            with patch.dict(self.api, postgres_scalar=lambda *_: json.dumps(actual).encode()):
                return plan(installed, candidate)
        self.assertEqual(check([base, expand]), "database_expand_verified")
        installed.pop("migration_ledger")
        with self.assertRaisesRegex(ValueError, "database migration history"):
            check([base, expand])
        installed["migration_ledger"] = [base]
        with self.assertRaisesRegex(ValueError, "database migration history"):
            check([base, dict(expand, sha256="c"*64)])
        installed.pop("rolling_schema")
        with self.assertRaisesRegex(ValueError, "database migration history"):
            check([base, expand])
        installed["rolling_schema"] = 1
        expand.pop("compatible_with_previous")
        with self.assertRaisesRegex(ValueError, "database migration history"):
            check([base, expand])

    def test_check_running_image_exports_the_container_image_id(self):
        config = b'{"architecture":"amd64","os":"linux"}'
        expected = "sha256:" + hashlib.sha256(config).hexdigest()
        manifest = "sha256:" + "a" * 64
        container = "c" * 64
        image = dict(engine="docker", service="directory", config_id=expected, ref="registry/directory@"+manifest)

        def inspect(*argv):
            if argv[1] == "ps":
                self.assertIn("label=com.docker.compose.service=directory", argv)
                return container
            self.assertEqual(argv[1:3], ("container", "inspect"))
            self.assertEqual(argv[-1], container)
            return f"{manifest} running 0"

        def export(*argv):
            self.assertEqual(argv[:4], ("docker", "image", "save", "--output"))
            self.assertEqual(argv[-1], manifest)
            with tarfile.open(argv[4], "w") as archive:
                for name, data in (("manifest.json", b'[{"Config":"config.json","RepoTags":null}]'),
                                   ("config.json", config)):
                    member = tarfile.TarInfo(name)
                    member.size = len(data)
                    archive.addfile(member, io.BytesIO(data))

        with patch.dict(self.api, output=inspect, run=export):
            report = self.api["runtime_image"](image, self.root)
            self.assertTrue(report["verified"])
            self.assertEqual((report["image_id"], report["expected_config_id"]), (manifest, expected))
            wrong = dict(image, config_id="sha256:" + "b" * 64)
            self.assertEqual(self.api["runtime_image"](wrong, self.root)["reason"], "configuration_mismatch")
        self.assertFalse((self.root / "loaded-image.tar").exists())

    def test_runtime_image_distinguishes_the_initializer_from_a_daemon(self):
        from unittest.mock import Mock
        image_id, container = "b" * 64, "c" * 64
        for service, engine, state, good in (("init", "docker", "exited 0", True),
                                             ("init", "docker", "exited 1", False),
                                             ("oidc", "podman", "exited 0", False),
                                             ("oidc", "podman", "running 0", True)):
            with self.subTest(service=service, state=state):
                inspect = Mock(side_effect=[container, image_id+" "+state])
                image = dict(engine=engine, service=service, config_id="sha256:"+image_id, ref="signed")
                with patch.dict(self.api, output=inspect):
                    self.assertEqual(self.api["runtime_image"](image, self.root)["verified"], good)
        with patch.dict(self.api, output=lambda *args: ""):
            self.assertEqual(self.api["runtime_image"](image, self.root)["reason"], "container_count")

    def test_image_diagnostics_rejects_an_empty_or_replaced_inventory(self):
        active = self.api["RELEASES"] / self.version
        active.mkdir(parents=True)
        self.api["ACTIVE"].symlink_to(active)
        index = active / "offline-images.json"
        index.write_text("[]")
        manifest = active / "bundle.json"
        self.api["save"](manifest, {"version": self.version, "sha256": {index.name: self.api["sha"](index)}})
        dist = self.state / "downloads" / self.version
        dist.mkdir(parents=True)
        sums = dist / "SHA256SUMS"
        sums.write_text(self.api["sha"](manifest) + "  agentcapsule-bundle.json\n")
        (dist / "verified-manifest.sha256").write_text(self.api["sha"](sums))
        with self.assertRaisesRegex(ValueError, "incomplete"):
            self.api["runtime_images"]()
        index.write_text("[{}]")
        with self.assertRaisesRegex(ValueError, "inventory differs"):
            self.api["runtime_images"]()
        self.api["save"](manifest, {"version": self.version, "sha256": {index.name: self.api["sha"](index)}})
        with self.assertRaisesRegex(ValueError, "manifest differs"):
            self.api["runtime_images"]()
        sums.write_text(self.api["sha"](manifest) + "  agentcapsule-bundle.json\n")
        with self.assertRaisesRegex(ValueError, "checksums differ"):
            self.api["runtime_images"]()

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

    def test_update_opts_unsigned_registry_rules_out_explicitly(self):
        # L-16: a production worker refuses a registry rule without publisher
        # keys unless it says allow_unsigned. An update keeps the rules of a
        # host installed before as they worked: it writes the opt-out, and
        # names the rules it opted out; a signed or opted-out rule, and the
        # file's mode, stay as they were.
        path=self.root/"worker.json"
        rules=[{"host":"ghcr.io","repositories":["a/"]},
               {"host":"registry.example","repositories":["b/"],"publisher_keys":["/etc/agentcapsule/b.pub"]},
               {"host":"lab.example","repositories":["c/"],"allow_unsigned":True}]
        path.write_text(json.dumps({"root":"/var/lib/agentcapsule/host","registry":{"inspection_uid":61999,"rules":rules}}))
        path.chmod(0o640)
        self.assertEqual(self.api["opt_out_unsigned_registry_rules"](path),["ghcr.io"])
        cfg=json.loads(path.read_text())
        self.assertEqual([r.get("allow_unsigned") for r in cfg["registry"]["rules"]],[True,None,True])
        self.assertEqual(cfg["registry"]["inspection_uid"],61999)
        self.assertEqual(cfg["root"],"/var/lib/agentcapsule/host")
        self.assertEqual(path.stat().st_mode&0o777,0o640)
        self.assertEqual(self.api["opt_out_unsigned_registry_rules"](path),[])
        path.write_text(json.dumps({"root":"/var/lib/agentcapsule/host"}))
        self.assertEqual(self.api["opt_out_unsigned_registry_rules"](path),[])

    def test_profile_registry_rules_trust_a_key_or_opt_out(self):
        # L-16: an installation profile's registry rule trusts publisher keys
        # or says allow_unsigned: a production worker refuses any other.
        normalize=self.api["normalize_profile"]
        for rule in ({"host":"ghcr.io","repositories":["a/"]},{"host":"ghcr.io","repositories":["a/"],"publisher_keys":[]},
                     {"host":"ghcr.io","repositories":["a/"],"allow_unsigned":False},"ghcr.io"):
            with self.assertRaisesRegex(ValueError,"publisher_keys or allow_unsigned"):
                normalize({"registry_rules":[rule]})
        for rule in ({"host":"ghcr.io","repositories":["a/"],"allow_unsigned":True},
                     {"host":"ghcr.io","repositories":["a/"],"publisher_keys":["/etc/agentcapsule/a.pub"]}):
            self.assertEqual(normalize({"registry_rules":[rule]})["registry_rules"],[rule])
        with self.assertRaisesRegex(ValueError,"publisher_keys or allow_unsigned"):
            normalize({"registry_rules":{"host":"ghcr.io"}})

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

    def test_update_drains_after_reboot_before_it_suspends_migration_services(self):
        self.api["UNIT_DIR"]=self.root/"units"
        self.api["UNIT_DIR"].mkdir()
        for unit in self.api["SUSPENDED_SERVICES"]:
            if unit!="agentcapsule-oidc":  # its unit is the identity provider's, set up apart
                (self.api["UNIT_DIR"]/(unit+".service")).write_text("")
        maintenance=self.state/"maintenance"
        admission=self.state/"admissions-paused"
        # A reboot during the old helper's drain left even the worker gated.
        maintenance.write_text("platform update\n")
        counts=iter([2,1,0,1,1,0,0])
        events=[]
        def systemctl(*command):
            events.append((tuple(command[1:]),admission.exists(),maintenance.exists()))
        with patch.dict(self.api,run=systemctl,pending_operations=lambda _:next(counts)), patch("time.sleep"):
            self.api["drain"]({"database_url_file":None})
        self.assertTrue(admission.exists() and maintenance.exists())
        starts=[e for e in events if e[0][0]=="start" and "agentcapsule-worker" in e[0]]
        self.assertEqual(len(starts),2)  # a final delivery raced the first stop
        # The helper starts with the worker, before it (ADR 024).
        self.assertTrue(all(e[0].index("agentcapsule-worker-helper")<e[0].index("agentcapsule-worker") for e in starts))
        self.assertTrue(all(paused and not suspended for _,paused,suspended in starts))
        stops=[e for e in events if e[0][0]=="stop" and "agentcapsule-worker" in e[0]]
        self.assertEqual(len(stops),2)
        self.assertTrue(all(paused and suspended for _,paused,suspended in stops))
        for service in (*self.api["SUSPENDED_SERVICES"],"agentcapsule-api"):
            unit=(self.root/"units"/(service+".service.d")/"agentcapsule-update.conf").read_text()
            self.assertIn("ConditionPathExists=!"+str(maintenance),unit)
            self.assertEqual(str(admission) in unit,service=="agentcapsule-api")

    def test_update_counts_actual_invocation_states(self):
        with sqlite3.connect(":memory:") as db:
            db.executescript("""
                CREATE TABLE platform_operations (id text, kind text, status text);
                CREATE TABLE owner_instructions (operation_id text, run_at text, released_at text);
            """)
            for i,(kind,state,at,released,want) in enumerate([
                ("instruction","PENDING",None,None,1),
                ("instruction","PENDING","2999-01-01",None,0),
                ("instruction","PENDING","2000-01-01",None,1),
                ("instruction","PENDING","2999-01-01","2020-01-01",1),
                ("instruction","RUNNING","2999-01-01",None,1),
                ("instruction","SUCCEEDED",None,None,0),
                ("instruction","CANCELED",None,None,0),
                ("instruction","FAILED",None,None,0),
                ("provision","PENDING",None,None,1),
            ]):
                with self.subTest(kind=kind,state=state,at=at):
                    db.execute("INSERT INTO platform_operations VALUES(?,?,?)",(str(i),kind,state))
                    if kind=="instruction":
                        db.execute("INSERT INTO owner_instructions VALUES(?,?,?)",(str(i),at,released))
                    self.assertEqual(db.execute(self.api["DRAIN_QUERY"]).fetchone()[0],want)
                    db.execute("DELETE FROM platform_operations")

    @unittest.skipUnless(os.environ.get("AGENTCAPSULE_TEST_POSTGRES"),"requires PostgreSQL")
    def test_drain_reads_postgresql_through_the_configured_libpq_dsn(self):
        fixtures="""WITH platform_operations(id,kind,status) AS (VALUES
            ('working','instruction','RUNNING'),('future','instruction','PENDING'),
            ('immediate','instruction','PENDING'),('done','instruction','SUCCEEDED')),
            owner_instructions(operation_id,run_at,released_at) AS (VALUES
            ('future',CURRENT_TIMESTAMP + interval '1 day',NULL::timestamptz)) """
        env={"AGENTCAPSULE_DATABASE_URL":os.environ["AGENTCAPSULE_TEST_POSTGRES"]}
        with patch.dict(self.api,DRAIN_QUERY=fixtures+self.api["DRAIN_QUERY"],db_env=lambda _:env):
            self.assertEqual(self.api["pending_operations"]({}),2)

    def test_service_retry_keeps_api_closed_until_workers_and_oidc_are_up(self):
        self.api["UNIT_DIR"]=self.root/"units"
        p=self.api["normalize_profile"]({"api_name":"local.test"})
        admission=self.state/"admissions-paused"
        maintenance=self.state/"maintenance"
        maintenance.write_text("suspended")
        calls=[]
        def systemctl(*cmd):
            calls.append(cmd)
            if "--now" in cmd:
                self.assertFalse(maintenance.exists())
                self.assertEqual(admission.exists(),cmd[-1]!="agentcapsule-api.service")
        actual=self.api["start_services"]
        # A failed identity provider check does not release the API on reboot.
        with patch.dict(self.api, run=systemctl, output=lambda *_:"{}"), patch("time.sleep"):
            with self.assertRaisesRegex(ValueError,"OIDC issuer"):
                actual(p)
        self.assertTrue(admission.exists())
        self.assertNotIn(("systemctl","enable","--now","agentcapsule-api.service"),calls)
        issuer=json.dumps({"issuer":"https://local.test:9444/realms/agentcapsule"})
        with patch.dict(self.api,run=systemctl,output=lambda *_:issuer,request_api=lambda *_:None):
            self.assertTrue(actual(p)["services_started"])
        self.assertFalse(admission.exists() or maintenance.exists())

    def test_failed_offline_migration_reinstates_old_bundle_guards_before_retry(self):
        self.api["UNIT_DIR"]=self.root/"units"
        op=self.state/("host_"+"b"*32)
        op.mkdir()
        profile={"database_url_file":None}
        req=dict(action="update",profile=profile,version=self.version,**{"from":"v0.0.1"})
        self.api["save"](op/"request.json",req)
        self.api["state"](op,state="queued")
        calls=[]
        def migrate(*_):
            calls.append("migration")
            self.assertTrue((self.state/"maintenance").exists())
            self.assertTrue((self.state/"admissions-paused").exists())
            if calls.count("migration")==1:
                raise ValueError("test migration failure")
        def no_action(*_,**__):
            pass
        fixtures=dict(preflight=no_action,current=lambda:"v0.0.1",stage=no_action,prepare_release=no_action,
                      backup=lambda *_,**__:calls.append("backup"),install_dependencies=no_action,
                      activate=no_action,configure=migrate,start_services=no_action,smoke=no_action,
                      pending_operations=lambda _:0,run=no_action)
        with patch.dict(self.api,**fixtures):
            with self.assertRaisesRegex(ValueError,"test migration failure"):
                self.api["execute"](op)
            # Resuming an original bundle can find only its old shared gate.
            (self.state/"admissions-paused").unlink()
            self.api["execute"](op)
        self.assertEqual(calls,["backup","migration","migration"])
        self.assertEqual(self.api["read"](op/"status.json")["state"],"succeeded")

    def test_reboot_qualification_waits_for_a_new_boot_and_the_expected_services(self):
        import uuid
        from unittest.mock import Mock
        before, after = uuid.uuid4(), uuid.uuid4()
        active = [{"service": "worker", "ActiveState": "active"}]
        health = Mock(side_effect=[
            {"boot_id": str(before), "services": active},
            subprocess.CalledProcessError(1, "ssh"),
            {"boot_id": str(after), "services": []},
            {"boot_id": str(after), "services": active},
        ])
        verify = runpy.run_path(str(ROOT / "scripts/verify-cli-host.py"))["verify_reboot"]
        with patch("subprocess.run") as run, patch("time.sleep"):
            receipt = verify(["reboot-test-instance"], before, health, ("worker",))
        run.assert_called_once_with(["reboot-test-instance"], timeout=300, check=True)
        self.assertEqual(health.call_count, 4)
        self.assertEqual(receipt, {"boot_before": str(before), "boot_after": str(after)})

    def test_image_qualification_waits_for_startup_and_reports_mismatches_immediately(self):
        from unittest.mock import Mock
        verify = runpy.run_path(str(ROOT / "scripts/verify-cli-host.py"))["observe_service_images"]
        missing = dict(verified=False, reason="container_count", container_count=0, service="oidc")
        starting = dict(verified=False, reason="container_state", state="running", service="init")
        wrong = dict(verified=False, reason="configuration_mismatch", service="directory")
        for last in (dict(verified=True), wrong):
            with self.subTest(last=last), patch("time.sleep") as sleep:
                reports = [dict(installed=self.version, verified=image["verified"], images=[image])
                           for image in (missing, starting, last)]
                observe = Mock(side_effect=reports)
                self.assertEqual(verify(self.version, observe), reports[-1])
                self.assertEqual(sleep.call_count, 2)

    def test_starter_restore_retries_echo_without_reapplying_the_volume(self):
        from unittest.mock import Mock
        agent = "agt_" + "1" * 32
        save = self.api["save"]
        save(self.state / "smoke.json", {"agent": agent})
        save(self.state / "profile.json", {})
        receipt = {"invocation_verified": True, "probe_agent": agent, "probe_invocation": "op_" + "4" * 32}
        restore = Mock(return_value={"storage_result": {"incarnation": 2}})
        probe = Mock(side_effect=[ValueError("worker restarting"), receipt])
        options = ["--archive-id", "arc_" + "2" * 32, "--restore-id", "rst_" + "3" * 32, "--verify-starter"]
        def start(target):
            result = self.api["main"](["restore", "apply", "--agent", target, *options], self.version)
            return self.api["opdir"](result["operation_id"])
        with patch.dict(self.api, preflight=lambda: None, launch=lambda _: None, HELPER_SOURCE=b"",
                        run_storage=restore, smoke=probe):
            wrong = start("agt_" + "9" * 32)
            with self.assertRaisesRegex(ValueError, "original installation probe"):
                self.api["execute"](wrong)
            restore.assert_not_called()
            op = start(agent)
            with self.assertRaisesRegex(ValueError, "worker restarting"):
                self.api["execute"](op)
            failed = self.api["main"](["host", "operation", "show", op.name], self.version)
            self.assertEqual(failed["completed"], ["restore-apply"])
            self.assertEqual(failed["phase"], "invocation")
            self.api["main"](["host", "operation", "resume", op.name], self.version)
            self.api["execute"](op)
            result = self.api["main"](["host", "operation", "wait", op.name], self.version)
        restore.assert_called_once()
        self.assertEqual(result["storage_result"]["incarnation"], 2)
        self.assertEqual(result["phases"], ["restore-apply", "invocation"])
        self.assertEqual(result["probe_invocation"], receipt["probe_invocation"])

    def test_concurrent_executors_observe_completed_storage_operation_under_lock(self):
        import fcntl
        import threading
        from concurrent.futures import ThreadPoolExecutor
        from unittest.mock import Mock
        op = self.state / ("host_" + "b" * 32)
        op.mkdir()
        self.api["save"](op / "request.json", {"action": "restore-apply"})
        self.api["state"](op, state="queued")
        arrived = threading.Barrier(2)
        flock = fcntl.flock
        def simultaneous_lock(file, flags):
            arrived.wait(timeout=5)
            return flock(file, flags)
        storage = Mock(return_value={"storage_result": {"incarnation": 2}})
        with patch.dict(self.api, preflight=lambda: None, run_storage=storage), patch("fcntl.flock", simultaneous_lock):
            with ThreadPoolExecutor(max_workers=2) as pool:
                list(pool.map(self.api["execute"], (op, op)))
        storage.assert_called_once()
        self.assertEqual(self.api["read"](op/"status.json")["state"], "succeeded")

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

    def test_database_roles_map_each_account_to_its_own_role(self):
        # An installation of an earlier release mapped the API's account to
        # the owner of the database, then root to the worker's role. The
        # update maps root to the owner, the worker's account to the worker's
        # role only (ADR 024), the API's account to the API's role only, and
        # creates the roles, owning nothing and with no cluster privilege.
        from unittest.mock import Mock
        folder=self.root/"cluster"
        folder.mkdir()
        (folder/"pg_ident.conf").write_text("agentcapsule root agentcapsule\nagentcapsule agentcapsule-api agentcapsule\n"
                                            "# MAPNAME SYSTEM-USERNAME PG-USERNAME\nother alice bob\n")
        (folder/"pg_hba.conf").write_text("local agentcapsule agentcapsule peer map=agentcapsule\n"
                                          "host all all 127.0.0.1/32 scram-sha-256\nhost all all ::1/128 scram-sha-256\n"
                                          "local all postgres peer\n")
        statements=[]
        def run_user(user,*cmd,env=None,capture=False):
            self.assertEqual(user,"postgres")
            statements.append(cmd[-1])
            return "" if capture else None
        run=Mock()
        with patch.dict(self.api,run=run,run_user=run_user,user_id=lambda _:0), patch("os.chown"), \
             patch("pwd.getpwnam",return_value=Mock(pw_gid=0)):
            self.api["database_roles"](folder)
            ident=(folder/"pg_ident.conf").read_text()
            hba=(folder/"pg_hba.conf").read_text()
            self.assertEqual(ident,"agentcapsule root agentcapsule\nagentcapsule agentcapsule-worker agentcapsule_worker\n"
                                   "agentcapsule agentcapsule-api agentcapsule_api\n"
                                   "# MAPNAME SYSTEM-USERNAME PG-USERNAME\nother alice bob\n")
            self.assertEqual(hba,"local agentcapsule agentcapsule,agentcapsule_api,agentcapsule_worker peer map=agentcapsule\n"
                                 "host all all 127.0.0.1/32 scram-sha-256\nhost all all ::1/128 scram-sha-256\n"
                                 "local all postgres peer\n")
            for role in ("agentcapsule","agentcapsule_api","agentcapsule_worker"):
                self.assertIn("CREATE ROLE "+role+" LOGIN",statements)
                self.assertIn("ALTER ROLE "+role+" NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS",statements)
            run.assert_called_with("pg_ctlcluster","16","agentcapsule","reload")
            # Again: the files are already as they should be.
            before=(folder/"pg_ident.conf").stat().st_mtime_ns,(folder/"pg_hba.conf").stat().st_mtime_ns
            self.api["database_roles"](folder)
            self.assertEqual(((folder/"pg_ident.conf").stat().st_mtime_ns,(folder/"pg_hba.conf").stat().st_mtime_ns),before)
            self.assertEqual((folder/"pg_ident.conf").read_text(),ident)

    def test_each_unit_connects_as_its_own_role(self):
        # The update rewrites the connection string of each unit's file,
        # which an earlier release set to the owner's, and keeps the rest.
        etc=self.root/"etc"
        etc.mkdir()
        owner='AGENTCAPSULE_DATABASE_URL="host=/run/postgresql port=55432 dbname=agentcapsule user=agentcapsule"\n'
        (etc/"api.env").write_text(owner+'API_LISTEN="0.0.0.0:9443"\nHOST_ID="local"\n')
        (etc/"worker.env").write_text(owner)
        with patch.dict(self.api,ETC=etc):
            self.api["service_environment"]({"database_url_file":None})
        local="host=/run/postgresql port=55432 dbname=agentcapsule user="
        self.assertEqual((etc/"api.env").read_text(),'AGENTCAPSULE_DATABASE_URL="'+local+'agentcapsule_api"\n'
                                                     'API_LISTEN="0.0.0.0:9443"\nHOST_ID="local"\n')
        self.assertEqual((etc/"worker.env").read_text(),'AGENTCAPSULE_DATABASE_URL="'+local+'agentcapsule_worker"\n')
        self.assertEqual((etc/"admin.env").read_text(),'AGENTCAPSULE_DATABASE_URL="'+local+'agentcapsule"\n')
        for name in ("api.env","worker.env","admin.env"):
            self.assertEqual((etc/name).stat().st_mode&0o777,0o600)
        # The worker's operator modes run as the worker's role too.
        self.assertEqual(self.api["worker_env"]({"database_url_file":None})["AGENTCAPSULE_DATABASE_URL"],local+"agentcapsule_worker")

    def test_the_runtime_roots_parent_has_one_mode(self):
        # The installer, the tmpfiles line that every boot applies and the
        # update's searchable_parent agree: /var/lib/agentcapsule is root's,
        # 0711 (FIX-2). The tmpfiles line set 0710 root:agentcapsule-authority,
        # and each boot undid the installer's mode.
        lines=[l.split() for l in (ROOT/"deploy/systemd/agentcapsule-authority.tmpfiles").read_text().splitlines()
               if l.split()[1:2]==["/var/lib/agentcapsule"]]
        self.assertEqual(lines,[["d","/var/lib/agentcapsule","0711","root","root","-"]])
        from unittest.mock import Mock
        calls=[]
        def run(*cmd,**kw):
            calls.append(cmd)
            return ""
        etc=self.root/"etc"
        etc.mkdir()
        with patch.dict(self.api,ETC=etc,run=run,run_user=Mock(return_value=json.dumps(dict(authority_id="id"))),
                        user_id=Mock(return_value=1000),write_file=Mock()):
            self.api["authority"]()
        self.assertIn(("install","-d","-m","0711","/var/lib/agentcapsule"),calls)
        # A parent the update made searchable has the same execute bits.
        parent=self.root/"lib-agentcapsule"
        parent.mkdir()
        os.chmod(parent,0o710)
        self.assertTrue(self.api["searchable_parent"](str(parent/"host")))
        self.assertEqual(parent.stat().st_mode&0o111,0o111)

    def test_update_lets_the_authority_traverse_the_runtime_roots_parent(self):
        # A v0.1.0 worker left /var/lib/agentcapsule 0700: the authority's
        # account could not resolve the runtime root under it, and the
        # update's init-restore-authority failed with EACCES. The update
        # adds o+x to the parent, nothing else, and leaves the root 0700.
        parent=self.root/"lib-agentcapsule"
        parent.mkdir()
        os.chmod(parent,0o700)
        root=parent/"host"
        root.mkdir()
        os.chmod(root,0o700)
        self.assertTrue(self.api["searchable_parent"](str(root)))
        self.assertEqual(parent.stat().st_mode&0o7777,0o701)
        self.assertEqual(root.stat().st_mode&0o7777,0o700)
        self.assertFalse(self.api["searchable_parent"](str(root)))
        os.chmod(parent,0o755)
        self.assertFalse(self.api["searchable_parent"](str(root)))
        self.assertEqual(parent.stat().st_mode&0o7777,0o755)
        # A missing parent, or one behind a symbolic link, is left as it is.
        self.assertFalse(self.api["searchable_parent"](str(self.root/"missing"/"host")))
        os.chmod(parent,0o700)
        (self.root/"link").symlink_to(parent)
        self.assertFalse(self.api["searchable_parent"](str(self.root/"link"/"host")))
        self.assertEqual(parent.stat().st_mode&0o7777,0o700)

    def test_update_makes_the_parent_searchable_before_the_authority_checks_it(self):
        from unittest.mock import Mock
        events=[]
        files={"authority.json":dict(restore_authority=dict(root="/var/lib/agentcapsule-restore-authority",identity="ra"),
                                     key_authority=dict(root="/var/lib/agentcapsule-key-authority",identity="ka")),
               "worker.json":dict(root="/var/lib/agentcapsule/host")}
        def run_user(user,*cmd,env=None,capture=False):
            events.append((user,cmd[1]))
            return json.dumps(dict(authority_id="ra"))
        etc=self.root/"etc"
        etc.mkdir()
        separate=Mock(return_value=0)
        with patch.dict(self.api,ETC=etc,service_dsns=Mock(),configure_system=Mock(),read=lambda path:files[Path(path).name],
                        db_env=Mock(return_value={}),run=Mock(),database_roles=Mock(),service_environment=Mock(),run_user=run_user,
                        searchable_parent=lambda root:events.append(("searchable_parent",root)),renew_certificates=Mock(return_value=[]),
                        setup_oidc_unit=Mock(),setup_interop_images=Mock(),separate_worker=separate):
            self.api["configure"]({"database_url_file":None},self.version,False)
        self.assertEqual(events,[("searchable_parent","/var/lib/agentcapsule/host"),("agentcapsule-authority","init-restore-authority")])
        # The update gives the worker its own account's files (ADR 024 §9).
        separate.assert_called_once_with()

    def test_the_update_gives_the_worker_its_trees_but_the_vms_and_the_jails(self):
        # ADR 024 §9: what root owns in the worker's trees goes to the
        # worker's account; a VM's volume keeps its UID, a root worker's
        # jails stay root's, and no link is followed.
        uid,gid=os.getuid(),os.getgid()
        root=self.root/"host"
        for d in ("volumes","jails/firecracker/00000000000000a1/root","bin"):
            (root/d).mkdir(parents=True)
        (root/"registry.json").write_text("{}")
        outside=self.root/"outside"
        outside.write_text("x")
        (root/"bin"/"link").symlink_to(outside)
        given=[]
        def lchown(path,u,g):
            self.assertEqual((u,g),(uid,gid))
            given.append(Path(path).relative_to(self.root).as_posix())
        owners={}
        real=os.lstat
        def lstat(path):
            st=real(path)
            values=list(st)
            values[4]=owners.get(Path(path).name,0)  # st_uid: root's, but the volume
            return os.stat_result(values)
        (root/"volumes"/"vol.luks").write_text("")
        owners["vol.luks"]=20001
        with patch.dict(self.api,worker_ids=lambda:(uid,gid),RESTORE_TESTS=self.root/"tests"), \
             patch("os.lchown",side_effect=lchown), patch("os.lstat",side_effect=lstat):
            count=self.api["give_worker_trees"](dict(root=str(root),archives=dict(root=str(self.root/"archives"))))
        self.assertEqual(count,len(given))
        self.assertEqual(sorted(given),["archives","host","host/bin","host/registry.json","host/volumes","tests"])
        with patch.dict(self.api,worker_ids=lambda:(uid,gid)):
            for bad in ("/","/var/lib","relative"):
                with self.assertRaisesRegex(ValueError,"its own"):
                    self.api["give_worker_trees"](dict(root=bad))

    def test_external_database_names_a_role_per_service(self):
        with self.assertRaisesRegex(ValueError,"api_database_url_file and worker_database_url_file"):
            self.api["service_dsns"]({"database_url_file":"/root/db.url"})
        with self.assertRaisesRegex(ValueError,"needs database_url_file"):
            self.api["normalize_profile"]({"api_database_url_file":"/root/api.url"})
        files={"/root/api.url":"host=db.example user=capsule_api","/root/worker.url":"host=db.example user=capsule_worker"}
        with patch.dict(self.api,database_url=lambda path:files[path]):
            dsns=self.api["service_dsns"]({"database_url_file":"/root/db.url","api_database_url_file":"/root/api.url",
                                           "worker_database_url_file":"/root/worker.url"})
        self.assertEqual(dsns,{"api":"host=db.example user=capsule_api","worker":"host=db.example user=capsule_worker"})


if __name__=="__main__":
    unittest.main()
