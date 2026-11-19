"""Exercise the real host plan and operation using signed offline media.

Set AGENTCAPSULE_TEST_POSTGRES and AGENTCAPSULE_TEST_ADMIN to also exercise
rollback on a physical PostgreSQL copy. The test role needs CREATEDB.
"""
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
import unittest
import uuid


ROOT = Path(__file__).resolve().parents[1]
OLD, NEW = "v0.1.0-dev.9", "v0.1.0-dev.10"


def digest(data):
    return hashlib.sha256(data).hexdigest()


class BinaryRollbackTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.api = {"__name__": "host_test", "HELPER_SOURCE": b"test"}
        for name in ("setup.py", "diagnose.py", "host.py"):
            path = ROOT / "internal/hostops" / name
            exec(compile(path.read_bytes(), str(path), "exec"), self.api)
        self.state = self.root / "state"
        self.state.mkdir()
        self.active = self.root / "active"
        self.releases = self.root / "releases"
        self.api.update(STATE=self.state, ACTIVE=self.active, RELEASES=self.releases,
                        OPERATIONS=self.state / "operations")
        self.profile = self.api["normalize_profile"]({"api_name":"rollback.test"})
        self.api["save"](self.state / "profile.json", self.profile)
        self.ledger = [dict(version=1, name="baseline", sha256=digest(b"baseline"))]
        self.migrations = []
        self.key = self.root / "key"
        self.pub = self.root / "key.pub"
        self.keypair(self.key, self.pub)
        self.calls = []
        self.api.update(preflight=lambda: None, launch=self.api["execute"],
                        backup=lambda *args, **kw: self.calls.append("backup"),
                        drain=lambda *_: self.calls.append("drain"),
                        start_services=lambda *_: self.calls.append("services"),
                        smoke=lambda *_: self.calls.append("invocation"),
                        install_dependencies=lambda *_: self.fail("unexpected dependency installation"),
                        configure=lambda *_: self.fail("unexpected schema/authority initialization"),
                        postgres_scalar=lambda *_: json.dumps(self.ledger))

    def keypair(self, key, pub):
        subprocess.run(["openssl","genpkey","-algorithm","ed25519","-out",key],check=True)
        subprocess.run(["openssl","pkey","-pubout","-in",key,"-out",pub],check=True)

    def media(self, version, **changes):
        assets = self.root / version
        assets.mkdir(exist_ok=True)
        files = {name: name.encode() for name in ("firecracker","jailer","vmlinux","product.initrd",
                                                  "host-packages.json","offline-images.json","agentcapsule-worker")}
        files["agentcapsule-api"] = version.encode()
        if hasattr(self, "binaries"):
            files["agentcapsule-admin"] = self.binaries[version].read_bytes()
            files["agentcapsule-api"] = self.apis[version].read_bytes()
        manifest = dict(schema="agentcapsule.bundle/v1", platform="ubuntu-24.04-amd64", version=version,
                        protocol="v1", migration_mode="offline-exact-history", commit=version,
                        migration_ledger=self.ledger, migrations=self.migrations, binary_rollback_epoch="agentcapsule-state/v1",
                        sha256={n:digest(b) for n,b in files.items()})
        manifest.update(changes)
        files["bundle.json"] = json.dumps(manifest).encode()
        (assets / "agentcapsule-bundle.json").write_bytes(files["bundle.json"])
        with tarfile.open(assets / self.api["SERVER"], "w:gz", compresslevel=1) as archive:
            for name, data in files.items():
                member = tarfile.TarInfo(name)
                member.size, member.mode = len(data), 0o755
                archive.addfile(member, io.BytesIO(data))
        for k in ("DEBS", "IMAGES"):
            (assets / self.api[k]).write_bytes(k.encode())
        sums = assets / "SHA256SUMS"
        sums.write_text("".join(f"{digest(f.read_bytes())}  {f.name}\n" for f in sorted(assets.iterdir())
                                if not f.name.startswith("SHA256SUMS")))
        subprocess.run(["openssl","pkeyutl","-sign","-inkey",self.key,"-rawin","-in",sums,
                        "-out",assets/"SHA256SUMS.dev.sig"],check=True)
        return assets

    def install_new(self):
        path = self.media(NEW)
        request = dict(action="install", version=NEW, offline=str(path), development_key=str(self.pub))
        dist = self.api["stage"](request)
        self.api["prepare_release"](self.releases / NEW, dist, NEW)
        self.api["activate_verified"](Path("original-install"), request, self.releases / NEW, dist)

    def plan(self, version=OLD, key=None, action="rollback"):
        args = [action, "plan", "--to", version, "--offline", str(self.root / version),
                "--development-key", str(key or self.pub)]
        return self.api["main"](args, "development")

    def apply(self, plan, action="rollback"):
        return self.api["main"]([action, "apply", "--plan", plan["operation_id"]], "development")

    def test_compatible_rollback_preserves_state_and_is_idempotent(self):
        self.install_new()
        self.media(OLD)
        plan = self.plan()
        self.assertTrue(plan["binary_rollback_compatible"])
        self.assertEqual(plan["migration_check"], "database_ledger_verified")
        self.assertFalse((self.state / "downloads" / OLD / self.api["SERVER"]).exists())
        with self.assertRaisesRegex(ValueError, "expected update plan"):
            self.apply(plan, "update")
        result = self.apply(plan)
        self.assertEqual(result["completed"], self.api["phases"]("rollback"))
        self.assertEqual(result["state"], "succeeded")
        self.assertEqual((self.active / "agentcapsule-api").read_text(), OLD)
        self.assertFalse((self.state / "downloads" / OLD / self.api["DEBS"]).exists())
        self.assertEqual(self.apply(plan), result)
        self.assertEqual(self.calls, ["backup","drain","services","invocation"])

    def test_rollback_rejects_unknown_formats_ledger_environment_and_trust(self):
        self.install_new()
        for i, (changes, reason) in enumerate([
                ({"binary_rollback_epoch":None}, "formats"), ({"binary_rollback_epoch":"v2"}, "formats"),
                ({"migration_ledger":[]}, "histories"), ({"migrations":["other.sql"]}, "histories"),
                ({"protocol":"v2"}, "formats"), ({"migration_mode":"offline-other"}, "formats"),
                ({"sha256":{}}, "dependencies")]):
            version = f"v0.0.1-dev.{i}"
            self.media(version, **changes)
            with self.subTest(changes=changes), self.assertRaisesRegex(ValueError, reason + ".*Writes after"):
                self.plan(version)
        self.media(OLD)
        key, pub = self.root/"other", self.root/"other.pub"
        self.keypair(key, pub)
        with self.assertRaisesRegex(ValueError, "signing key differs"):
            self.plan(key=pub)
        self.assertEqual(self.api["current"](), NEW)
        pinned = self.state / "downloads" / NEW / "activated-origin.json"
        origin = self.api["read"](pinned)
        origin["signer"] = {"mode":"sigstore"}
        self.api["save"](pinned,origin)
        with self.assertRaisesRegex(ValueError, "signing authority differs"):
            self.plan()
        pinned.unlink()
        with self.assertRaisesRegex(ValueError, "lacks a verified activation receipt"):
            self.plan()

    def test_stale_plan_and_implicit_downgrade_refused(self):
        self.install_new()
        self.media(OLD)
        with self.assertRaisesRegex(ValueError,"use rollback plan"):
            self.plan(action="update")
        with self.assertRaisesRegex(ValueError,"strictly older"):
            self.plan(NEW)
        plan = self.plan()
        self.api["save"](self.state / "active-release.json", {"operation_id":"other-install", "version":NEW})
        with self.assertRaisesRegex(ValueError, "activation changed"):
            self.apply(plan)
        self.assertFalse(self.calls)

    def test_after_drain_changed_database_leaves_source_active(self):
        self.install_new()
        self.media(OLD)
        plan = self.plan()
        self.api["drain"] = lambda _: self.api.update(postgres_scalar=lambda *_: "[]")
        with self.assertRaisesRegex(ValueError, "database migration history"):
            self.apply(plan)
        self.assertEqual(self.api["current"](), NEW)
        self.assertFalse((self.state / "transition.json").exists())
        self.assertEqual(self.calls, ["backup","services"])
        self.api["postgres_scalar"] = lambda *_: json.dumps(self.ledger)
        self.api["drain"] = lambda _: self.calls.append("drain")
        resumed = self.api["main"](["host","operation","resume",plan["operation_id"]], "development")
        self.assertEqual(resumed["state"], "succeeded")
        self.assertEqual(self.calls, ["backup","services","drain","services","invocation"])

    def test_repeated_upgrade_rollback_cycle_gets_new_operation_ids(self):
        self.install_new()
        self.media(OLD)
        first = self.plan()
        self.apply(first)
        self.api.update(install_dependencies=lambda *_: None, configure=lambda *_: None)
        upgrade = self.plan(NEW, action="update")
        self.assertEqual(self.apply(upgrade, "update")["state"], "succeeded")
        second = self.plan()
        self.assertNotEqual(first["operation_id"], second["operation_id"])
        self.assertEqual(self.apply(second)["state"], "succeeded")
        self.assertEqual(self.api["current"](), OLD)

    def test_interrupted_switch_requires_its_owner_and_recovers(self):
        self.install_new()
        self.media(OLD)
        intermediate = "v0.1.0-dev.8"
        self.media(intermediate)
        plan, other = self.plan(), self.plan(intermediate)
        real_activate = self.api["activate"]
        def interrupted(link, target):
            real_activate(link, target)
            raise RuntimeError("lost power after atomic rename")
        self.api["activate"] = interrupted
        with self.assertRaisesRegex(RuntimeError, "lost power"):
            self.apply(plan)
        self.assertEqual(self.api["current"](), OLD)
        with self.assertRaisesRegex(ValueError, "another host transition"):
            self.apply(other)
        self.api.update(activate=real_activate,install_maintenance_gates=lambda: None,
                        pause_admissions=lambda: None,suspend_services=lambda: None)
        result = self.api["main"](["host","operation","resume",plan["operation_id"]], "development")
        self.assertEqual(result["state"],"succeeded")
        self.assertEqual(self.api["read"](self.state/"active-release.json")["operation_id"],plan["operation_id"])
        self.assertEqual(self.calls, ["backup","drain","services","invocation"])

    @unittest.skipUnless(os.environ.get("AGENTCAPSULE_TEST_POSTGRES") and os.environ.get("AGENTCAPSULE_TEST_ADMIN"),
                         "requires local PostgreSQL and two admin builds")
    def test_postgres_copy_keeps_data_credentials_and_revocations(self):
        base = os.environ["AGENTCAPSULE_TEST_POSTGRES"]
        postgres = Path(os.environ["AGENTCAPSULE_TEST_PG_BIN"])
        psql = postgres / "psql"
        self.binaries = {OLD:Path(os.environ["AGENTCAPSULE_TEST_ADMIN"]),
                         NEW:Path(os.environ["AGENTCAPSULE_TEST_ADMIN_NEW"])}
        self.apis = {OLD:Path(os.environ["AGENTCAPSULE_TEST_API"]), NEW:Path(os.environ["AGENTCAPSULE_TEST_API_NEW"])}
        source = "rollback_source_" + uuid.uuid4().hex
        copy = "rollback_copy_" + uuid.uuid4().hex
        def sql(dsn, query):
            return subprocess.check_output([psql,"-XAt","-v","ON_ERROR_STOP=1","-d",dsn,"-c",query],
                                           text=True).strip()
        def private(dsn):
            return dict(os.environ, AGENTCAPSULE_MODE="development", AGENTCAPSULE_DATABASE_URL=dsn)
        sql(base, "CREATE DATABASE " + source)
        self.addCleanup(sql, base, "DROP DATABASE " + source)
        src = base + " dbname=" + source
        subprocess.run([self.binaries[OLD], "migrate"],env=private(src),check=True,stdout=subprocess.DEVNULL)
        receipt_key = self.root / "api-receipt-key"
        receipt_key.write_bytes(os.urandom(32))
        receipt_key.chmod(0o600)
        def token():
            return "acpp_" + base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip("=")
        active, revoked = token(), token()
        sql(src, f"""INSERT INTO api_receipt_key(singleton,key_hash)
                    VALUES (true,decode('{digest(receipt_key.read_bytes())}','hex'));
                    INSERT INTO platform_credentials(id,account,token_hash,scopes,expires_at,revoked_at)
                    VALUES ('revoked-id','rollback-user',decode('{digest(revoked.encode())}','hex'),ARRAY['platform:admin'],
                            now()+interval '1 day',now()),
                           ('live-id','rollback-user',decode('{digest(active.encode())}','hex'),ARRAY['platform:admin'],
                            now()+interval '1 day',NULL);
                    INSERT INTO revocation_catalogue(subject) VALUES ('agent/rollback-victim');
                    INSERT INTO organizations(id,name) VALUES ('rollback-tenant','rollback tenant');""")
        sql(base, "CREATE DATABASE " + copy + " TEMPLATE " + source)
        self.addCleanup(sql, base, "DROP DATABASE " + copy)
        dsn = base + " dbname=" + copy
        self.api["db_env"] = lambda _: private(dsn)
        # Reinstall the production libpq query, used during both plan and apply.
        setup = ROOT / "internal/hostops/setup.py"
        ns = dict(self.api)
        exec(compile(setup.read_bytes(), str(setup), "exec"), ns)
        ns["db_env"] = self.api["db_env"]
        self.api["postgres_scalar"] = ns["postgres_scalar"]
        self.ledger = json.loads(subprocess.check_output([self.binaries[NEW],"migration-manifest"]))
        self.migrations = sorted(f.name for f in (ROOT/"internal/controlplane/migrations").glob("*.sql"))
        # The older admin predates migration-manifest. Read the schema that
        # its compiled migrations actually wrote before cloning the database.
        old_schema = json.loads(sql(src, """SELECT json_agg(json_build_object('version',version,
                                'name',name,'sha256',encode(checksum,'hex')) ORDER BY version) FROM schema_migrations"""))
        self.assertEqual(self.ledger, old_schema)
        state_query = """SELECT json_build_array(
            (SELECT json_agg(row_to_json(c)) FROM platform_credentials c),
            (SELECT json_agg(row_to_json(r)) FROM revocation_catalogue r),
            (SELECT json_agg(row_to_json(o)) FROM organizations o),
            (SELECT json_agg(row_to_json(m) ORDER BY version) FROM schema_migrations m))::text"""
        before = sql(dsn,state_query)
        self.assertEqual(before,sql(src,state_query))
        self.install_new()
        self.media(OLD)
        plan = self.plan()
        sql(dsn,"INSERT INTO revocation_catalogue(subject) VALUES ('request/revoked-after-plan')")
        latest_state = sql(dsn,state_query)
        def http_checks():
            with socket.socket() as listener:
                listener.bind(("127.0.0.1", 0))
                port = listener.getsockname()[1]
            endpoint = f"http://127.0.0.1:{port}"
            with subprocess.Popen([self.active/"agentcapsule-api","-listen",f"127.0.0.1:{port}",
                                   "-receipt-key-file",receipt_key,"-host-id","rollback-host"],
                                  env=private(dsn),stdout=subprocess.DEVNULL,stderr=subprocess.PIPE) as server:
                try:
                    for _ in range(80):
                        if server.poll() is not None:
                            self.fail(server.stderr.read().decode())
                        try:
                            with urllib.request.urlopen(endpoint+"/v1/health/ready",timeout=1) as ready:
                                if ready.status == 200:
                                    break
                        except OSError:
                            time.sleep(0.05)
                    else:
                        self.fail("API readiness timeout")
                    def organizations(credential):
                        return urllib.request.urlopen(urllib.request.Request(endpoint+"/v1/organizations",
                             headers={"Authorization":"Bearer "+credential}),timeout=4)
                    with organizations(active) as response:
                        self.assertEqual(response.status,200)
                        self.assertIn(b"rollback-tenant",response.read())
                    with self.assertRaises(urllib.error.HTTPError) as error:
                        organizations(revoked)
                    self.assertEqual(error.exception.code,401)
                    error.exception.close()
                finally:
                    server.terminate()
        http_checks()
        def probe(*_):
            # Execute the binary actually selected by the active symlink.
            result = subprocess.check_output([self.active/"agentcapsule-admin","list-credentials"],
                                             env=private(dsn),text=True)
            self.assertIn("revoked-id", result)
            http_checks()
        self.api["smoke"] = probe
        sql(dsn, """INSERT INTO schema_migrations(version,name,checksum) VALUES (999,'future-schema',decode(repeat('ff',32),'hex'))""")
        with self.assertRaisesRegex(ValueError, "database migration history"):
            self.apply(plan)
        self.assertEqual(self.api["current"](),NEW)
        sql(dsn, "DELETE FROM schema_migrations WHERE version=999")
        result = self.api["main"](["host","operation","resume",plan["operation_id"]], "development")
        self.assertEqual(result["state"],"succeeded")
        self.assertEqual(sql(dsn,state_query),latest_state)
        self.assertEqual(sql(src,state_query),before)
        self.assertEqual(sql(dsn,"SELECT count(*) FROM platform_credentials WHERE id='revoked-id' AND revoked_at IS NULL"),"0")
        print(json.dumps(dict(rollback=result["state"],source=NEW,target=OLD,migrations=len(self.ledger),
                              physical_copy=True,data_and_revocations_sha256=digest(latest_state.encode()),
                              late_revocation_retained=True,source_database_unchanged=True,
                              incompatible_live_ledger_refused=True,
                              http_new={"active":200,"revoked":401},http_old={"active":200,"revoked":401},
                              old_admin_sha256=digest(self.binaries[OLD].read_bytes()),
                              new_admin_sha256=digest(self.binaries[NEW].read_bytes()))))
