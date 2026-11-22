"""The bundled identity provider's exposure (S-19).

Keycloak listens on loopback only, with its administration and management,
one node and no JGroups port; agentcapsule-oidc-edge serves the public port
and forwards only the realms' pages and endpoints (internal/oidcedge, tested
in Go). The realm limits password guessing. The host helper moves an
installation's listeners there on update, and retires the bootstrap
administrator once a permanent one exists, against Keycloak's loopback API.
"""
import http.server
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch
import urllib.parse

ROOT = Path(__file__).resolve().parents[1]
HELPERS = ROOT / "internal/hostops"
OIDC = ROOT / "deploy/oidc"


def service(text):
    out = {}
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith(("#", "[")) and "=" in line:
            key, _, value = line.partition("=")
            out.setdefault(key, []).append(value)
    return out


class FakeKeycloak(http.server.BaseHTTPRequestHandler):
    admins = []
    password = "bootstrap-secret"  # gitleaks:allow test fixture, not a credential
    calls = None

    def reply(self, status, body=None):
        raw = json.dumps(body).encode() if body is not None else b""
        self.send_response(status)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def body(self):
        return self.rfile.read(int(self.headers.get("Content-Length", 0)))

    def do_POST(self):
        form = urllib.parse.parse_qs(self.body().decode())
        self.calls.append(("POST", self.path, form.get("username", [""])[0]))
        if self.path != "/realms/master/protocol/openid-connect/token" or form.get("client_id") != ["admin-cli"]:
            return self.reply(404)
        if form.get("password") != [self.password]:
            return self.reply(401, {"error": "invalid_grant"})
        self.reply(200, {"access_token": "token"})

    def authorized(self):
        return self.headers.get("Authorization") == "Bearer token"

    def do_PUT(self):
        settings = json.loads(self.body())
        self.calls.append(("PUT", self.path, settings.get("bruteForceProtected")))
        self.reply(204 if self.authorized() else 401)

    def do_GET(self):
        self.calls.append(("GET", self.path, None))
        if not self.authorized():
            return self.reply(401)
        if self.path.startswith("/admin/realms/master/roles/admin/users"):
            return self.reply(200, self.admins)
        if self.path.startswith("/admin/realms/master/users?"):
            name = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)["username"][0]
            return self.reply(200, [a for a in self.admins if a["username"] == name])
        self.reply(404)

    def do_DELETE(self):
        self.calls.append(("DELETE", self.path, None))
        self.reply(204 if self.authorized() else 401)

    def log_message(self, *args):
        pass


class OIDCEdgeTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.api = {"__name__": "host_test"}
        for file in ("setup.py", "diagnose.py", "host.py"):
            exec(compile((HELPERS / file).read_bytes(), file, "exec"), self.api)
        self.etc = self.root / "etc"
        self.etc.mkdir()
        self.api.update(STATE=self.root / "state", ACTIVE=self.root / "active", ETC=self.etc, UNIT_DIR=self.root / "units")
        self.profile = self.api["normalize_profile"](dict(api_name="api.example.net", oidc_name="id.example.net"))

    def test_shipped_units_keep_keycloak_on_loopback_behind_the_edge(self):
        keycloak = (OIDC / "agentcapsule-oidc.service").read_text()
        start = service(keycloak)["ExecStart"][0]
        self.assertNotIn("keycloak-tls", start, "Keycloak no longer holds the TLS key")
        self.assertNotIn("--publish", start)
        self.assertNotIn(" -p ", start)
        edge = service((OIDC / "agentcapsule-oidc-edge.service").read_text())
        self.assertEqual(edge["DynamicUser"], ["yes"])
        self.assertEqual(edge["LoadCredential"], ["tls.crt:/etc/agentcapsule/oidc-tls/tls.crt",
                                                  "tls.key:/etc/agentcapsule/oidc-tls/tls.key"])
        self.assertIn(" oidc-edge -listen ${OIDC_LISTEN} -upstream 127.0.0.1:9445 ", edge["ExecStart"][0])
        self.assertEqual(edge["CapabilityBoundingSet"], [""])

    def test_realm_limits_password_guessing(self):
        realm = json.loads((OIDC / "realm.json").read_text())
        self.assertIs(realm["bruteForceProtected"], True)
        self.assertIs(realm["permanentLockout"], False)
        self.assertLessEqual(realm["failureFactor"], 10)
        self.assertGreaterEqual(realm["maxFailureWaitSeconds"], 300)
        self.assertEqual({k: realm[k] for k in self.api["BRUTE_FORCE"]}, self.api["BRUTE_FORCE"])

    def test_update_moves_an_installation_to_the_loopback_listener(self):
        legacy = {"KC_DB": "postgres", "KC_DB_PASSWORD": "db-secret",  # gitleaks:allow test fixture, not a credential
                  "KC_HOSTNAME": "https://old:9444", "KC_HTTPS_PORT": "9444",
                  "KC_HTTPS_CERTIFICATE_FILE": "/keycloak-tls/tls.crt",
                  "KC_HTTPS_CERTIFICATE_KEY_FILE": "/keycloak-tls/tls.key", "KC_BOOTSTRAP_ADMIN_USERNAME": "operator",
                  "KC_BOOTSTRAP_ADMIN_PASSWORD": "x", "MONAPP_REDIRECT_URI": "https://m/cb"}
        (self.etc / "oidc.env").write_text("".join(f"{k}={v}\n" for k, v in legacy.items()))
        self.api["oidc_listeners"](self.profile)
        values = self.api["read_oidc_env"]()
        for key in ("KC_HTTPS_PORT", "KC_HTTPS_CERTIFICATE_FILE", "KC_HTTPS_CERTIFICATE_KEY_FILE"):
            self.assertNotIn(key, values)
        self.assertEqual((values["KC_HTTP_HOST"], values["KC_HTTP_PORT"], values["KC_CACHE"]), ("127.0.0.1", "9445", "local"))
        self.assertEqual(values["KC_HOSTNAME"], "https://id.example.net:9444")
        self.assertEqual(values["KC_HOSTNAME_ADMIN"], "http://localhost:9445")
        self.assertEqual((values["KC_PROXY_HEADERS"], values["KC_PROXY_TRUSTED_ADDRESSES"]), ("xforwarded", "127.0.0.1/32"))
        self.assertEqual((values["KC_HEALTH_ENABLED"], values["KC_METRICS_ENABLED"]), ("false", "false"))
        for key in ("KC_DB_PASSWORD", "KC_BOOTSTRAP_ADMIN_PASSWORD", "MONAPP_REDIRECT_URI"):
            self.assertEqual(values[key], legacy[key])
        self.assertEqual((self.etc / "oidc-edge.env").read_text(),
                         'OIDC_LISTEN="0.0.0.0:9444"\nOIDC_NAME="id.example.net"\n')
        self.assertEqual((self.etc / "oidc.env").stat().st_mode & 0o777, 0o600)

    def test_both_units_are_installed_and_the_edge_follows_keycloak(self):
        active = self.root / "active"
        (active / "oidc").mkdir(parents=True)
        for name in ("agentcapsule-oidc.service", "agentcapsule-oidc-edge.service"):
            (active / "oidc" / name).write_bytes((OIDC / name).read_bytes())
        ref = next(w for w in service((OIDC / "agentcapsule-oidc.service").read_text())["ExecStart"][0].split()
                   if w.startswith("quay.io/keycloak/keycloak@"))
        (active / "offline-images.json").write_text(json.dumps([dict(service="oidc", ref=ref, tag="localhost/kc:1")]))
        self.assertEqual(self.api["oidc_edge"](), ())
        with patch.dict(self.api, OIDC_LIFECYCLE=b"helper", write_file=self.write), patch("os.chown"):
            self.api["setup_oidc_unit"]()
        self.assertIn("localhost/kc:1", self.written["agentcapsule-oidc.service"])
        self.assertIn("oidc-edge", self.written["agentcapsule-oidc-edge.service"])

    written = None

    def write(self, path, data, mode=0o600):
        self.written = self.written or {}
        self.written[Path(path).name] = data.decode()
        if Path(path).parent == self.root / "units":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
            Path(path).write_bytes(data)

    def test_suspension_and_start_include_the_installed_edge(self):
        units = self.root / "units"
        units.mkdir()
        (units / "agentcapsule-oidc-edge.service").write_text("[Service]\n")
        calls = []
        with patch.dict(self.api, run=lambda *a, **k: calls.append(a)):
            (self.root / "state").mkdir()
            self.api["suspend_services"]()
        self.assertEqual(calls[-1][:3], ("systemctl", "stop", "agentcapsule-oidc-edge"))

    def test_profile_reserves_keycloaks_loopback_port(self):
        for field in ("api_port", "oidc_port"):
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.api["normalize_profile"]({field: 9445})

    def keycloak(self, admins, password="bootstrap-secret"):  # gitleaks:allow test fixture, not a credential
        handler = type("Handler", (FakeKeycloak,), dict(admins=admins, password=password, calls=[]))
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        self.api["OIDC_LOOPBACK"] = f"http://127.0.0.1:{server.server_port}"
        (self.etc / "oidc.env").write_text("KC_DB=postgres\nKC_BOOTSTRAP_ADMIN_USERNAME=operator\n"
                                           "KC_BOOTSTRAP_ADMIN_PASSWORD=bootstrap-secret\n")  # gitleaks:allow test fixture
        return handler.calls

    def test_bootstrap_admin_is_kept_until_a_permanent_one_exists(self):
        calls = self.keycloak([dict(id="b1", username="operator", enabled=True)])
        self.assertEqual(self.api["harden_oidc"](), "kept")
        self.assertIn(("PUT", "/admin/realms/master", True), calls)
        self.assertIn(("PUT", "/admin/realms/agentcapsule", True), calls)
        self.assertFalse([c for c in calls if c[0] == "DELETE"])
        self.assertIn("KC_BOOTSTRAP_ADMIN_PASSWORD", self.api["read_oidc_env"]())
        with self.assertRaisesRegex(ValueError, "permanent administrator"):
            self.api["harden_oidc"](required=True)

    def test_bootstrap_admin_is_retired_once_another_admin_exists(self):
        calls = self.keycloak([dict(id="b1", username="operator", enabled=True),
                               dict(id="p1", username="alice", enabled=True)])
        self.assertEqual(self.api["harden_oidc"](), "retired")
        self.assertIn(("DELETE", "/admin/realms/master/users/b1", None), calls)
        self.assertEqual(self.api["read_oidc_env"](), {"KC_DB": "postgres"})
        calls.clear()
        self.assertEqual(self.api["harden_oidc"](), "retired")
        self.assertEqual(calls, [], "nothing left to retire")

    def test_a_disabled_admin_does_not_count(self):
        self.keycloak([dict(id="b1", username="operator", enabled=True), dict(id="p1", username="old", enabled=False)])
        self.assertEqual(self.api["harden_oidc"](), "kept")

    def test_refused_credentials_change_nothing(self):
        calls = self.keycloak([dict(id="p1", username="alice", enabled=True)], password="changed")
        self.assertEqual(self.api["harden_oidc"](), "credentials_refused")
        self.assertIn("KC_BOOTSTRAP_ADMIN_PASSWORD", self.api["read_oidc_env"]())
        self.assertEqual([c[0] for c in calls], ["POST"])
        with self.assertRaisesRegex(ValueError, "refused"):
            self.api["harden_oidc"](required=True)

    def test_keycloak_is_reached_without_any_proxy(self):
        self.keycloak([dict(id="b1", username="operator", enabled=True)])
        with patch.dict("os.environ", {"http_proxy": "http://192.0.2.1:9", "HTTP_PROXY": "http://192.0.2.1:9"}):
            self.assertEqual(self.api["harden_oidc"](), "kept")


if __name__ == "__main__":
    unittest.main()
