package main

import (
	"bytes"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVerifyApplicationAgainstIssuer(t *testing.T) {
	dir := t.TempDir()
	pin := appKey{"RSA", "key", "public-modulus", "AQAB"}
	for _, mode := range []string{"valid", "unadvertised", "wrong issuer", "http endpoint", "redirect", "no code", "no S256", "key drift", "encryption key", "disabled"} {
		t.Run(mode, func(t *testing.T) {
			basePath := "/realm"
			if mode == "unadvertised" {
				// Tenant-specific discovery and shared keys, as exposed by Entra.
				basePath = "/tenant-id/v2.0"
			}
			var issuer string
			s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" || r.Method != "GET" {
					t.Error("issuer received credentials or a mutation")
				}
				switch r.URL.Path {
				case basePath + "/.well-known/openid-configuration":
					m := map[string]any{"issuer": issuer, "authorization_endpoint": issuer + "/authorize", "token_endpoint": issuer + "/token",
						"jwks_uri": issuer + "/keys", "response_types_supported": []string{"code"}}
					switch mode {
					case "wrong issuer":
						m["issuer"] = issuer + "/other"
					case "http endpoint":
						m["token_endpoint"] = "http://invalid.test/token"
					case "redirect":
						http.Redirect(w, r, issuer+"/unexpected", http.StatusFound)
						return
					case "no code":
						m["response_types_supported"] = []string{"id_token"}
					case "no S256":
						m["code_challenge_methods_supported"] = []string{"plain"}
					case "unadvertised":
						m["jwks_uri"] = strings.TrimSuffix(issuer, basePath) + "/common/discovery/v2.0/keys"
					default:
						m["code_challenge_methods_supported"] = []string{"S256"}
					}
					json.NewEncoder(w).Encode(m)
				case "/realm/keys", "/common/discovery/v2.0/keys":
					key := map[string]string{"kty": pin.Kty, "kid": pin.Kid, "n": pin.N, "e": pin.E}
					if mode == "key drift" {
						key["n"] = "other-modulus"
					}
					if mode == "encryption key" {
						key["use"] = "enc"
					}
					json.NewEncoder(w).Encode(map[string]any{"keys": []any{key}})
				default:
					t.Error("unexpected issuer request", r.URL.Path)
				}
			}))
			issuer = "https://" + s.Listener.Addr().String() + basePath
			s.StartTLS()
			defer s.Close()
			path := filepath.Join(dir, "issuer.pem")
			if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.Certificate().Raw}), 0600); err != nil {
				t.Fatal(err)
			}
			app := registration{ID: "app_test", Tenant: "acme", Issuer: issuer, Status: "active", VerificationKeys: []appKey{pin}}
			if mode == "disabled" {
				app.Status = "disabled"
			}
			var out bytes.Buffer
			cli := console{out: &out}
			err := cli.verifyApplication(t.Context(), app, path, "req_test")
			if mode == "valid" || mode == "unadvertised" {
				want := "S256"
				if mode == "unadvertised" {
					want = mode
				}
				if err != nil || !strings.Contains(out.String(), `"advertised_pkce":"`+want+`"`) {
					t.Fatal(out.String(), err)
				}
			} else if err == nil || out.Len() != 0 {
				t.Fatal("expected a failed verification")
			}
		})
	}
}

func TestPublicApplicationHandoffChecksContextAndAllowsDisabled(t *testing.T) {
	var out bytes.Buffer
	cli := console{out: &out}
	cmd := action{name: "app connection", path: "/v1/applications/app1"}
	r := reply{Data: []byte(`{"id":"app1","tenant_id":"org1","issuer":"https://id.test","status":"disabled","provisioning_token":"private-proof"}`)}
	c := connection{Organization: "org1"}
	if err := cli.applicationCommand(t.Context(), cmd, c, r, ""); err != nil || !strings.Contains(out.String(), "disabled") || strings.Contains(out.String(), "private-proof") {
		t.Fatal("invalid handoff", err)
	}
	cmd.name = "app verify"
	if err := cli.applicationCommand(t.Context(), cmd, c, r, ""); err == nil {
		t.Fatal("disabled application passed verification")
	}
	for _, tc := range []struct{ path, org string }{
		{"/v1/applications/foreign", "org1"},
		{"/v1/applications/app1", "other"},
	} {
		cmd.path, c.Organization = tc.path, tc.org
		if err := cli.applicationCommand(t.Context(), cmd, c, r, ""); err == nil || err.Error() != "invalid application connection response" {
			t.Fatal("wrong application or context accepted", err)
		}
	}
}

func TestProvisioningTokenRequiresPrivateInput(t *testing.T) {
	if !hasSecret(map[string]any{"data": map[string]any{"provisioning_token": "proof"}}) {
		t.Fatal("public input accepted for a private application credential")
	}
}
