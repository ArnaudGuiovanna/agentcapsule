package api

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
)

func TestHTTPHarnessImportsAreForThePlatformAndReleasesForMembers(t *testing.T) {
	l, _, owner := apiAgentsLab(t)
	ref := `{"reference":"ghcr.io/acme/echo@sha256:` + strings.Repeat("a", 64) + `"}`
	if r := call(t, l.server, "POST", "/v1/harness-imports", owner, "m", ref); r.Code != 403 {
		t.Fatal("a member requested an import", r.Code)
	}
	if r := call(t, l.server, "POST", "/v1/harness-imports", l.platform, "bad", `{"reference":"ghcr.io/acme/echo:latest"}`); r.Code != 400 {
		t.Fatal("an unpinned reference was accepted", r.Code)
	}
	made := call(t, l.server, "POST", "/v1/harness-imports", l.platform, "imp", ref)
	var imp controlplane.HarnessImport
	if made.Code != 202 || json.Unmarshal(made.Body.Bytes(), &imp) != nil || imp.State != "IMPORTING" {
		t.Fatal("import request", made.Code, made.Body.String())
	}
	if r := call(t, l.server, "POST", "/v1/harness-imports", l.platform, "imp", ref); r.Code != 202 || r.Header().Get("Idempotency-Replayed") != "true" {
		t.Fatal("replay", r.Code)
	}
	if r := call(t, l.server, "GET", "/v1/harness-imports/"+imp.ID, l.platform, "", ""); r.Code != 200 {
		t.Fatal("import view", r.Code)
	}
	if r := call(t, l.server, "GET", "/v1/harness-imports/"+imp.ID, owner, "", ""); r.Code != 403 {
		t.Fatal("a member read an import", r.Code)
	}
	// The worker side publishes the release.
	job, err := l.store.ClaimHarnessImport(t.Context(), "w", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	done, err := l.store.CompleteHarnessImport(t.Context(), job, controlplane.ImportedRelease{Name: "echo-oci", Version: "1.0.0",
		RootfsDigest: "sha256:" + strings.Repeat("b", 64), RootfsBytes: 1 << 20})
	if err != nil || done.State != "READY" {
		t.Fatal(done, err)
	}
	list := call(t, l.server, "GET", "/v1/harness-releases", owner, "", "")
	if list.Code != 200 || !strings.Contains(list.Body.String(), done.ReleaseID) || !strings.Contains(list.Body.String(), `"state":"READY"`) {
		t.Fatal("member release list", list.Code, list.Body.String())
	}
	if r := call(t, l.server, "GET", "/v1/harness-releases?include_deprecated=maybe", owner, "", ""); r.Code != 400 {
		t.Fatal("bad filter accepted", r.Code)
	}
	if r := call(t, l.server, "POST", "/v1/harness-releases/"+done.ReleaseID+"/deprecate", owner, "d", "{}"); r.Code != 403 {
		t.Fatal("a member deprecated a release", r.Code)
	}
	if r := call(t, l.server, "POST", "/v1/harness-releases/"+done.ReleaseID+"/deprecate", l.platform, "d", "{}"); r.Code != 200 || !strings.Contains(r.Body.String(), `"DEPRECATED"`) {
		t.Fatal("deprecate", r.Code, r.Body.String())
	}
	if r := call(t, l.server, "GET", "/v1/harness-releases", owner, "", ""); strings.Contains(r.Body.String(), done.ReleaseID) {
		t.Fatal("a deprecated release is still offered")
	}
	if r := call(t, l.server, "GET", "/v1/harness-releases?include_deprecated=true", l.platform, "", ""); !strings.Contains(r.Body.String(), done.ReleaseID) {
		t.Fatal("the full list misses the deprecated release")
	}
}
