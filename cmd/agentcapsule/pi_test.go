package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func TestPiProfilePersistsOnlyInSelectedContext(t *testing.T) {
	t.Setenv("AGENTCAPSULE_CONFIG_DIR", filepath.Join(t.TempDir(), "config"))
	dir, err := configDir()
	if err != nil {
		t.Fatal(err)
	}
	c := connection{URL: "https://example.test", Kind: "organization", Organization: "org1", Token: "private"}
	for _, n := range []string{"one", "two"} {
		if err = saveContext(dir, n, c); err != nil {
			t.Fatal(err)
		}
	}
	runLocal := func(args ...string) error {
		return run(t.Context(), args, strings.NewReader(""), io.Discard, io.Discard)
	}
	set := []string{"--context", "one", "pi", "profile", "set", "pi-model", "--provider", "capsule-openai", "--context-window", "64000", "--max-output-tokens", "2048"}
	if err = runLocal(set...); err != nil {
		t.Fatal(err)
	}
	if err = runLocal(append(set, "--typo", "value")...); err == nil {
		t.Fatal("accepted unused option")
	}
	if err = runLocal("--context", "two", "pi", "profile", "show", "pi-model"); err == nil {
		t.Fatal("profile shared across organizations")
	}
	c, err = loadContext(dir, "one")
	if err != nil || c.Token != "private" {
		t.Fatal(err)
	}
	b, err := piInvocation([]byte(`{"content":[{"type":"text","text":"read"}],"attachments":["att_1"]}`), c, "pi-model", false)
	if err != nil {
		t.Fatal(err)
	}
	var body struct {
		Content []struct {
			Type, Text string
			JSON       struct {
				Control map[string]any `json:"agentcapsule_pi"`
			}
		}
		Attachments []string
	}
	if err = json.Unmarshal(b, &body); err != nil || len(body.Content) != 2 || body.Content[0].JSON.Control["context_window"] != float64(64000) ||
		body.Content[1].Text != "read" || len(body.Attachments) != 1 {
		t.Fatal(string(b), err)
	}
	if _, err = piInvocation([]byte(`{"content":[]}`), c, "pi-model", false); err == nil {
		t.Fatal("empty prompt accepted")
	}
	if _, err = piInvocation([]byte(`{"content":[]}`), c, "", true); err == nil {
		t.Fatal("status accepted a prompt")
	}
	b, err = piInvocation([]byte("{}"), c, "", true)
	if err != nil || !bytes.Contains(b, []byte(`"action":"status"`)) {
		t.Fatal(err, string(b))
	}
}

func TestPiTemplateDelegationIsOptional(t *testing.T) {
	for _, flag := range []string{"", "true"} {
		b, err := piTemplate([]string{"lesson"}, options{"release": "v0.1.6", "alias": "pi-model", "corpus": "compagnon", "corpus-version": "1", "a2a": flag})
		if err != nil || bytes.Contains(b, []byte("agents.delegate")) != (flag != "") || !bytes.Contains(b, []byte("pi-linux@0.1.6")) {
			t.Fatal(err, string(b))
		}
	}
}

func TestPiImportRequiresBothRecordedSignatures(t *testing.T) {
	digest := func(c string) string { return "sha256:" + strings.Repeat(c, 64) }
	names := []string{"pi-agent", "agentcapsule-corpus-builder"}
	h := piHostReceipt{Schema: "agentcapsule.pi-host/v1", Release: "v0.1.6", Signer: digest("f"), Packages: map[string]string{
		names[0]: piRegistry + "@" + digest("a"), names[1]: piRegistry + "@" + digest("b")}}
	h.Image.Reference = "pi-linux@0.1.6"
	h.Image.Kernel, h.Image.Initrd = digest("c"), digest("d")
	h.Image.Features = []string{"corpus.mount"}
	for _, trusted := range []bool{true, false} {
		t.Run(map[bool]string{true: "signed", false: "existing unsigned image"}[trusted], func(t *testing.T) {
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/v1/version":
					io.WriteString(w, `{"api_major":1,"cli_protocol":1}`)
				case "/v1/platform/session", "/v1/system-images":
					io.WriteString(w, `{"id":"approved"}`)
				case "/v1/harness-imports":
					if r.Header.Get("Idempotency-Key") == "" {
						t.Error("missing key")
					}
					io.WriteString(w, `{"id":"imp_test"}`)
				case "/v1/harness-imports/imp_test":
					io.WriteString(w, `{"state":"READY"}`)
				case "/v1/harness-releases":
					items := []map[string]string{}
					for _, name := range names {
						signer := h.Signer
						if !trusted && name == names[0] {
							signer = ""
						}
						items = append(items, map[string]string{"name": name, "version": "0.1.6", "base": "agentcapsule-guest/2", "signer": signer, "digest": strings.Split(h.Packages[name], "@")[1]})
					}
					json.NewEncoder(w).Encode(map[string]any{"items": items})
				default:
					t.Errorf("unexpected request %s", r.URL)
					http.NotFound(w, r)
				}
			}))
			defer srv.Close()
			raw, _ := json.Marshal(h)
			api := &client{http: srv.Client(), connection: connection{URL: srv.URL, Kind: "platform", Token: "test"}}
			err := (console{in: bytes.NewReader(raw), out: io.Discard, errout: io.Discard}).piImport(t.Context(), api, options{"file": "-"})
			if (err == nil) != trusted {
				t.Fatalf("trusted=%v result %v", trusted, err)
			}
		})
	}
}
