package main

import (
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
)

// PRs exercise a native build. On tags, verify and execute the uploaded
// release bytes; missing inputs must never silently fall back to rebuilding.
func portableCLI(t *testing.T) (string, string) {
	t.Helper()
	target := runtime.GOOS + "-" + runtime.GOARCH
	if want := os.Getenv("AGENTCAPSULE_TEST_TARGET"); want != "" && target != want {
		t.Fatalf("native test process is %s, expected %s", target, want)
	}
	name := "agentcapsule-" + target
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	version := os.Getenv("AGENTCAPSULE_TEST_RELEASE")
	if version == "" {
		path := filepath.Join(t.TempDir(), name)
		build := exec.CommandContext(t.Context(), "go", "build", "-o", path, ".")
		build.Env = append(os.Environ(), "CGO_ENABLED=0")
		if out, err := build.CombinedOutput(); err != nil {
			t.Fatalf("build native CLI: %v: %s", err, out)
		}
		return path, "development"
	}
	dir := os.Getenv("AGENTCAPSULE_TEST_RELEASE_DIR")
	if !filepath.IsAbs(dir) {
		t.Fatal("expected an absolute release artifact directory")
	}
	path := filepath.Join(dir, name)
	index, err := os.ReadFile(filepath.Join(dir, "SHA256SUMS"))
	if err != nil || fmt.Sprintf("%x", sha256.Sum256(index)) != os.Getenv("AGENTCAPSULE_TEST_RELEASE_INDEX") {
		t.Fatal("release checksum index differs from the build job")
	}
	binary, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	digest := fmt.Sprintf("%x", sha256.Sum256(binary))
	if !strings.Contains("\n"+string(index), "\n"+digest+"  "+name+"\n") {
		t.Fatalf("%s does not match the release index", name)
	}
	info, err := buildinfo.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	settings := make(map[string]string)
	for _, setting := range info.Settings {
		settings[setting.Key] = setting.Value
	}
	commit, err := exec.CommandContext(t.Context(), "git", "rev-parse", "HEAD").Output()
	if err != nil || settings["vcs.revision"] != strings.TrimSpace(string(commit)) || settings["vcs.modified"] != "false" ||
		settings["GOOS"] != runtime.GOOS || settings["GOARCH"] != runtime.GOARCH || settings["CGO_ENABLED"] != "0" {
		t.Fatal("release CLI build information differs from the native target or tagged checkout")
	}
	if runtime.GOOS != "windows" {
		// Artifact downloads do not preserve executable mode bits.
		if err := os.Chmod(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("release=%s file=%s sha256=%s commit=%s", version, name, digest, settings["vcs.revision"])
	return path, version
}

func TestPortableCLI(t *testing.T) {
	path, version := portableCLI(t)
	dir := t.TempDir()
	t.Setenv("AGENTCAPSULE_CONFIG_DIR", filepath.Join(dir, "private context"))
	const token = "test-organization-credential"
	call := func(input string, ok bool, args ...string) string {
		t.Helper()
		cmd := exec.CommandContext(t.Context(), path, args...)
		cmd.Stdin = strings.NewReader(input)
		out, err := cmd.CombinedOutput()
		if strings.Contains(string(out), token) {
			t.Fatal("credential appeared in CLI output")
		}
		if (err == nil) != ok {
			t.Fatalf("%v: %v: %s", args, err, out)
		}
		return string(out)
	}
	var v struct {
		Data struct {
			Release  string `json:"release"`
			Major    int    `json:"api_major"`
			Protocol int    `json:"cli_protocol"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(call("", true, "version")), &v); err != nil || v.Data.Release != version || v.Data.Major != 1 || v.Data.Protocol != 1 {
		t.Fatal("unexpected CLI version or protocol", v, err)
	}
	// The local corpus commands work on every target, without a context.
	corpus := filepath.Join(dir, "corpus sources")
	call("", true, "corpus", "init", corpus, "--title", "Native corpus")
	if err := os.WriteFile(filepath.Join(corpus, "notes.md"), []byte("# Notes\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if out := call("", true, "corpus", "lint", corpus); !strings.Contains(out, `"valid":true`) || !strings.Contains(out, `"path":"notes.md"`) {
		t.Fatal("corpus lint", out)
	}
	const corID = "cor_00000000000000000000000000000011"
	const credID = "scr_00000000000000000000000000000012"
	const buildID = "cbd_00000000000000000000000000000013"
	var submitted, polled atomic.Int32
	var compatible atomic.Bool
	var authenticated atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method + " " + r.URL.Path {
		case "GET /v1/version":
			if r.Header.Get("Authorization") != "" {
				t.Error("credential on version check")
			}
			if compatible.Load() {
				io.WriteString(w, `{"api_major":1,"cli_protocol":1}`)
			} else {
				io.WriteString(w, `{"api_major":1,"cli_protocol":2}`)
			}
		case "GET /v1/organizations/current":
			if !compatible.Load() || r.Header.Get("Authorization") != "Bearer "+token {
				t.Error("unexpected authenticated request")
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			authenticated.Add(1)
			io.WriteString(w, `{"organization":{"id":"org_native"}}`)
		case "GET /v1/source-credentials":
			fmt.Fprintf(w, `{"items":[{"name":"finance-key","id":%q,"kind":"gitlab"}]}`, credID)
		case "POST /v1/corpora":
			var in struct {
				Name   string
				Source map[string]string
			}
			if json.NewDecoder(r.Body).Decode(&in) != nil || in.Name != "finance" || in.Source["credential_id"] != credID || in.Source["kind"] != "gitlab" || in.Source["path"] != "cours" || r.Header.Get("Idempotency-Key") == "" {
				t.Errorf("invalid creation %#v", in)
			}
			fmt.Fprintf(w, `{"id":%q}`, corID)
		case "GET /v1/corpora":
			if r.URL.Query().Get("name") != "finance" {
				t.Error("missing name filter")
			}
			fmt.Fprintf(w, `{"items":[{"name":"finance","id":%q}]}`, corID)
		case "POST /v1/corpora/" + corID + "/builds":
			submitted.Add(1)
			w.WriteHeader(202)
			fmt.Fprintf(w, `{"id":%q,"state":"QUEUED"}`, buildID)
		case "GET /v1/corpus-builds/" + buildID:
			if polled.Add(1) == 1 {
				fmt.Fprint(w, `{"state":"FETCHING_LFS"}`)
			} else {
				fmt.Fprint(w, `{"state":"REVIEW"}`)
			}
		case "GET /v1/corpus-builds/" + buildID + "/review-file":
			if r.URL.Query().Get("path") == "INDEX.md" {
				w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
				fmt.Fprint(w, "# Finance\n")
			} else {
				fmt.Fprintf(w, `{"schema":"agentcapsule.corpus-report/v1","build_id":%q,"commit":"0000000000000000000000000000000000000000","files":[],"totals":{}}`, buildID)
			}
		case "POST /v1/corpus-builds/" + buildID + "/try", "POST /v1/corpus-builds/" + buildID + "/publish", "POST /v1/corpus-releases/rel/deprecate":
			fmt.Fprint(w, `{}`)
		case "GET /v1/corpus-releases":
			if r.URL.Query().Get("corpus_id") != corID {
				t.Error("unexpected release filter", r.URL.RawQuery)
			}
			fmt.Fprint(w, `{"items":[]}`)
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	ca := filepath.Join(dir, "test CA.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	call("", true, "context", "add", "native", "--url", server.URL, "--ca", ca, "--kind", "organization", "--organization", "org_native")
	call("", true, "context", "use", "native")
	if out := call(token, false, "login", "--token-file", "-"); !strings.Contains(out, "incompatible") || authenticated.Load() != 0 {
		t.Fatal("incompatible peer was not rejected before authentication", out)
	}
	compatible.Store(true)
	call(token, true, "login", "--token-file", "-")
	context, err := loadContext(os.Getenv("AGENTCAPSULE_CONFIG_DIR"), "native")
	if err != nil || context.Token != token {
		t.Fatal("persisted private context unavailable", err)
	}
	if out := call("", true, "organization", "current"); !strings.Contains(out, `"org_native"`) || authenticated.Load() < 2 {
		t.Fatal("a fresh CLI process did not use its saved organization session", out)
	}
	call("", true, "corpus", "create", "finance", "--git", "https://gitlab.example.org/school/finance", "--ref", "main", "--path", "cours", "--credential", "finance-key")
	call("", true, "corpus", "build", "finance")
	call("", true, "operation", "wait", "--type", "corpus-build", buildID)
	if submitted.Load() != 1 || polled.Load() != 2 {
		t.Fatal("build and wait", submitted.Load(), polled.Load())
	}
	out := call("", true, "corpus-build", "files", buildID, "--status", "failed")
	if !strings.Contains(out, `"items":[]`) {
		t.Fatal("filtered report", out)
	}
	index := filepath.Join(dir, "review.md")
	call("", true, "corpus-build", "index", buildID, "--output-file", index)
	data, err := os.ReadFile(index)
	if err != nil || string(data) != "# Finance\n" {
		t.Fatal("exported review index", err, string(data))
	}
	call("", false, "corpus-build", "index", buildID, "--output-file", index)
	call("", true, "corpus-build", "try", buildID, "--agent", "agent")
	call("", true, "corpus-build", "publish", buildID, "--version", "3")
	call("", true, "corpus", "versions", "finance")
	call("", true, "corpus-release", "deprecate", "rel")

}
