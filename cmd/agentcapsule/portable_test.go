package main

import (
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/json"
	"encoding/pem"
	"errors"
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
	"time"
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
	var compatible atomic.Bool
	var authenticated, submissions, connections atomic.Int32
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
		case "POST /v1/agents/support/invocations":
			submissions.Add(1)
			if r.Header.Get("Idempotency-Key") == "" {
				t.Error("missing idempotency key")
			}
			fmt.Fprint(w, `{"id":"streamed"}`)
		case "GET /v1/invocations/streamed/events":
			if r.Header.Get("Authorization") != "Bearer "+token || r.Header.Get("Accept") != "text/event-stream" {
				t.Error("unexpected stream headers")
			}
			w.Header().Set("Content-Type", "text/event-stream")
			if connections.Add(1) == 1 {
				fmt.Fprint(w, "event: delta\nid: 1:1\ndata: {\"text\":\"hello\"}\n\nevent: delta\nid: 1:2\ndata: {\"text\":\"discard")
				return
			}
			if r.Header.Get("Last-Event-ID") != "1:1" {
				t.Error("lost replay cursor")
			}
			fmt.Fprint(w, ": heartbeat\n\nevent: delta\nid: 1:2\ndata: {\"text\":\" world\"}\n\nevent: end\ndata: {\"state\":\"completed\"}\n\n")
		case "GET /v1/invocations/long/events":
			w.Header().Set("Content-Type", "text/event-stream")
			fmt.Fprint(w, "event: state\ndata: {\"state\":\"working\",\"attempt\":1}\n\n")
			w.(http.Flusher).Flush()
			heartbeat := time.NewTicker(15 * time.Second)
			defer heartbeat.Stop()
			duration := time.NewTimer(5 * time.Minute)
			defer duration.Stop()
			for {
				select {
				case <-r.Context().Done():
					return
				case <-heartbeat.C:
					fmt.Fprint(w, ": heartbeat\n\n")
					w.(http.Flusher).Flush()
				case <-duration.C:
					fmt.Fprint(w, "event: end\ndata: {\"state\":\"completed\"}\n\n")
					return
				}
			}
		case "GET /v1/invocations/denied/events":
			http.Error(w, "denied", 403)
		case "GET /v1/invocations/missing/events":
			http.NotFound(w, r)
		case "GET /v1/invocations/failed/events", "GET /v1/invocations/expired/events", "GET /v1/invocations/canceled/events", "GET /v1/invocations/lost/events", "GET /v1/invocations/revoked/events":
			state := strings.Split(r.URL.Path, "/")[3]
			w.Header().Set("Content-Type", "text/event-stream")
			if state == "revoked" {
				fmt.Fprint(w, "event: revoked\ndata: {}\n\n")
			} else {
				fmt.Fprintf(w, "event: end\ndata: {\"state\":%q,\"error_code\":\"terminated\"}\n\n", state)
			}
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
	cmd := exec.CommandContext(t.Context(), path, "agent", "invoke", "support", "--file", "-", "--watch", "--text")
	cmd.Stdin = strings.NewReader(`{"content":[{"type":"text","text":"hello"}]}`)
	if out, err := cmd.Output(); err != nil || string(out) != "hello world" || submissions.Load() != 1 || connections.Load() != 2 {
		t.Fatal("submitting once and resuming the output", string(out), err, submissions.Load(), connections.Load())
	}
	for state, code := range map[string]int{"failed": 5, "expired": 5, "canceled": 5, "lost": 5, "revoked": 5, "denied": 3, "missing": 4} {
		cmd := exec.CommandContext(t.Context(), path, "invocation", "watch", state)
		out, err := cmd.Output()
		var exited *exec.ExitError
		if !errors.As(err, &exited) || exited.ExitCode() != code {
			t.Fatal(state, string(out), err)
		}
		if code == 5 && !strings.Contains(string(out), `"version":1,"event":`) {
			t.Fatal("missing JSON event", state, string(out))
		}
	}
	if os.Getenv("AGENTCAPSULE_TEST_LONG_STREAM") == "1" {
		start := time.Now()
		out := call("", true, "invocation", "watch", "long")
		if time.Since(start) < 5*time.Minute || strings.Count(out, `"event":`) != 2 || !strings.Contains(out, `"state":"completed"`) {
			t.Fatal("five-minute stream", out)
		}
	}

}
