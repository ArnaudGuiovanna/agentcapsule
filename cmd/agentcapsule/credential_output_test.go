package main

import (
	"bytes"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func TestRotationReservesPrivateOutputBeforeSending(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("AGENTCAPSULE_CONFIG_DIR", filepath.Join(dir, "config"))
	config, err := configDir()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "rotation.json")
	var requests, rotations atomic.Int32
	var serverFails atomic.Bool
	const secret = "only-in-the-private-output"
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		switch r.Method + " " + r.URL.Path {
		case "GET /v1/version":
			io.WriteString(w, `{"api_major":1,"cli_protocol":1}`)
		case "GET /v1/organizations/current":
			io.WriteString(w, `{"organization":{"id":"org_test"}}`)
		case "POST /v1/applications/app_test/rotate":
			rotations.Add(1)
			if b, err := readFile(path, true); err != nil || len(b) != 0 {
				t.Error("credential output must already be privately reserved and empty", err)
			}
			if serverFails.Load() {
				w.WriteHeader(http.StatusConflict)
				io.WriteString(w, `{"code":"invalid_transition"}`)
				return
			}
			json.NewEncoder(w).Encode(map[string]string{"token": secret})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	ca := filepath.Join(dir, "api.crt")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	c := connection{URL: server.URL, CA: ca, Kind: "organization", Organization: "org_test", Token: "context-token"}
	if err := saveContext(config, "test", c); err != nil {
		t.Fatal(err)
	}
	rotate := func() error {
		t.Helper()
		var output bytes.Buffer
		args := []string{"--context", "test", "app", "rotate", "app_test", "--output-file", path}
		err := run(t.Context(), args, strings.NewReader(""), &output, &output)
		if strings.Contains(output.String(), secret) {
			t.Fatal("credential reached the console")
		}
		return err
	}
	if err := os.WriteFile(path, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := rotate(); !errors.Is(err, os.ErrExist) || requests.Load() != 0 {
		t.Fatal("existing destination caused a request", requests.Load(), err)
	}
	if b, err := os.ReadFile(path); err != nil || string(b) != "keep" {
		t.Fatal("existing output was changed", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	serverFails.Store(true)
	var problem *apiError
	if err := rotate(); !errors.As(err, &problem) || problem.Status != http.StatusConflict || rotations.Load() != 1 {
		t.Fatal("expected a refused rotation", err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("refused rotation left an output file", err)
	}
	serverFails.Store(false)
	if err := rotate(); err != nil || rotations.Load() != 2 {
		t.Fatal("retry failed", err)
	}
	b, err := readFile(path, true)
	var result struct {
		Data struct{ Token string }
	}
	if err != nil || json.Unmarshal(b, &result) != nil || result.Data.Token != secret {
		t.Fatal("issued credential missing from private output", err)
	}
}
