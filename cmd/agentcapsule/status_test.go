package main

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSupportArchiveExportsOnlyReviewedFields(t *testing.T) {
	const private = "private-test-value"
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body string
		switch r.URL.Path {
		case "/v1/health/ready":
			body = `{"status":"ready","authority":"normal","detail":"private-test-value"}`
		case "/v1/version":
			body = `{"api_major":1,"cli_protocol":1}`
		case "/v1/platform/session":
			body = `{"id":"private-test-value"}`
		case "/v1/platform/diagnostics":
			body = `{"observed_at":"2026-11-19T09:00:00Z","diagnostics":{"expected_migration":54,"message":"private-test-value","hosts":[{"host":"worker1","storage_reserved_mib":128,"agent":"private-test-value","queue":[{"kind":"provision","failing":1,"detail":"private-test-value"}]}]}}`
		default:
			http.NotFound(w, r)
			return
		}
		io.WriteString(w, body)
	}))
	defer srv.Close()
	api := &client{http: srv.Client(), connection: connection{URL: srv.URL, Kind: "platform", Token: private}}
	path := filepath.Join(t.TempDir(), "support.tar.gz")
	cli := console{out: io.Discard, outputFile: path}
	if err := cli.status(t.Context(), api, "support export", false); err != nil {
		t.Fatal(err)
	}
	if err := cli.status(t.Context(), api, "support export", false); !errors.Is(err, os.ErrExist) {
		t.Fatalf("existing archive: %v", err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	defer gz.Close()
	reader := tar.NewReader(gz)
	header, err := reader.Next()
	if err != nil || header.Name != "diagnostics.json" {
		t.Fatalf("archive header: %v, %v", header, err)
	}
	data, err := io.ReadAll(reader)
	if err != nil || strings.Contains(string(data), private) {
		t.Fatal("support report contains unexpected private data or could not be read", err)
	}
	var result struct {
		Version    int       `json:"version"`
		ObservedAt time.Time `json:"observed_at"`
		Report     struct {
			Platform platformSummary `json:"platform"`
			Checks   []finding       `json:"checks"`
		} `json:"report"`
	}
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	hosts := result.Report.Platform.Diagnostics.Hosts
	if result.Version != 1 || result.ObservedAt.IsZero() || len(hosts) != 1 || hosts[0].StorageReserved != 128 ||
		len(result.Report.Checks) != 2 || result.Report.Checks[0].State != "jobs_retrying" {
		t.Fatalf("incomplete support report: %s", data)
	}
	if _, err := reader.Next(); err != io.EOF {
		t.Fatal("unexpected additional archive member", err)
	}
}
