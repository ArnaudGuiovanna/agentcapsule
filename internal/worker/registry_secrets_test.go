//go:build linux

package worker

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/api"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/ociregistry"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/telemetry"
)

// REG-008: a rejected import leaks no registry secret. A hostile private
// registry echoes the credentials and the token it is sent, in its bodies,
// its headers and its challenges, while it refuses them. The imports are
// rejected or retried with a closed code, and neither the import's record in
// any table, nor the API's answers, logs and metrics, nor the errors the
// importer meets hold the password, the Basic header or the token.
func TestRejectedImportLeaksNoRegistrySecret(t *testing.T) {
	l := newImportLab(t)
	random := func(prefix string) string {
		b := make([]byte, 16)
		_, _ = rand.Read(b)
		return prefix + hex.EncodeToString(b)
	}
	const user = "ci-bot"
	password, token := random("registry-password-"), random("registry-token-")
	basic := base64.StdEncoding.EncodeToString([]byte(user + ":" + password))
	var mode atomic.Int32 // 0: the token service refuses; 1: the manifest is refused; 2: the registry fails
	var tokens atomic.Int32
	var registry *httptest.Server
	registry = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sent := r.Header.Get("Authorization")
		u, p, _ := r.BasicAuth()
		w.Header().Set("X-Echo", sent+" "+user+":"+password+" "+token)
		switch {
		case r.URL.Path == "/token":
			if mode.Load() == 0 || u != user || p != password {
				w.Header().Set("WWW-Authenticate", `Basic realm="you sent `+u+`:`+p+`"`)
				w.WriteHeader(http.StatusUnauthorized)
				fmt.Fprintf(w, `{"errors":[{"code":"UNAUTHORIZED","message":"bad credentials %s:%s, expected %s"}]}`, u, p, password)
				return
			}
			tokens.Add(1)
			fmt.Fprintf(w, `{"token":%q}`, token)
		case sent != "Bearer "+token:
			w.Header().Set("WWW-Authenticate", `Bearer realm="`+registry.URL+`/token",service="hostile",scope="repository:acme/echo:pull",error="invalid_token `+sent+`"`)
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprintf(w, "unauthorized %s", sent)
		case mode.Load() == 1:
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprintf(w, `{"errors":[{"code":"DENIED","message":"%s of %s:%s may not pull"}]}`, sent, user, password)
		default:
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, "internal error while checking %s for %s", sent, password)
		}
	}))
	defer registry.Close()
	host := strings.TrimPrefix(registry.URL, "http://")
	rule := ociregistry.Rule{Host: host, Repositories: []string{"acme/"}, Local: true}
	credentials := filepath.Join(t.TempDir(), "registry.json")
	if err := os.WriteFile(credentials, []byte(`{"username":"`+user+`","password":"`+password+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	c := ServiceConfig{Root: t.TempDir(), Registry: &ServiceRegistry{Cache: l.cache, MaxHarnessMiB: 64,
		Rules: []RegistryRule{{Rule: rule, CredentialsFile: credentials}}}}
	importer, err := c.OpenRegistry(l.store, "importer-hostile", false)
	if err != nil {
		t.Fatal(err)
	}
	l.importer = importer

	// The platform asks over the API, whose events and metrics are kept.
	server, err := api.New(l.store, l.accounts)
	if err != nil {
		t.Fatal(err)
	}
	metrics := telemetry.NewRegistry()
	var apiLog bytes.Buffer
	server.EnableTelemetry(metrics, &apiLog)
	var answers strings.Builder
	call := func(method, path, key, body string) (int, string) {
		t.Helper()
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+l.secret)
		if key != "" {
			r.Header.Set("Idempotency-Key", key)
			r.Header.Set("Content-Type", "application/json")
		}
		w := httptest.NewRecorder()
		server.ServeHTTP(w, r)
		fmt.Fprintln(&answers, w.Code, w.Header(), w.Body.String())
		return w.Code, w.Body.String()
	}
	var met []string
	imports := map[int32]string{}
	for _, step := range []struct {
		mode      int32
		digit     string
		state     string
		errorCode string
	}{{0, "a", "REJECTED", "access_denied"}, {1, "b", "REJECTED", "access_denied"}, {2, "c", "IMPORTING", ""}} {
		mode.Store(step.mode)
		reference := host + "/acme/echo@sha256:" + strings.Repeat(step.digit, 64)
		code, body := call("POST", "/v1/harness-imports", "import-"+step.digit, `{"reference":"`+reference+`"}`)
		var id string
		if _, after, ok := strings.Cut(body, `"id":"`); code == 202 && ok {
			id, _, _ = strings.Cut(after, `"`)
		}
		if id == "" {
			t.Fatal("import request", code, body)
		}
		imports[step.mode] = id
		l.importOne(t)
		code, body = call("GET", "/v1/harness-imports/"+id, "", "")
		if code != 200 || !strings.Contains(body, `"state":"`+step.state+`"`) || (step.errorCode != "" && !strings.Contains(body, `"error_code":"`+step.errorCode+`"`)) {
			t.Fatal("import", step.mode, code, body)
		}
		// The error the importer met, before its code, holds no secret either.
		ref, err := ociregistry.ParseReference(reference)
		if err != nil {
			t.Fatal(err)
		}
		_, err = importer.fetcher.Fetch(t.Context(), ref, t.TempDir())
		if err == nil {
			t.Fatal("the hostile registry served a package")
		}
		met = append(met, err.Error())
		if code, transient := classifyImport(err); code != map[int32]string{0: "access_denied", 1: "access_denied", 2: "unavailable"}[step.mode] || transient != (step.mode == 2) {
			t.Fatal("classification", step.mode, code, transient, err)
		}
	}
	if tokens.Load() == 0 {
		t.Fatal("the token service never issued its token: the manifest refusal was not reached")
	}
	// A reference that carries credentials is refused, and not echoed.
	if code, body := call("POST", "/v1/harness-imports", "userinfo", `{"reference":"`+user+`:`+password+`@`+host+`/acme/echo@sha256:`+strings.Repeat("d", 64)+`"}`); code != 400 || strings.Contains(body, password) {
		t.Fatal("a reference with credentials", code, body)
	}

	// Everything the platform wrote or answered.
	var exposition bytes.Buffer
	if _, err = metrics.WriteTo(&exposition); err != nil {
		t.Fatal(err)
	}
	var tables strings.Builder
	rows, err := l.db.Query(t.Context(), `SELECT tablename FROM pg_tables WHERE schemaname=current_schema()`)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for rows.Next() {
		var name string
		if err = rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		names = append(names, name)
	}
	rows.Close()
	if len(names) < 50 {
		t.Fatal("tables", names)
	}
	for _, name := range names {
		var dump string
		if err = l.db.QueryRow(t.Context(), `SELECT coalesce(string_agg(t::text, E'\n'),'') FROM `+name+` t`).Scan(&dump); err != nil {
			t.Fatal(name, err)
		}
		fmt.Fprintln(&tables, name, dump)
	}
	written := map[string]string{"tables": tables.String(), "API answers": answers.String(), "API events": apiLog.String(),
		"API metrics": exposition.String(), "importer errors": strings.Join(met, "\n")}
	for where, text := range written {
		for _, secret := range []string{password, password[len(password)-16:], basic, token, token[len(token)-16:]} {
			if strings.Contains(text, secret) {
				t.Errorf("%s hold a registry secret: %q", where, secret)
			}
		}
	}
	// The search reads what it should: the imports, their codes, the events.
	for where, want := range map[string]string{"tables": imports[1], "API answers": "access_denied", "API events": `"route":"/v1/harness-imports/{id}"`,
		"importer errors": "registry access denied"} {
		if !strings.Contains(written[where], want) {
			t.Errorf("%s lack %q", where, want)
		}
	}
}
