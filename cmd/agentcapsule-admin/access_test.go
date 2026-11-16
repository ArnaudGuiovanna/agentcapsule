//go:build linux && cgo

package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	svc "github.com/ArnaudGuiovanna/agentcapsule/internal/authorityservice"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/keyauthority"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/restoreauthority"
)

// serveAuthority runs an authority service in this process, standalone,
// and returns the flags that reach its API socket, and its catalogue.
func serveAuthority(t *testing.T) ([]string, *restoreauthority.Catalog) {
	t.Helper()
	dir := t.TempDir()
	keys, err := keyauthority.Initialize(t.Context(), filepath.Join(dir, "keys"))
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := restoreauthority.Initialize(t.Context(), filepath.Join(dir, "restore"), keys.Identity())
	if err != nil {
		t.Fatal(err)
	}
	uid := uint32(os.Getuid())
	server, err := svc.New(t.Context(), svc.Config{Catalog: catalog, Keys: keys, WorkerUID: uid, APIUID: uid})
	if err != nil {
		t.Fatal(err)
	}
	sockets, err := os.MkdirTemp("", "acadm-") // a socket path has at most 107 bytes
	if err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(sockets, "api.sock")
	listener, err := svc.Listen(socket, 0660)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx, nil, listener) }()
	t.Cleanup(func() {
		cancel()
		<-done
		catalog.Close()
		os.RemoveAll(sockets)
	})
	return []string{"-authority-socket", socket, "-restore-authority-id", catalog.Identity(), "-key-authority-id", keys.Identity()}, catalog
}

// A revoking command of agentcapsule-admin appends its access revocation
// record to the authority service before it commits (ADR 006 wave 5). In
// production it refuses without the service; standalone, the record needs
// nothing more and the revocation is confirmed. A dry run records nothing.
func TestRevokingCommandsAppendTheirRecord(t *testing.T) {
	s, _ := operatorDatabase(t)
	platformSecret := secret("acpp_")
	if err := s.BootstrapPlatformToken(t.Context(), "access-platform", platformSecret, time.Hour); err != nil {
		t.Fatal(err)
	}
	creds, err := s.ListOperatorCredentials(t.Context())
	if err != nil || len(creds) != 1 {
		t.Fatal(creds, err)
	}
	id := creds[0].ID
	t.Setenv("AGENTCAPSULE_MODE", "")
	if out, code := trimmed(t, "revoke-credential", "-kind", "platform", "-id", id, "-confirm", id); code == 0 || out != "authority_required_in_production" {
		t.Fatal("revoked without the authority service", out, code)
	}
	if _, err = s.Authenticate(t.Context(), platformSecret); err != nil {
		t.Fatal("refused, yet revoked", err)
	}
	flags, catalog := serveAuthority(t)
	if out, code := trimmed(t, append([]string{"revoke-credential", "-kind", "platform", "-id", id, "-dry-run"}, flags...)...); code != 0 || strings.Contains(out, "revocations") {
		t.Fatal("dry run", out, code)
	}
	if records, err := catalog.AccessRecords(t.Context()); err != nil || len(records) != 0 {
		t.Fatal("a dry run recorded", records, err)
	}
	if out, code := trimmed(t, append([]string{"revoke-credential", "-kind", "platform", "-id", id, "-confirm", id}, flags[:2]...)...); code == 0 || out != "configuration_required" {
		t.Fatal("half the authority flags", out, code)
	}
	out, code := trimmed(t, append([]string{"revoke-credential", "-kind", "platform", "-id", id, "-confirm", id}, flags...)...)
	var outcome controlplane.OperatorOutcome
	if code != 0 || json.Unmarshal([]byte(out), &outcome) != nil || outcome.Outcome != "done" || len(outcome.Revocations) != 1 ||
		outcome.Revocations[0].State != controlplane.RevocationConfirmed {
		t.Fatal("revocation", out, code)
	}
	records, err := catalog.AccessRecords(t.Context())
	if err != nil || len(records) != 1 || records[0].ID != outcome.Revocations[0].ID || records[0].Kind != "platform_credential" ||
		records[0].Organization != "" || len(records[0].Objects) != 1 || records[0].Objects[0][0] != id {
		t.Fatal("the authority's record", records, err)
	}
	if _, err = s.Authenticate(t.Context(), platformSecret); err == nil {
		t.Fatal("the revoked credential still authenticates")
	}
	// The service that does not answer: try again, nothing revoked.
	other := secret("acpp_")
	if err = s.BootstrapPlatformToken(t.Context(), "access-platform-2", other, time.Hour); err != nil {
		t.Fatal(err)
	}
	creds, err = s.ListOperatorCredentials(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	second := ""
	for _, c := range creds {
		if c.Status == "active" {
			second = c.ID
		}
	}
	dead := append([]string(nil), flags...)
	dead[1] = filepath.Join(filepath.Dir(flags[1]), "gone.sock")
	if out, code = trimmed(t, append([]string{"revoke-credential", "-kind", "platform", "-id", second, "-confirm", second}, dead...)...); code == 0 || out != "authority_service_unavailable" {
		t.Fatal("a service that does not answer", out, code)
	}
	if _, err = s.Authenticate(t.Context(), other); err != nil {
		t.Fatal("revoked without the record", err)
	}
}
