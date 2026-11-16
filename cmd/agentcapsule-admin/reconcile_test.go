//go:build linux && cgo

package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authoritylog"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/restoreauthority"
)

// agentcapsule-admin reconcile (ADR 006 wave 7) runs on the authority
// service's API socket with the API's three flags: it replays a revocation
// the authority holds and PostgreSQL lacks, prints what it did, records the
// epoch, and does nothing more when run again.
func TestReconcileCommand(t *testing.T) {
	s, _ := operatorDatabase(t)
	platformSecret := secret("acpp_")
	if err := s.BootstrapPlatformToken(t.Context(), "reconcile-platform", platformSecret, time.Hour); err != nil {
		t.Fatal(err)
	}
	creds, err := s.ListOperatorCredentials(t.Context())
	if err != nil || len(creds) != 1 {
		t.Fatal(creds, err)
	}
	flags, catalog := serveAuthority(t)
	// The credential's revocation reached the authority, not this database.
	record := restoreauthority.AccessRecord{ID: "arv_" + strings.Repeat("7", 32), Kind: authoritylog.AccessPlatformCredential,
		Objects: [][]string{{creds[0].ID}}}
	if _, err = catalog.AppendAccess(t.Context(), record); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AGENTCAPSULE_MODE", "") // production: the database is on a Unix socket
	if out, code := trimmed(t, "reconcile"); code == 0 || out != "configuration_required" {
		t.Fatal("without the authority flags", out, code)
	}
	wrong := append([]string{"reconcile"}, flags...)
	wrong[4] = "restoreauth_" + strings.Repeat("0", 32)
	if out, code := trimmed(t, wrong...); code == 0 || out != "authority_identity_mismatch" {
		t.Fatal("another installation's authorities", out, code)
	}
	out, code := trimmed(t, append([]string{"reconcile"}, flags...)...)
	var r controlplane.Reconciliation
	if code != 0 || json.Unmarshal([]byte(out), &r) != nil || r.Epoch != 1 || r.RestoreAuthority != catalog.Identity() || r.Replayed != 1 {
		t.Fatal("the reconciliation", out, code)
	}
	if _, err = s.Authenticate(t.Context(), platformSecret); err == nil {
		t.Fatal("the revocation was not replayed")
	}
	if ok, err := s.Reconciled(t.Context(), 1); err != nil || !ok {
		t.Fatal("epoch 1", ok, err)
	}
	out, code = trimmed(t, append([]string{"reconcile"}, flags...)...)
	if code != 0 || json.Unmarshal([]byte(out), &r) != nil || r.Replayed != 0 {
		t.Fatal("run again", out, code)
	}
}
