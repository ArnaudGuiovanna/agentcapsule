//go:build linux && cgo

package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
)

// trimmed runs the command and returns its output without the final newline.
func trimmed(t *testing.T, args ...string) (string, int) {
	t.Helper()
	out, code := command(t, args...)
	return strings.TrimSpace(out), code
}

// Every destructive command (API-02, ADR 014) runs only when -confirm names
// its target again; -dry-run checks and changes nothing; each run is audited
// with its outcome.
func TestDestructiveCommandsAreConfirmedDryRunAndAudited(t *testing.T) {
	s, _ := operatorDatabase(t)
	platformSecret := secret("acpp_")
	if err := s.BootstrapPlatformToken(t.Context(), "guarded-platform", platformSecret, time.Hour); err != nil {
		t.Fatal(err)
	}
	creds, err := s.ListOperatorCredentials(t.Context())
	if err != nil || len(creds) != 1 {
		t.Fatal(creds, err)
	}
	id := creds[0].ID
	active := func() bool {
		_, err := s.Authenticate(t.Context(), platformSecret)
		return err == nil
	}
	audit := func() []controlplane.OperatorAuditEvent {
		events, err := s.ListOperatorAudit(t.Context(), "", 100)
		if err != nil {
			t.Fatal(err)
		}
		return events
	}
	for _, args := range [][]string{
		{"revoke-credential", "-kind", "platform", "-id", id},
		{"revoke-credential", "-kind", "platform", "-id", id, "-confirm", "ptok_other"},
		{"abandon-provisioning", "-agent-id", "agt_x"},
		{"configure-delegation", "-action", "revoke-token", "-operation-id", "op", "-tenant-id", "org", "-issuer", "https://i.example", "-token-id", "jti"},
		{"configure-delegation", "-action", "revoke-trust", "-operation-id", "op", "-tenant-id", "org", "-issuer", "https://i.example", "-audience", "a", "-confirm", "jti"},
		{"configure-delegation", "-action", "rotate", "-operation-id", "op", "-tenant-id", "org", "-issuer", "https://i.example", "-audience", "a"},
		{"set-audit-retention", "-days", "30"},
		{"set-audit-retention", "-days", "30", "-confirm", "31"},
	} {
		if out, code := trimmed(t, args...); code == 0 || out != "confirmation_required" {
			t.Fatal("ran without its confirmation:", args, out)
		}
	}
	if !active() || len(audit()) != 0 {
		t.Fatal("an unconfirmed command changed or recorded something")
	}
	var outcome controlplane.OperatorOutcome
	out, code := trimmed(t, "revoke-credential", "-kind", "platform", "-id", id, "-dry-run")
	if code != 0 || json.Unmarshal([]byte(out), &outcome) != nil || !outcome.DryRun || outcome.Outcome != "done" {
		t.Fatal("dry run", out, code)
	}
	if !active() || len(audit()) != 0 {
		t.Fatal("a dry run revoked or recorded")
	}
	out, code = trimmed(t, "revoke-credential", "-kind", "platform", "-id", id, "-confirm", id)
	if code != 0 || json.Unmarshal([]byte(out), &outcome) != nil || outcome.DryRun || outcome.Outcome != "done" || outcome.Target != id {
		t.Fatal("revocation", out, code)
	}
	if active() {
		t.Fatal("the confirmed revocation did not revoke")
	}
	if out, code = trimmed(t, "abandon-provisioning", "-agent-id", "agt_x", "-confirm", "agt_x"); code == 0 || out != "abandon_provisioning_rejected_not_found" {
		t.Fatal("abandon", out, code)
	}
	if out, code = trimmed(t, "set-audit-retention", "-days", "30", "-dry-run"); code != 0 || !strings.Contains(out, `"events":0`) || !strings.Contains(out, `"dry_run":true`) {
		t.Fatal("retention dry run", out, code)
	}
	if out, code = trimmed(t, "set-audit-retention", "-days", "30", "-confirm", "30"); code != 0 || !strings.Contains(out, `"outcome":"done"`) {
		t.Fatal("retention", out, code)
	}
	if out, code = trimmed(t, "set-audit-retention", "-keep-all"); code != 0 || !strings.Contains(out, `"target":"keep_all"`) {
		t.Fatal("keep all", out, code)
	}
	if out, code = trimmed(t, "set-audit-retention", "-days", "30", "-keep-all"); code == 0 || out != "configuration_required" {
		t.Fatal("ambiguous retention", out, code)
	}
	events := audit()
	want := []struct{ action, outcome string }{{"credential.revoked", "done"}, {"provisioning.abandoned", "refused"},
		{"audit.retention_set", "done"}, {"audit.retention_set", "done"}}
	if len(events) != len(want) {
		t.Fatal("operator audit", events)
	}
	for i, w := range want {
		if events[i].Action != w.action || events[i].Outcome != w.outcome || !strings.HasPrefix(events[i].Actor, "local-uid:") {
			t.Fatal("operator audit event", i, events[i])
		}
	}
	out, code = trimmed(t, "list-operator-audit")
	if code != 0 || strings.Count(out, "\n")+1 != len(want) || strings.Contains(out, platformSecret) {
		t.Fatal("list-operator-audit", out, code)
	}
}
