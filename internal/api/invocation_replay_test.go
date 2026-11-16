package api

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/jackc/pgx/v5"
)

// POST /v1/invocations/{id}/replay (ADR 017): an owner or administrator puts
// a dead letter back in the queue; the requester cannot; a replay is
// idempotent; each refusal has its own code.
func TestHTTPReplayOfADeadLetter(t *testing.T) {
	l, at, owner := apiAgentsLab(t)
	transit, err := controlplane.NewTransit(l.store, "v1", map[string][]byte{"v1": bytes.Repeat([]byte{0x45}, 32)}, 7*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err = transit.ActivateKeys(t.Context()); err != nil {
		t.Fatal(err)
	}
	server, err := NewForHostWithTransit(l.store, l.server.accounts, "local", transit)
	if err != nil {
		t.Fatal(err)
	}
	server.SetDelegatedIdentityVerifier(l.verifier)
	l.server = server
	agent := apiActiveTenantAgent(t, l, owner, "replaying")
	bob := apiAddMember(t, l, owner, "bob", "agent_user")
	bobToken := l.sign(t, at, "bob-invoke", "bob", invokeScopes)
	assignment := `{"principal_id":"` + bob.PrincipalID + `","permissions":["read_metadata","invoke","read_content"]}`
	if r := call(t, l.server, "POST", "/v1/agents/"+agent+"/assignments", owner, "asg", assignment); r.Code != 201 {
		t.Fatal("assign", r.Code, r.Body.String())
	}
	db, err := pgx.Connect(t.Context(), l.dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close(t.Context())
	// deadLetter admits an invocation and lets it die unsent.
	deadLetter := func(key string, reached bool) string {
		t.Helper()
		r := call(t, l.server, "POST", "/v1/agents/"+agent+"/invocations", bobToken, key, `{"content":[{"type":"text","text":"x"}]}`)
		var v controlplane.Invocation
		if r.Code != 202 || json.Unmarshal(r.Body.Bytes(), &v) != nil {
			t.Fatal("invoke", r.Code, r.Body.String())
		}
		for _, q := range []string{
			`UPDATE agent_mailboxes SET delivery_state='DEAD',attempts=attempt_limit,may_have_reached=$2 WHERE instruction_id=$1`,
			`DELETE FROM outbox WHERE mailbox_id=(SELECT id FROM agent_mailboxes WHERE instruction_id=$1) AND $2 IN (true,false)`,
			`UPDATE platform_operations SET status='FAILED',error_code='delivery_failed',completed_at=clock_timestamp() WHERE id=$1 AND $2 IN (true,false)`,
			`UPDATE owner_instructions SET close_reason='attempts_exhausted' WHERE operation_id=$1 AND $2 IN (true,false)`,
		} {
			if _, err := db.Exec(t.Context(), q, v.ID, reached); err != nil {
				t.Fatal(err)
			}
		}
		return v.ID
	}
	dead := deadLetter("d1", false)
	path := "/v1/invocations/" + dead + "/replay"
	if r := call(t, l.server, "POST", path, bobToken, "r0", `{}`); r.Code != 403 {
		t.Fatal("the requester replayed", r.Code)
	}
	if r := call(t, l.server, "POST", path, owner, "r1", `{"ttl_seconds":0.5}`); r.Code != 400 {
		t.Fatal("bad window", r.Code)
	}
	if r := call(t, l.server, "POST", path, owner, "r2", `{"ttl_seconds":86401}`); r.Code != 400 {
		t.Fatal("window out of range", r.Code)
	}
	first := call(t, l.server, "POST", path, owner, "r3", `{}`)
	if first.Code != 202 || !strings.Contains(first.Body.String(), `"state":"accepted"`) || !strings.Contains(first.Body.String(), `"replayed_at"`) {
		t.Fatal("replay", first.Code, first.Body.String())
	}
	if r := call(t, l.server, "POST", path, owner, "r3", `{}`); r.Code != 202 || r.Header().Get("Idempotency-Replayed") != "true" {
		t.Fatal("idempotent replay", r.Code)
	}
	if r := call(t, l.server, "POST", path, owner, "r4", `{}`); r.Code != 409 || !strings.Contains(r.Body.String(), "invalid_transition") {
		t.Fatal("a pending instruction replayed", r.Code, r.Body.String())
	}
	reached := deadLetter("d2", true)
	if r := call(t, l.server, "POST", "/v1/invocations/"+reached+"/replay", owner, "r5", `{}`); r.Code != 409 || !strings.Contains(r.Body.String(), "outcome_unknown") {
		t.Fatal("an outcome unknown replayed", r.Code, r.Body.String())
	}
	if r := call(t, l.server, "GET", "/v1/invocations/"+dead, bobToken, "", ""); r.Code != 200 || !strings.Contains(r.Body.String(), `"replayed_at"`) {
		t.Fatal("the requester does not see the replay", r.Code, r.Body.String())
	}
}
