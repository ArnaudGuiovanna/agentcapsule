package api

import (
	"net/http/httptest"
	"testing"
	"time"
)

// A subscriber checks its rights at its first read, every eventRightsInterval
// and when its organization's policy changes; in between it reads only what
// is new (P-11, ADR 022 §6.3). A revocation thus cuts it off within the
// interval, at once on a policy notification, and no longer costs every
// wake a full authorization.
func TestSubscribersCheckTheirRightsOnTheirInterval(t *testing.T) {
	f := newRBACFixture(t)
	ctx := t.Context()
	token := f.token(t, "user")
	op := f.invoke(t, "user")
	req := httptest.NewRequest("GET", "/v1/invocations/"+op+"/events", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	p, ok := f.server.principal(httptest.NewRecorder(), req)
	if !ok {
		t.Fatal("no principal")
	}
	subscribe := func() *subscriber {
		t.Helper()
		sub := &subscriber{catalog: f.server.catalog, principal: p, op: op}
		if _, err := sub.read(ctx); err != nil || sub.authorized.IsZero() {
			t.Fatal("the first read checks the rights", err)
		}
		return sub
	}
	byTime, byPolicy := subscribe(), subscribe()
	checked := byTime.authorized
	if _, err := byTime.read(ctx); err != nil || !byTime.authorized.Equal(checked) {
		t.Fatal("a read within the interval checked the rights again", err)
	}
	var assignment string
	if err := f.db.QueryRow(ctx, "SELECT id FROM agent_assignments WHERE agent_id=$1 AND principal_id=$2 AND status='active'", f.ids["agent"], f.ids["user_principal"]).Scan(&assignment); err != nil {
		t.Fatal(err)
	}
	f.must(t, "owner", "POST", "/v1/agents/"+f.ids["agent"]+"/assignments/"+assignment+"/revoke", "{}", 200, nil)
	// Within the interval and without a notification: what is new only.
	if _, err := byTime.read(ctx); err != nil {
		t.Fatal("a read between two checks", err)
	}
	byTime.authorized = time.Now().Add(-eventRightsInterval)
	if _, err := byTime.read(ctx); !lostRights(err) {
		t.Fatal("the interval passed without a check of the rights", err)
	}
	byPolicy.recheck = true
	if _, err := byPolicy.read(ctx); !lostRights(err) {
		t.Fatal("a policy notification did not check the rights", err)
	}
}
