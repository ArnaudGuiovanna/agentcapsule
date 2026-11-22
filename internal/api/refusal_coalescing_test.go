package api

import (
	"context"
	"encoding/json"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
)

// L-04: in a window, the first attempt at each target is recorded in full,
// up to refusalTargets targets; the others are counted, and their number is
// recorded once at the window's end, with no target.
func TestRefusalWindowsCountRepeatedAttempts(t *testing.T) {
	s := noDatabaseServer(t)
	var mu sync.Mutex
	var counted []controlplane.RefusedAttempt
	done := make(chan struct{}, 4)
	s.guards.refusals.length = 200 * time.Millisecond
	s.guards.refusals.record = func(_ context.Context, p controlplane.Principal, a controlplane.RefusedAttempt) error {
		mu.Lock()
		defer mu.Unlock()
		if p.ID != "prn_bob" {
			t.Error("counted for", p.ID)
		}
		counted = append(counted, a)
		done <- struct{}{}
		return nil
	}
	bob := controlplane.Principal{Kind: "tenant", ID: "prn_bob", TenantID: "org_a"}
	attempt := func(action, target, reason string) controlplane.RefusedAttempt {
		return controlplane.RefusedAttempt{Action: action, Target: target, Reason: reason}
	}
	full := 0
	for i := 0; i < 5; i++ {
		if s.admitRefusal(bob, attempt("member.created", "", "forbidden")) {
			full++
		}
	}
	if full != 1 {
		t.Fatal("the same attempt five times, recorded in full", full)
	}
	// Another reason, another actor: their own windows.
	if !s.admitRefusal(bob, attempt("member.created", "", "invalid_json")) ||
		!s.admitRefusal(controlplane.Principal{Kind: "tenant", ID: "prn_eve", TenantID: "org_a"}, attempt("member.created", "", "forbidden")) {
		t.Fatal("another window was counted")
	}
	// Distinct targets are recorded in full up to refusalTargets.
	full = 0
	for i := 0; i < refusalTargets+3; i++ {
		if s.admitRefusal(bob, attempt("assignment.created", "agt_"+strings.Repeat(string(rune('a'+i)), 32), "not_found")) {
			full++
		}
	}
	if full != refusalTargets {
		t.Fatal("distinct targets recorded in full", full)
	}
	for i := 0; i < 2; i++ {
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("a window did not close")
		}
	}
	mu.Lock()
	got := map[string]int{}
	for _, a := range counted {
		if a.Target != "" || a.Reference != "" {
			t.Error("a count names a target", a)
		}
		got[a.Action+"/"+a.Reason] = a.Attempts
	}
	mu.Unlock()
	if len(got) != 2 || got["member.created/forbidden"] != 4 || got["assignment.created/not_found"] != 3 {
		t.Fatal("counts", got)
	}
	// A window that closed opens again with an attempt in full; FlushRefusals
	// records an open window's count at once.
	if !s.admitRefusal(bob, attempt("member.created", "", "forbidden")) || s.admitRefusal(bob, attempt("member.created", "", "forbidden")) {
		t.Fatal("the next window")
	}
	s.guards.refusals.length = time.Hour
	if !s.admitRefusal(bob, attempt("team.created", "", "forbidden")) || s.admitRefusal(bob, attempt("team.created", "", "forbidden")) {
		t.Fatal("an hour's window")
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the next window did not close")
	}
	s.FlushRefusals()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("the flush recorded nothing")
	}
	mu.Lock()
	last := counted[len(counted)-1]
	mu.Unlock()
	if last.Action != "team.created" || last.Attempts != 1 {
		t.Fatal("flushed", last)
	}
}

// L-04: a member refused the same action again and again leaves one event in
// full, then one event that counts the rest of the window; attempts at
// distinct targets are each recorded in full. The feed and the export carry
// the count.
func TestRepeatedRefusalsAreCountedInTheTrail(t *testing.T) {
	l, at, owner := apiAgentsLab(t)
	l.server.guards.refusals.length = 300 * time.Millisecond
	apiAddMember(t, l, owner, "bob", "agent_user")
	bob := l.sign(t, at, "bob-refused", "bob", allAgentScopes)
	for i := 0; i < 5; i++ {
		if r := call(t, l.server, "POST", "/v1/members", bob, "b"+strconv.Itoa(i), apiMemberBody(l, "carol", "org_admin")); r.Code != 403 {
			t.Fatal(r.Code, r.Body.String())
		}
	}
	guesses := []string{"agt_" + strings.Repeat("1", 32), "agt_" + strings.Repeat("2", 32)}
	for i, guess := range guesses {
		if r := call(t, l.server, "POST", "/v1/agents/"+guess+"/assignments", owner, "o"+strconv.Itoa(i), `{"principal_id":"prn_x","permissions":["invoke"]}`); r.Code != 404 {
			t.Fatal(r.Code, r.Body.String())
		}
	}
	type event struct {
		action, target, reason string
		attempts               int
	}
	refused := func(body []byte) []event {
		var page controlplane.AuditPage
		if err := json.Unmarshal(body, &page); err != nil {
			t.Fatal(err)
		}
		var out []event
		for _, e := range page.Items {
			if e.Outcome == "refused" {
				out = append(out, event{e.Action, e.Target, e.Reason, e.Attempts})
			} else if e.Attempts != 0 {
				t.Fatal("a done event with attempts", e)
			}
		}
		return out
	}
	r := call(t, l.server, "GET", "/v1/audit?limit=200", owner, "", "")
	want := []event{{"member.created", l.org.ID, "forbidden", 1}, {"assignment.created", guesses[0], "not_found", 1}, {"assignment.created", guesses[1], "not_found", 1}}
	if got := refused(r.Body.Bytes()); len(got) != 3 || got[0] != want[0] || got[1] != want[1] || got[2] != want[2] {
		t.Fatalf("before the window's end:\n got %v\nwant %v", got, want)
	}
	want = append(want, event{"member.created", l.org.ID, "forbidden", 4})
	deadline := time.Now().Add(10 * time.Second)
	for {
		r = call(t, l.server, "GET", "/v1/audit?limit=200", owner, "", "")
		got := refused(r.Body.Bytes())
		if len(got) == 4 {
			if got[3] != want[3] {
				t.Fatalf("the window's count: %v", got[3])
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the window's count was not recorded", got)
		}
		time.Sleep(50 * time.Millisecond)
	}
	from, to := url.QueryEscape(time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)), url.QueryEscape(time.Now().Add(time.Hour).UTC().Format(time.RFC3339))
	export := call(t, l.server, "GET", "/v1/audit/export?from="+from+"&to="+to, owner, "", "")
	if export.Code != 200 || strings.Count(export.Body.String(), `"attempts":1`) != 3 || strings.Count(export.Body.String(), `"attempts":4`) != 1 {
		t.Fatal("export", export.Code, export.Body.String())
	}
}
