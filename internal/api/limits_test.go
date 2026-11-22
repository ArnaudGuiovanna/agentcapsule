package api

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/telemetry"
)

// A server whose store and accounts are empty: any request that reaches the
// database panics, so a test that passes proves its answers came first.
func noDatabaseServer(t *testing.T) *Server {
	t.Helper()
	s, err := NewForHost(&controlplane.Store{}, &controlplane.Accounts{}, "local")
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// S-07: each principal's bucket and its organization's admit a burst, then
// their rate; a refusal names its limit and when to retry, and takes nothing.
func TestRequestBucketsAdmitABurstThenTheirRate(t *testing.T) {
	l := newRequestLimiter(RequestLimits{PrincipalRate: 2, PrincipalBurst: 3, OrganizationRate: 1, OrganizationBurst: 4})
	now := time.Unix(1_800_000_000, 0)
	l.now = func() time.Time { return now }
	alice := controlplane.Principal{Kind: "tenant", ID: "prn_alice", TenantID: "org_a"}
	bob := controlplane.Principal{Kind: "tenant", ID: "prn_bob", TenantID: "org_a"}
	other := controlplane.Principal{Kind: "tenant", ID: "prn_carol", TenantID: "org_b"}
	for i := 0; i < 3; i++ {
		if limit, _ := l.admit(alice); limit != "" {
			t.Fatal("the burst is refused at", i, limit)
		}
	}
	limit, wait := l.admit(alice)
	if limit != "principal_rate" || wait <= 0 || wait > 500*time.Millisecond {
		t.Fatal("past the burst", limit, wait)
	}
	// Bob, of the same organization, takes its last request; then the
	// organization refuses him though his own bucket is full.
	if limit, _ = l.admit(bob); limit != "" {
		t.Fatal("bob", limit)
	}
	if limit, wait = l.admit(bob); limit != "organization_rate" || wait != time.Second {
		t.Fatal("the organization's bucket", limit, wait)
	}
	// Another organization is untouched, and a platform principal has no
	// organization's bucket.
	if limit, _ = l.admit(other); limit != "" {
		t.Fatal("another organization", limit)
	}
	platform := controlplane.Principal{Kind: "platform", ID: "admin"}
	for i := 0; i < 3; i++ {
		if limit, _ = l.admit(platform); limit != "" {
			t.Fatal("platform", i, limit)
		}
	}
	// A refused request took nothing: half a second gives alice one more.
	now = now.Add(500 * time.Millisecond)
	if limit, _ = l.admit(alice); limit != "organization_rate" {
		t.Fatal("alice after half a second", limit)
	}
	now = now.Add(500 * time.Millisecond)
	if limit, _ = l.admit(alice); limit != "" {
		t.Fatal("alice after a second", limit)
	}
	if err := (RequestLimits{PrincipalRate: 1}).Validate(); err == nil {
		t.Fatal("a rate without a burst")
	}
	if err := (RequestLimits{PrincipalRate: -1}).Validate(); err == nil {
		t.Fatal("a negative rate")
	}
	if err := (RequestLimits{}).Validate(); err != nil {
		t.Fatal("every limit off", err)
	}
}

// S-07, L-19: failed authentications count against their source (an IPv4
// address, an IPv6 /64). Past the limit, an unknown credential from that
// source is refused before any database work, with Retry-After; the events
// name the source by a pseudonym, never its address.
func TestFailedAuthenticationsLimitTheirSourceBeforeTheDatabase(t *testing.T) {
	s := noDatabaseServer(t)
	registry := telemetry.NewRegistry()
	var events bytes.Buffer
	s.EnableTelemetry(registry, &events)
	if err := s.LimitRequests(RequestLimits{FailuresPerMinute: 3}); err != nil {
		t.Fatal(err)
	}
	ask := func(source, token string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", "/v1/organizations/current", nil)
		r.RemoteAddr = source
		if token != "" {
			r.Header.Set("Authorization", token)
		}
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		return w
	}
	// Three failures that need no database: no header, a malformed one.
	for _, header := range []string{"", "Basic x", "Bearer a b"} {
		if w := ask("198.51.100.7:4000", header); w.Code != 401 {
			t.Fatal("a failure", w.Code, w.Body.String())
		}
	}
	// A credential the database would look up is refused first.
	w := ask("198.51.100.7:4001", "Bearer acps_"+strings.Repeat("x", 43)) // gitleaks:allow test fixture, not a credential
	if retry, err := strconv.Atoi(w.Header().Get("Retry-After")); w.Code != 429 || !strings.Contains(w.Body.String(), `"authentication_rate_limited"`) ||
		err != nil || retry < 15 || retry > 20 {
		t.Fatal("past the source's failures", w.Code, w.Header(), w.Body.String())
	}
	// An IPv6 source counts by its /64: another address of it is refused,
	// another /64 is not.
	for i, source := range []string{"[2001:db8:1:2::1]:1", "[2001:db8:1:2::2]:1", "[2001:db8:1:2:ffff::3]:1"} {
		if w = ask(source, ""); w.Code != 401 {
			t.Fatal("IPv6 failure", i, w.Code)
		}
	}
	if w = ask("[2001:db8:1:2:abcd::9]:1", "Bearer acps_"+strings.Repeat("y", 43)); w.Code != 429 { // gitleaks:allow test fixture, not a credential
		t.Fatal("the same /64", w.Code)
	}
	for remote, want := range map[string]string{"192.0.2.1:1234": "192.0.2.1", "[::ffff:192.0.2.9]:1": "192.0.2.9",
		"[2001:db8:1:3::5]:443": "2001:db8:1:3::/64", "[fe80::1%eth0]:1": "fe80::/64", "not an address": "unknown"} {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = remote
		if got := sourceOf(r); got != want {
			t.Fatal("source of", remote, got)
		}
	}
	// The events: one per failure and refusal, a pseudonym per source.
	var failures int
	pseudonyms := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(events.String()), "\n") {
		var e map[string]any
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatal(err, line)
		}
		if e["event"] == "authentication_failed" {
			failures++
			source, _ := e["source"].(string)
			if len(source) != telemetry.PseudonymLength || e["route"] != "/v1/organizations/current" || len(e["request_id"].(string)) != 32 {
				t.Fatal("event", line)
			}
			pseudonyms[source] = true
		}
	}
	if failures != 8 || len(pseudonyms) != 2 || pseudonyms[s.sourcePseudonym("198.51.100.7")] != true {
		t.Fatal("authentication_failed events", failures, pseudonyms, events.String())
	}
	var exposition bytes.Buffer
	if _, err := registry.WriteTo(&exposition); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`agentcapsule_api_limited_requests_total{limit="authentication_failures"} 2`, `agentcapsule_api_limited_requests_total{limit="principal_rate"} 0`} {
		if !strings.Contains(exposition.String(), want) {
			t.Fatal("missing", want, exposition.String())
		}
	}
	for _, address := range []string{"198.51.100.7", "2001:db8:1:2", "acps_"} {
		if strings.Contains(events.String()+exposition.String(), address) {
			t.Fatalf("%s reached the telemetry", address)
		}
	}
	// With the operator's key, a source's pseudonym is the same in every process.
	key := bytes.Repeat([]byte{7}, 32)
	a, b := noDatabaseServer(t), noDatabaseServer(t)
	if a.UseSourcePseudonymKey(key) != nil || b.UseSourcePseudonymKey(key) != nil || a.sourcePseudonym("198.51.100.7") != b.sourcePseudonym("198.51.100.7") ||
		a.sourcePseudonym("198.51.100.7") != telemetry.Pseudonym(key, "198.51.100.7") || a.UseSourcePseudonymKey(key[:31]) == nil {
		t.Fatal("configured pseudonym key")
	}
}

// S-09: the upload slots bound the process and each principal, and a slot
// comes back when its upload ends.
func TestUploadSlotsBoundTheProcessAndEachPrincipal(t *testing.T) {
	s := noDatabaseServer(t)
	if s.LimitUploads(3, 4) == nil || s.LimitUploads(0, 1) == nil || s.LimitUploads(1025, 1) == nil {
		t.Fatal("invalid bounds accepted")
	}
	if err := s.LimitUploads(3, 2); err != nil {
		t.Fatal(err)
	}
	u := &s.guards.uploads
	a1, _ := u.acquire("a")
	a2, _ := u.acquire("a")
	if a1 == nil || a2 == nil {
		t.Fatal("a principal's two slots")
	}
	if release, refused := u.acquire("a"); release != nil || refused != "principal_uploads" {
		t.Fatal("a third for the same principal", refused)
	}
	b1, _ := u.acquire("b")
	if release, refused := u.acquire("c"); release != nil || refused != "process_uploads" {
		t.Fatal("past the process's slots", refused)
	}
	a1()
	if release, refused := u.acquire("c"); release == nil {
		t.Fatal("a slot did not come back", refused)
	}
	a2()
	b1()
	var zero uploadSlots
	for i := 0; i < DefaultMaxPrincipalUploads; i++ {
		if release, _ := zero.acquire("p"); release == nil {
			t.Fatal("the default per-principal slots")
		}
	}
	if _, refused := zero.acquire("p"); refused != "principal_uploads" {
		t.Fatal("the default per-principal bound", refused)
	}
}

// S-08: one principal's and one organization's subscriptions are bounded in
// the process under -max-event-streams, each with its own code.
func TestEventStreamCeilingsPerPrincipalAndOrganization(t *testing.T) {
	s := noDatabaseServer(t)
	if s.LimitEventStreams(0, 1) == nil || s.LimitEventStreams(1, 100001) == nil {
		t.Fatal("invalid ceilings accepted")
	}
	if err := s.LimitEventStreams(3, 5); err != nil {
		t.Fatal(err)
	}
	e := &s.events
	e.limit = 7
	var releases []func()
	take := func(tenant, principal, op, want string) {
		t.Helper()
		release, refused := e.acquire(subscriptionKey{tenant, principal, op})
		if refused != want || (want == "") != (release != nil) {
			t.Fatal(tenant, principal, op, "refused", refused, "want", want)
		}
		if release != nil {
			releases = append(releases, release)
		}
	}
	take("org_a", "alice", "op1", "")
	take("org_a", "alice", "op2", "")
	take("org_a", "alice", "op3", "")
	take("org_a", "alice", "op4", "principal_streams")
	take("org_a", "bob", "op1", "")
	take("org_a", "bob", "op2", "")
	take("org_a", "carol", "op1", "organization_streams")
	take("org_b", "dave", "op1", "")
	take("org_b", "dave", "op2", "")
	take("org_c", "erin", "op1", "process_streams")
	releases[0]()
	take("org_a", "alice", "op4", "")
	for _, release := range releases[1:] {
		release()
	}
	if e.active != 0 || len(e.principals) != 0 || len(e.organizations) != 0 || len(e.counts) != 0 {
		t.Fatal("slots left after every release", e.active, e.principals, e.organizations, e.counts)
	}
	// The per-invocation bound comes first, with its own code.
	e.limit = 100
	if err := s.LimitEventStreams(10, 10); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4; i++ {
		take("org_d", "frank", "op", "")
	}
	take("org_d", "frank", "op", "invocation_streams")
	if DefaultMaxPrincipalEventStreams >= DefaultMaxOrganizationEventStreams || DefaultMaxOrganizationEventStreams*4 > DefaultMaxEventStreams {
		t.Fatal("the default ceilings are not well under the process's")
	}
}
