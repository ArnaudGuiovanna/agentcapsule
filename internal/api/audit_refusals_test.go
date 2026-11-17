package api

import (
	"bytes"
	"encoding/json"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/jackc/pgx/v5/pgxpool"
)

// unauditedRoutes are the routes that change something and are not
// administrative actions: work given to an agent, its results, and the
// historical owner domain. Their refusals stay out of the trail.
var unauditedRoutes = []string{
	"POST /v1/agents/{id}/messages", "POST /v1/agents/{id}/invocations", "POST /v1/invocations/{id}/cancel",
	"POST /v1/attachments/{id}/link", "POST /v1/invocations/{id}/result/link",
	"POST /v1/users", "POST /v1/users/{id}/tokens", "PUT /v1/me/messaging-settings",
	"POST /v1/me/inbox/requests/{id}/accept", "POST /v1/me/inbox/requests/{id}/decline", "POST /v1/agent-requests/{id}/cancel",
}

// Every route that changes something is either an audited action, whose
// refusals join the trail, or listed as not administrative; every audited
// action is a route the server serves, under a name its trail can hold.
func TestEveryAuditedRouteIsServed(t *testing.T) {
	served := rbacServerRoutes()
	mutations := map[string]bool{}
	for _, r := range rbacRoutes {
		if r.Method == "GET" {
			continue
		}
		key := r.Method + " " + served[rbacPattern(r.Path)]
		mutations[key] = true
		if _, ok := auditedRoutes[key]; !ok && !slices.Contains(unauditedRoutes, key) {
			t.Error("a route that changes something is neither audited nor listed as not administrative:", key)
		}
	}
	action := regexp.MustCompile(`^[a-z_]+(\.[a-z_]+){1,2}$`)
	for key, route := range auditedRoutes {
		if !mutations[key] {
			t.Error("an audited route the server does not serve:", key)
		}
		if !action.MatchString(route.action) {
			t.Error("an action the trail cannot hold:", route.action)
		}
		for _, name := range []string{route.target, route.reference} {
			if name != "" && !strings.Contains(key, "{"+name+"}") {
				t.Error(key, "names no path value", name)
			}
		}
	}
	for _, key := range unauditedRoutes {
		if !mutations[key] {
			t.Error("a route listed as not administrative that the server does not serve:", key)
		}
	}
}

// TEN-009: the organization's refused administrative attempts join its trail
// with outcome refused: who, when, the action, the identifiers the path
// named and the refusal's code. A refusal for want of a role, a validation
// refusal, a guessed identifier, a technical account's attempt and a
// member's attempt at a platform route are recorded; the request's body is
// not. Reads, invocations and unauthenticated requests leave no event.
func TestRefusedAdministrativeAttemptsJoinTheTrail(t *testing.T) {
	l, at, owner := apiAgentsLab(t)
	transit, err := controlplane.NewTransit(l.store, "v1", map[string][]byte{"v1": bytes.Repeat([]byte{0x46}, 32)}, 7*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err = transit.ActivateKeys(t.Context()); err != nil {
		t.Fatal(err)
	}
	if l.server, err = NewForHostWithTransit(l.store, l.server.accounts, "local", transit); err != nil {
		t.Fatal(err)
	}
	l.server.SetDelegatedIdentityVerifier(l.verifier)
	agent := apiActiveTenantAgent(t, l, owner, "audited")
	apiAddMember(t, l, owner, "bob", "agent_user")
	bob := l.sign(t, at, "bob-all", "bob", allAgentScopes)
	principalOf := func(token string) string {
		t.Helper()
		p, err := l.store.AuthenticateDelegation(t.Context(), l.verifier, token)
		if err != nil {
			t.Fatal(err)
		}
		return p.ID
	}
	ownerID, bobID := principalOf(owner), principalOf(bob)
	var account controlplane.ServiceAccount
	if r := call(t, l.server, "POST", "/v1/service-accounts", owner, "bot", `{"name":"bot","role":"auditor"}`); r.Code != 201 || json.Unmarshal(r.Body.Bytes(), &account) != nil {
		t.Fatal(r.Code, r.Body.String())
	}
	var issued controlplane.IssuedServiceToken
	expires := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	if r := call(t, l.server, "POST", "/v1/service-accounts/"+account.ID+"/tokens", owner, "bot-token", `{"scopes":["org:read","audit:read"],"expires_at":"`+expires+`"}`); r.Code != 201 || json.Unmarshal(r.Body.Bytes(), &issued) != nil {
		t.Fatal(r.Code, r.Body.String())
	}
	bot, err := l.store.Authenticate(t.Context(), issued.Token)
	if err != nil {
		t.Fatal(err)
	}
	const planted = "PLANTED-BODY-TEXT"
	guessed := "agt_" + strings.Repeat("0", 32)
	type refusal struct{ action, actor, target, reference, reason string }
	var want []refusal
	attempt := func(token, method, path, key, body string, status int, expected *refusal) {
		t.Helper()
		if r := call(t, l.server, method, path, token, key, body); r.Code != status {
			t.Fatal(method, path, r.Code, r.Body.String())
		}
		if expected != nil {
			want = append(want, *expected)
		}
	}
	// A member without the role.
	attempt(bob, "POST", "/v1/members", "b1", apiMemberBody(l, "carol", "org_admin"), 403, &refusal{"member.created", bobID, l.org.ID, "", "forbidden"})
	// Validation: a body the route refuses, and no idempotency key.
	attempt(owner, "POST", "/v1/teams", "o1", `{"name":"`+planted+`","unknown":true}`, 400, &refusal{"team.created", ownerID, l.org.ID, "", "invalid_json"})
	attempt(owner, "POST", "/v1/members", "", apiMemberBody(l, "dave", "agent_user"), 400, &refusal{"member.created", ownerID, l.org.ID, "", "idempotency_key_required"})
	// A guessed identifier is recorded as the target it named; a name that
	// is not an identifier is not kept.
	attempt(owner, "POST", "/v1/agents/"+guessed+"/assignments", "o2", `{"principal_id":"`+bobID+`","permissions":["invoke"]}`, 404, &refusal{"assignment.created", ownerID, guessed, "", "not_found"})
	attempt(owner, "POST", "/v1/llm/aliases/"+url.PathEscape(planted)+"/prices", "o3", `{"input_micro_per_mtok":1}`, 400, &refusal{"llm.alias.prices_set", ownerID, l.org.ID, "", "invalid_request"})
	attempt(bob, "POST", "/v1/agents/"+agent+"/assignments/asg_"+strings.Repeat("1", 32)+"/revoke", "b2", `{}`, 403, nil)
	want = append(want, refusal{"assignment.revoked", bobID, agent, "asg_" + strings.Repeat("1", 32), "forbidden"})
	// A technical account, and a member's attempt at a platform route.
	attempt(issued.Token, "POST", "/v1/teams", "s1", `{"name":"bots"}`, 403, &refusal{"team.created", bot.ID, l.org.ID, "", "forbidden"})
	attempt(bob, "POST", "/v1/organizations", "b3", `{"name":"`+planted+`","initial_owner":{"issuer":"https://client.example","subject":"x","display_name":"X"}}`, 403, &refusal{"organization.created", bobID, l.org.ID, "", "forbidden"})
	// Not recorded: a read, an invocation, an unauthenticated attempt, a
	// method the route does not serve.
	attempt(bob, "GET", "/v1/audit", "", "", 403, nil)
	attempt(bob, "POST", "/v1/agents/"+agent+"/invocations", "b4", `{"content":[{"type":"text","text":"`+planted+`"}]}`, 404, nil)
	attempt("", "POST", "/v1/members", "u1", apiMemberBody(l, "eve", "org_owner"), 401, nil)
	attempt(owner, "PATCH", "/v1/members", "o4", `{}`, 405, nil)
	// What succeeds is recorded as done.
	attempt(owner, "POST", "/v1/teams", "o5", `{"name":"done"}`, 201, nil)

	r := call(t, l.server, "GET", "/v1/audit?limit=200", owner, "", "")
	var page controlplane.AuditPage
	if r.Code != 200 || json.Unmarshal(r.Body.Bytes(), &page) != nil {
		t.Fatal("audit", r.Code, r.Body.String())
	}
	var got []refusal
	done := map[string]bool{}
	for _, e := range page.Items {
		switch e.Outcome {
		case "refused":
			got = append(got, refusal{e.Action, e.Actor, e.Target, e.Reference, e.Reason})
		case "done":
			if e.Reason != "" {
				t.Fatal("a done event with a refusal's reason", e)
			}
			done[e.Action] = true
		default:
			t.Fatal("an event without an outcome", e)
		}
	}
	if !slices.Equal(got, want) {
		t.Fatalf("refused attempts in the trail:\n got %v\nwant %v", got, want)
	}
	for _, action := range []string{"organization.created", "member.created", "agent.created", "service_account.created", "token.issued", "team.created"} {
		if !done[action] {
			t.Fatal("the trail lacks the done event", action)
		}
	}
	// The export holds the same, and neither holds the bodies.
	from, to := url.QueryEscape(time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)), url.QueryEscape(time.Now().Add(time.Hour).UTC().Format(time.RFC3339))
	export := call(t, l.server, "GET", "/v1/audit/export?from="+from+"&to="+to, owner, "", "")
	if export.Code != 200 || strings.Count(export.Body.String(), `"outcome":"refused"`) != len(want) {
		t.Fatal("export", export.Code, export.Body.String())
	}
	for _, body := range []string{r.Body.String(), export.Body.String()} {
		if strings.Contains(body, planted) || strings.Contains(body, issued.Token) {
			t.Fatal("the trail holds a request's body or a token")
		}
	}
	// The refusals belong to the organization: another one's trail has none.
	var other int
	pool, err := pgxpool.New(t.Context(), l.dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if err = pool.QueryRow(t.Context(), "SELECT count(*) FROM tenant_refusal_audit WHERE tenant_id<>$1", l.org.ID).Scan(&other); err != nil || other != 0 {
		t.Fatal("refusals outside the organization", other, err)
	}
}
