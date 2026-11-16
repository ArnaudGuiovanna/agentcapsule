package api

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/delegatedidentity"
	"github.com/jackc/pgx/v5/pgxpool"
)

// This file holds the expected authorization matrix of the HTTP API: every
// route against every kind of caller. docs/api/rbac.md is generated from
// rbacRoutes (TestRBACMatrixIsDocumented), so the documentation and the test
// cannot drift apart.

// rbacActors are the matrix columns. All human actors hold every scope their
// organization's trust allows, so the role and the assignments decide alone.
//
//   - owner, admin, operator, auditor: one member per administrative role,
//     none of them assigned to the agent;
//   - user: an agent_user assigned to the agent with read_metadata, invoke and
//     read_content;
//   - team: an agent_user who holds the same permissions through a team;
//   - former: an agent_user who held them, invoked and uploaded a file, then
//     lost the assignment;
//   - unassigned: an agent_user never assigned to anything;
//   - service: a technical account with role org_admin, a token restricted to
//     org:read member:read team:read agent:read agent:operate agent:invoke
//     agent:content:read audit:read, and a read_metadata+invoke assignment;
//   - foreign: the owner of another organization, using the first
//     organization's identifiers;
//   - revoked: a member who was assigned, then revoked;
//   - revoked-token: a revoked token of the technical account;
//   - platform: the platform operator.
var rbacActors = []string{"owner", "admin", "operator", "auditor", "user", "team", "former", "unassigned", "service", "foreign", "revoked", "revoked-token", "platform"}

// Expected outcomes. Any other token is the exact HTTP status.
const (
	rbacOK       = "S" // the route's success status
	rbacFiltered = "F" // the success status, and the answer names none of the route's hidden resources
)

// rbacRoute is one row of the matrix. Path and body take placeholders: the
// fixture's resources ({agent}, {team}, ...), the caller's own invocation and
// file when it has one ({inv}, {file}: the user's and the former assignee's
// own, otherwise the user's), and the disposable targets that fresh creates
// for each call, so that one caller's success never changes another's case.
type rbacRoute struct {
	Method, Path string
	Success      int
	Want         string
	Note         string
	body         string
	fresh        func(t *testing.T, f *rbacFixture) map[string]string
	hides        []string
	upload       bool
}

const (
	rbacPlatformOnly = "403 403 403 403 403 403 403 403 403 403 401 401 S"
	rbacLegacyOnly   = "403 403 403 403 403 403 403 403 403 403 401 401 403"
	rbacManage       = "S S 403 403 403 403 403 403 403 404 401 401 403"
	rbacReadAdmin    = "S S 403 S 403 403 403 403 S 404 401 401 403"
	rbacCreateAdmin  = "S S 403 403 403 403 403 403 403 S 401 401 403"
	rbacIdentity     = "S S 403 403 403 403 403 403 403 404 401 401 403"
	rbacOperate      = "S S S 403 403 403 403 403 S 404 401 401 403"
	rbacConfigure    = "S S S 403 403 403 403 403 403 404 401 401 403"
	rbacSeeAgent     = "S S S S S S 404 404 S 404 401 401 400"
	rbacInvoke       = "403 403 403 403 S S 404 404 S 404 401 401 403"
	rbacDecideHeld   = "S S S 403 S S 404 404 S 404 401 401 400"
	rbacRequester    = "S S S S S 404 404 404 S 404 401 401 404"
	rbacContent      = "404 404 404 404 S 404 404 404 404 404 401 401 403"
	rbacSender       = "404 404 404 404 S 404 404 404 404 404 401 401 404"
)

var rbacRoutes = []rbacRoute{
	{Method: "GET", Path: "/v1/health/live", Success: 200, Want: "S S S S S S S S S S S S S", Note: "no authentication"},
	{Method: "GET", Path: "/v1/health/ready", Success: 200, Want: "S S S S S S S S S S S S S", Note: "no authentication"},

	{Method: "GET", Path: "/v1/organizations", Success: 200, Want: rbacPlatformOnly},
	{Method: "POST", Path: "/v1/organizations", Success: 201, Want: rbacPlatformOnly, body: `{"name":"{name}","initial_owner":{"issuer":"https://client.example","subject":"{name}","display_name":"X"}}`, fresh: rbacName},
	{Method: "GET", Path: "/v1/organizations/{org}", Success: 200, Want: rbacPlatformOnly},
	{Method: "POST", Path: "/v1/organizations/{fresh}/disable", Success: 200, Want: rbacPlatformOnly, body: `{}`, fresh: rbacFreshOrganization, Note: "a disposable organization"},
	{Method: "POST", Path: "/v1/harness-imports", Success: 202, Want: rbacPlatformOnly, body: `{"reference":"ghcr.io/acme/matrix@sha256:{digest}"}`, fresh: rbacName},
	{Method: "GET", Path: "/v1/harness-imports/{import}", Success: 200, Want: rbacPlatformOnly},
	{Method: "GET", Path: "/v1/harness-releases", Success: 200, Want: "S S S S 403 403 403 403 S S 401 401 S", Note: "the platform's catalog"},
	{Method: "POST", Path: "/v1/harness-releases/{fresh}/deprecate", Success: 200, Want: rbacPlatformOnly, body: `{}`, fresh: rbacFreshRelease, Note: "a disposable release"},
	{Method: "GET", Path: "/v1/organizations/current", Success: 200, Want: "S S S S S S S S S F 401 401 403", hides: []string{"{org}"}, Note: "the caller's own organization"},

	{Method: "GET", Path: "/v1/members", Success: 200, Want: "S S 403 S 403 403 403 403 S F 401 401 403", hides: []string{"{user_principal}"}},
	{Method: "POST", Path: "/v1/members", Success: 201, Want: rbacCreateAdmin, body: `{"issuer":"https://client.example","subject":"{name}","display_name":"X","role":"agent_user"}`, fresh: rbacName},
	{Method: "POST", Path: "/v1/members/{member}/role", Success: 200, Want: rbacManage, body: `{"role":"auditor"}`, fresh: rbacFreshMember, Note: "a disposable agent_user"},
	{Method: "POST", Path: "/v1/members/{member}/revoke", Success: 200, Want: rbacManage, body: `{}`, fresh: rbacFreshMember, Note: "a disposable agent_user"},

	{Method: "GET", Path: "/v1/teams", Success: 200, Want: "S S 403 S 403 403 403 403 S F 401 401 403", hides: []string{"{team}"}},
	{Method: "POST", Path: "/v1/teams", Success: 201, Want: rbacCreateAdmin, body: `{"name":"{name}"}`, fresh: rbacName},
	{Method: "GET", Path: "/v1/teams/{team}", Success: 200, Want: rbacReadAdmin},
	{Method: "POST", Path: "/v1/teams/{fresh}/disable", Success: 200, Want: rbacManage, body: `{}`, fresh: rbacFreshTeam, Note: "a disposable team"},
	{Method: "GET", Path: "/v1/teams/{team}/members", Success: 200, Want: rbacReadAdmin},
	{Method: "POST", Path: "/v1/teams/{fresh}/members", Success: 201, Want: rbacManage, body: `{"principal_id":"{member}"}`, fresh: rbacFreshTeamAndMember, Note: "a disposable team and member"},
	{Method: "POST", Path: "/v1/teams/{fresh}/members/{member}/revoke", Success: 200, Want: rbacManage, body: `{}`, fresh: rbacFreshTeamMembership, Note: "a disposable team membership"},

	{Method: "GET", Path: "/v1/service-accounts", Success: 200, Want: "S S 403 403 403 403 403 403 403 F 401 401 403", hides: []string{"{spare}"}},
	{Method: "POST", Path: "/v1/service-accounts", Success: 201, Want: rbacCreateAdmin, body: `{"name":"{name}","role":"agent_user"}`, fresh: rbacName},
	{Method: "POST", Path: "/v1/service-accounts/{fresh}/disable", Success: 200, Want: rbacIdentity, body: `{}`, fresh: rbacFreshServiceAccount, Note: "a disposable agent_user account"},
	{Method: "GET", Path: "/v1/service-accounts/{spare}/tokens", Success: 200, Want: rbacIdentity, Note: "an agent_user account"},
	{Method: "POST", Path: "/v1/service-accounts/{spare}/tokens", Success: 201, Want: "S S 403 403 403 403 403 403 403 404 401 401 400", body: `{"scopes":["agent:read"],"expires_at":"{expires}"}`, fresh: rbacName, Note: "an agent_user account"},
	{Method: "POST", Path: "/v1/service-accounts/{spare}/tokens/{token}/revoke", Success: 200, Want: rbacIdentity, body: `{}`, fresh: rbacFreshServiceToken, Note: "a disposable token"},

	{Method: "GET", Path: "/v1/audit", Success: 200, Want: "S S 403 S 403 403 403 403 S F 401 401 403", hides: []string{"{agent}"}},

	{Method: "GET", Path: "/v1/llm/providers", Success: 200, Want: "S S 403 403 403 403 403 403 403 F 401 401 403", hides: []string{"{provider}"}},
	{Method: "POST", Path: "/v1/llm/providers", Success: 201, Want: rbacCreateAdmin, body: `{"name":"{name}","kind":"openai_compatible","base_url":"https://llm.example.org/v1","secret":"matrix-credential-0123456789"}`, fresh: rbacName},
	{Method: "POST", Path: "/v1/llm/providers/{fresh}/rotate", Success: 200, Want: rbacManage, body: `{"secret":"matrix-credential-rotated-0123"}`, fresh: rbacFreshProvider, Note: "a disposable provider"},
	{Method: "POST", Path: "/v1/llm/providers/{fresh}/disable", Success: 200, Want: rbacManage, body: `{}`, fresh: rbacFreshProvider, Note: "a disposable provider"},
	{Method: "GET", Path: "/v1/llm/aliases", Success: 200, Want: "S S 403 403 403 403 403 403 403 F 401 401 403", hides: []string{"{alias}"}},
	{Method: "POST", Path: "/v1/llm/aliases", Success: 201, Want: rbacManage, body: `{"alias":"{name}","provider_id":"{provider}","upstream_model":"model-x"}`, fresh: rbacName},
	{Method: "POST", Path: "/v1/llm/aliases/{fresh}/disable", Success: 200, Want: rbacManage, body: `{}`, fresh: rbacFreshAlias, Note: "a disposable alias"},
	{Method: "POST", Path: "/v1/llm/aliases/{fresh}/access", Success: 200, Want: rbacManage, body: `{"access":"listed"}`, fresh: rbacFreshAlias, Note: "a disposable alias"},
	{Method: "POST", Path: "/v1/llm/aliases/{fresh}/prices", Success: 200, Want: rbacManage, body: `{"input_micro_per_mtok":1,"output_micro_per_mtok":2}`, fresh: rbacFreshAlias, Note: "a disposable alias"},
	{Method: "GET", Path: "/v1/llm/aliases/{alias}/grants", Success: 200, Want: rbacManage},
	{Method: "POST", Path: "/v1/llm/aliases/{fresh}/grants", Success: 201, Want: rbacManage, body: `{"agent_id":"{agent}"}`, fresh: rbacFreshAlias, Note: "a disposable alias, to the agent"},
	{Method: "POST", Path: "/v1/llm/aliases/{fresh}/grants/{grant}/revoke", Success: 200, Want: rbacManage, body: `{}`, fresh: rbacFreshGrant, Note: "a disposable grant"},
	{Method: "GET", Path: "/v1/llm/calls/unresolved", Success: 200, Want: "S S 403 S 403 403 403 403 403 F 401 401 403", hides: []string{"{call}"}},
	{Method: "POST", Path: "/v1/llm/calls/{fresh}/settle", Success: 200, Want: rbacManage, body: `{"input_tokens":10,"output_tokens":5}`, fresh: rbacFreshCall, Note: "a disposable call of unknown outcome"},
	{Method: "POST", Path: "/v1/llm/calls/{fresh}/release", Success: 200, Want: rbacManage, body: `{}`, fresh: rbacFreshCall, Note: "a disposable call of unknown outcome"},
	{Method: "GET", Path: "/v1/llm/budgets", Success: 200, Want: "S S 403 403 403 403 403 403 403 F 401 401 403", hides: []string{"{budget}"}},
	{Method: "POST", Path: "/v1/llm/budgets", Success: 201, Want: rbacManage, body: `{"alias":"{fresh}","period":"day","limit_tokens":1000,"mode":"soft"}`, fresh: rbacFreshAlias, Note: "for a disposable alias"},
	{Method: "POST", Path: "/v1/llm/budgets/{fresh}/disable", Success: 200, Want: rbacManage, body: `{}`, fresh: rbacFreshBudget, Note: "a disposable budget"},
	{Method: "GET", Path: "/v1/llm/usage", Success: 200, Want: "S S 403 S 403 403 403 403 403 S 401 401 403"},
	{Method: "GET", Path: "/v1/queue", Success: 200, Want: "S S 403 S 403 403 403 403 403 S 401 401 403"},
	{Method: "POST", Path: "/v1/queue/limits", Success: 200, Want: rbacCreateAdmin, body: `{"max_pending_per_agent":100,"max_pending_tenant":1000}`},

	{Method: "GET", Path: "/v1/agents", Success: 200, Want: "S S S S S S F F S F 401 401 403", hides: []string{"{agent}"}},
	{Method: "POST", Path: "/v1/agents", Success: 202, Want: "S S S 403 403 403 403 403 403 S 401 401 400", body: `{"name":"{name}","harness":{"name":"reference","version":"1.0.0"},"resources":{"vcpus":1,"memory_mib":256,"data_volume_mib":64}}`, fresh: rbacName},
	{Method: "GET", Path: "/v1/agents/{agent}", Success: 200, Want: "S S S S S S 404 404 S 404 401 401 403"},
	{Method: "DELETE", Path: "/v1/agents/{fresh}", Success: 202, Want: rbacManage, fresh: rbacFreshAgent, Note: "a disposable agent"},
	{Method: "POST", Path: "/v1/agents/{agent}/wake", Success: 202, Want: rbacOperate, body: `{}`},
	{Method: "POST", Path: "/v1/agents/{agent}/sleep", Success: 202, Want: rbacOperate, body: `{}`},
	{Method: "POST", Path: "/v1/agents/{agent}/idle-policy", Success: 200, Want: rbacOperate, body: `{"idle_timeout_seconds":0}`},
	{Method: "POST", Path: "/v1/agents/{agent}/release", Success: 200, Want: rbacConfigure, body: `{"harness":{"name":"reference","version":"1.0.1"}}`},
	{Method: "GET", Path: "/v1/agents/{agent}/directory", Success: 200, Want: rbacSeeAgent},
	{Method: "PUT", Path: "/v1/agents/{agent}/directory", Success: 200, Want: "S S S 403 403 403 403 403 403 404 401 401 400", body: `{"visible":true,"description":"Matrix agent.","skills":[10302],"domains":[111]}`},
	{Method: "GET", Path: "/v1/agents/{agent}/inbound", Success: 200, Want: rbacSeeAgent},
	{Method: "PUT", Path: "/v1/agents/{agent}/inbound", Success: 200, Want: "S S S 403 403 403 403 403 403 404 401 401 400", body: `{"mode":"manual"}`},

	{Method: "GET", Path: "/v1/agents/{agent}/assignments", Success: 200, Want: rbacManage},
	{Method: "POST", Path: "/v1/agents/{agent}/assignments", Success: 201, Want: rbacManage, body: `{"principal_id":"{member}","permissions":["read_metadata"]}`, fresh: rbacFreshMember, Note: "to a disposable member"},
	{Method: "POST", Path: "/v1/agents/{agent}/assignments/{assignment}/revoke", Success: 200, Want: rbacManage, body: `{}`, fresh: rbacFreshAssignment, Note: "a disposable assignment"},
	{Method: "POST", Path: "/v1/agents/{agent}/assignments/{assignment}/replace", Success: 201, Want: rbacManage, body: `{"permissions":["read_metadata","invoke"]}`, fresh: rbacFreshAssignment, Note: "a disposable assignment"},
	{Method: "POST", Path: "/v1/agents/{agent}/assignments/{assignment}/reassign", Success: 201, Want: rbacManage, body: `{"principal_id":"{member}"}`, fresh: rbacFreshReassignment, Note: "a disposable assignment, to a disposable member"},

	{Method: "POST", Path: "/v1/agents/{agent}/messages", Success: 202, Want: rbacInvoke, body: `{"content":[{"type":"text","text":"matrix"}]}`},
	{Method: "POST", Path: "/v1/agents/{agent}/invocations", Success: 202, Want: "403 403 403 403 S S 404 404 S 404 401 401 400", body: `{"content":[{"type":"text","text":"matrix"}]}`},
	{Method: "GET", Path: "/v1/agents/{agent}/invocations", Success: 200, Want: "S S S S S F 404 404 S 404 401 401 400", hides: []string{"{inv}"}, Note: "a requester sees only its own"},
	{Method: "GET", Path: "/v1/invocations/{inv}", Success: 200, Want: rbacRequester, Note: "the caller's own, else the user's"},
	{Method: "GET", Path: "/v1/operations/{inv}", Success: 200, Want: "S S S S S 404 404 404 S 404 401 401 403", Note: "the caller's own, else the user's"},
	{Method: "GET", Path: "/v1/invocations/{inv}/result", Success: 200, Want: rbacContent, Note: "the caller's own, else the user's"},
	{Method: "GET", Path: "/v1/operations/{inv}/result", Success: 200, Want: rbacContent, Note: "the caller's own, else the user's"},
	{Method: "POST", Path: "/v1/invocations/{fresh}/cancel", Success: 200, Want: rbacSender, fresh: rbacFreshScheduled, Note: "a disposable invocation of the user"},

	{Method: "GET", Path: "/v1/agents/{agent}/held-requests", Success: 200, Want: rbacDecideHeld},
	{Method: "POST", Path: "/v1/agents/{agent}/held-requests/{held}/accept", Success: 200, Want: rbacDecideHeld, body: `{}`, fresh: rbacFreshHeld, Note: "a disposable held request"},
	{Method: "POST", Path: "/v1/agents/{agent}/held-requests/{held}/decline", Success: 200, Want: rbacDecideHeld, body: `{}`, fresh: rbacFreshHeld, Note: "a disposable held request"},

	{Method: "POST", Path: "/v1/agents/{agent}/attachments", Success: 201, Want: "403 403 403 403 S S 404 404 S 404 401 401 404", body: "matrix file", upload: true},
	{Method: "GET", Path: "/v1/attachments/{file}", Success: 200, Want: rbacRequester, Note: "the caller's own, else the user's"},
	{Method: "DELETE", Path: "/v1/attachments/{fresh}", Success: 200, Want: rbacSender, fresh: rbacFreshFile, Note: "a disposable file of the user"},

	{Method: "GET", Path: "/v1/users", Success: 200, Want: rbacLegacyOnly, Note: "historical owner domain"},
	{Method: "POST", Path: "/v1/users", Success: 201, Want: rbacLegacyOnly, body: `{"display_name":"X"}`, Note: "historical owner domain"},
	{Method: "POST", Path: "/v1/users/usr_matrix/tokens", Success: 201, Want: rbacLegacyOnly, body: `{"expires_at":"{expires}"}`, fresh: rbacName, Note: "historical owner domain"},
	{Method: "GET", Path: "/v1/me", Success: 200, Want: rbacLegacyOnly, Note: "historical owner domain"},
	{Method: "GET", Path: "/v1/me/messaging-settings", Success: 200, Want: rbacLegacyOnly, Note: "historical owner domain"},
	{Method: "PUT", Path: "/v1/me/messaging-settings", Success: 200, Want: rbacLegacyOnly, body: `{"discoverable":false,"inbound_mode":"manual"}`, Note: "historical owner domain"},
	{Method: "GET", Path: "/v1/me/inbox", Success: 200, Want: rbacLegacyOnly, Note: "historical owner domain"},
	{Method: "GET", Path: "/v1/me/inbox/messages/msg_matrix", Success: 200, Want: rbacLegacyOnly, Note: "historical owner domain"},
	{Method: "POST", Path: "/v1/me/inbox/requests/req_matrix/accept", Success: 200, Want: rbacLegacyOnly, body: `{}`, Note: "historical owner domain"},
	{Method: "POST", Path: "/v1/me/inbox/requests/req_matrix/decline", Success: 200, Want: rbacLegacyOnly, body: `{}`, Note: "historical owner domain"},
	{Method: "GET", Path: "/v1/agent-requests/req_matrix", Success: 200, Want: rbacLegacyOnly, Note: "historical owner domain"},
	{Method: "POST", Path: "/v1/agent-requests/req_matrix/cancel", Success: 202, Want: rbacLegacyOnly, body: `{}`, Note: "historical owner domain"},
}

func TestRBACMatrixIsWellFormed(t *testing.T) {
	seen := map[string]bool{}
	for _, r := range rbacRoutes {
		key := r.Method + " " + r.Path
		if seen[key] {
			t.Fatal("route listed twice", key)
		}
		seen[key] = true
		if cells := strings.Fields(r.Want); len(cells) != len(rbacActors) {
			t.Fatal(key, "has", len(cells), "expectations for", len(rbacActors), "callers")
		}
		if strings.Contains(r.Want, rbacFiltered) && len(r.hides) == 0 {
			t.Fatal(key, "filters without naming what it hides")
		}
	}
}

// TestRBACMatrixCoversEveryRoute keeps the matrix complete and real: a route
// added to the server without a row fails, and so does a row for a route the
// server does not serve.
func TestRBACMatrixCoversEveryRoute(t *testing.T) {
	served := rbacServerRoutes()
	listed := map[string]bool{}
	for _, r := range rbacRoutes {
		listed[rbacPattern(r.Path)] = true
		if _, ok := served[rbacPattern(r.Path)]; !ok {
			t.Error("RBAC row for a route the server does not serve:", r.Path)
		}
	}
	for shape, pattern := range served {
		if !listed[shape] {
			t.Error("route without an RBAC row:", pattern)
		}
	}
}

// rbacServerRoutes maps each route shape to the server's own pattern. The
// server is built without a database: routing needs none.
func rbacServerRoutes() map[string]string {
	s, err := NewForHost(&controlplane.Store{}, &controlplane.Accounts{}, "local")
	if err != nil {
		panic(err)
	}
	served := map[string]string{}
	for _, pattern := range s.routes {
		if pattern != "/" {
			served[rbacPattern(pattern)] = pattern
		}
	}
	return served
}

var rbacPlaceholder = regexp.MustCompile(`\{[a-z_]+\}`)

// rbacPattern reduces a path to its shape, so that /v1/agents/{agent} and the
// server's /v1/agents/{id} match, and fixed test identifiers match too.
func rbacPattern(path string) string {
	parts := strings.Split(path, "/")
	for i, p := range parts {
		if rbacPlaceholder.MatchString(p) || strings.Contains(p, "_matrix") {
			parts[i] = "*"
		}
	}
	return strings.Join(parts, "/")
}

// rbacMatrixMarkdown renders the matrix for docs/api/rbac.md, with the
// server's path patterns.
func rbacMatrixMarkdown() string {
	served := rbacServerRoutes()
	var b strings.Builder
	b.WriteString("| Route | " + strings.Join(rbacActors, " | ") + " |\n")
	b.WriteString("|---|" + strings.Repeat("---|", len(rbacActors)) + "\n")
	for _, r := range rbacRoutes {
		path := served[rbacPattern(r.Path)]
		if path == "" {
			path = r.Path
		}
		route := "`" + r.Method + " " + path + "`"
		if r.Note != "" {
			route += " (" + r.Note + ")"
		}
		cells := []string{}
		for _, c := range strings.Fields(r.Want) {
			switch c {
			case rbacOK:
				c = "yes"
			case rbacFiltered:
				c = "filtered"
			}
			cells = append(cells, c)
		}
		b.WriteString("| " + route + " | " + strings.Join(cells, " | ") + " |\n")
	}
	return b.String()
}

const (
	rbacDoc   = "../../docs/api/rbac.md"
	rbacBegin = "<!-- rbac-matrix:begin -->\n"
	rbacEnd   = "<!-- rbac-matrix:end -->\n"
)

// TestRBACMatrixIsDocumented checks that docs/api/rbac.md shows this matrix.
// AGENTCAPSULE_WRITE_RBAC_DOC=1 rewrites the table in place. It needs no
// database and runs in CI. The PostgreSQL campaign tests a copy of the
// sources without docs/: there is nothing to compare, and the test says so
// rather than skip, which that campaign refuses.
func TestRBACMatrixIsDocumented(t *testing.T) {
	if _, err := os.Stat("../../docs"); errors.Is(err, fs.ErrNotExist) {
		t.Log("this copy of the sources has no docs/ directory")
		return
	}
	raw, err := os.ReadFile(rbacDoc)
	if err != nil {
		t.Fatal(err)
	}
	doc := string(raw)
	begin, end := strings.Index(doc, rbacBegin), strings.Index(doc, rbacEnd)
	if begin < 0 || end < begin {
		t.Fatal("docs/api/rbac.md lacks the matrix markers")
	}
	want := rbacMatrixMarkdown()
	if doc[begin+len(rbacBegin):end] == want {
		return
	}
	if os.Getenv("AGENTCAPSULE_WRITE_RBAC_DOC") == "1" {
		doc = doc[:begin+len(rbacBegin)] + want + doc[end:]
		if err = os.WriteFile(rbacDoc, []byte(doc), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	t.Fatal("docs/api/rbac.md is out of date; rerun with AGENTCAPSULE_WRITE_RBAC_DOC=1")
}

type rbacFixture struct {
	l, second *apiDelegationFixture
	server    *Server
	transit   *controlplane.Transit
	db        *pgxpool.Pool
	minimum   time.Time
	signedAt  time.Time
	jwt       map[string]string // actor -> delegated JWT
	static    map[string]string // actor -> long-lived credential
	subjects  map[string]string // human actor -> subject in its organization
	ids       map[string]string // placeholder -> resource of the first organization
	own       map[string]map[string]string
	n         int
}

func (f *rbacFixture) next() string {
	f.n++
	return fmt.Sprintf("matrix-%d", f.n)
}

// token returns the actor's credential. Delegated JWTs live five minutes, so
// they are signed again when the run grows long.
func (f *rbacFixture) token(t *testing.T, actor string) string {
	t.Helper()
	if v, ok := f.static[actor]; ok {
		return v
	}
	if f.jwt == nil || time.Since(f.signedAt) > 2*time.Minute {
		at := time.Now().UTC().Truncate(time.Second)
		if at.Before(f.minimum) {
			at = f.minimum
		}
		waitAPITenantClock(t, f.l.dsn, at)
		f.jwt, f.signedAt = map[string]string{}, time.Now()
		jti := f.next()
		for actor, subject := range f.subjects {
			if actor == "foreign" {
				f.jwt[actor] = f.second.sign(t, at, actor+jti, subject, allAgentScopes)
			} else {
				f.jwt[actor] = f.l.sign(t, at, actor+jti, subject, allAgentScopes)
			}
		}
	}
	return f.jwt[actor]
}

func (f *rbacFixture) call(t *testing.T, actor, method, path, key, body string) *httptest.ResponseRecorder {
	t.Helper()
	return call(t, f.server, method, path, f.token(t, actor), key, body)
}

// must calls as actor and decodes a success into out.
func (f *rbacFixture) must(t *testing.T, actor, method, path, body string, want int, out any) {
	t.Helper()
	key := ""
	if method != "GET" {
		key = f.next()
	}
	r := f.call(t, actor, method, path, key, body)
	if r.Code != want {
		t.Fatal(method, path, r.Code, r.Body.String())
	}
	if out != nil {
		if err := json.Unmarshal(r.Body.Bytes(), out); err != nil {
			t.Fatal(method, path, err)
		}
	}
}

func (f *rbacFixture) member(t *testing.T, role string) controlplane.Member {
	t.Helper()
	var m controlplane.Member
	f.must(t, "owner", "POST", "/v1/members", apiMemberBody(f.l, f.next(), role), 201, &m)
	return m
}

func (f *rbacFixture) assign(t *testing.T, target string, team bool, perms ...string) controlplane.AgentAssignment {
	t.Helper()
	field := "principal_id"
	if team {
		field = "team_id"
	}
	body, _ := json.Marshal(map[string]any{field: target, "permissions": perms})
	var a controlplane.AgentAssignment
	f.must(t, "owner", "POST", "/v1/agents/"+f.ids["agent"]+"/assignments", string(body), 201, &a)
	return a
}

func (f *rbacFixture) invoke(t *testing.T, actor string) string {
	t.Helper()
	var inv controlplane.Invocation
	f.must(t, actor, "POST", "/v1/agents/"+f.ids["agent"]+"/invocations", `{"content":[{"type":"text","text":"private question"}]}`, 202, &inv)
	return inv.ID
}

// complete plays the worker: the agent answers the invocation.
func (f *rbacFixture) complete(t *testing.T, op string) {
	t.Helper()
	ctx := t.Context()
	var mailbox string
	if err := f.db.QueryRow(ctx, "SELECT id FROM agent_mailboxes WHERE instruction_id=$1", op).Scan(&mailbox); err != nil {
		t.Fatal(err)
	}
	attempt, err := f.transit.ClaimInstruction(ctx, mailbox, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.transit.AuthorizeInstruction(ctx, mailbox, attempt.Token); err != nil {
		t.Fatal(err)
	}
	if err = f.transit.AcknowledgeInstruction(ctx, mailbox, attempt.Token, []byte(`{"content":[{"type":"text","text":"private answer"}]}`)); err != nil {
		t.Fatal(err)
	}
}

func (f *rbacFixture) upload(t *testing.T, actor string) string {
	t.Helper()
	r := rbacRequest(t, f.server, "POST", "/v1/agents/"+f.ids["agent"]+"/attachments", f.token(t, actor), f.next(), "private file", true)
	var file controlplane.Attachment
	if r.Code != 201 || json.Unmarshal(r.Body.Bytes(), &file) != nil {
		t.Fatal("upload", r.Code, r.Body.String())
	}
	return file.ID
}

func rbacRequest(t *testing.T, s *Server, method, path, token, key, body string, upload bool) *httptest.ResponseRecorder {
	t.Helper()
	if !upload {
		return call(t, s, method, path, token, key, body)
	}
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("Idempotency-Key", key)
	r.Header.Set("Content-Type", "text/plain")
	r.Header.Set("X-Attachment-Name", "matrix.txt")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}

func rbacName(t *testing.T, f *rbacFixture) map[string]string {
	name := f.next()
	sum := sha256.Sum256([]byte(name))
	return map[string]string{"name": name, "digest": hex.EncodeToString(sum[:]), "expires": time.Now().Add(time.Hour).UTC().Format(time.RFC3339)}
}

func rbacFreshOrganization(t *testing.T, f *rbacFixture) map[string]string {
	name := f.next()
	r := call(t, f.server, "POST", "/v1/organizations", f.l.platform, name, `{"name":"`+name+`","initial_owner":{"issuer":"https://client.example","subject":"x","display_name":"X"}}`)
	var o controlplane.CreateOrganizationResponse
	if r.Code != 201 || json.Unmarshal(r.Body.Bytes(), &o) != nil {
		t.Fatal("organization", r.Code, r.Body.String())
	}
	return map[string]string{"fresh": o.ID}
}

func rbacFreshRelease(t *testing.T, f *rbacFixture) map[string]string {
	name := f.next()
	sum := sha256.Sum256([]byte(name))
	id, err := f.l.store.RegisterLocalRelease(t.Context(), controlplane.HarnessReference{Name: "matrix", Version: name}, "sha256:"+hex.EncodeToString(sum[:]))
	if err != nil {
		t.Fatal(err)
	}
	return map[string]string{"fresh": id}
}

func rbacFreshMember(t *testing.T, f *rbacFixture) map[string]string {
	return map[string]string{"member": f.member(t, "agent_user").PrincipalID}
}

func rbacFreshTeam(t *testing.T, f *rbacFixture) map[string]string {
	var team controlplane.Team
	f.must(t, "owner", "POST", "/v1/teams", `{"name":"`+f.next()+`"}`, 201, &team)
	return map[string]string{"fresh": team.ID}
}

func rbacFreshTeamAndMember(t *testing.T, f *rbacFixture) map[string]string {
	v := rbacFreshTeam(t, f)
	v["member"] = f.member(t, "agent_user").PrincipalID
	return v
}

func rbacFreshTeamMembership(t *testing.T, f *rbacFixture) map[string]string {
	v := rbacFreshTeamAndMember(t, f)
	f.must(t, "owner", "POST", "/v1/teams/"+v["fresh"]+"/members", teamMemberBody(v["member"]), 201, nil)
	return v
}

func rbacFreshServiceAccount(t *testing.T, f *rbacFixture) map[string]string {
	var s controlplane.ServiceAccount
	f.must(t, "owner", "POST", "/v1/service-accounts", `{"name":"`+f.next()+`","role":"agent_user"}`, 201, &s)
	return map[string]string{"fresh": s.ID}
}

func rbacFreshServiceToken(t *testing.T, f *rbacFixture) map[string]string {
	var tok controlplane.IssuedServiceToken
	f.must(t, "owner", "POST", "/v1/service-accounts/"+f.ids["spare"]+"/tokens", `{"scopes":["agent:read"],"expires_at":"`+time.Now().Add(time.Hour).UTC().Format(time.RFC3339)+`"}`, 201, &tok)
	return map[string]string{"token": tok.ID}
}

func rbacFreshProvider(t *testing.T, f *rbacFixture) map[string]string {
	var p controlplane.LLMProvider
	f.must(t, "owner", "POST", "/v1/llm/providers", `{"name":"`+f.next()+`","kind":"openai_compatible","base_url":"https://llm.example.org/v1","secret":"matrix-credential-0123456789"}`, 201, &p)
	return map[string]string{"fresh": p.ID}
}

func rbacFreshAlias(t *testing.T, f *rbacFixture) map[string]string {
	alias := f.next()
	f.must(t, "owner", "POST", "/v1/llm/aliases", `{"alias":"`+alias+`","provider_id":"`+f.ids["provider"]+`","upstream_model":"model-x"}`, 201, nil)
	return map[string]string{"fresh": alias}
}

func rbacFreshBudget(t *testing.T, f *rbacFixture) map[string]string {
	alias := rbacFreshAlias(t, f)["fresh"]
	var b controlplane.LLMBudget
	f.must(t, "owner", "POST", "/v1/llm/budgets", `{"alias":"`+alias+`","period":"day","limit_tokens":1000,"mode":"soft"}`, 201, &b)
	return map[string]string{"fresh": b.ID}
}

func rbacFreshGrant(t *testing.T, f *rbacFixture) map[string]string {
	v := rbacFreshAlias(t, f)
	var g controlplane.LLMAliasGrant
	f.must(t, "owner", "POST", "/v1/llm/aliases/"+v["fresh"]+"/grants", `{"agent_id":"`+f.ids["agent"]+`"}`, 201, &g)
	v["grant"] = g.ID
	return v
}

// rbacFreshCall plays the gateway: the agent reserves a model call whose
// outcome stays unknown, which only the organization can resolve.
func rbacFreshCall(t *testing.T, f *rbacFixture) map[string]string {
	res, err := f.server.accounts.ReserveLLM(t.Context(), f.l.org.ID, f.ids["agent"], f.ids["alias"], f.next(), 100, 200)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.server.accounts.MarkLLMUnknown(t.Context(), f.l.org.ID, res.ID); err != nil {
		t.Fatal(err)
	}
	return map[string]string{"fresh": res.ID}
}

func rbacFreshAgent(t *testing.T, f *rbacFixture) map[string]string {
	return map[string]string{"fresh": f.activeAgent(t, f.next())}
}

// activeAgent drives a reservation to LIVE like apiActiveTenantAgent, and
// also replays the revocations published since the first agent was created,
// which a new store must acknowledge before it may serve.
func (f *rbacFixture) activeAgent(t *testing.T, name string) string {
	t.Helper()
	ctx, s := t.Context(), f.l.store
	id := apiTenantAgent(t, f.l, f.token(t, "owner"), name)
	jobs, err := s.PendingProvisioning(ctx, "local", 200)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range jobs {
		if e.AgentID != id {
			continue
		}
		if err = s.RecordProvisionedVolume(ctx, controlplane.ProvisionedVolume{AgentID: id, HostID: e.HostID, VolumeID: e.VolumeID, OperationID: e.OperationID, Device: 1, Inode: 100}); err != nil {
			t.Fatal(err)
		}
		p, err := s.ClaimFencePlacement(ctx, id, e.HostID, "fixture", time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		vm := "0123456789abcdef"
		if err = s.ConfirmFencePlacement(ctx, id, e.HostID, "fixture", p.Generation, vm); err != nil {
			t.Fatal(err)
		}
		if err = s.RecordEnrollmentInitialized(ctx, controlplane.EnrollmentBoot{Incarnation: 1, AgentID: id, HostID: e.HostID, VolumeID: e.VolumeID, Generation: p.Generation, VMID: vm}); err != nil {
			t.Fatal(err)
		}
		subjects, err := s.EnrollmentPendingFences(ctx, id, e.HostID, e.VolumeID)
		if err != nil {
			t.Fatal(err)
		}
		for _, subject := range subjects {
			if err = s.RecordEnrollmentFence(ctx, controlplane.EnrollmentFence{Incarnation: 1, AgentID: id, VolumeID: e.VolumeID, HostID: e.HostID, VMID: vm, Subject: subject, Generation: p.Generation}); err != nil {
				t.Fatal(err)
			}
		}
		if err = s.BeginPlacementStop(ctx, id, e.HostID, p.Generation); err != nil {
			t.Fatal(err)
		}
		if err = s.ObservePlacementStopped(ctx, id, e.HostID, p.Generation, true); err != nil {
			t.Fatal(err)
		}
		if err = s.ActivateProvisionedAgent(ctx, e); err != nil {
			t.Fatal(err)
		}
		return id
	}
	t.Fatal("reservation not found")
	return ""
}

func rbacFreshAssignment(t *testing.T, f *rbacFixture) map[string]string {
	m := f.member(t, "agent_user")
	return map[string]string{"assignment": f.assign(t, m.PrincipalID, false, "read_metadata").ID}
}

func rbacFreshReassignment(t *testing.T, f *rbacFixture) map[string]string {
	v := rbacFreshAssignment(t, f)
	v["member"] = f.member(t, "agent_user").PrincipalID
	return v
}

func rbacFreshScheduled(t *testing.T, f *rbacFixture) map[string]string {
	var inv controlplane.Invocation
	at := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	f.must(t, "user", "POST", "/v1/agents/"+f.ids["agent"]+"/invocations", `{"content":[{"type":"text","text":"later"}],"run_at":"`+at+`"}`, 202, &inv)
	return map[string]string{"fresh": inv.ID}
}

func rbacFreshHeld(t *testing.T, f *rbacFixture) map[string]string {
	key := f.next()
	r, err := f.l.store.Submit(t.Context(), f.ids["sender"], key, controlplane.Submission{RecipientAgentID: f.ids["agent"], MandateID: "matrix-mandate",
		PayloadRef: "payload-" + key, PayloadHash: [32]byte{1}, ExpiresAt: time.Now().Add(time.Hour)})
	if err != nil || r.State != controlplane.PendingApproval {
		t.Fatal("held request", r, err)
	}
	return map[string]string{"held": r.RequestID}
}

func rbacFreshFile(t *testing.T, f *rbacFixture) map[string]string {
	return map[string]string{"fresh": f.upload(t, "user")}
}

// newRBACFixture builds two organizations. The first holds one agent, its
// assignments, invocations with private results and files, a team, technical
// accounts and model settings; the second only its owner.
func newRBACFixture(t *testing.T) *rbacFixture {
	t.Helper()
	ctx := t.Context()
	l, minimum, _ := apiAgentsLab(t)
	f := &rbacFixture{l: l, minimum: minimum, ids: map[string]string{}, own: map[string]map[string]string{},
		subjects: map[string]string{"owner": "alice"}, static: map[string]string{"platform": l.platform}}
	if err := l.store.ConfigureHostStorage(ctx, "local", 1<<20); err != nil {
		t.Fatal(err)
	}
	if _, err := l.store.RegisterLocalRelease(ctx, controlplane.HarnessReference{Name: "reference", Version: "1.0.1"}, "sha256:"+strings.Repeat("c", 64)); err != nil {
		t.Fatal(err)
	}
	transit, err := controlplane.NewTransit(l.store, "v1", map[string][]byte{"v1": bytes.Repeat([]byte{0x52}, 32)}, 7*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err = transit.ActivateKeys(ctx); err != nil {
		t.Fatal(err)
	}
	f.transit = transit
	if f.server, err = NewForHostWithTransit(l.store, l.server.accounts, "local", transit); err != nil {
		t.Fatal(err)
	}
	if f.db, err = pgxpool.New(ctx, l.dsn); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.db.Close)

	// The second organization and its owner, under their own trust.
	second := *l
	r := call(t, l.server, "POST", "/v1/organizations", l.platform, "matrix-second", `{"name":"second","initial_owner":{"issuer":"https://client.example","subject":"alice","display_name":"Alice"}}`)
	if r.Code != 201 || json.Unmarshal(r.Body.Bytes(), &second.org) != nil {
		t.Fatal("second organization", r.Code, r.Body.String())
	}
	second.trust.TenantID, second.trust.Audience = second.org.ID, "second-capsule"
	v, err := delegatedidentity.NewVerifier(delegatedidentity.Config{Trusts: []delegatedidentity.Trust{l.trust, second.trust}})
	if err != nil {
		t.Fatal(err)
	}
	f.server.SetDelegatedIdentityVerifier(v)
	l.server = f.server
	installed, err := l.store.ChangeDelegationAuthority(ctx, controlplane.DelegationChange{OperationID: "matrix-second-install", Actor: "test-operator", Action: "install",
		TenantID: second.org.ID, Issuer: second.trust.Issuer, Audience: second.trust.Audience, Trust: &second.trust})
	if err != nil {
		t.Fatal(err)
	}
	if installed.MinimumIAT.After(f.minimum) {
		f.minimum = installed.MinimumIAT
	}
	f.second = &second
	f.subjects["foreign"] = "alice"
	f.ids["org"] = l.org.ID

	for _, actor := range []struct{ name, role string }{{"admin", "org_admin"}, {"operator", "agent_operator"}, {"auditor", "auditor"},
		{"user", "agent_user"}, {"team", "agent_user"}, {"former", "agent_user"}, {"unassigned", "agent_user"}, {"revoked", "agent_user"}} {
		subject := "matrix-" + actor.name
		m := apiAddMember(t, l, f.token(t, "owner"), subject, actor.role)
		f.subjects[actor.name] = subject
		f.ids[actor.name+"_principal"] = m.PrincipalID
		f.jwt = nil
	}
	f.ids["agent"] = apiActiveTenantAgent(t, l, f.token(t, "owner"), "matrix-agent")
	f.ids["sender"] = apiActiveTenantAgent(t, l, f.token(t, "owner"), "matrix-sender")

	var team controlplane.Team
	f.must(t, "owner", "POST", "/v1/teams", `{"name":"matrix-team"}`, 201, &team)
	f.ids["team"] = team.ID
	f.must(t, "owner", "POST", "/v1/teams/"+team.ID+"/members", teamMemberBody(f.ids["team_principal"]), 201, nil)
	all := []string{"read_metadata", "invoke", "read_content"}
	f.assign(t, team.ID, true, all...)

	// The former assignee invokes and uploads, then loses the assignment.
	former := f.assign(t, f.ids["former_principal"], false, all...)
	f.own["former"] = map[string]string{"inv": f.invoke(t, "former"), "file": f.upload(t, "former")}
	f.complete(t, f.own["former"]["inv"])
	f.must(t, "owner", "POST", "/v1/agents/"+f.ids["agent"]+"/assignments/"+former.ID+"/revoke", `{}`, 200, nil)

	f.assign(t, f.ids["user_principal"], false, all...)
	f.own["user"] = map[string]string{"inv": f.invoke(t, "user"), "file": f.upload(t, "user")}
	f.complete(t, f.own["user"]["inv"])
	f.ids["inv"], f.ids["file"] = f.own["user"]["inv"], f.own["user"]["file"]

	// The revoked member was assigned too; its organization then revoked it.
	f.assign(t, f.ids["revoked_principal"], false, all...)
	f.must(t, "owner", "POST", "/v1/members/"+f.ids["revoked_principal"]+"/revoke", `{}`, 200, nil)

	// The technical account: a broad role, a narrow token, an invoke assignment.
	var account controlplane.ServiceAccount
	f.must(t, "owner", "POST", "/v1/service-accounts", `{"name":"matrix bot","role":"org_admin"}`, 201, &account)
	f.assign(t, account.ID, false, "read_metadata", "invoke")
	expires := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	scopes := `["org:read","member:read","team:read","agent:read","agent:operate","agent:invoke","agent:content:read","audit:read"]`
	var live, dead controlplane.IssuedServiceToken
	f.must(t, "owner", "POST", "/v1/service-accounts/"+account.ID+"/tokens", `{"scopes":`+scopes+`,"expires_at":"`+expires+`"}`, 201, &live)
	f.must(t, "owner", "POST", "/v1/service-accounts/"+account.ID+"/tokens", `{"scopes":`+scopes+`,"expires_at":"`+expires+`"}`, 201, &dead)
	f.must(t, "owner", "POST", "/v1/service-accounts/"+account.ID+"/tokens/"+dead.ID+"/revoke", `{}`, 200, nil)
	f.static["service"], f.static["revoked-token"] = live.Token, dead.Token
	var spare controlplane.ServiceAccount
	f.must(t, "owner", "POST", "/v1/service-accounts", `{"name":"matrix spare","role":"agent_user"}`, 201, &spare)
	f.ids["spare"] = spare.ID

	var provider controlplane.LLMProvider
	f.must(t, "owner", "POST", "/v1/llm/providers", `{"name":"matrix","kind":"openai_compatible","base_url":"https://llm.example.org/v1","secret":"matrix-credential-0123456789"}`, 201, &provider)
	f.ids["provider"] = provider.ID
	f.ids["alias"] = rbacFreshAlias(t, f)["fresh"]
	f.ids["budget"] = rbacFreshBudget(t, f)["fresh"]
	f.ids["call"] = rbacFreshCall(t, f)["fresh"]

	var imported controlplane.HarnessImport
	f.must(t, "platform", "POST", "/v1/harness-imports", `{"reference":"ghcr.io/acme/matrix@sha256:`+strings.Repeat("a", 64)+`"}`, 202, &imported)
	f.ids["import"] = imported.ID

	// Requests from the sender agent wait for approval on the agent.
	if _, err = f.db.Exec(ctx, `UPDATE agents SET discoverable=true WHERE id=$1`, f.ids["agent"]); err != nil {
		t.Fatal(err)
	}
	if _, err = f.db.Exec(ctx, `INSERT INTO mandates(id,agent_id,origin_event_id,max_requests,remaining,expires_at)
        VALUES ('matrix-mandate',$1,'matrix-event',1000,1000,clock_timestamp()+interval '1 hour')`, f.ids["sender"]); err != nil {
		t.Fatal(err)
	}
	return f
}

// resolve fills a path or body for one call.
func (f *rbacFixture) resolve(t *testing.T, s, actor string, fresh map[string]string) string {
	t.Helper()
	return rbacPlaceholder.ReplaceAllStringFunc(s, func(p string) string {
		name := p[1 : len(p)-1]
		if v, ok := fresh[name]; ok {
			return v
		}
		if v, ok := f.own[actor][name]; ok {
			return v
		}
		if v, ok := f.ids[name]; ok {
			return v
		}
		t.Fatal("unknown placeholder", p)
		return ""
	})
}

// TestRBACMatrix runs every route against every caller and checks the status.
// A filtered answer must also name none of the route's hidden resources.
func TestRBACMatrix(t *testing.T) {
	f := newRBACFixture(t)
	for i, route := range rbacRoutes {
		want := strings.Fields(route.Want)
		for j, actor := range rbacActors {
			var fresh map[string]string
			if route.fresh != nil {
				fresh = route.fresh(t, f)
			}
			path := f.resolve(t, route.Path, actor, fresh)
			body := f.resolve(t, route.body, actor, fresh)
			key := ""
			if route.Method != "GET" {
				key = fmt.Sprintf("rbac-%d-%s", i, actor)
			}
			r := rbacRequest(t, f.server, route.Method, path, f.token(t, actor), key, body, route.upload)
			expected := want[j]
			code := fmt.Sprint(r.Code)
			if (expected == rbacOK || expected == rbacFiltered) && r.Code == route.Success {
				code = expected
			}
			if code != expected {
				t.Errorf("%s %s as %s: %d, want %s: %s", route.Method, route.Path, actor, r.Code, expected, strings.TrimSpace(r.Body.String()))
				continue
			}
			if expected == rbacFiltered {
				for _, hidden := range route.hides {
					if v := f.resolve(t, hidden, actor, fresh); strings.Contains(r.Body.String(), v) {
						t.Errorf("%s %s as %s: the answer names %s", route.Method, route.Path, actor, hidden)
					}
				}
			}
		}
	}
}
