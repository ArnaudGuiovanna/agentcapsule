package api

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
)

// isolationReaders are the first organization's callers whose answers the
// statistics test compares: every one but the other organization's owner and
// the platform.
var isolationReaders = []string{"owner", "admin", "operator", "auditor", "user", "team", "former", "unassigned", "service", "revoked", "revoked-token"}

var exportedAt = regexp.MustCompile(`"exported_at":"[^"]*"`)

// isolationAnswers reads, as each reader, every GET route of the API with
// the first organization's identifiers, and the usage of the month too.
func isolationAnswers(t *testing.T, f *rbacFixture, fresh map[string]map[string]string) map[string]string {
	t.Helper()
	answers := map[string]string{}
	for _, route := range rbacRoutes {
		if route.Method != "GET" {
			continue
		}
		paths := []string{route.Path}
		if route.Path == "/v1/llm/usage" {
			paths = append(paths, "/v1/llm/usage?period=month")
		}
		for _, actor := range isolationReaders {
			for _, raw := range paths {
				path := f.resolve(t, raw, actor, fresh[route.Path])
				r := f.call(t, actor, "GET", path, "", "")
				// An export says when it was made; nothing else may differ.
				body := exportedAt.ReplaceAllString(strings.TrimSpace(r.Body.String()), `"exported_at":"-"`)
				answers[actor+" GET "+raw] = fmt.Sprintf("%d %s", r.Code, body)
			}
		}
	}
	return answers
}

// ISO-6: statistics are isolated. Whatever another organization does, every
// answer the first organization can read stays the same, byte for byte: its
// model usage by day and by month, its budgets and what they used, its calls
// of unknown outcome, its queue depths, limits and peer wakes, its audit
// trail and export, its agents, members, teams and settings. The other
// organization works under the same names (its agents', its model alias's)
// and gets numbers of its own, which only its own answers carry.
func TestAnotherOrganizationsNumbersStayOutOfEveryAnswer(t *testing.T) {
	f := newRBACFixture(t)
	ctx := t.Context()
	// The first organization's own numbers: a settled call and work waiting.
	res, err := f.server.accounts.ReserveLLM(ctx, f.l.org.ID, f.ids["agent"], f.ids["alias"], "first-settled", 100, 50)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.server.accounts.SettleLLM(ctx, f.l.org.ID, res.ID, 120, 40); err != nil {
		t.Fatal(err)
	}
	f.invoke(t, "user")
	fresh := map[string]map[string]string{}
	for _, route := range rbacRoutes {
		if route.Method == "GET" && route.fresh != nil {
			fresh[route.Path] = route.fresh(t, f)
		}
	}
	before := isolationAnswers(t, f, fresh)

	// The second organization, under the same names.
	second := *f.second
	second.server = f.server
	owner := f.token(t, "foreign")
	as := func(method, path, body string, want int, out any) {
		t.Helper()
		key := ""
		if method != "GET" {
			key = f.next()
		}
		r := call(t, f.server, method, path, owner, key, body)
		if r.Code != want {
			t.Fatal(method, path, r.Code, r.Body.String())
		}
		if out != nil {
			if err := json.Unmarshal(r.Body.Bytes(), out); err != nil {
				t.Fatal(err)
			}
		}
	}
	agent := f.activeAgentOf(t, &second, owner, "matrix-agent")
	sender := f.activeAgentOf(t, &second, owner, "matrix-sender")
	hidden := []string{second.org.ID, agent, sender}
	var provider controlplane.LLMProvider
	as("POST", "/v1/llm/providers", `{"name":"matrix","kind":"openai_compatible","base_url":"https://llm.example.org/v1","secret":"second-credential-0123456789"}`, 201, &provider)
	alias := f.ids["alias"]
	as("POST", "/v1/llm/aliases", `{"alias":"`+alias+`","provider_id":"`+provider.ID+`","upstream_model":"model-x"}`, 201, nil)
	as("POST", "/v1/llm/aliases/"+alias+"/grants", `{"agent_id":"`+agent+`"}`, 201, nil)
	var budget controlplane.LLMBudget
	as("POST", "/v1/llm/budgets", `{"alias":"`+alias+`","period":"day","limit_tokens":90000000,"mode":"soft"}`, 201, &budget)
	hidden = append(hidden, provider.ID, budget.ID)
	// Its model calls: settled, pending and of unknown outcome.
	for i, outcome := range []string{"settled", "settled", "reserved", "unknown"} {
		res, err := f.server.accounts.ReserveLLM(ctx, second.org.ID, agent, alias, fmt.Sprintf("second-%d", i), 900_000, 400_000)
		if err != nil {
			t.Fatal(err)
		}
		hidden = append(hidden, res.ID)
		switch outcome {
		case "settled":
			err = f.server.accounts.SettleLLM(ctx, second.org.ID, res.ID, 7_777_777, 3_333_333)
		case "unknown":
			err = f.server.accounts.MarkLLMUnknown(ctx, second.org.ID, res.ID)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	// Its queue: a technical account invokes its agent, now and later; its
	// own limits; requests between its agents that woke one.
	var account controlplane.ServiceAccount
	as("POST", "/v1/service-accounts", `{"name":"second bot","role":"agent_user"}`, 201, &account)
	as("POST", "/v1/agents/"+agent+"/assignments", `{"principal_id":"`+account.ID+`","permissions":["read_metadata","invoke"]}`, 201, nil)
	var bot controlplane.IssuedServiceToken
	as("POST", "/v1/service-accounts/"+account.ID+"/tokens", `{"scopes":["agent:read","agent:invoke"],"expires_at":"`+
		time.Now().Add(time.Hour).UTC().Format(time.RFC3339)+`"}`, 201, &bot)
	hidden = append(hidden, account.ID)
	for i := range 7 {
		body := `{"content":[{"type":"text","text":"second question"}]}`
		if i == 6 {
			body = `{"content":[{"type":"text","text":"second question"}],"run_at":"` + time.Now().Add(time.Hour).UTC().Format(time.RFC3339) + `"}`
		}
		r := call(t, f.server, "POST", "/v1/agents/"+agent+"/invocations", bot.Token, f.next(), body)
		var inv controlplane.Invocation
		if r.Code != 202 || json.Unmarshal(r.Body.Bytes(), &inv) != nil {
			t.Fatal("invocation", r.Code, r.Body.String())
		}
		hidden = append(hidden, inv.ID)
	}
	as("POST", "/v1/queue/limits", `{"max_pending_per_agent":91,"max_pending_tenant":9100}`, 200, nil)
	if _, err = f.db.Exec(ctx, `UPDATE agents SET discoverable=true WHERE id=$1`, agent); err != nil {
		t.Fatal(err)
	}
	if _, err = f.db.Exec(ctx, `INSERT INTO mandates(id,agent_id,origin_event_id,max_requests,remaining,expires_at)
        VALUES ('second-mandate',$1,'second-event',1000,1000,clock_timestamp()+interval '1 hour')`, sender); err != nil {
		t.Fatal(err)
	}
	for i := range 3 {
		key := f.next()
		r, err := f.l.store.Submit(ctx, sender, key, controlplane.Submission{RecipientAgentID: agent, MandateID: "second-mandate",
			PayloadRef: "payload-" + key, PayloadHash: [32]byte{2}, ExpiresAt: time.Now().Add(time.Hour)})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = f.db.Exec(ctx, `INSERT INTO peer_wakes(id,tenant_id,agent_id,request_id) VALUES($1,$2,$3,$4)`,
			fmt.Sprintf("second-wake-%d", i), second.org.ID, agent, r.RequestID); err != nil {
			t.Fatal(err)
		}
	}
	// Its trail: a member named, and attempts refused.
	as("POST", "/v1/members", apiMemberBody(&second, "second-member", "auditor"), 201, nil)
	as("POST", "/v1/members", `{"role":"nobody"}`, 400, nil)
	as("POST", "/v1/agents/"+f.ids["agent"]+"/sleep", `{}`, 404, nil)

	// Its own answers hold its numbers: the test is not vacuous.
	var usage controlplane.LLMUsageReport
	as("GET", "/v1/llm/usage", "", 200, &usage)
	if usage.Totals.SettledInput != 2*7_777_777 || usage.Totals.SettledOutput != 2*3_333_333 || usage.Totals.Calls != 4 {
		t.Errorf("the second organization's usage: %+v", usage.Totals)
	}
	var queue controlplane.QueueStatus
	as("GET", "/v1/queue", "", 200, &queue)
	if queue.PendingTenant != 7 || queue.PeerWakesLastHour != 3 || queue.Limits.MaxPendingPerAgent != 91 {
		t.Errorf("the second organization's queue: %+v", queue)
	}

	after := isolationAnswers(t, f, fresh)
	for key, answer := range after {
		if before[key] != answer {
			t.Errorf("%s changed with another organization's activity:\nbefore %s\nafter  %s", key, before[key], answer)
		}
		for _, id := range hidden {
			if strings.Contains(answer, id) {
				t.Errorf("%s names %s of the other organization", key, id)
			}
		}
	}
	if len(after) != len(before) || len(after) < 300 {
		t.Fatal("answers compared", len(before), len(after))
	}
}
