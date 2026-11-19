package api

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"
)

// The API conventions of docs/product.md §4, route by route over the RBAC
// matrix's routes: every mutation takes an Idempotency-Key (CONV-3), every
// asynchronous route answers 202 with what to follow (CONV-4), identifiers
// and cursors are opaque (CONV-5).

// conventionNotMutations are the routes other than GET that store nothing.
var conventionNotMutations = map[string]string{
	"POST /v1/attachments/{file}/link":       "a sealed link: nothing is stored, two calls give two links (ADR 016)",
	"POST /v1/invocations/{inv}/result/link": "a sealed link: nothing is stored, two calls give two links (ADR 016)",
}

// idempotencyOtherBody is, for each mutation that takes input, another valid
// input for the same path: the first call's key with it is refused.
var idempotencyOtherBody = map[string]string{
	"POST /v1/applications":                                     "{other_app_config}",
	"POST /v1/organizations":                                    `{"name":"{name}-b","initial_owner":{"issuer":"https://client.example","subject":"{name}","display_name":"X"}}`,
	"POST /v1/harness-imports":                                  `{"reference":"ghcr.io/acme/other@sha256:{digest}"}`,
	"POST /v1/members":                                          `{"issuer":"https://client.example","subject":"{name}-b","display_name":"X","role":"agent_user"}`,
	"POST /v1/members/{member}/role":                            `{"role":"agent_operator"}`,
	"POST /v1/teams":                                            `{"name":"{name}-b"}`,
	"POST /v1/teams/{fresh}/members":                            `{"principal_id":"{user_principal}"}`,
	"POST /v1/service-accounts":                                 `{"name":"{name}-b","role":"agent_user"}`,
	"POST /v1/service-accounts/{spare}/tokens":                  `{"scopes":["agent:read","agent:invoke"],"expires_at":"{expires}"}`,
	"POST /v1/llm/providers":                                    `{"name":"{name}-b","kind":"openai_compatible","base_url":"https://llm.example.org/v1","secret":"matrix-credential-0123456789"}`,
	"POST /v1/llm/providers/{fresh}/rotate":                     `{"secret":"matrix-credential-other-0123"}`,
	"POST /v1/llm/aliases":                                      `{"alias":"{name}-b","provider_id":"{provider}","upstream_model":"model-x"}`,
	"POST /v1/llm/aliases/{fresh}/access":                       `{"access":"organization"}`,
	"POST /v1/llm/aliases/{fresh}/prices":                       `{"input_micro_per_mtok":3,"output_micro_per_mtok":4}`,
	"POST /v1/llm/aliases/{fresh}/grants":                       `{"agent_id":"{sender}"}`,
	"POST /v1/llm/calls/{fresh}/settle":                         `{"input_tokens":11,"output_tokens":5}`,
	"POST /v1/llm/budgets":                                      `{"alias":"{fresh}","period":"day","limit_tokens":2000,"mode":"soft"}`,
	"POST /v1/queue/limits":                                     `{"max_pending_per_agent":101,"max_pending_tenant":1000}`,
	"PUT /v1/organizations/{org}/quotas":                        `{"max_agents":999}`,
	"POST /v1/agents":                                           `{"name":"{name}-b","harness":{"name":"reference","version":"1.0.0"},"resources":{"vcpus":1,"memory_mib":256,"data_volume_mib":64}}`,
	"POST /v1/agents/{agent}/idle-policy":                       `{"idle_timeout_seconds":600}`,
	"POST /v1/agents/{agent}/release":                           `{"harness":{"name":"reference","version":"1.0.0"}}`,
	"PUT /v1/agents/{agent}/directory":                          `{"visible":true,"description":"Another description.","skills":[10302],"domains":[111]}`,
	"PUT /v1/agents/{agent}/capabilities":                       `{"allowed":["llm.invoke"]}`,
	"PUT /v1/organizations/current/capabilities":                `{"allowed":["llm.invoke"]}`,
	"PUT /v1/agents/{agent}/inbound":                            `{"mode":"auto"}`,
	"POST /v1/agents/{agent}/assignments":                       `{"principal_id":"{member}","permissions":["read_metadata","invoke"]}`,
	"POST /v1/agents/{agent}/assignments/{assignment}/replace":  `{"permissions":["read_metadata"]}`,
	"POST /v1/agents/{agent}/assignments/{assignment}/reassign": `{"principal_id":"{member}","permissions":["read_metadata","invoke"]}`,
	"POST /v1/agents/{agent}/messages":                          `{"content":[{"type":"text","text":"another"}]}`,
	"POST /v1/agents/{agent}/invocations":                       `{"content":[{"type":"text","text":"another"}]}`,
	"POST /v1/invocations/{fresh}/replay":                       `{"ttl_seconds":3600}`,
	"POST /v1/agents/{agent}/attachments":                       "another file",
}

// idempotencyOtherPath is, for each mutation that takes no input and has no
// disposable target, another path where the same key is reused.
var idempotencyOtherPath = map[string]string{
	"POST /v1/agents/{agent}/wake":  "/v1/agents/{sender}/wake",
	"POST /v1/agents/{agent}/sleep": "/v1/agents/{sender}/sleep",
}

// conventionActor is the first caller the route serves.
func conventionActor(r rbacRoute) (string, bool) {
	if r.Path == "/v1/applications/{app}/accept" {
		return "applicant", true
	}
	for i, want := range strings.Fields(r.Want) {
		if want == rbacOK || want == rbacFiltered {
			return rbacActors[i], true
		}
	}
	return "", false
}

func problemCode(r *httptest.ResponseRecorder) string {
	var p struct {
		Code string `json:"code"`
	}
	_ = json.Unmarshal(r.Body.Bytes(), &p)
	return p.Code
}

// mutationRoutes are the matrix's routes that change state, in its order,
// with the caller each is tried as. The legacy domain's routes are left out:
// production refuses every credential that could reach them
// (TestOperatorBootstrapFromEmptyDatabase).
func mutationRoutes(t *testing.T) ([]rbacRoute, []string) {
	t.Helper()
	var routes []rbacRoute
	var actors []string
	for _, r := range rbacRoutes {
		key := r.Method + " " + r.Path
		if r.Method == "GET" || conventionNotMutations[key] != "" || r.Want == rbacLegacyOnly {
			continue
		}
		actor, ok := conventionActor(r)
		if !ok {
			t.Fatal(key, "serves no caller")
		}
		routes, actors = append(routes, r), append(actors, actor)
	}
	return routes, actors
}

// TestIdempotencyTablesNameRealRoutes keeps the tables above in step with the
// matrix: a mutation is either given another input or another target.
func TestIdempotencyTablesNameRealRoutes(t *testing.T) {
	routes, _ := mutationRoutes(t)
	listed := map[string]bool{}
	for _, r := range routes {
		key := r.Method + " " + r.Path
		listed[key] = true
		_, other := idempotencyOtherBody[key]
		_, path := idempotencyOtherPath[key]
		if other && path || !other && !path && r.fresh == nil {
			t.Error(key, "needs exactly one of: another input, another path, a disposable target")
		}
	}
	for key := range idempotencyOtherBody {
		if !listed[key] {
			t.Error("another input for a route that is not a mutation of the matrix:", key)
		}
	}
	for key := range idempotencyOtherPath {
		if !listed[key] {
			t.Error("another path for a route that is not a mutation of the matrix:", key)
		}
	}
	for key := range conventionNotMutations {
		found := false
		for _, r := range rbacRoutes {
			found = found || r.Method+" "+r.Path == key
		}
		if !found {
			t.Error("no such route:", key)
		}
	}
}

// CONV-3: every mutation of the API, as a caller it serves. Without a key it
// is refused before anything happens; with one it succeeds; the same key and
// input give back the first answer; the same key with another input is
// refused, and on another target never gives back the first answer.
func TestEveryMutationNeedsAnIdempotencyKey(t *testing.T) {
	f := newRBACFixture(t)
	routes, actors := mutationRoutes(t)
	if len(routes) < 50 {
		t.Fatal("too few mutations:", len(routes))
	}
	for i, route := range routes {
		key, actor := route.Method+" "+route.Path, actors[i]
		var fresh map[string]string
		if route.fresh != nil {
			fresh = route.fresh(t, f)
		}
		path, body := f.resolve(t, route.Path, actor, fresh), f.resolve(t, route.body, actor, fresh)
		send := func(path, key, body string) *httptest.ResponseRecorder {
			return rbacRequest(t, f.server, route.Method, path, f.token(t, actor), key, body, route.upload)
		}
		if r := send(path, "", body); r.Code != 400 || problemCode(r) != "idempotency_key_required" {
			t.Errorf("%s as %s without a key: %d %s", key, actor, r.Code, r.Body.String())
			continue
		}
		idem := fmt.Sprintf("conv3-%d", i)
		first := send(path, idem, body)
		if first.Code != route.Success {
			t.Errorf("%s as %s: %d, want %d: %s", key, actor, first.Code, route.Success, first.Body.String())
			continue
		}
		again := send(path, idem, body)
		if again.Code != first.Code || again.Body.String() != first.Body.String() || again.Header().Get("Idempotency-Replayed") != "true" {
			t.Errorf("%s as %s: the replay differs: %d %s, first %s", key, actor, again.Code, again.Body.String(), first.Body.String())
		}
		if other, ok := idempotencyOtherBody[key]; ok {
			if r := send(path, idem, f.resolve(t, other, actor, fresh)); r.Code != 422 || problemCode(r) != "idempotency_key_reused" {
				t.Errorf("%s as %s: the key with another input: %d %s", key, actor, r.Code, r.Body.String())
			}
			continue
		}
		otherPath := idempotencyOtherPath[key]
		otherFresh := fresh
		if otherPath == "" {
			otherPath, otherFresh = route.Path, route.fresh(t, f)
		}
		r := send(f.resolve(t, otherPath, actor, otherFresh), idem, f.resolve(t, route.body, actor, otherFresh))
		switch {
		case r.Code == 422 && problemCode(r) == "idempotency_key_reused":
		case r.Code == route.Success && r.Header().Get("Idempotency-Replayed") == "" && r.Body.String() != first.Body.String():
		default:
			t.Errorf("%s as %s: the key on another target: %d %s", key, actor, r.Code, r.Body.String())
		}
	}
	t.Logf("%d mutations", len(routes))
}

// asyncRoute is what an asynchronous route answers: the field that names the
// work, and the route that follows it.
type asyncRoute struct{ field, follow string }

// asyncRoutes lists every route that answers 202 (CONV-4), the legacy
// domain's aside.
var asyncRoutes = map[string]asyncRoute{
	"POST /v1/harness-imports":            {"id", "/v1/harness-imports/{id}"},
	"POST /v1/agents":                     {"operation_id", "/v1/operations/{id}"},
	"DELETE /v1/agents/{fresh}":           {"operation_id", "/v1/operations/{id}"},
	"POST /v1/agents/{agent}/wake":        {"operation_id", "/v1/operations/{id}"},
	"POST /v1/agents/{agent}/sleep":       {"operation_id", "/v1/operations/{id}"},
	"POST /v1/agents/{agent}/messages":    {"operation_id", "/v1/operations/{id}"},
	"POST /v1/agents/{agent}/invocations": {"id", "/v1/invocations/{id}"},
	"POST /v1/invocations/{fresh}/replay": {"id", "/v1/invocations/{id}"},
}

// TestAsynchronousRoutesAreListed keeps asyncRoutes complete: every route of
// the matrix that answers 202 is in it, and nothing else.
func TestAsynchronousRoutesAreListed(t *testing.T) {
	seen := map[string]bool{}
	for _, r := range rbacRoutes {
		key := r.Method + " " + r.Path
		if r.Success != 202 || r.Want == rbacLegacyOnly {
			continue
		}
		seen[key] = true
		if _, ok := asyncRoutes[key]; !ok {
			t.Error("a route answers 202 without an entry in asyncRoutes:", key)
		}
	}
	for key := range asyncRoutes {
		if !seen[key] {
			t.Error("asyncRoutes names a route that does not answer 202:", key)
		}
	}
}

// CONV-4: every asynchronous route answers 202 with the identifier of its
// work, and the route that follows that work finds it.
func TestAsynchronousRoutesAnswer202WithWorkToFollow(t *testing.T) {
	f := newRBACFixture(t)
	tried := 0
	defer func() {
		if tried != len(asyncRoutes) {
			t.Error("tried", tried, "of the", len(asyncRoutes), "asynchronous routes")
		}
	}()
	for i, route := range rbacRoutes {
		key := route.Method + " " + route.Path
		shape, ok := asyncRoutes[key]
		if !ok {
			continue
		}
		tried++
		actor, _ := conventionActor(route)
		var fresh map[string]string
		if route.fresh != nil {
			fresh = route.fresh(t, f)
		}
		path, body := f.resolve(t, route.Path, actor, fresh), f.resolve(t, route.body, actor, fresh)
		r := rbacRequest(t, f.server, route.Method, path, f.token(t, actor), fmt.Sprintf("conv4-%d", i), body, route.upload)
		var answer map[string]any
		if r.Code != 202 || json.Unmarshal(r.Body.Bytes(), &answer) != nil {
			t.Errorf("%s: %d %s", key, r.Code, r.Body.String())
			continue
		}
		id, _ := answer[shape.field].(string)
		if id == "" {
			t.Errorf("%s: no %s in %s", key, shape.field, r.Body.String())
			continue
		}
		if _, named := answer["operation_id"]; named != (shape.field == "operation_id") {
			t.Errorf("%s: operation_id present=%v, the table says the work is named by %s", key, named, shape.field)
		}
		follow := strings.Replace(shape.follow, "{id}", id, 1)
		got := rbacRequest(t, f.server, "GET", follow, f.token(t, actor), "", "", false)
		if got.Code != 200 || !strings.Contains(got.Body.String(), `"`+id+`"`) {
			t.Errorf("%s: GET %s: %d %s", key, shape.follow, got.Code, got.Body.String())
		}
	}
}

// opaqueID is an identifier: a kind, then 128 random bits.
var opaqueID = regexp.MustCompile(`^[a-z]+_[0-9a-f]{32}$`)

// collectIDs gathers every identifier of a JSON answer: the values of "id"
// and of the fields named "..._id".
func collectIDs(v any, field string, out map[string]string) {
	switch v := v.(type) {
	case map[string]any:
		for k, x := range v {
			collectIDs(x, k, out)
		}
	case []any:
		for _, x := range v {
			collectIDs(x, field, out)
		}
	case string:
		if field != "client_id" && v != "" && (field == "id" || strings.HasSuffix(field, "_id")) {
			out[v] = field
		}
	}
}

// CONV-5: every identifier the API gives is a kind and 128 random bits, so
// it tells nothing of the organization, the time or the order of creation.
// A page goes on from the last identifier or from the audit's cursor; a
// cursor that is not one, or another organization's identifier, shows
// nothing more.
func TestIdentifiersAndCursorsAreOpaque(t *testing.T) {
	f := newRBACFixture(t)
	ids := map[string]string{}
	for _, route := range rbacRoutes {
		if route.Method != "GET" || route.Want == rbacLegacyOnly || strings.Contains(route.Path, "/downloads/") {
			continue
		}
		actor, _ := conventionActor(route)
		var fresh map[string]string
		if route.fresh != nil {
			fresh = route.fresh(t, f)
		}
		r := f.call(t, actor, "GET", f.resolve(t, route.Path, actor, fresh), "", "")
		var answer any
		if r.Code != 200 || json.Unmarshal(r.Body.Bytes(), &answer) != nil {
			t.Fatal(route.Path, r.Code, r.Body.String())
		}
		collectIDs(answer, "", ids)
	}
	kinds := map[string]bool{}
	for id, field := range ids {
		if !opaqueID.MatchString(id) {
			t.Errorf("%s %q is not a kind and 128 random bits", field, id)
			continue
		}
		kinds[id[:strings.Index(id, "_")]] = true
	}
	var names []string
	for k := range kinds {
		names = append(names, k)
	}
	sort.Strings(names)
	if len(names) < 12 {
		t.Fatal("too few kinds of identifiers seen:", names)
	}
	t.Logf("%d identifiers of %d kinds: %s", len(ids), len(names), strings.Join(names, " "))

	// Identifiers made one after the other share nothing but their kind: no
	// counter and no clock at their start.
	var made []string
	for i := 0; i < 3; i++ {
		id := rbacFreshTeam(t, f)["fresh"]
		made = append(made, id[strings.Index(id, "_")+1:])
	}
	for i := 1; i < len(made); i++ {
		if made[i][:8] == made[i-1][:8] {
			t.Fatal("identifiers made in a row start alike:", made)
		}
	}

	// Pages: the audit's cursor shows none of its page's fields; one that is
	// not a cursor is refused.
	var page struct {
		Items []map[string]any `json:"items"`
		Next  string           `json:"next"`
	}
	r := f.call(t, "owner", "GET", "/v1/audit?limit=2", "", "")
	if r.Code != 200 || json.Unmarshal(r.Body.Bytes(), &page) != nil || page.Next == "" || len(page.Items) != 2 {
		t.Fatal("audit page", r.Code, r.Body.String())
	}
	for _, item := range page.Items {
		for _, v := range item {
			if s, ok := v.(string); ok && len(s) > 3 && strings.Contains(page.Next, s) {
				t.Fatal("the audit cursor shows", s, "in clear")
			}
		}
	}
	for _, bad := range []string{"not-a-cursor!", page.Items[1]["id"].(string), "MTIzNA"} {
		if r = f.call(t, "owner", "GET", "/v1/audit?after="+bad, "", ""); r.Code != 400 || problemCode(r) != "invalid_request" {
			t.Error("a forged audit cursor", bad, r.Code, r.Body.String())
		}
	}
	// Lists go on from an identifier: another organization's, or one that
	// does not exist, shows only what the caller sees without it.
	items := func(path string) []string {
		var page struct {
			Items []map[string]any `json:"items"`
		}
		r := f.call(t, "owner", "GET", path, "", "")
		if r.Code != 200 || json.Unmarshal(r.Body.Bytes(), &page) != nil {
			t.Fatal(path, r.Code, r.Body.String())
		}
		var out []string
		for _, item := range page.Items {
			out = append(out, fmt.Sprint(item["id"], item["principal_id"]))
		}
		return out
	}
	for _, list := range []string{"/v1/teams", "/v1/members", "/v1/agents", "/v1/service-accounts", "/v1/llm/providers", "/v1/agents/" + f.ids["agent"] + "/invocations"} {
		own := items(list)
		for _, after := range []string{f.second.org.ID, f.second.org.OwnerPrincipalID, "zzz_" + strings.Repeat("f", 32)} {
			for _, item := range items(list + "?after=" + after) {
				if !slices.Contains(own, item) {
					t.Fatal(list, "after", after, "shows", item)
				}
			}
		}
	}
}
