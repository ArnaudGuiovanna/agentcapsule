package capability

import (
	"reflect"
	"testing"
)

func TestVocabularyAndIntersection(t *testing.T) {
	if err := ValidSet([]string{LLMInvoke, AgentsDelegate}); err != nil {
		t.Fatal(err)
	}
	if err := ValidSet([]string{}); err != nil {
		t.Fatal("an empty set is a valid request for nothing", err)
	}
	for _, bad := range [][]string{{"files.write"}, {LLMInvoke, LLMInvoke}, {""}, {"LLM.INVOKE"}} {
		if ValidSet(bad) == nil {
			t.Error("accepted", bad)
		}
	}
	got := Intersect([]string{AgentsDiscover, LLMInvoke, AgentsDelegate}, []string{LLMInvoke, AgentsDiscover}, []string{AgentsDiscover, LLMInvoke})
	if !reflect.DeepEqual(got, []string{AgentsDiscover, LLMInvoke}) {
		t.Fatal(got)
	}
	if got := Intersect(Known(), []string{}); len(got) != 0 || got == nil {
		t.Fatal("an empty policy allows nothing", got)
	}
	if !reflect.DeepEqual(Known(), []string{AgentsDelegate, AgentsDiscover, LLMInvoke}) {
		t.Fatal(Known())
	}
}

// Each platform channel route that an agent's rights govern names exactly one
// capability; the others need none.
func TestRouteCapabilities(t *testing.T) {
	for path, want := range map[string]string{
		"/v1/llm/complete":                  LLMInvoke,
		"/v1/llm/forward":                   LLMInvoke,
		"/v1/agent-requests":                AgentsDelegate,
		"/v1/agent-requests/arq_1/status":   AgentsDelegate,
		"/v1/directory/find":                AgentsDiscover,
		"/v1/directory/search":              AgentsDiscover,
		"/v1/directory/agent":               AgentsDiscover,
		"/v1/agent-requests/arq_1/reply":    "",
		"/v1/invocations/complete":          "",
		"/v1/attachments/read":              "",
		"/v1/owner/messages":                "",
		"/v1/health":                        "",
		"/v1/agent-requests/a/b/status":     AgentsDelegate,
		"/v1/llm/completeness":              "",
		"/v1/agent-requests/arq_1/statuses": "",
	} {
		if got := ForRoute(path); got != want {
			t.Errorf("%s: %q, want %q", path, got, want)
		}
	}
}
