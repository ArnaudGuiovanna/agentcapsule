package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestDeploymentAndConfigurationSyntax(t *testing.T) {
	for _, test := range []struct {
		args        []string
		input, path string
		body        map[string]any
	}{
		{[]string{"deployment", "plan", "--count", "100", "--template", "support@3", "--active-count", "2"}, "", "/v1/deployment-plans", map[string]any{"count": float64(100), "template": "support@3", "active_count": float64(2)}},
		{[]string{"corpus-build", "files", "b", "--status", "failed"}, "", "/v1/corpus-builds/b/review-file?path=report.json", nil},
		{[]string{"corpus-build", "index", "b"}, "", "/v1/corpus-builds/b/review-file?path=INDEX.md", nil},
		{[]string{"corpus-build", "try", "b", "--agent", "a", "--mount", "finance"}, "", "/v1/corpus-builds/b/try", map[string]any{"agent_id": "a", "mount": "finance"}},
		{[]string{"corpus-build", "publish", "b", "--version", "3"}, "", "/v1/corpus-builds/b/publish", map[string]any{"version": float64(3)}},
		{[]string{"corpus", "versions", "finance", "--include-deprecated"}, "", "/v1/corpus-releases?corpus_id=finance&include_deprecated=true", nil},
		{[]string{"operation", "wait", "--type", "corpus-build", "b"}, "", "/v1/corpus-builds/b", nil},
		{[]string{"source-credential", "create", "--kind", "gitlab", "--name", "local", "--host", "gitlab.example.org", "--secret-file", "-"}, "token", "/v1/source-credentials", map[string]any{"host": "gitlab.example.org", "kind": "gitlab", "name": "local", "secret": "token"}},
		{[]string{"agent", "resize", "agt_1", "--vcpus", "2", "--memory-mib", "512"}, "", "/v1/agents/agt_1/resize", map[string]any{"vcpus": float64(2), "memory_mib": float64(512)}},
		{[]string{"deployment", "apply", "--plan", "plan_3"}, "", "/v1/deployment-plans/plan_3/apply", nil},
		{[]string{"app", "register", "monapp", "--config", "-"}, "issuer: https://id.example.org", "/v1/applications", map[string]any{"name": "monapp", "issuer": "https://id.example.org"}},
		{[]string{"access", "explain", "--member", "alice", "--agent", "support"}, "", "/v1/access/explain?agent=support&member=alice", nil},
		{[]string{"operation", "show", "--type", "revocation", "arv_1"}, "", "/v1/access-revocations/arv_1", nil},
		{[]string{"operation", "wait", "--type", "revocation", "arv_1"}, "", "/v1/access-revocations/arv_1", nil},
	} {
		pos, opts, err := parse(test.args)
		if err != nil {
			t.Fatal(err)
		}
		a, err := buildAction(pos, opts, strings.NewReader(test.input))
		if err != nil || a.path != test.path {
			t.Fatal(test.args, a.path, err)
		}
		if len(test.body) > 0 {
			var b map[string]any
			if err = json.Unmarshal(a.body, &b); err != nil {
				t.Fatal(err)
			}
			for k, v := range test.body {
				if b[k] != v {
					t.Fatal(b)
				}
			}
		}
	}
	for _, route := range []string{"https://other/v1/agents", "//other/v1/agents", "/v1/agents/%2e%2e", "/v1/x%2fy"} {
		if validRoute(route) {
			t.Fatal("unsafe path", route)
		}
	}
}

func TestOperationStates(t *testing.T) {
	for input, want := range map[string]string{
		`{"state":"REVIEW"}`: "success", `{"state":"PUBLISHED"}`: "success", `{"state":"FAILED"}`: "failure", `{"state":"CANCELED"}`: "failure", `{"state":"EXPIRED"}`: "failure",
		`{"state":"QUEUED"}`: "pending", `{"state":"FETCHING"}`: "pending", `{"state":"SCANNING"}`: "pending", `{"state":"FETCHING_LFS"}`: "pending", `{"state":"CONVERTING"}`: "pending", `{"state":"PACKAGING"}`: "pending",
		`{"status":"SUCCEEDED"}`: "success", `{"state":"completed"}`: "success", `{"state":"READY"}`: "success",
		`{"state":"IMPORTING"}`: "pending", `{"state":"working"}`: "pending", `{"state":"scheduled"}`: "pending",
		`{"state":"REJECTED"}`: "failure", `{"status":"paused"}`: "failure",
		`{"kind":"member","state":"pending"}`: "pending", `{"kind":"member","state":"confirmed"}`: "success",
		`{"state":"lost","result_available":true}`:               "pending",
		`{"state":"lost","error_code":"requester_revoked"}`:      "failure",
		`{"state":"completed","lost_at":"2026-11-19T09:00:00Z"}`: "success",
	} {
		_, got, err := operationState([]byte(input))
		if err != nil || got != want {
			t.Fatal(input, got, err)
		}
	}
	if _, _, err := operationState([]byte(`{"status":"future_state"}`)); err == nil {
		t.Fatal("unknown state")
	}
}

func TestNamedCommandsHavePublishedHTTPContracts(t *testing.T) {
	raw, err := os.ReadFile("../../openapi/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var contract struct {
		Paths map[string]map[string]any `yaml:"paths"`
	}
	if err = yaml.Unmarshal(raw, &contract); err != nil {
		t.Fatal(err)
	}
	routes := map[string]bool{}
	for path, verbs := range contract.Paths {
		for verb := range verbs {
			routes[strings.ToUpper(verb)+" "+param.ReplaceAllString(path, "{}")] = true
		}
	}
	for cmd, spec := range commands {
		method, path, _ := strings.Cut(spec, " ")
		if !routes[method+" /v1"+param.ReplaceAllString(path, "{}")] {
			t.Errorf("%s has no published contract for %s", cmd, spec)
		}
	}
}
