package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestDeploymentAndConfigurationSyntax(t *testing.T) {
	for _, test := range []struct {
		args        []string
		input, path string
		body        map[string]any
	}{
		{[]string{"deployment", "plan", "--count", "100", "--template", "support@3", "--active-count", "2"}, "", "/v1/deployment-plans", map[string]any{"count": float64(100), "template": "support@3", "active_count": float64(2)}},
		{[]string{"deployment", "apply", "--plan", "plan_3"}, "", "/v1/deployment-plans/plan_3/apply", nil},
		{[]string{"app", "register", "monapp", "--config", "-"}, "issuer: https://id.example.org", "/v1/applications", map[string]any{"name": "monapp", "issuer": "https://id.example.org"}},
		{[]string{"access", "explain", "--member", "alice", "--agent", "support"}, "", "/v1/access/explain?agent=support&member=alice", nil},
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
