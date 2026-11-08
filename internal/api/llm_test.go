package api

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
)

func TestLLMProviderEndpointsNeverReturnTheCredential(t *testing.T) {
	l, cutoff, owner := apiAgentsLab(t)
	secret := "sk-http-0123456789abcdef"
	body := `{"name":"main","kind":"openai_compatible","base_url":"https://llm.example.org/v1","secret":"` + secret + `"}`
	r := call(t, l.server, "POST", "/v1/llm/providers", owner, "p1", body)
	var p controlplane.LLMProvider
	if r.Code != 201 || json.Unmarshal(r.Body.Bytes(), &p) != nil || strings.Contains(r.Body.String(), secret) {
		t.Fatal("create", r.Code, r.Body.String())
	}
	if again := call(t, l.server, "POST", "/v1/llm/providers", owner, "p1", body); again.Header().Get("Idempotency-Replayed") != "true" || strings.Contains(again.Body.String(), secret) {
		t.Fatal("replay", again.Code, again.Body.String())
	}
	if r = call(t, l.server, "POST", "/v1/llm/aliases", owner, "a1", `{"alias":"fast","provider_id":"`+p.ID+`","upstream_model":"gpt-x"}`); r.Code != 201 {
		t.Fatal("alias", r.Code, r.Body.String())
	}
	for _, path := range []string{"/v1/llm/providers", "/v1/llm/aliases"} {
		if r = call(t, l.server, "GET", path, owner, "", ""); r.Code != 200 || strings.Contains(r.Body.String(), secret) {
			t.Fatal("list", path, r.Code)
		}
	}
	if r = call(t, l.server, "POST", "/v1/llm/providers/"+p.ID+"/rotate", owner, "r1", `{"secret":"sk-rotated-1234567890"}`); r.Code != 200 || strings.Contains(r.Body.String(), "sk-rotated") { // gitleaks:allow test fixture
		t.Fatal("rotate", r.Code, r.Body.String())
	}
	// A credential without the scope is refused.
	narrow := l.sign(t, cutoff, "owner", "alice", "org:read")
	if r = call(t, l.server, "GET", "/v1/llm/providers", narrow, "", ""); r.Code != 403 {
		t.Fatal("scope-less list", r.Code)
	}
	if r = call(t, l.server, "POST", "/v1/llm/providers/"+p.ID+"/disable", owner, "d1", `{}`); r.Code != 200 {
		t.Fatal("disable", r.Code, r.Body.String())
	}
	if r = call(t, l.server, "POST", "/v1/llm/providers", owner, "p2", `{"name":"x","kind":"openai_compatible","base_url":"http://evil.example.org","secret":"`+secret+`"}`); r.Code != 400 {
		t.Fatal("plain http accepted", r.Code)
	}
}
