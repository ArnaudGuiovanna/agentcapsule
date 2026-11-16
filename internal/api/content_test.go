package api

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnessstore"
)

// echoRuntime answers each invocation with its own content, as the reference
// harness does, and keeps the envelope it received.
type echoRuntime struct{ received []byte }

func (r *echoRuntime) Send(context.Context, string, harnessstore.Event) (harnessstore.Receipt, error) {
	return harnessstore.Receipt{}, capsuleprotocol.ErrTransport
}
func (r *echoRuntime) Fence(context.Context, string, string) error { return nil }
func (r *echoRuntime) Invoke(_ context.Context, target string, e harnessstore.Event) (harnessstore.Receipt, error) {
	in, err := capsuleprotocol.DecodeInvocation(e, target)
	if err != nil {
		return harnessstore.Receipt{}, err
	}
	r.received = bytes.Clone(e.Body)
	result, err := json.Marshal(capsuleprotocol.OwnerMessage{Content: in.Content})
	return harnessstore.Receipt{Result: result}, err
}

// tenantInvocationLab is an organization agent with transit keys, and bob
// assigned to it with invoke and read_content.
func tenantInvocationLab(t *testing.T) (*apiDelegationFixture, *controlplane.Transit, string, string, string) {
	t.Helper()
	l, at, owner := apiAgentsLab(t)
	transit, err := controlplane.NewTransit(l.store, "v1", map[string][]byte{"v1": bytes.Repeat([]byte{0x45}, 32)}, 7*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err = transit.ActivateKeys(t.Context()); err != nil {
		t.Fatal(err)
	}
	server, err := NewForHostWithTransit(l.store, l.server.accounts, "local", transit)
	if err != nil {
		t.Fatal(err)
	}
	server.SetDelegatedIdentityVerifier(l.verifier)
	l.server = server
	agent := apiActiveTenantAgent(t, l, owner, "structured")
	bob := apiAddMember(t, l, owner, "bob", "agent_user")
	assignment := `{"principal_id":"` + bob.PrincipalID + `","permissions":["read_metadata","invoke","read_content"]}`
	if r := call(t, l.server, "POST", "/v1/agents/"+agent+"/assignments", owner, "asg", assignment); r.Code != 201 {
		t.Fatal("assign", r.Code, r.Body.String())
	}
	return l, transit, agent, owner, l.sign(t, at, "bob-invoke", "bob", invokeScopes)
}

// EXT-001: an invocation carries text and JSON parts, the JSON is validated
// at the API, crosses the transit encryption unchanged, reaches the agent as
// a JSON part and comes back in the result.
func TestHTTPInvocationCarriesStructuredJSON(t *testing.T) {
	l, transit, agent, _, bob := tenantInvocationLab(t)
	path := "/v1/agents/" + agent + "/invocations"
	for name, bad := range map[string]string{
		"null value":     `{"content":[{"type":"json","json":null}]}`,
		"no value":       `{"content":[{"type":"json"}]}`,
		"invalid JSON":   `{"content":[{"type":"json","json":{"a":}}]}`,
		"too deep":       `{"content":[{"type":"json","json":` + strings.Repeat("[", 33) + strings.Repeat("]", 33) + `}]}`,
		"text and json":  `{"content":[{"type":"json","json":1,"text":"x"}]}`,
		"unknown type":   `{"content":[{"type":"xml","text":"<a/>"}]}`,
		"unknown field":  `{"content":[{"type":"json","json":1,"media_type":"application/json"}]}`,
		"over 32 KiB":    `{"content":[{"type":"text","text":"` + strings.Repeat("a", 20<<10) + `"},{"type":"json","json":"` + strings.Repeat("b", 13<<10) + `"}]}`,
		"no part at all": `{"content":[]}`,
	} {
		if r := call(t, l.server, "POST", path, bob, "bad-"+name, bad); r.Code != 400 {
			t.Error(name, r.Code, r.Body.String())
		}
	}
	input := `{"content":[{"type":"text","text":"Total these rows."},{"type":"json","json":{"rows": [ {"id": 1, "amount": 12.5}, {"id": 2, "amount": 7} ]}}]}`
	made := call(t, l.server, "POST", path, bob, "structured", input)
	var inv controlplane.Invocation
	if made.Code != 202 || json.Unmarshal(made.Body.Bytes(), &inv) != nil {
		t.Fatal("structured invocation refused", made.Code, made.Body.String())
	}
	// The same value with other spacing is the same request.
	if r := call(t, l.server, "POST", path, bob, "structured", strings.Replace(input, `{"rows": [`, `{ "rows" :[`, 1)); r.Code != 202 || r.Header().Get("Idempotency-Replayed") != "true" {
		t.Fatal("replay with the same value", r.Code, r.Body.String())
	}
	id, err := l.store.HeadDelivery(t.Context(), agent)
	if err != nil {
		t.Fatal(err)
	}
	runtime := &echoRuntime{}
	if err = transit.DispatchMailbox(t.Context(), id, time.Minute, runtime); err != nil {
		t.Fatal(err)
	}
	want := capsuleprotocol.ContentPart{Type: "json", JSON: `{"rows":[{"id":1,"amount":12.5},{"id":2,"amount":7}]}`}
	delivered, err := capsuleprotocol.DecodeInvocation(harnessstore.Event{ID: id, Subjects: []string{"agent/" + agent, "event/" + id}, Body: runtime.received}, agent)
	if err != nil || len(delivered.Content) != 2 || delivered.Content[1] != want {
		t.Fatal("delivered content", delivered.Content, err)
	}
	r := call(t, l.server, "GET", "/v1/invocations/"+inv.ID+"/result", bob, "", "")
	var result capsuleprotocol.OwnerMessage
	if r.Code != 200 || json.Unmarshal(r.Body.Bytes(), &result) != nil || len(result.Content) != 2 ||
		result.Content[0] != (capsuleprotocol.ContentPart{Type: "text", Text: "Total these rows."}) || result.Content[1] != want {
		t.Fatal("result", r.Code, r.Body.String())
	}
}
