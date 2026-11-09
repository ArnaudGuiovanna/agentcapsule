package capsuleprotocol

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"
)

func (a *platformFake) FindAgents(_ context.Context, q DirectoryQuery) ([]DirectoryAgent, error) {
	a.calls.Add(1)
	switch q.Skills[0] {
	case 1:
		return nil, nil
	case 2:
		return nil, errors.New("directory at 10.0.0.7 refused the private credential")
	}
	return []DirectoryAgent{{AgentID: "b", Description: "Summarizes.", Skills: q.Skills, Domains: []int{111}}}, nil
}

func TestDirectoryFindCarriesOnlySkillsAndTypedOutcomes(t *testing.T) {
	c, _, _, api, _ := platformFixture(t)
	found, err := c.FindAgents(t.Context(), DirectoryQuery{Skills: []int{10302}})
	if err != nil || !reflect.DeepEqual(found, []DirectoryAgent{{AgentID: "b", Description: "Summarizes.", Skills: []int{10302}, Domains: []int{111}}}) {
		t.Fatal(found, err)
	}
	if found, err = c.FindAgents(t.Context(), DirectoryQuery{Skills: []int{1}}); err != nil || found == nil || len(found) != 0 {
		t.Fatal("an empty answer", found, err)
	}
	// An adapter error crosses the channel as a code, never as its text.
	_, err = c.FindAgents(t.Context(), DirectoryQuery{Skills: []int{2}})
	var pe *PlatformError
	if !errors.As(err, &pe) || pe.Code != "unavailable" || bytes.Contains([]byte(err.Error()), []byte("10.0.0.7")) {
		t.Fatal(err)
	}
	// Invalid queries, and a query on another route, never reach the adapter.
	calls := api.calls.Load()
	for _, bad := range []DirectoryQuery{{}, {Skills: []int{0}}, {Skills: []int{5, 5}}, {Skills: make([]int, 21)}} {
		if _, err = c.FindAgents(t.Context(), bad); err == nil {
			t.Fatal("invalid query accepted", bad)
		}
	}
	q := DirectoryQuery{Skills: []int{10302}}
	if _, err = c.call(t.Context(), "/v1/directory/search", &platformRequest{Candidates: []string{"b"}, Query: &q}); err == nil {
		t.Fatal("a query rode on the candidate search")
	}
	if _, err = c.call(t.Context(), "/v1/directory/find", &platformRequest{Query: &q, Key: "k"}); err == nil {
		t.Fatal("a query carried an idempotency key")
	}
	if api.calls.Load() != calls {
		t.Fatal("a refused query reached the adapter")
	}
}

// minimalPlatform offers no Directory.
type minimalPlatform struct{}

func (minimalPlatform) Validate(context.Context) error { return nil }
func (minimalPlatform) Submit(context.Context, string, Submission) (PlatformReceipt, error) {
	return PlatformReceipt{}, nil
}
func (minimalPlatform) Reply(context.Context, string, string, Reply) (PlatformReceipt, error) {
	return PlatformReceipt{}, nil
}
func (minimalPlatform) Search(context.Context, []string) ([]string, error) { return nil, nil }

func TestDirectoryFindWithoutADirectoryIsUnavailable(t *testing.T) {
	id := Identity{Incarnation: 1, AgentID: "a", Generation: 1, VMID: "0123456789abcdef"}
	h := &platformHandler{id: id, api: minimalPlatform{}, slots: make(chan struct{}, 1), localAuth: func(*http.Request) bool { return true }}
	body, _ := json.Marshal(platformRequest{Protocol: Version, Identity: id, Query: &DirectoryQuery{Skills: []int{10302}}})
	rec := httptest.NewRecorder()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	h.ServeHTTP(rec, httptest.NewRequestWithContext(ctx, http.MethodPost, "/v1/directory/find", bytes.NewReader(body)))
	var out platformResponse
	if rec.Code != http.StatusServiceUnavailable || json.Unmarshal(rec.Body.Bytes(), &out) != nil || out.Code != "unavailable" {
		t.Fatal(rec.Code, rec.Body.String())
	}
}
