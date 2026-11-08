package capsuleprotocol

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
)

func (a *platformFake) CompleteInvocation(_ context.Context, key string, in InvocationCompletion) (CompletionReceipt, error) {
	a.calls.Add(1)
	if key == "late" {
		return CompletionReceipt{}, &PlatformError{Code: "expired"}
	}
	return CompletionReceipt{OperationID: in.OperationID, State: in.Outcome}, nil
}

func TestWorkingAcknowledgmentIsExact(t *testing.T) {
	if !IsWorkingResult(WorkingResult()) || !IsWorkingResult([]byte(` {"status":"working"} `)) {
		t.Fatal("the working acknowledgment is not recognized")
	}
	for _, b := range []string{`{"status":"done"}`, `{"status":"working","content":[]}`, `{"status":"working"} {}`,
		`{"status":"working"} x`, `{"content":[{"type":"text","text":"working"}]}`, `"working"`, ``} {
		if IsWorkingResult([]byte(b)) {
			t.Fatal("not a working acknowledgment:", b)
		}
	}
}

func TestInvocationCompletionCrossesTheBridgeStrictly(t *testing.T) {
	c, host, _, api, _ := platformFixture(t)
	done := InvocationCompletion{OperationID: "op-1", Outcome: "completed", Content: []TextContent{{Type: "text", Text: "answer"}}}
	r, err := c.CompleteInvocation(t.Context(), "k1", done)
	if err != nil || r.OperationID != "op-1" || r.State != "completed" {
		t.Fatal(r, err)
	}
	var pe *PlatformError
	if _, err = c.CompleteInvocation(t.Context(), "late", done); !errors.As(err, &pe) || pe.Code != "expired" {
		t.Fatal("typed refusal lost", err)
	}
	calls := api.calls.Load()
	for i, bad := range []InvocationCompletion{
		{OperationID: "", Outcome: "completed", Content: done.Content},
		{OperationID: "op", Outcome: "maybe", Content: done.Content},
		{OperationID: "op", Outcome: "completed"},
		{OperationID: "op", Outcome: "failed", Content: done.Content},
	} {
		if _, err = c.CompleteInvocation(t.Context(), "bad", bad); err == nil {
			t.Fatal("invalid completion accepted", i)
		}
	}
	if api.calls.Load() != calls {
		t.Fatal("an invalid completion reached the adapter")
	}
	// A completion cannot ride on another operation, nor lack its key.
	for _, req := range []platformRequest{
		{Protocol: Version, Identity: host.Identity, Key: "k", Completion: &done, LLM: &LLMRequest{Alias: "a", Messages: []LLMMessage{{Role: "user", Content: "x"}}}},
		{Protocol: Version, Identity: host.Identity, Completion: &done},
	} {
		b, _ := json.Marshal(req)
		for _, path := range []string{"/v1/invocations/complete", "/v1/llm/complete"} {
			hr, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://"+c.client.serverName+path, bytes.NewReader(b))
			resp, err := c.client.http.Do(hr)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != 400 {
				t.Fatal("mixed or keyless completion accepted", path, resp.StatusCode)
			}
		}
	}
}
