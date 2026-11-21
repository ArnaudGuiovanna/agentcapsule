//go:build linux && cgo && kvm_integration && kvm_product_integration

package worker

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capability"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/pgnotify"
)

// The output stream through the real guest (ADR 022, lot 3): capsule-echo,
// packed with stream.output, streams fake deltas over capsule-init's bridge
// and the worker's platform channel, which stores them as chunks before the
// answer is filed; and the requester's cancellation reaches the harness,
// which reports the invocations it saw canceled ("/stream canceled").
func TestProductWorkerCarriesTheOutputStreamAndTheCancellation(t *testing.T) {
	l := newRegistryLab(t)
	hub, err := pgnotify.New(l.store.Connect, "agentcapsule_invocation_stream")
	if err != nil {
		t.Fatal(err)
	}
	ctx, stop := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = hub.Run(ctx) }()
	t.Cleanup(func() { stop(); <-done })
	if err = l.worker.EnableOutputStreams(DefaultOutputStreams, hub); err != nil {
		t.Fatal(err)
	}
	l.publishManifest("1.0.0", "opt/stream", &[]string{capability.StreamOutput})
	agent := l.create("streams", "1.0.0").AgentID
	var catalog controlplane.AgentCapabilities
	l.request(l.owner(), "GET", "/v1/agents/"+agent+"/capabilities", "", nil, 200, &catalog)
	if !catalog.Declared || !slices.Contains(catalog.Effective, capability.StreamOutput) {
		t.Fatal("catalog", catalog)
	}
	text := func(s string) []capsuleprotocol.ContentPart { return []capsuleprotocol.ContentPart{{Type: "text", Text: s}} }

	// A stream's deltas reach the chunk table; the answer is their text.
	got := l.askContent(agent, "stream-20", text("/stream 20"))
	var want []string
	for i := 1; i <= 20; i++ {
		want = append(want, fmt.Sprintf("word%d", i))
	}
	if len(got) != 1 || got[0].Text != strings.Join(want, " ") {
		t.Fatal("the streamed answer", got)
	}
	var chunks int
	var last int64
	if err = l.db.QueryRow(t.Context(), `SELECT count(*),coalesce(max(c.last_seq),0) FROM invocation_stream_chunks c
        JOIN platform_operations o ON o.id=c.operation_id WHERE o.agent_id=$1 AND c.attempt=1`, agent).Scan(&chunks, &last); err != nil {
		t.Fatal(err)
	}
	// Two steps around the twenty deltas.
	if chunks < 1 || last != 22 {
		t.Fatal("the stream's deltas did not reach the chunk table", chunks, last)
	}

	// The requester cancels a long stream: the harness receives cancel.
	var inv controlplane.Invocation
	l.request(l.user(), "POST", "/v1/agents/"+agent+"/invocations", "stream-long", map[string]any{"content": text("/stream 1200")}, 202, &inv)
	l.await("the long stream's first chunk", true, func() bool {
		var n int
		if err := l.db.QueryRow(t.Context(), "SELECT count(*) FROM invocation_stream_chunks WHERE operation_id=$1", inv.ID).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n > 0
	})
	var canceled controlplane.Invocation
	l.request(l.user(), "POST", "/v1/invocations/"+inv.ID+"/cancel", "cancel-long", nil, 200, &canceled)
	if canceled.State != "canceled" {
		t.Fatal("cancel", canceled.State)
	}
	asked := 0
	l.await("the cancellation reaches the harness", true, func() bool {
		asked++
		answer := l.askContent(agent, fmt.Sprintf("canceled-%d", asked), text("/stream canceled"))
		return len(answer) == 1 && strings.Contains(answer[0].Text, inv.ID)
	})
	var late int
	if err = l.db.QueryRow(t.Context(), `SELECT count(*) FROM invocation_stream_chunks c JOIN platform_operations o ON o.id=c.operation_id
        WHERE c.operation_id=$1 AND c.created_at>o.completed_at`, inv.ID).Scan(&late); err != nil || late != 0 {
		t.Fatal("a chunk was stored after the cancellation", late, err)
	}
	var v controlplane.Invocation
	l.request(l.user(), "GET", "/v1/invocations/"+inv.ID, "", nil, 200, &v)
	if v.State != "canceled" || v.ResultAvailable {
		t.Fatal("the canceled invocation", v.State, v.ResultAvailable)
	}
}
