package api

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
)

// Use real sealed frames owned by a technical principal. A review reader
// can receive only the conversion's file steps, even after the worker moves
// to another phase and clears the live invocation reference.
func TestCorpusBuildWatchFiltersAndReplaysConversion(t *testing.T) {
	f := newRBACFixture(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	if err := f.server.StartEventStreams(ctx, 8); err != nil {
		t.Fatal(err)
	}
	agent := f.ids["agent"]
	op := f.invoke(t, "service")
	claim, err := f.l.store.ClaimPlacement(ctx, agent, "local", "corpus-worker", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	vm := controlplane.VMCaller{AgentID: agent, HostID: "local", Generation: claim.Generation, VMID: fmt.Sprintf("%016x", claim.Generation)}
	if err = f.l.store.ConfirmPlacement(ctx, agent, vm.HostID, "corpus-worker", vm.Generation, vm.VMID); err != nil {
		t.Fatal(err)
	}
	var mb string
	if err = f.db.QueryRow(ctx, "SELECT id FROM agent_mailboxes WHERE instruction_id=$1", op).Scan(&mb); err != nil {
		t.Fatal(err)
	}
	delivery, err := f.transit.ClaimInstruction(ctx, mb, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.transit.AuthorizeInstruction(ctx, mb, delivery.Token); err != nil {
		t.Fatal(err)
	}
	if err = f.transit.AcknowledgeInstruction(ctx, mb, delivery.Token, capsuleprotocol.WorkingResult()); err != nil {
		t.Fatal(err)
	}
	if _, err = f.transit.OpenOutputStreamFromVM(ctx, vm, op, 0); err != nil {
		t.Fatal(err)
	}
	build := f.ids["review"]
	// Use the fixture's live agent as the hidden technical builder on this
	// isolated schema. Its requester remains the real service account.
	if _, err = f.db.Exec(ctx, `UPDATE agents SET discoverable=false,kind='corpus_builder',builder_principal=(SELECT requested_by_principal_id FROM platform_operations WHERE id=$2) WHERE id=$1`, agent, op); err != nil {
		t.Fatal(err)
	}
	if _, err = f.db.Exec(ctx, "UPDATE corpus_builds SET state='CONVERTING',invocation_id=$2,builder_agent_id=$3 WHERE id=$1", build, op, agent); err != nil {
		t.Fatal(err)
	}
	h := httptest.NewServer(f.server)
	defer h.Close()
	c := http.Client{Timeout: 9 * time.Second}
	open := func(actor, cursor string) *http.Response {
		t.Helper()
		req, _ := http.NewRequestWithContext(ctx, "GET", h.URL+"/v1/corpus-builds/"+build+"/events", nil)
		req.Header.Set("Authorization", "Bearer "+f.token(t, actor))
		if cursor != "" {
			req.Header.Set("Last-Event-ID", cursor)
		}
		res, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	denied := open("foreign", "")
	denied.Body.Close()
	if denied.StatusCode != 404 {
		t.Fatal("foreign organization", denied.StatusCode)
	}
	live := open("owner", "")
	defer live.Body.Close()
	if live.StatusCode != 200 {
		body, _ := io.ReadAll(live.Body)
		t.Fatal(live.StatusCode, string(body))
	}
	buf := bufio.NewReader(live.Body)
	readEvent := func() string {
		t.Helper()
		var data strings.Builder
		for {
			line, err := buf.ReadString('\n')
			if err != nil {
				t.Fatal("event", data.String(), err)
			}
			data.WriteString(line)
			if line == "\n" {
				return data.String()
			}
		}
	}
	if state := readEvent(); !strings.Contains(state, `"state":"CONVERTING"`) {
		t.Fatal(state)
	}
	frames := []capsuleprotocol.OutputFrame{
		{Type: "delta", Seq: 1, Text: "PRIVATE_BUILDER_RESULT"},
		{Type: "step", Seq: 2, Step: "file-1", State: "started", Label: "course/one.pdf"},
		{Type: "step", Seq: 3, Step: "calculation", State: "done", Label: "PRIVATE_BUILDER_LABEL"},
		{Type: "step", Seq: 4, Step: "file-1", State: "done", Label: "course/one.pdf"},
	}
	if _, err = f.transit.AppendOutputStreamFromVM(ctx, vm, op, 1, frames, controlplane.DefaultStreamLimits); err != nil {
		t.Fatal(err)
	}
	first, second := readEvent(), readEvent()
	if !strings.Contains(first, "id: 1:2") || !strings.Contains(second, "id: 1:4") || strings.Contains(first+second, "PRIVATE") || !strings.Contains(second, "course/one.pdf") {
		t.Fatal(first + second)
	}
	if _, err = f.db.Exec(ctx, "UPDATE corpus_builds SET state='REVIEW',invocation_id=NULL WHERE id=$1", build); err != nil {
		t.Fatal(err)
	}
	ending, err := io.ReadAll(buf)
	if err != nil || !strings.Contains(string(ending), "event: end") || !strings.Contains(string(ending), `"state":"REVIEW"`) {
		t.Fatal(string(ending), err)
	}
	replay := open("admin", "1:2")
	body, err := io.ReadAll(replay.Body)
	replay.Body.Close()
	if err != nil || replay.StatusCode != 200 || strings.Count(string(body), "event: step") != 1 || !strings.Contains(string(body), "id: 1:4") || strings.Contains(string(body), "PRIVATE") {
		t.Fatal(replay.StatusCode, string(body), err)
	}
}
