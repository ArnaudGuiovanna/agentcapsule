package api

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/telemetry"
)

// The load fixture binds seven authenticated platform channels to seven
// registered boots. Normal protocol coalescing, transit storage, the shared
// LISTEN connection and the public SSE handler all run against one database.
type loadGuest struct {
	capsuleprotocol.PlatformAPI
	transit *controlplane.Transit
	caller  controlplane.VMCaller
}
type loadOutput struct {
	guest  *loadGuest
	op     string
	opened controlplane.StreamOpening
}

func (g *loadGuest) OpenOutputStream(ctx context.Context, op string, attempt int) (capsuleprotocol.OutputStream, error) {
	opened, err := g.transit.OpenOutputStreamFromVM(ctx, g.caller, op, attempt)
	if err != nil {
		return nil, err
	}
	return &loadOutput{g, op, opened}, nil
}
func (s *loadOutput) Attempt() int                                 { return s.opened.Attempt }
func (s *loadOutput) LastSeq() int64                               { return s.opened.LastSeq }
func (s *loadOutput) Closing() string                              { return s.opened.Closing }
func (s *loadOutput) Signals() <-chan capsuleprotocol.StreamSignal { return nil }
func (s *loadOutput) Close(string, int)                            {}
func (s *loadOutput) Append(ctx context.Context, frames []capsuleprotocol.OutputFrame) (string, error) {
	r, err := s.guest.transit.AppendOutputStreamFromVM(ctx, s.guest.caller, s.op, s.Attempt(), frames, controlplane.DefaultStreamLimits)
	s.opened.LastSeq = r.LastSeq
	return r.Reason, err
}
func (g *loadGuest) client(t *testing.T) *capsuleprotocol.PlatformClient {
	t.Helper()
	id := capsuleprotocol.Identity{Incarnation: 1, AgentID: g.caller.AgentID, Generation: uint64(g.caller.Generation), VMID: g.caller.VMID}
	host, guest, err := capsuleprotocol.NewBootCredentials(id, time.Hour, true)
	if err != nil {
		t.Fatal(err)
	}
	h, err := capsuleprotocol.NewPlatformHandler(id, g)
	if err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { defer close(done); _ = capsuleprotocol.ServeAuthenticated(ctx, l, *host.Platform, h) }()
	t.Cleanup(func() { cancel(); <-done })
	client, err := capsuleprotocol.NewPlatformClient(*guest.Platform, func(ctx context.Context) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", l.Addr().String())
	})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func TestInvocationEventsLoad(t *testing.T) {
	if os.Getenv("AGENTCAPSULE_STREAM_LOAD") != "1" {
		t.Skip("set AGENTCAPSULE_STREAM_LOAD=1 for the 100-stream qualification")
	}
	f := newRBACFixture(t)
	ctx := t.Context()
	const streams = 100
	const frames = 10
	const sentinel = "load-private-8b453a-"
	type trial struct {
		op      string
		vm      controlplane.VMCaller
		client  *capsuleprotocol.PlatformClient
		writer  *capsuleprotocol.OutputStreamWriter
		latency time.Duration
	}
	jobs := make([]trial, 0, streams)
	for n := 0; len(jobs) < streams; n++ {
		agent := f.ids["agent"]
		if n > 0 {
			agent = apiActiveTenantAgent(t, f.l, f.token(t, "owner"), fmt.Sprintf("load-%d", n))
			f.must(t, "owner", "POST", "/v1/agents/"+agent+"/assignments", fmt.Sprintf(`{"principal_id":%q,"permissions":["read_metadata","invoke","read_content"]}`, f.ids["user_principal"]), 201, nil)
		}
		claim, err := f.l.store.ClaimPlacement(ctx, agent, "local", "load-worker", 5*time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		vm := controlplane.VMCaller{AgentID: agent, HostID: "local", Generation: claim.Generation, VMID: fmt.Sprintf("%016x", n+1)}
		if err = f.l.store.ConfirmPlacement(ctx, agent, "local", "load-worker", vm.Generation, vm.VMID); err != nil {
			t.Fatal(err)
		}
		client := (&loadGuest{transit: f.transit, caller: vm}).client(t)
		for i := 0; i < 15 && len(jobs) < streams; i++ {
			var inv controlplane.Invocation
			f.must(t, "user", "POST", "/v1/agents/"+agent+"/invocations", `{"content":[{"type":"text","text":"load"}]}`, 202, &inv)
			var mailbox string
			if err := f.db.QueryRow(ctx, "SELECT id FROM agent_mailboxes WHERE instruction_id=$1", inv.ID).Scan(&mailbox); err != nil {
				t.Fatal(err)
			}
			delivery, err := f.transit.ClaimInstruction(ctx, mailbox, time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = f.transit.AuthorizeInstruction(ctx, mailbox, delivery.Token); err != nil {
				t.Fatal(err)
			}
			if err = f.transit.AcknowledgeInstruction(ctx, mailbox, delivery.Token, capsuleprotocol.WorkingResult()); err != nil {
				t.Fatal(err)
			}
			jobs = append(jobs, trial{op: inv.ID, vm: vm, client: client})
		}
	}

	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	metrics := telemetry.NewRegistry()
	var logs bytes.Buffer
	f.server.EnableTelemetry(metrics, &logs)
	if err := f.server.StartEventStreams(ctx, streams); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(f.server)
	defer server.Close()
	defer cancel()
	token := f.token(t, "user")
	listen, err := f.l.store.Connect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer listen.Close(context.Background())
	if _, err = listen.Exec(ctx, "LISTEN agentcapsule_invocation_stream"); err != nil {
		t.Fatal(err)
	}
	expected := make(map[string]bool, len(jobs))
	for i := range jobs {
		j := &jobs[i]
		expected[j.op] = true
		j.writer, err = j.client.OpenOutputStream(ctx, j.op)
		if err != nil {
			t.Fatalf("open producer %d: %v", i, err)
		}
		defer j.writer.Abort()
	}
	gates := make(chan error, streams)
	var group sync.WaitGroup
	var started time.Time
	release := make(chan struct{})
	for i := range jobs {
		group.Go(func() {
			j := &jobs[i]
			req, err := http.NewRequestWithContext(ctx, "GET", server.URL+"/v1/invocations/"+j.op+"/events", nil)
			if err != nil {
				gates <- err
				return
			}
			req.Header.Set("Authorization", "Bearer "+token)
			res, err := server.Client().Do(req)
			if err != nil {
				gates <- err
				return
			}
			defer res.Body.Close()
			scan := bufio.NewScanner(res.Body)
			if res.StatusCode != 200 || !scan.Scan() || scan.Text() != "event: state" {
				gates <- fmt.Errorf("subscriber HTTP %d, %s", res.StatusCode, scan.Text())
				return
			}
			gates <- nil
			select {
			case <-release:
			case <-ctx.Done():
				return
			}
			var count int
			for scan.Scan() {
				if scan.Text() != "event: delta" {
					continue
				}
				if count == 0 {
					j.latency = time.Since(started)
				}
				count++
				if !scan.Scan() || !scan.Scan() || !strings.Contains(scan.Text(), fmt.Sprintf("%s%d/%d", sentinel, i, count)) {
					t.Errorf("unexpected delta for %d, sequence %d", i, count)
					return
				}
				if count == frames {
					return
				}
			}
			t.Errorf("subscriber %d ended at %d: %v", i, count, scan.Err())
		})
	}
	for range jobs {
		if err := <-gates; err != nil {
			t.Fatal(err)
		}
	}
	var lsn string
	if err = f.db.QueryRow(ctx, "SELECT pg_current_wal_insert_lsn()::text").Scan(&lsn); err != nil {
		t.Fatal(err)
	}
	started = time.Now()
	close(release)
	for i := range jobs {
		group.Go(func() {
			j := &jobs[i]
			for seq := 1; seq <= frames; seq++ {
				if err := j.writer.Delta(fmt.Sprintf("%s%d/%d", sentinel, i, seq)); err != nil {
					t.Error(err)
					return
				}
			}
			// Let the real 150 ms coalescer commit while the call is open.
			select {
			case <-ctx.Done():
				return
			case <-time.After(250 * time.Millisecond):
			}
			if reason, err := j.writer.Close(ctx); err != nil || reason != capsuleprotocol.StreamDone {
				t.Errorf("close %s %v", reason, err)
			}
		})
	}
	group.Wait()
	elapsed := time.Since(started)
	cancel()
	server.Close()
	notes, stopNotes := context.WithTimeout(t.Context(), 5*time.Second)
	defer stopNotes()
	var notifications int
	for len(expected) > 0 {
		note, err := listen.WaitForNotification(notes)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(note.Payload, sentinel) {
			t.Fatal("payload appeared in NOTIFY")
		}
		if !strings.HasPrefix(note.Payload, "op_") {
			t.Fatalf("unexpected notification payload shape, length %d", len(note.Payload))
		}
		delete(expected, note.Payload)
		notifications++
	}
	var chunks, saved int
	var wal int64
	if err = f.db.QueryRow(t.Context(), "SELECT count(*),coalesce(sum(last_seq-first_seq+1),0) FROM invocation_stream_chunks").Scan(&chunks, &saved); err != nil {
		t.Fatal(err)
	}
	if err = f.db.QueryRow(t.Context(), "SELECT pg_wal_lsn_diff(pg_current_wal_insert_lsn(),$1::pg_lsn)::bigint", lsn).Scan(&wal); err != nil {
		t.Fatal(err)
	}
	if saved != streams*frames || chunks < streams || chunks >= saved {
		t.Fatal("data loss or no coalescing", chunks, saved)
	}
	latencies := make([]time.Duration, 0, streams)
	for _, j := range jobs {
		latencies = append(latencies, j.latency)
	}
	slices.Sort(latencies)
	var exposition bytes.Buffer
	_, err = metrics.WriteTo(&exposition)
	if err != nil || strings.Contains(exposition.String()+logs.String(), sentinel) {
		t.Fatal("telemetry exposed content", err)
	}
	t.Logf("%d producers, %d SSE clients, %d frames, %d sealed chunks, %d notifications through last distinct operation, WAL bytes %d; first delta p50=%s p95=%s max=%s; elapsed=%s", streams, streams, saved, chunks, notifications, wal, latencies[49], latencies[94], latencies[99], elapsed)
	if latencies[0] <= 0 || latencies[99] >= time.Second {
		t.Error("first delta outside target", latencies[99])
	}
}
