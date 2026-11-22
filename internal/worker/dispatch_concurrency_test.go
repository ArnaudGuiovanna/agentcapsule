//go:build linux && cgo

package worker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/api"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnessstore"
	vmruntime "github.com/ArnaudGuiovanna/agentcapsule/internal/runtime"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// dispatchLab is a worker over a real PostgreSQL and the real API with its
// transit, and agents recorded as running whose VMs are the mock runtime.
type dispatchLab struct {
	t      *testing.T
	store  *controlplane.Store
	db     *pgxpool.Pool
	w      *Placements
	post   func(path, key, body string) (int, []byte)
	as     func(token string)
	agents []string
	owners map[string]string // agent -> its owner's token
	mock   *vmruntime.MockRuntime
}

func newDispatchLab(t *testing.T, agents int) *dispatchLab {
	t.Helper()
	dsn := os.Getenv("AGENTCAPSULE_TEST_POSTGRES")
	if dsn == "" {
		if os.Getenv("AGENTCAPSULE_REQUIRE_POSTGRES") == "1" {
			t.Fatal("PostgreSQL required")
		}
		t.Skip("run scripts/verify-postgres.py")
	}
	ctx := t.Context()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	schema := fmt.Sprintf("worker_dispatch_%d", time.Now().UnixNano())
	if _, err = admin.Exec(ctx, "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	scoped := cfg.ConnString() + " search_path=" + schema + ",pg_catalog"
	s, err := controlplane.Open(ctx, scoped)
	if err != nil {
		t.Fatal(err)
	}
	db, err := pgxpool.New(ctx, scoped)
	if err != nil {
		t.Fatal(err)
	}
	l := &dispatchLab{t: t, store: s, db: db}
	t.Cleanup(func() {
		if l.mock != nil {
			l.mock.Close()
		}
		s.Close()
		db.Close()
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, err := admin.Exec(cleanup, "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE"); err != nil {
			t.Error(err)
		}
		admin.Close()
	})
	if err = s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	accounts, err := controlplane.NewAccounts(s, bytes.Repeat([]byte{0x61}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if err = accounts.InitializeReceiptKey(ctx); err != nil {
		t.Fatal(err)
	}
	transit, err := controlplane.NewTransit(s, "v1", map[string][]byte{"v1": bytes.Repeat([]byte{0x62}, 32)}, 7*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err = transit.ActivateKeys(ctx); err != nil {
		t.Fatal(err)
	}
	handler, err := api.NewForHostWithTransit(s, accounts, "local", transit)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	var token string
	l.as = func(owner string) { token = owner }
	l.post = func(path, key, body string) (int, []byte) {
		t.Helper()
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, server.URL+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Idempotency-Key", key)
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, b
	}
	if err = s.ConfigureHostStorage(ctx, "local", int64(agents)*128+64); err != nil {
		t.Fatal(err)
	}
	if _, err = s.RegisterLocalRelease(ctx, controlplane.HarnessReference{Name: "reference", Version: "1.0.0"}, "sha256:"+strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
	root, err := s.BootstrapService(ctx, "dispatch-admin", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	l.owners = map[string]string{}
	// One owner per agent: an owner has one companion.
	for i := range agents {
		l.as(root)
		code, body := l.post("/v1/users", fmt.Sprintf("user-%d", i), fmt.Sprintf(`{"display_name":"Dispatcher %d"}`, i))
		var user controlplane.User
		if code != 201 || json.Unmarshal(body, &user) != nil {
			t.Fatal("user", code)
		}
		code, body = l.post("/v1/users/"+user.ID+"/tokens", fmt.Sprintf("token-%d", i), `{"expires_at":"`+time.Now().Add(time.Hour).UTC().Format(time.RFC3339)+`"}`)
		var issued controlplane.TokenResponse
		if code != 201 || json.Unmarshal(body, &issued) != nil {
			t.Fatal("token", code)
		}
		l.as(issued.Token)
		code, body = l.post("/v1/agents", fmt.Sprintf("agent-%d", i), fmt.Sprintf(`{"name":"dispatched-%d","harness":{"name":"reference","version":"1.0.0"},"resources":{"vcpus":1,"memory_mib":256,"data_volume_mib":128}}`, i))
		var created controlplane.AgentCreation
		if code != 202 || json.Unmarshal(body, &created) != nil {
			t.Fatal("agent", code, string(body))
		}
		agent := provisionedForTraces(t, s, db, created.AgentID)
		l.agents = append(l.agents, agent)
		l.owners[agent] = issued.Token
	}
	if l.mock, err = vmruntime.NewMock(ctx, t.TempDir(), l.agents...); err != nil {
		t.Fatal(err)
	}
	l.w = &Placements{store: s, hostID: "local", workerID: "dispatch-worker", lease: time.Minute, deliveries: echoRuntime{l.mock}}
	if err = l.w.EnableTransit(ctx, transit); err != nil {
		t.Fatal(err)
	}
	return l
}

// invoke sends an invocation to agent and returns its mailbox entry.
func (l *dispatchLab) invoke(agent, key string) string {
	l.t.Helper()
	l.as(l.owners[agent])
	code, body := l.post("/v1/agents/"+agent+"/messages", key, `{"content":[{"type":"text","text":"hello"}]}`)
	var accepted controlplane.AgentCreation
	if code != 202 || json.Unmarshal(body, &accepted) != nil {
		l.t.Fatal("invocation", code, string(body))
	}
	var mailbox string
	if err := l.db.QueryRow(l.t.Context(), "SELECT id FROM agent_mailboxes WHERE instruction_id=$1", accepted.OperationID).Scan(&mailbox); err != nil {
		l.t.Fatal(err)
	}
	return mailbox
}

func (l *dispatchLab) delivered(mailbox string) bool {
	l.t.Helper()
	var state string
	if err := l.db.QueryRow(l.t.Context(), "SELECT delivery_state FROM agent_mailboxes WHERE id=$1", mailbox).Scan(&state); err != nil {
		l.t.Fatal(err)
	}
	return state == "DELIVERED"
}

// A slow harness on one agent does not delay a delivery to another agent in
// the same pass (S-02): the pass runs the two jobs at once. With one job at
// a time, the delivery to slow waits behind it and times out.
func TestADispatchPassDeliversToAnotherAgentWhileOneIsSlow(t *testing.T) {
	l := newDispatchLab(t, 2)
	slow, fast := l.agents[0], l.agents[1]
	reached := make(chan struct{})
	var once sync.Once
	l.mock.SetHandler(func(ctx context.Context, agent string, e harnessstore.Event, tx harnessstore.SQL) ([]byte, error) {
		if agent == fast {
			once.Do(func() { close(reached) })
			return []byte(`{"text":"fast"}`), nil
		}
		// The slow harness answers only once the other agent got its event.
		select {
		case <-reached:
			return []byte(`{"text":"slow"}`), nil
		case <-time.After(3 * time.Second):
			return nil, errors.New("the other agent's delivery waited behind this one")
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	})
	slowBox := l.invoke(slow, "slow-invocation")
	fastBox := l.invoke(fast, "fast-invocation")
	o := DispatchOptions{Batch: 4, Concurrency: 2, WorkLease: time.Minute, DeliveryLease: time.Minute, RetryBase: time.Millisecond, RetryMax: time.Second}
	if err := l.w.DispatchPass(t.Context(), o, 10*time.Second); err != nil {
		t.Fatal(err)
	}
	if !l.delivered(slowBox) || !l.delivered(fastBox) {
		t.Fatal("not both delivered in one pass")
	}
}

// An agent's jobs keep their order however many run at once: its second
// delivery starts once its first is acknowledged.
func TestConcurrentDispatchKeepsEachAgentsOrder(t *testing.T) {
	l := newDispatchLab(t, 3)
	var mu sync.Mutex
	running := map[string]bool{}
	var order []string
	l.mock.SetHandler(func(ctx context.Context, agent string, e harnessstore.Event, tx harnessstore.SQL) ([]byte, error) {
		mu.Lock()
		if running[agent] {
			mu.Unlock()
			return nil, errors.New("two deliveries to one agent at once")
		}
		running[agent] = true
		order = append(order, agent+"/"+e.ID)
		mu.Unlock()
		time.Sleep(20 * time.Millisecond)
		mu.Lock()
		running[agent] = false
		mu.Unlock()
		return []byte(`{"text":"done"}`), nil
	})
	var boxes []string
	want := map[string][]string{}
	for round := range 3 {
		for _, agent := range l.agents {
			box := l.invoke(agent, fmt.Sprintf("%s-%d", agent, round))
			boxes = append(boxes, box)
			want[agent] = append(want[agent], agent+"/"+box)
		}
	}
	o := DispatchOptions{Batch: 16, Concurrency: 4, WorkLease: time.Minute, DeliveryLease: time.Minute, RetryBase: time.Millisecond, RetryMax: 10 * time.Millisecond}
	for pass := 0; ; pass++ {
		if err := l.w.DispatchPass(t.Context(), o, 10*time.Second); err != nil {
			t.Fatal(err)
		}
		done := true
		for _, box := range boxes {
			done = done && l.delivered(box)
		}
		if done {
			break
		}
		if pass == 30 {
			t.Fatal("not delivered")
		}
		time.Sleep(20 * time.Millisecond)
	}
	got := map[string][]string{}
	for _, entry := range order {
		agent, _, _ := strings.Cut(entry, "/")
		got[agent] = append(got[agent], entry)
	}
	for agent, events := range want {
		if fmt.Sprint(got[agent]) != fmt.Sprint(events) {
			t.Fatalf("%s received %v, want %v", agent, got[agent], events)
		}
	}
}
