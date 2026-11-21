//go:build linux && cgo

package worker

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/api"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnessstore"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/pgnotify"
	vmruntime "github.com/ArnaudGuiovanna/agentcapsule/internal/runtime"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/telemetry"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestOutputStreamSettingsAreBounded(t *testing.T) {
	if o, err := (ServiceConfig{}).OutputStreamBounds(); err != nil || o != DefaultOutputStreams {
		t.Fatal("defaults", o, err)
	}
	c := ServiceConfig{OutputStreams: &ServiceOutputStreams{CoalesceWindow: "50ms", CoalesceBytes: 1024, MaxBytes: 1 << 20, MaxFrames: 1000, Retention: "1h", IdleTimeout: "2m"}}
	o, err := c.OutputStreamBounds()
	if err != nil || o.Settings.CoalesceWindow != 50*time.Millisecond || o.Settings.CoalesceBytes != 1024 || o.Limits.MaxBytes != 1<<20 ||
		o.Limits.MaxFrames != 1000 || o.Limits.Retention != time.Hour || o.Settings.IdleTimeout != 2*time.Minute {
		t.Fatal("settings", o, err)
	}
	for _, bad := range []ServiceOutputStreams{{CoalesceWindow: "5ms"}, {CoalesceWindow: "2s"}, {CoalesceBytes: 100}, {CoalesceBytes: 70000},
		{MaxBytes: 1024}, {MaxBytes: 32 << 20}, {MaxFrames: 10}, {MaxFrames: 70000}, {Retention: "30s"}, {Retention: "25h"},
		{IdleTimeout: "5s"}, {IdleTimeout: "301s"}, {Retention: "ten minutes"}} {
		if _, err := (ServiceConfig{OutputStreams: &bad}).OutputStreamBounds(); err == nil {
			t.Error("accepted", bad)
		}
	}
	if _, err := decodeServiceConfig(strings.NewReader(`{"output_streams":{"coalesce_window":"150ms","unknown":1}}`)); err == nil {
		t.Fatal("an unknown output_streams key was accepted")
	}
}

// streamLab is a worker over a real PostgreSQL and the real API with its
// transit, an owner's agent recorded as running, and its boot's platform
// channel served as a VM sees it: through capsule-init's local bridge.
type streamLab struct {
	t        *testing.T
	store    *controlplane.Store
	db       *pgxpool.Pool
	w        *Placements
	registry *telemetry.Registry
	post     func(path, key, body string) (int, []byte)
	agent    string
	run      vmruntime.VMRun
}

func newStreamLab(t *testing.T) *streamLab {
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
	schema := fmt.Sprintf("worker_stream_%d", time.Now().UnixNano())
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
	t.Cleanup(func() {
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
	accounts, err := controlplane.NewAccounts(s, bytes.Repeat([]byte{0x51}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if err = accounts.InitializeReceiptKey(ctx); err != nil {
		t.Fatal(err)
	}
	transit, err := controlplane.NewTransit(s, "v1", map[string][]byte{"v1": bytes.Repeat([]byte{0x52}, 32)}, 7*24*time.Hour)
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
	l := &streamLab{t: t, store: s, db: db}
	var token string
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
	if err = s.ConfigureHostStorage(ctx, "local", 256); err != nil {
		t.Fatal(err)
	}
	if _, err = s.RegisterLocalRelease(ctx, controlplane.HarnessReference{Name: "reference", Version: "1.0.0"}, "sha256:"+strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
	if token, err = s.BootstrapService(ctx, "stream-admin", time.Hour); err != nil {
		t.Fatal(err)
	}
	code, body := l.post("/v1/users", "user", `{"display_name":"Streamer"}`)
	var user controlplane.User
	if code != 201 || json.Unmarshal(body, &user) != nil {
		t.Fatal("user", code)
	}
	code, body = l.post("/v1/users/"+user.ID+"/tokens", "token", `{"expires_at":"`+time.Now().Add(time.Hour).UTC().Format(time.RFC3339)+`"}`)
	var issued controlplane.TokenResponse
	if code != 201 || json.Unmarshal(body, &issued) != nil {
		t.Fatal("token", code)
	}
	token = issued.Token
	code, body = l.post("/v1/agents", "agent", `{"name":"streamer","harness":{"name":"reference","version":"1.0.0"},"resources":{"vcpus":1,"memory_mib":256,"data_volume_mib":128}}`)
	var created controlplane.AgentCreation
	if code != 202 || json.Unmarshal(body, &created) != nil {
		t.Fatal("agent", code)
	}
	l.agent = provisionedForTraces(t, s, db, created.AgentID)
	var generation int64
	if err = db.QueryRow(ctx, "SELECT generation FROM agent_placements WHERE agent_id=$1", l.agent).Scan(&generation); err != nil {
		t.Fatal(err)
	}
	l.run = vmruntime.VMRun{Incarnation: 1, ID: "0000000000101092", Generation: uint64(generation), Phase: "RUNNING"}
	mock, err := vmruntime.NewMock(ctx, t.TempDir(), l.agent)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(mock.Close)
	// The agent answers each invocation "working": it streams, then files.
	mock.SetHandler(func(context.Context, string, harnessstore.Event, harnessstore.SQL) ([]byte, error) {
		return capsuleprotocol.WorkingResult(), nil
	})
	l.w = &Placements{store: s, hostID: "local", workerID: "stream-worker", lease: time.Minute, deliveries: echoRuntime{mock}}
	if err = l.w.EnableTransit(ctx, transit); err != nil {
		t.Fatal(err)
	}
	l.registry = telemetry.NewRegistry()
	if err = l.w.EnableStreamTelemetry(l.registry); err != nil {
		t.Fatal(err)
	}
	hub, err := pgnotify.New(s.Connect, "agentcapsule_invocation_stream")
	if err != nil {
		t.Fatal(err)
	}
	hubCtx, stop := context.WithCancel(context.Background())
	hubDone := make(chan struct{})
	go func() { defer close(hubDone); _ = hub.Run(hubCtx) }()
	t.Cleanup(func() { stop(); <-hubDone })
	if err = l.w.EnableOutputStreams(DefaultOutputStreams, hub); err != nil {
		t.Fatal(err)
	}
	if l.w.EnableOutputStreams(DefaultOutputStreams, hub) == nil {
		t.Fatal("output streams are enabled once")
	}
	return l
}

// working creates an invocation and has the worker deliver it; the agent
// answers working.
func (l *streamLab) working(key, text string) string {
	t := l.t
	t.Helper()
	code, body := l.post("/v1/agents/"+l.agent+"/messages", key, `{"content":[{"type":"text","text":"`+text+`"}]}`)
	var accepted controlplane.AgentCreation
	if code != 202 || json.Unmarshal(body, &accepted) != nil || accepted.OperationID == "" {
		t.Fatal("invocation", code, string(body))
	}
	o := DispatchOptions{Batch: 4, WorkLease: time.Minute, DeliveryLease: time.Minute, RetryBase: time.Millisecond, RetryMax: time.Second}
	for pass := 0; ; pass++ {
		if pass == 20 {
			t.Fatal("not working")
		}
		if err := l.w.DispatchPass(t.Context(), o, 10*time.Second); err != nil {
			t.Fatal(err)
		}
		var working bool
		if err := l.db.QueryRow(t.Context(), "SELECT working_since IS NOT NULL FROM owner_instructions WHERE operation_id=$1", accepted.OperationID).Scan(&working); err != nil {
			t.Fatal(err)
		}
		if working {
			return accepted.OperationID
		}
	}
}

func (l *streamLab) metrics() string {
	var b bytes.Buffer
	if _, err := l.registry.WriteTo(&b); err != nil {
		l.t.Fatal(err)
	}
	return b.String()
}

// A harness streams through capsule-init's bridge and the worker's platform
// channel: its deltas reach the chunk table, sealed, acknowledged; the
// invocation's cancellation reaches the harness, as cancel then closed
// terminal, and so does its outcome; the worker purges the chunks after
// their retention. Nothing of the content reaches the metrics.
func TestOutputStreamReachesTheChunksAndCancellationReachesTheHarness(t *testing.T) {
	l := newStreamLab(t)
	ctx := t.Context()
	op := l.working("first", "stream for me")
	ml := &modelLab{t: t, store: l.store, db: l.db, w: l.w}
	harness, host := ml.guestBoot(l.agent, l.run)
	admitted := host.admitted.Load()
	w, err := harness.OpenOutputStream(ctx, op)
	if err != nil || w.Attempt() != 1 {
		t.Fatal("open", err)
	}
	if host.admitted.Load() != admitted+1 {
		t.Fatal("the opening was not admitted by the host once", host.admitted.Load()-admitted)
	}
	const secret = "the streamed secret 9031"
	for _, text := range []string{secret, " and more", " words"} {
		if err = w.Delta(text); err != nil {
			t.Fatal(err)
		}
	}
	if err = w.Step("retrieval", capsuleprotocol.StepDone, "Searching the course"); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for w.Acked() != 4 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if w.Acked() != 4 {
		t.Fatal("acknowledged", w.Acked())
	}
	if host.admitted.Load() != admitted+1 {
		t.Fatal("a chunk took the host's admission")
	}
	var chunks, frames int
	if err = l.db.QueryRow(ctx, "SELECT count(*),coalesce(max(last_seq),0) FROM invocation_stream_chunks WHERE operation_id=$1 AND attempt=1", op).Scan(&chunks, &frames); err != nil || chunks < 1 || frames != 4 {
		t.Fatal("chunks", chunks, frames, err)
	}
	var sealed int
	if err = l.db.QueryRow(ctx, `SELECT count(*) FROM invocation_stream_chunks c JOIN transit_payloads p ON p.id=c.payload_id
        WHERE c.operation_id=$1 AND p.kind='stream_chunk' AND position($2::bytea in p.ciphertext)=0`, op, []byte(secret)).Scan(&sealed); err != nil || sealed != chunks {
		t.Fatal("chunks not sealed", sealed, err)
	}
	// The requester cancels: the same statement as CancelInvocation's.
	if _, err = l.db.Exec(ctx, `UPDATE platform_operations SET status='CANCELED',error_code='canceled',completed_at=clock_timestamp() WHERE id=$1`, op); err != nil {
		t.Fatal(err)
	}
	select {
	case <-w.Canceled():
	case <-time.After(10 * time.Second):
		t.Fatal("the cancellation did not reach the harness")
	}
	<-w.Done()
	if w.Reason() != capsuleprotocol.StreamTerminal {
		t.Fatal("closed", w.Reason(), w.Err())
	}
	// An outcome closes a stream too, without cancel.
	second := l.working("second", "another")
	w, err = harness.OpenOutputStream(ctx, second)
	if err != nil {
		t.Fatal(err)
	}
	if err = w.Delta("partial"); err != nil {
		t.Fatal(err)
	}
	if _, err = l.db.Exec(ctx, `UPDATE platform_operations SET status='FAILED',error_code='work_timeout',completed_at=clock_timestamp() WHERE id=$1`, second); err != nil {
		t.Fatal(err)
	}
	<-w.Done()
	select {
	case <-w.Canceled():
		t.Fatal("an expiry is no cancellation")
	default:
	}
	if w.Reason() != capsuleprotocol.StreamExpired {
		t.Fatal("closed", w.Reason(), w.Err())
	}
	// A third opening, of an invocation no longer working, is refused.
	if _, err = harness.OpenOutputStream(ctx, op); err == nil {
		t.Fatal("a canceled invocation's stream opened")
	}
	m := l.metrics()
	for _, want := range []string{`agentcapsule_worker_streams_open{kind="output"} 0`, `agentcapsule_worker_stream_frames_total{outcome="stored"} 4`,
		`agentcapsule_worker_stream_frames_total{outcome="truncated"} 0`, `agentcapsule_worker_stream_first_delta_seconds_count 1`} {
		if !strings.Contains(m, want) {
			t.Error("metrics lack", want)
		}
	}
	if strings.Contains(m, secret) || strings.Contains(m, op) {
		t.Fatal("content or an identifier reached the metrics")
	}
	// The chunks go after their retention, in the worker's purge pass.
	later := time.Now().Add(controlplane.DefaultStreamLimits.Retention + time.Minute)
	if n, err := l.store.PurgeStreamChunks(ctx, &later, l.w.streamRetention(), 100); err != nil || n < 1 {
		t.Fatal("purge", n, err)
	}
}
