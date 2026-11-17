//go:build linux

package worker

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
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
	"github.com/ArnaudGuiovanna/agentcapsule/internal/telemetry"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// spanRecord is what the trace tests read of an OTLP/JSON span.
type spanRecord struct {
	Service      string
	TraceID      string `json:"traceId"`
	SpanID       string `json:"spanId"`
	ParentSpanID string `json:"parentSpanId"`
	Name         string `json:"name"`
	Attributes   []struct {
		Key   string `json:"key"`
		Value struct {
			StringValue string `json:"stringValue"`
			IntValue    string `json:"intValue"`
		} `json:"value"`
	} `json:"attributes"`
	Status struct {
		Code int `json:"code"`
	} `json:"status"`
}

func (s spanRecord) attr(key string) string {
	for _, a := range s.Attributes {
		if a.Key == key {
			return a.Value.StringValue + a.Value.IntValue
		}
	}
	return ""
}

func readSpans(t *testing.T, raw []byte) []spanRecord {
	t.Helper()
	var out []spanRecord
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(nil, 16<<20)
	for scanner.Scan() {
		var line struct {
			ResourceSpans []struct {
				Resource struct {
					Attributes []struct {
						Value struct {
							StringValue string `json:"stringValue"`
						} `json:"value"`
					} `json:"attributes"`
				} `json:"resource"`
				ScopeSpans []struct {
					Spans []spanRecord `json:"spans"`
				} `json:"scopeSpans"`
			} `json:"resourceSpans"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &line); err != nil {
			t.Fatal("not an OTLP/JSON line", err)
		}
		for _, r := range line.ResourceSpans {
			for _, scope := range r.ScopeSpans {
				for _, s := range scope.Spans {
					s.Service = r.Resource.Attributes[0].Value.StringValue
					out = append(out, s)
				}
			}
		}
	}
	return out
}

// traceFile is what the collector reads: both processes append to it.
type traceFile struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (f *traceFile) Write(p []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.b.Write(p)
}

// echoRuntime stands for the VMs: the mock runtime's store, an invocation
// answered as a delivery.
type echoRuntime struct{ *vmruntime.MockRuntime }

func (r echoRuntime) Invoke(ctx context.Context, target string, e harnessstore.Event) (harnessstore.Receipt, error) {
	return r.Send(ctx, target, e)
}

// One invocation is followed from the API to its delivery by the worker,
// across PostgreSQL: the API request's span is the root of a trace whose ID
// is its X-Request-ID; the admission is its child; the worker's delivery job
// joins the same trace as a child of the request's span, with nothing but the
// request ID PostgreSQL kept. Both processes read the same pseudonym key, so
// the agent has one pseudonym in both. No identifier, token, name or content
// planted in the request appears in any span.
func TestTraceFollowsAnInvocationFromTheAPIToItsDelivery(t *testing.T) {
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
	schema := fmt.Sprintf("worker_trace_%d", time.Now().UnixNano())
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
	accounts, err := controlplane.NewAccounts(s, bytes.Repeat([]byte{0x71}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if err = accounts.InitializeReceiptKey(ctx); err != nil {
		t.Fatal(err)
	}
	transit, err := controlplane.NewTransit(s, "v1", map[string][]byte{"v1": bytes.Repeat([]byte{0x72}, 32)}, 7*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err = transit.ActivateKeys(ctx); err != nil {
		t.Fatal(err)
	}
	// The installation's key, as each process reads it at start.
	key, err := s.TraceKey(ctx)
	if err != nil || len(key) != 32 || bytes.Equal(key, make([]byte, 32)) {
		t.Fatal("the migration gives the installation a random key", err)
	}
	var file traceFile
	apiTracer, err := telemetry.NewTracer(&file, "agentcapsule-api", key)
	if err != nil {
		t.Fatal(err)
	}
	workerTracer, err := telemetry.NewTracer(&file, "agentcapsule-worker", key)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := api.NewForHostWithTransit(s, accounts, "local", transit)
	if err != nil {
		t.Fatal(err)
	}
	handler.EnableTracing(apiTracer)
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	post := func(path, token, idempotency, body string) (int, []byte, string) {
		t.Helper()
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, server.URL+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Idempotency-Key", idempotency)
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, b, resp.Header.Get("X-Request-ID")
	}
	if err = s.ConfigureHostStorage(ctx, "local", 256); err != nil {
		t.Fatal(err)
	}
	if _, err = s.RegisterLocalRelease(ctx, controlplane.HarnessReference{Name: "reference", Version: "1.0.0"}, "sha256:"+strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
	root, err := s.BootstrapService(ctx, "trace-admin", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	const person = "Trace Planted Person"
	code, body, _ := post("/v1/users", root, "user-key-planted", `{"display_name":"`+person+`"}`)
	var user controlplane.User
	if code != 201 || json.Unmarshal(body, &user) != nil {
		t.Fatal("user", code)
	}
	code, body, _ = post("/v1/users/"+user.ID+"/tokens", root, "token-key-planted", `{"expires_at":"`+time.Now().Add(time.Hour).UTC().Format(time.RFC3339)+`"}`)
	var token controlplane.TokenResponse
	if code != 201 || json.Unmarshal(body, &token) != nil {
		t.Fatal("token", code)
	}
	code, body, _ = post("/v1/agents", token.Token, "agent-key-planted",
		`{"name":"Planted agent name","harness":{"name":"reference","version":"1.0.0"},"resources":{"vcpus":1,"memory_mib":256,"data_volume_mib":128}}`)
	var created controlplane.AgentCreation
	if code != 202 || json.Unmarshal(body, &created) != nil {
		t.Fatal("agent", code)
	}
	agent := provisionedForTraces(t, s, db, created.AgentID)
	mock, err := vmruntime.NewMock(ctx, t.TempDir(), agent)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(mock.Close)
	mock.SetHandler(func(ctx context.Context, _ string, e harnessstore.Event, tx harnessstore.SQL) ([]byte, error) {
		return []byte(`{"text":"the planted answer"}`), nil
	})
	w := &Placements{store: s, hostID: "local", workerID: "trace-worker", lease: time.Minute, deliveries: echoRuntime{mock}}
	if err = w.EnableTransit(ctx, transit); err != nil {
		t.Fatal(err)
	}
	if err = w.EnableTracing(workerTracer); err != nil {
		t.Fatal(err)
	}
	if w.EnableTracing(workerTracer) == nil {
		t.Fatal("tracing is enabled once")
	}

	const content = "the planted secret content 4417"
	code, body, requestID := post("/v1/agents/"+agent+"/messages", token.Token, "invocation-key-planted",
		`{"content":[{"type":"text","text":"`+content+`"}]}`)
	var accepted controlplane.AgentCreation
	if code != 202 || json.Unmarshal(body, &accepted) != nil || accepted.OperationID == "" || len(requestID) != 32 {
		t.Fatal("invocation", code)
	}
	var mailbox string
	if err = db.QueryRow(ctx, "SELECT id FROM agent_mailboxes WHERE instruction_id=$1", accepted.OperationID).Scan(&mailbox); err != nil {
		t.Fatal(err)
	}
	o := DispatchOptions{Batch: 4, WorkLease: time.Minute, DeliveryLease: time.Minute, RetryBase: time.Millisecond, RetryMax: time.Second}
	for pass, delivered := 0, false; !delivered; pass++ {
		if pass == 20 {
			t.Fatal("not delivered")
		}
		if err = w.DispatchPass(ctx, o, 10*time.Second); err != nil {
			t.Fatal(err)
		}
		var state string
		if err = db.QueryRow(ctx, "SELECT delivery_state FROM agent_mailboxes WHERE id=$1", mailbox).Scan(&state); err != nil {
			t.Fatal(err)
		}
		delivered = state == "DELIVERED"
	}
	apiTracer.Close()
	workerTracer.Close()

	file.mu.Lock()
	raw := bytes.Clone(file.b.Bytes())
	file.mu.Unlock()
	for _, planted := range []string{agent, accepted.OperationID, mailbox, user.ID, token.ID, token.Token, root, person, "Planted agent name",
		"invocation-key-planted", content, "the planted answer", "trace-worker", string(key), hex.EncodeToString(key)} {
		if planted != "" && bytes.Contains(raw, []byte(planted)) {
			t.Fatalf("%q reached a span", planted)
		}
	}
	var request, admission, job spanRecord
	for _, s := range readSpans(t, raw) {
		if s.TraceID != requestID {
			continue
		}
		switch s.Name {
		case "api.request":
			request = s
		case "invocation.admit":
			admission = s
		case "worker.job":
			job = s
		}
	}
	if request.Service != "agentcapsule-api" || request.ParentSpanID != "" || request.attr("http.route") != "/v1/agents/{id}/messages" ||
		request.attr("http.response.status_code") != "202" || request.attr("http.request.method") != "POST" {
		t.Fatal("the request's span is the root of the trace named by X-Request-ID", request)
	}
	pseudonym := telemetry.Pseudonym(key, agent)
	if request.attr("agentcapsule.path.id") != pseudonym || request.attr("agentcapsule.principal") != telemetry.Pseudonym(key, user.ID) {
		t.Fatal("the path's agent and the principal are pseudonyms", request.Attributes)
	}
	if admission.ParentSpanID != request.SpanID || admission.attr("agentcapsule.outcome") != "accepted" ||
		admission.attr("agentcapsule.agent") != pseudonym || admission.attr("agentcapsule.invocation") != telemetry.Pseudonym(key, accepted.OperationID) {
		t.Fatal("the admission is a child of the request", admission)
	}
	if job.Service != "agentcapsule-worker" || job.ParentSpanID != request.SpanID || job.attr("agentcapsule.job.kind") != "delivery" ||
		job.attr("agentcapsule.outcome") != "done" || job.attr("agentcapsule.agent") != pseudonym ||
		job.attr("agentcapsule.job") != telemetry.Pseudonym(key, mailbox) || job.Status.Code != 0 {
		t.Fatal("the worker's delivery joins the request's trace, under its span", job)
	}
}

// provisionedForTraces stands for the provisioning and first boot of agent,
// as the API's messaging tests do: recorded, not performed. It returns the
// agent, running on host local.
func provisionedForTraces(t *testing.T, s *controlplane.Store, db *pgxpool.Pool, agent string) string {
	t.Helper()
	ctx := t.Context()
	jobs, err := s.PendingProvisioning(ctx, "local", 10)
	if err != nil {
		t.Fatal(err)
	}
	var e controlplane.Enrollment
	for _, j := range jobs {
		if j.AgentID == agent {
			e = j
		}
	}
	if err = s.RecordProvisionedVolume(ctx, controlplane.ProvisionedVolume{AgentID: e.AgentID, HostID: e.HostID, VolumeID: e.VolumeID, OperationID: e.OperationID, Device: 1, Inode: 4242}); err != nil {
		t.Fatal(err)
	}
	p, err := s.ClaimFencePlacement(ctx, e.AgentID, e.HostID, "fixture", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.ConfirmFencePlacement(ctx, e.AgentID, e.HostID, "fixture", p.Generation, "0000000000001092"); err != nil {
		t.Fatal(err)
	}
	if err = s.RecordEnrollmentInitialized(ctx, controlplane.EnrollmentBoot{Incarnation: 1, AgentID: e.AgentID, HostID: e.HostID, VolumeID: e.VolumeID, Generation: p.Generation, VMID: "0000000000001092"}); err != nil {
		t.Fatal(err)
	}
	if err = s.BeginPlacementStop(ctx, e.AgentID, e.HostID, p.Generation); err != nil {
		t.Fatal(err)
	}
	if err = s.ObservePlacementStopped(ctx, e.AgentID, e.HostID, p.Generation, true); err != nil {
		t.Fatal(err)
	}
	if err = s.ActivateProvisionedAgent(ctx, e); err != nil {
		t.Fatal(err)
	}
	if p, err = s.ClaimPlacement(ctx, e.AgentID, e.HostID, "fixture", time.Minute); err != nil {
		t.Fatal(err)
	}
	if err = s.ConfirmPlacement(ctx, e.AgentID, e.HostID, "fixture", p.Generation, "0000000000101092"); err != nil {
		t.Fatal(err)
	}
	// The provisioning job the worker would run is done here.
	if _, err = db.Exec(ctx, "DELETE FROM worker_jobs WHERE agent_id=$1", e.AgentID); err != nil {
		t.Fatal(err)
	}
	return e.AgentID
}

// A guest's platform call during a delivery to its agent is a child of that
// delivery's span; after the delivery, a call that names no work begins its
// own trace. The call's outcome is the code the guest receives.
func TestPlatformCallsJoinTheDeliveryInProgress(t *testing.T) {
	var file traceFile
	tracer, err := telemetry.NewTracer(&file, "agentcapsule-worker", bytes.Repeat([]byte{0x73}, 32))
	if err != nil {
		t.Fatal(err)
	}
	w := &Placements{}
	if err = w.EnableTracing(tracer); err != nil {
		t.Fatal(err)
	}
	a := platformAPI{caller: controlplane.VMCaller{AgentID: "agt_planted_caller"}, traces: w.tracing.Load}
	work := telemetry.ContinueTrace(context.Background(), tracer, "00112233445566778899aabbccddeeff")
	_, delivery := deliverSpan.Start(work)
	done := w.turn("agt_planted_caller", delivery)
	_, end := a.trace(context.Background(), "llm_complete", "", "")
	end(controlplane.ErrBudgetExceeded)
	done()
	delivery.End()
	_, end = a.trace(context.Background(), "search", "", "")
	end(nil)
	untraced := platformAPI{caller: a.caller}
	_, end = untraced.trace(context.Background(), "search", "", "")
	end(nil)
	tracer.Close()
	spans := readSpans(t, file.b.Bytes())
	if len(spans) != 3 || bytes.Contains(file.b.Bytes(), []byte("agt_planted_caller")) {
		t.Fatal("spans", len(spans))
	}
	call, deliverySpan, alone := spans[0], spans[1], spans[2]
	if call.Name != "platform.call" || call.ParentSpanID != deliverySpan.SpanID || call.TraceID != "00112233445566778899aabbccddeeff" ||
		call.attr("agentcapsule.platform.call") != "llm_complete" || call.attr("agentcapsule.outcome") != "quota_exceeded" ||
		call.attr("agentcapsule.trace.origin") != "delivery" || call.Status.Code != 2 {
		t.Fatal("a call during the delivery is its child", call)
	}
	if alone.ParentSpanID != "" || alone.TraceID == call.TraceID || alone.attr("agentcapsule.trace.origin") != "none" ||
		alone.attr("agentcapsule.outcome") != "ok" {
		t.Fatal("a call after the delivery begins its own trace", alone)
	}
}
