//go:build linux && cgo

package worker

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/api"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/delegatedidentity"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnessstore"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/llmgateway"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/runtime"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/telemetry"
	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const modelLabScopes = "org:read agent:read agent:create provider:manage quota:manage usage:read"

// modelBootHost is the test runtime of the platform channel: it stands for
// runtime.FirecrackerHost where the worker's platform API needs it. It admits
// each call as the host's shared admission does and gives the control session
// of the agent's one running boot, whose guest control server runs in this
// test over loopback with the boot's own mTLS credentials. It has no way to
// stop, retire or start a VM.
type modelBootHost struct {
	agentID  string
	control  *capsuleprotocol.Client
	admitted atomic.Int64
}

func (h *modelBootHost) WithApplication(ctx context.Context, fn func(context.Context) error) error {
	h.admitted.Add(1)
	return fn(ctx)
}

func (h *modelBootHost) Control(ctx context.Context, id string) (*capsuleprotocol.Client, error) {
	if id != h.agentID {
		return nil, runtime.ErrNoVM
	}
	// What runtime.FirecrackerHost.Control checks before it returns a session.
	if err := h.control.RequireControlContract(ctx); err != nil {
		return nil, err
	}
	return h.control, nil
}

// modelLab is a worker over a real PostgreSQL and the real HTTP API, with an
// organization whose agent is recorded as running on host "local": the
// provisioning and the boot are recorded, not performed.
type modelLab struct {
	t        *testing.T
	store    *controlplane.Store
	db       *pgxpool.Pool
	accounts *controlplane.Accounts
	server   *httptest.Server
	w        *Placements
	key      ed25519.PrivateKey
	trust    delegatedidentity.Trust
	jti      atomic.Int64
}

func newModelLab(t *testing.T) *modelLab {
	t.Helper()
	dsn := os.Getenv("AGENTCAPSULE_TEST_POSTGRES")
	if dsn == "" {
		if os.Getenv("AGENTCAPSULE_REQUIRE_POSTGRES") == "1" {
			t.Fatal("PostgreSQL required")
		}
		t.Skip("run scripts/verify-postgres.py")
	}
	admin, err := pgxpool.New(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	schema := fmt.Sprintf("worker_model_%d", time.Now().UnixNano())
	if _, err = admin.Exec(t.Context(), "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	scoped := cfg.ConnString() + " search_path=" + schema + ",pg_catalog"
	s, err := controlplane.Open(t.Context(), scoped)
	if err != nil {
		t.Fatal(err)
	}
	db, err := pgxpool.New(t.Context(), scoped)
	if err != nil {
		t.Fatal(err)
	}
	l := &modelLab{t: t, store: s, db: db}
	t.Cleanup(func() {
		if l.server != nil {
			l.server.Close()
		}
		s.Close()
		db.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, err := admin.Exec(ctx, "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE"); err != nil {
			t.Error(err)
		}
		admin.Close()
	})
	ctx := t.Context()
	if err = s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if l.accounts, err = controlplane.NewAccounts(s, bytes.Repeat([]byte{0x6d}, 32)); err != nil {
		t.Fatal(err)
	}
	if err = l.accounts.InitializeReceiptKey(ctx); err != nil {
		t.Fatal(err)
	}
	handler, err := api.NewForHost(s, l.accounts, "local")
	if err != nil {
		t.Fatal(err)
	}
	l.server = httptest.NewServer(handler)
	if err = s.ConfigureHostStorage(ctx, "local", 512); err != nil {
		t.Fatal(err)
	}
	if _, err = s.RegisterLocalRelease(ctx, controlplane.HarnessReference{Name: "reference", Version: "1.0.0"}, "sha256:"+strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
	// An organization, created by the platform, whose identity provider the
	// API trusts, as an operator installs it.
	secret := make([]byte, 32)
	_, _ = rand.Read(secret)
	platform := "acpp_" + base64.RawURLEncoding.EncodeToString(secret)
	if err = s.BootstrapPlatformToken(ctx, "model-platform", platform, time.Hour); err != nil {
		t.Fatal(err)
	}
	var org controlplane.CreateOrganizationResponse
	l.request(platform, "POST", "/v1/organizations", "org", controlplane.CreateOrganizationInput{Name: "Model Tenant",
		InitialOwner: controlplane.InitialOrganizationOwner{Issuer: "https://idp.example", Subject: "alice", DisplayName: "Alice"}}, 201, &org)
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	l.key = key
	l.trust = delegatedidentity.Trust{TenantID: org.ID, Issuer: "https://idp.example", Audience: "capsule",
		Keys: map[string]ed25519.PublicKey{"primary": pub}, AllowedScopes: strings.Fields(modelLabScopes), MaxTTL: 5 * time.Minute}
	verifier, err := delegatedidentity.NewVerifier(delegatedidentity.Config{Trusts: []delegatedidentity.Trust{l.trust}})
	if err != nil {
		t.Fatal(err)
	}
	handler.SetDelegatedIdentityVerifier(verifier)
	r, err := s.ChangeDelegationAuthority(ctx, controlplane.DelegationChange{OperationID: "model-install", Actor: "test-operator",
		Action: "install", TenantID: org.ID, Issuer: l.trust.Issuer, Audience: l.trust.Audience, Trust: &l.trust})
	if err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		var ok bool
		if err := db.QueryRow(ctx, "SELECT clock_timestamp()>$1::timestamptz+interval '1 second'", r.MinimumIAT).Scan(&ok); err != nil {
			t.Fatal(err)
		}
		if ok && time.Now().After(r.MinimumIAT.Add(time.Second)) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("tenant clock")
		}
	}
	l.w = &Placements{store: s, hostID: "local", workerID: "model-worker", lease: time.Minute}
	return l
}

// owner signs a short-lived token for the organization's owner.
func (l *modelLab) owner() string {
	l.t.Helper()
	now := time.Now()
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, jwt.MapClaims{"iss": l.trust.Issuer, "aud": l.trust.Audience, "sub": "alice",
		"jti": fmt.Sprintf("alice-%d", l.jti.Add(1)), "iat": now.Unix(), "exp": now.Add(4 * time.Minute).Unix(), "scope": modelLabScopes,
		"role": "platform", "trust_generation": int64(1)})
	token.Header["kid"] = "primary"
	raw, err := token.SignedString(l.key)
	if err != nil {
		l.t.Fatal(err)
	}
	return raw
}

func (l *modelLab) request(token, method, path, key string, in any, code int, out any) {
	l.t.Helper()
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			l.t.Fatal(err)
		}
		body = bytes.NewReader(b)
	}
	r, err := http.NewRequestWithContext(l.t.Context(), method, l.server.URL+path, body)
	if err != nil {
		l.t.Fatal(err)
	}
	r.Header.Set("Authorization", "Bearer "+token)
	if in != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	if key != "" {
		r.Header.Set("Idempotency-Key", key)
	}
	response, err := l.server.Client().Do(r)
	if err != nil {
		l.t.Fatal(method, path, err)
	}
	defer response.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if response.StatusCode != code {
		l.t.Fatalf("%s %s: got %d, want %d: %s", method, path, response.StatusCode, code, data)
	}
	if out != nil && json.Unmarshal(data, out) != nil {
		l.t.Fatal("invalid response", path)
	}
}

// runningAgent creates an agent through the API and records its
// provisioning and boots, as the API's messaging tests do: the volume, the
// restricted first boot and an ordinary running boot are recorded, not
// performed.
func (l *modelLab) runningAgent() runtime.VMRun {
	t, s := l.t, l.store
	ctx := t.Context()
	var created controlplane.AgentCreation
	l.request(l.owner(), "POST", "/v1/agents", "agent", controlplane.CreateAgentInput{Name: "modeler", Harness: controlplane.HarnessReference{Name: "reference", Version: "1.0.0"},
		Resources: controlplane.AgentResources{VCPUs: 1, MemoryMiB: 256, DataVolumeMiB: 128}}, 202, &created)
	jobs, err := s.PendingProvisioning(ctx, "local", 10)
	if err != nil || len(jobs) != 1 || jobs[0].AgentID != created.AgentID {
		t.Fatal("provisioning", jobs, err)
	}
	e := jobs[0]
	if err = s.RecordProvisionedVolume(ctx, controlplane.ProvisionedVolume{AgentID: e.AgentID, HostID: e.HostID, VolumeID: e.VolumeID, OperationID: e.OperationID, Device: 1, Inode: 600}); err != nil {
		t.Fatal(err)
	}
	p, err := s.ClaimFencePlacement(ctx, e.AgentID, e.HostID, "fixture", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	vm := fmt.Sprintf("%016x", 600)
	if err = s.ConfirmFencePlacement(ctx, e.AgentID, e.HostID, "fixture", p.Generation, vm); err != nil {
		t.Fatal(err)
	}
	if err = s.RecordEnrollmentInitialized(ctx, controlplane.EnrollmentBoot{Incarnation: 1, AgentID: e.AgentID, HostID: e.HostID, VolumeID: e.VolumeID, Generation: p.Generation, VMID: vm}); err != nil {
		t.Fatal(err)
	}
	if err = s.BeginPlacementStop(ctx, e.AgentID, e.HostID, p.Generation); err != nil {
		t.Fatal(err)
	}
	if err = s.ObservePlacementStopped(ctx, e.AgentID, e.HostID, p.Generation, false); err != nil {
		t.Fatal(err)
	}
	if err = s.ActivateProvisionedAgent(ctx, e); err != nil {
		t.Fatal(err)
	}
	if p, err = s.ClaimPlacement(ctx, e.AgentID, e.HostID, "model-worker", time.Minute); err != nil {
		t.Fatal(err)
	}
	vm = fmt.Sprintf("%016x", 601)
	if err = s.ConfirmPlacement(ctx, e.AgentID, e.HostID, "model-worker", p.Generation, vm); err != nil {
		t.Fatal(err)
	}
	// The provisioning job the worker would run is done here.
	if _, err = l.db.Exec(ctx, "DELETE FROM worker_jobs WHERE agent_id=$1", e.AgentID); err != nil {
		t.Fatal(err)
	}
	return runtime.VMRun{Incarnation: 1, ID: vm, Generation: p.Generation, Phase: "RUNNING"}
}

// guestBoot serves the boot's two channels as a VM would see them: the
// guest's control server, which the host's control session reaches, and the
// worker's platform channel, which the guest reaches through capsule-init's
// local bridge. It returns what the harness uses: the local platform client.
func (l *modelLab) guestBoot(id string, run runtime.VMRun) (*capsuleprotocol.PlatformClient, *modelBootHost) {
	t := l.t
	host, guest, err := capsuleprotocol.NewBootCredentials(capsuleprotocol.Identity{Incarnation: run.Incarnation, AgentID: id, Generation: run.Generation, VMID: run.ID}, time.Hour, true)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	var served []chan error
	serve := func(f func() error) {
		done := make(chan error, 1)
		served = append(served, done)
		go func() { done <- f() }()
	}
	t.Cleanup(func() {
		cancel()
		for _, done := range served {
			<-done
		}
	})
	listen := func() (net.Listener, func(context.Context) (net.Conn, error)) {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		return listener, func(ctx context.Context) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", listener.Addr().String())
		}
	}
	// The guest's control server (capsule-init), with its harness store.
	store, err := harnessstore.Open(t.Context(), filepath.Join(t.TempDir(), "harness.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	server, err := capsuleprotocol.NewServer(guest, capsuleprotocol.ShutdownClean, store, func(context.Context, harnessstore.Event, harnessstore.SQL) ([]byte, error) {
		return []byte(`{}`), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	controlListener, controlDial := listen()
	serve(func() error { return server.Serve(ctx, controlListener) })
	control, err := capsuleprotocol.NewClient(host, controlDial)
	if err != nil {
		t.Fatal(err)
	}
	h := &modelBootHost{agentID: id, control: control}
	// The worker's platform channel of this boot, as the host serves it.
	handler, err := l.w.platformHandler(h, id, run)
	if err != nil {
		t.Fatal(err)
	}
	platformListener, platformDial := listen()
	serve(func() error {
		return capsuleprotocol.ServeAuthenticated(ctx, platformListener, *host.Platform, handler)
	})
	remote, err := capsuleprotocol.NewPlatformClient(*guest.Platform, platformDial)
	if err != nil {
		t.Fatal(err)
	}
	// capsule-init's local bridge, which the harness reaches as its own user.
	bridge, err := capsuleprotocol.NewLocalPlatformServer(remote)
	if err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp("", "acp-model-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	path := filepath.Join(dir, "platform.sock")
	unix, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	serve(func() error { return bridge.Serve(ctx, unix, uint32(os.Geteuid())) })
	harness, err := capsuleprotocol.NewLocalPlatformClient(guest.Identity, path)
	if err != nil {
		t.Fatal(err)
	}
	return harness, h
}

// LLM-006: a guest's model call that its budget, the provider's rate limit,
// the provider's refusal or an outage turns down comes back to the guest as
// its explicit code, and nothing of it stops, fails or reboots the VM. The
// guest calls through capsule-init's local bridge and its authenticated
// platform channel, to the worker's platform API, the gateway and a provider
// standing in for the real one; only the VM is recorded, not run.
func TestModelErrorsReachTheGuestAndLeaveItsVMRunning(t *testing.T) {
	l := newModelLab(t)
	ctx := t.Context()
	var mode atomic.Int32 // the provider's next answer, an HTTP status; 0 answers
	var providerCalls atomic.Int32
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		providerCalls.Add(1)
		if code := int(mode.Load()); code != 0 {
			http.Error(w, "refused", code)
			return
		}
		_, _ = io.WriteString(w, `{"choices":[{"message":{"content":"from the model"},"finish_reason":"stop"}],"usage":{"prompt_tokens":5,"completion_tokens":3}}`)
	}))
	defer provider.Close()

	registry := telemetry.NewRegistry()
	if err := l.w.EnableTelemetry(registry, t.TempDir(), 2); err != nil {
		t.Fatal(err)
	}
	// A restart budget smaller than the errors to come: were any of them
	// counted as a guest failure, the agent would be FAILED.
	if err := l.w.SetRestartBudget(controlplane.RestartBudget{Failures: 2, Window: time.Hour}); err != nil {
		t.Fatal(err)
	}
	vocabulary := map[string][]string{"event": LLMEvents()}
	for k, v := range LLMEventCodes() {
		vocabulary[k] = v
	}
	var events bytes.Buffer
	svc, err := controlplane.NewLLMService(l.accounts, llmgateway.NewForTests(llmgateway.Config{Timeout: 5 * time.Second, MaxAttempts: 1,
		FailureLimit: 3, OpenFor: 2 * time.Second}, llmgateway.TestOptions{Loopback: true}))
	if err != nil {
		t.Fatal(err)
	}
	svc.Observe(NewLLMTelemetry(registry, telemetry.NewLogger(&events, vocabulary), l.store.LLMUnresolvedCalls))
	if err = l.w.EnableLLM(svc); err != nil {
		t.Fatal(err)
	}

	run := l.runningAgent()
	var agentID string
	if err = l.db.QueryRow(ctx, "SELECT agent_id FROM agent_placements WHERE vm_id=$1", run.ID).Scan(&agentID); err != nil {
		t.Fatal(err)
	}
	var p controlplane.LLMProvider
	l.request(l.owner(), "POST", "/v1/llm/providers", "provider", controlplane.CreateLLMProviderInput{Name: "model", Kind: "openai_compatible",
		BaseURL: provider.URL, Secret: "sk-quota-test-0123456789"}, 201, &p) // gitleaks:allow test fixture, not a credential
	for _, alias := range []string{"fast", "tight"} {
		l.request(l.owner(), "POST", "/v1/llm/aliases", alias, controlplane.CreateLLMAliasInput{Alias: alias, ProviderID: p.ID, UpstreamModel: "m"}, 201, nil)
	}
	// "tight" has a hard budget smaller than any call.
	l.request(l.owner(), "POST", "/v1/llm/budgets", "tight-budget", controlplane.CreateLLMBudgetInput{Alias: "tight", Period: "day", LimitTokens: 10, Mode: "hard"}, 201, nil)

	harness, host := l.guestBoot(agentID, run)
	n := 0
	complete := func(alias string) (capsuleprotocol.LLMResult, error) {
		n++
		return harness.CompleteLLM(ctx, fmt.Sprintf("model-%d", n), capsuleprotocol.LLMRequest{Alias: alias, MaxTokens: 32,
			Messages: []capsuleprotocol.LLMMessage{{Role: "user", Content: "hello"}}})
	}
	expect := func(what, alias, code string, reachesProvider bool) {
		t.Helper()
		before := providerCalls.Load()
		_, err := complete(alias)
		var pe *capsuleprotocol.PlatformError
		if !errors.As(err, &pe) || pe.Code != code {
			t.Fatalf("%s: the guest got %v, want the code %s", what, err, code)
		}
		if called := providerCalls.Load() != before; called != reachesProvider {
			t.Fatalf("%s: provider called=%v, want %v", what, called, reachesProvider)
		}
	}
	for range 3 {
		expect("hard budget", "tight", "quota_exceeded", false)
	}
	mode.Store(http.StatusTooManyRequests)
	expect("provider rate limit", "fast", "rate_limited", true)
	mode.Store(http.StatusUnauthorized)
	expect("provider refusal", "fast", "rejected", true)
	// An outage: three failures open the gateway's breaker, and calls are
	// then refused without reaching the provider until it half-opens.
	mode.Store(http.StatusServiceUnavailable)
	for range 3 {
		expect("provider outage", "fast", "unavailable", true)
	}
	mode.Store(0)
	expect("open breaker", "fast", "unavailable", false)
	if host.admitted.Load() == 0 {
		t.Fatal("the calls did not go through the host's admission")
	}

	// The same boot still serves its guest: the control session answers,
	// and once the breaker half-opens the next model call succeeds.
	if err = host.control.Health(ctx); err != nil {
		t.Fatal("the guest's control session no longer answers", err)
	}
	time.Sleep(2200 * time.Millisecond)
	if out, err := complete("fast"); err != nil || out.Text != "from the model" {
		t.Fatal("the boot cannot call its model after the errors", out, err)
	}

	// Nothing stopped, failed or rebooted the VM, before and after a dispatch
	// pass: the placement is the same boot, no guest failure counted against
	// the restart budget, no job for the agent.
	check := func(when string) {
		t.Helper()
		placements, err := l.store.Placements(ctx, "local")
		if err != nil || len(placements) != 1 {
			t.Fatal(when, placements, err)
		}
		if got := placements[0]; got.AgentID != agentID || got.State != "RUNNING" || got.Generation != run.Generation || got.VMID != run.ID {
			t.Fatalf("%s: the placement changed: %+v", when, got)
		}
		var failures, failed, jobs int
		if err = l.db.QueryRow(ctx, `SELECT (SELECT count(*) FROM guest_failures WHERE agent_id=$1),(SELECT count(*) FROM failed_agents WHERE agent_id=$1),
            (SELECT count(*) FROM worker_jobs WHERE agent_id=$1)`, agentID).Scan(&failures, &failed, &jobs); err != nil {
			t.Fatal(err)
		}
		if failures != 0 || failed != 0 || jobs != 0 {
			t.Fatalf("%s: guest failures %d, failed %d, jobs %d", when, failures, failed, jobs)
		}
	}
	check("after the errors")
	if err = l.w.DispatchPass(ctx, DispatchOptions{Batch: 4, WorkLease: time.Minute, DeliveryLease: time.Minute, RetryBase: time.Millisecond, RetryMax: time.Second}, 10*time.Second); err != nil {
		t.Fatal(err)
	}
	check("after a dispatch pass")
	rec := httptest.NewRecorder()
	registry.Handler(5*time.Second).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	metrics := rec.Body.String()
	for _, want := range []string{`agentcapsule_worker_guest_failures_total{kind="boot"} 0`, `agentcapsule_worker_guest_failures_total{kind="crash"} 0`,
		`agentcapsule_worker_agents_failed_total 0`, `agentcapsule_worker_agents_failed 0`, `agentcapsule_worker_vms_running 1`,
		`agentcapsule_llm_refusals_total{reason="budget_tokens"} 3`, `agentcapsule_llm_calls_total{provider="openai_compatible",outcome="settled"} 1`} {
		if !strings.Contains(metrics, want+"\n") {
			t.Fatal("metrics lack", want, "\n", metrics)
		}
	}
	if strings.Contains(metrics, "agentcapsule_worker_vm_starts_total{") {
		t.Fatal("a VM boot was counted\n", metrics)
	}
	if got := strings.Count(events.String(), `"event":"llm_call_refused","reason":"budget_tokens"`); got != 3 {
		t.Fatal("refusal events", got, events.String())
	}
}
