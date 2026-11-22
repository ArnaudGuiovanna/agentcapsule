//go:build linux && cgo

package api

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnessstore"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/llmgateway"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/llmservice"
	vmruntime "github.com/ArnaudGuiovanna/agentcapsule/internal/runtime"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/telemetry"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/volumearchive"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/worker"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// lockedBuffer is a log destination that several goroutines may write.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// guestBridge is the host side of one agent's platform channel, as the
// worker's adapter serves it (internal/worker platformAPI), without the host
// admission, since no VM runs: model calls go through the metered LLM
// service, requests, replies and the A2A reads through the transit. Errors
// cross as enumerated codes only, as the worker's do.
type guestBridge struct {
	caller  controlplane.VMCaller
	store   *controlplane.Store
	transit *controlplane.Transit
	llm     *llmservice.Service
}

func bridgeError(err error) error {
	if err == nil {
		return nil
	}
	code := "unavailable"
	switch {
	case errors.Is(err, controlplane.ErrBudgetExceeded):
		code = "quota_exceeded"
	case errors.Is(err, llmgateway.ErrRateLimited):
		code = "rate_limited"
	case errors.Is(err, llmgateway.ErrRejected):
		code = "rejected"
	case errors.Is(err, llmgateway.ErrOutcomeUnknown):
		code = "outcome_unknown"
	case errors.Is(err, controlplane.ErrNotFound):
		code = "not_found"
	case errors.Is(err, controlplane.ErrInput), errors.Is(err, llmgateway.ErrInvalid):
		code = "invalid"
	}
	return &capsuleprotocol.PlatformError{Code: code}
}

func (b *guestBridge) Validate(ctx context.Context) error {
	return bridgeError(b.store.ValidateVMCaller(ctx, b.caller))
}

func (b *guestBridge) Submit(ctx context.Context, key string, in capsuleprotocol.Submission) (capsuleprotocol.PlatformReceipt, error) {
	r, err := b.transit.SubmitFromVM(ctx, b.caller, key, in)
	return capsuleprotocol.PlatformReceipt{RequestID: r.RequestID, State: string(r.State), Replayed: r.Replayed}, bridgeError(err)
}

func (b *guestBridge) Reply(ctx context.Context, id, key string, in capsuleprotocol.Reply) (capsuleprotocol.PlatformReceipt, error) {
	r, err := b.transit.ReplyFromVM(ctx, b.caller, id, key, in)
	return capsuleprotocol.PlatformReceipt{RequestID: r.RequestID, State: string(r.State), Replayed: r.Replayed}, bridgeError(err)
}

func (b *guestBridge) Search(context.Context, []string) ([]string, error) {
	return nil, &capsuleprotocol.PlatformError{Code: "unavailable"}
}

func (b *guestBridge) CompleteLLM(ctx context.Context, key string, in capsuleprotocol.LLMRequest) (capsuleprotocol.LLMResult, error) {
	q := llmgateway.Request{MaxTokens: in.MaxTokens, Temperature: in.Temperature}
	for _, m := range in.Messages {
		q.Messages = append(q.Messages, llmgateway.Message{Role: m.Role, Content: m.Content})
	}
	res, err := b.llm.CallFromVM(ctx, b.caller, key, in.Alias, q, nil)
	if err != nil {
		return capsuleprotocol.LLMResult{}, bridgeError(err)
	}
	return capsuleprotocol.LLMResult{Text: res.Text, FinishReason: res.FinishReason, InputTokens: res.Usage.InputTokens,
		OutputTokens: res.Usage.OutputTokens, SoftExceeded: res.SoftBudgetExceeded}, nil
}

func (b *guestBridge) ForwardLLM(ctx context.Context, key string, in capsuleprotocol.LLMForward) (capsuleprotocol.LLMForwardResult, error) {
	res, err := b.llm.ForwardFromVM(ctx, b.caller, key, in.Alias, in.Dialect, in.Body, nil)
	if err != nil {
		return capsuleprotocol.LLMForwardResult{}, bridgeError(err)
	}
	return capsuleprotocol.LLMForwardResult{Body: res.Body, InputTokens: res.Usage.InputTokens, OutputTokens: res.Usage.OutputTokens,
		SoftExceeded: res.SoftBudgetExceeded}, nil
}

func (b *guestBridge) DescribeAgent(ctx context.Context, id string) (capsuleprotocol.DirectoryAgent, error) {
	d, err := b.store.DescribeAgentFromVM(ctx, b.caller, id)
	return capsuleprotocol.DirectoryAgent{AgentID: d.AgentID, Description: d.Description, Skills: d.Skills, Domains: d.Domains}, bridgeError(err)
}

func (b *guestBridge) RequestStatus(ctx context.Context, id string) (capsuleprotocol.RequestStatus, error) {
	r, err := b.transit.RequestStateFromVM(ctx, b.caller, id)
	return capsuleprotocol.RequestStatus{RequestID: r.RequestID, RecipientAgentID: r.RecipientAgentID, State: r.State, ExpiresAt: r.ExpiresAt,
		Reply: r.Reply, Reason: r.Reason}, bridgeError(err)
}

func (b *guestBridge) CompleteInvocation(ctx context.Context, key string, in capsuleprotocol.InvocationCompletion) (capsuleprotocol.CompletionReceipt, error) {
	r, err := b.transit.CompleteInvocationFromVM(ctx, b.caller, key, in)
	return r, bridgeError(err)
}

// guest is an agent's side of its platform channel, over the real mTLS
// protocol. received keeps everything the platform answered it, as its
// harness would write it to its volume.
type guest struct {
	client   *capsuleprotocol.PlatformClient
	received bytes.Buffer
}

func newGuest(t *testing.T, bridge *guestBridge) *guest {
	t.Helper()
	c := bridge.caller
	h, g, err := capsuleprotocol.NewBootCredentials(capsuleprotocol.Identity{Incarnation: 1, AgentID: c.AgentID, Generation: c.Generation, VMID: c.VMID}, time.Hour, true)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := capsuleprotocol.NewPlatformHandler(h.Identity, bridge)
	if err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- capsuleprotocol.ServeAuthenticated(ctx, l, *h.Platform, handler) }()
	t.Cleanup(func() { cancel(); <-done })
	client, err := capsuleprotocol.NewPlatformClient(*g.Platform, func(ctx context.Context) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", l.Addr().String())
	})
	if err != nil {
		t.Fatal(err)
	}
	return &guest{client: client}
}

// note records one answer as the guest received it.
func (g *guest) note(v any, err error) {
	b, _ := json.Marshal(v)
	g.received.Write(b)
	if err != nil {
		g.received.WriteString(" " + err.Error())
	}
	g.received.WriteByte('\n')
}

func (g *guest) code(err error) string {
	var pe *capsuleprotocol.PlatformError
	if errors.As(err, &pe) {
		return pe.Code
	}
	if err != nil {
		return err.Error()
	}
	return ""
}

// a2aRuntime is the mock runtime of the PostgreSQL tests: it keeps the body
// of every event delivered to an agent, by agent: invocations, and requests
// and replies between agents (the A2A messages).
type a2aRuntime struct {
	*vmruntime.MockRuntime
	mu     sync.Mutex
	events map[string][][]byte
}

func (r *a2aRuntime) Send(ctx context.Context, target string, e harnessstore.Event) (harnessstore.Receipt, error) {
	r.mu.Lock()
	r.events[target] = append(r.events[target], bytes.Clone(e.Body))
	r.mu.Unlock()
	return r.MockRuntime.Send(ctx, target, e)
}

func (r *a2aRuntime) Invoke(ctx context.Context, target string, e harnessstore.Event) (harnessstore.Receipt, error) {
	return r.Send(ctx, target, e)
}

// plantedSecret is a random secret of the given prefix.
func plantedSecret(t *testing.T, prefix string) string {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return prefix + base64.RawURLEncoding.EncodeToString(b)
}

// secretForms are the ways a secret could be written: whole, a 16-character
// fragment of its middle, in hex (as PostgreSQL prints bytea), in base64, and
// for a JWT its signature.
func secretForms(secret string) map[string]string {
	mid := len(secret) / 2
	forms := map[string]string{"whole": secret, "fragment": secret[mid-8 : mid+8], "hex": hex.EncodeToString([]byte(secret)),
		"base64": base64.StdEncoding.EncodeToString([]byte(secret)), "base64url": base64.RawURLEncoding.EncodeToString([]byte(secret))}
	if parts := strings.Split(secret, "."); len(parts) == 3 {
		forms["signature"] = parts[2]
	}
	return forms
}

// leak names the first form of secret that text holds, or "".
func leak(text, secret string) string {
	forms := secretForms(secret)
	names := make([]string, 0, len(forms))
	for name := range forms {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if strings.Contains(text, forms[name]) {
			return name
		}
	}
	return ""
}

// secretScenario is one organization's model calls and A2A exchange, with
// everything the platform wrote meanwhile, by where it was written.
type secretScenario struct {
	keys    map[string]string // provider keys, by name
	tokens  map[string]string // bearer tokens and delegation JWTs, by name
	written map[string]string // what the platform wrote, by where
	// The A2A messages: the bodies of the events delivered to the agents,
	// and the answers to the guests' A2A reads.
	a2a                    map[string]string
	agentA, agentB, provID string
}

func (s *secretScenario) check(t *testing.T, secrets map[string]string, where map[string]string) {
	t.Helper()
	for place, text := range where {
		for name, secret := range secrets {
			if form := leak(text, secret); form != "" {
				t.Errorf("%s holds the %s of %s", place, form, name)
			}
		}
	}
}

// newSecretScenario plants provider keys and an organization's bearer
// tokens, makes real gateway calls to a mock provider through the metered
// service, from two running agents over their platform channels, lets the
// agents exchange a request and its reply, and reads the usage, the calls,
// the providers and the audit over HTTP. It then gathers what the platform
// wrote: every row of the schema, the API's and the worker's logs and
// metrics, the HTTP answers, a volume archive of each agent and the
// authorities' files with a snapshot taken last.
func newSecretScenario(t *testing.T) *secretScenario {
	t.Helper()
	ctx := t.Context()
	l, at, owner := apiAgentsLab(t)
	transit, err := controlplane.NewTransit(l.store, "v1", map[string][]byte{"v1": bytes.Repeat([]byte{0x45}, 32)}, 7*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err = transit.ActivateKeys(ctx); err != nil {
		t.Fatal(err)
	}
	server, err := NewForHostWithTransit(l.store, l.server.accounts, "local", transit)
	if err != nil {
		t.Fatal(err)
	}
	server.SetDelegatedIdentityVerifier(l.verifier)
	l.server = server
	apiMetrics, workerMetrics := telemetry.NewRegistry(), telemetry.NewRegistry()
	apiLog, workerLog, stdLog := &lockedBuffer{}, &lockedBuffer{}, &lockedBuffer{}
	server.EnableTelemetry(apiMetrics, apiLog)
	previous := log.Writer()
	log.SetOutput(stdLog)
	t.Cleanup(func() { log.SetOutput(previous) })
	// The revocations are recorded with a real authority service and its
	// replica, as in production (ADR 006).
	authority := newReplicatedAuthority(t)
	l.store.RecordAccessWith(authority.api)

	s := &secretScenario{keys: map[string]string{"the provider key": plantedSecret(t, "sk-planted-"),
		"the rotated provider key": plantedSecret(t, "sk-rotated-"), "the anthropic key": plantedSecret(t, "sk-ant-planted-")},
		tokens:  map[string]string{"the platform credential": l.platform, "the legacy service token": l.legacy, "the owner's JWT": owner},
		written: map[string]string{}, a2a: map[string]string{}}
	var answers strings.Builder
	do := func(method, path, token, key, body string, want int) *httptest.ResponseRecorder {
		t.Helper()
		r := call(t, l.server, method, path, token, key, body)
		if r.Code != want {
			t.Fatal(method, path, r.Code, r.Body.String())
		}
		fmt.Fprintf(&answers, "%s %s %d %v %s\n", method, path, r.Code, r.Header(), r.Body.String())
		return r
	}

	// The mock provider: it answers only to the current key of each provider,
	// and echoes it, in its body and headers, in every refusal.
	var mode atomic.Value
	mode.Store("ok")
	var openaiKey atomic.Value
	openaiKey.Store(s.keys["the provider key"])
	seen := map[string]int{}
	var seenMu sync.Mutex
	release := make(chan struct{})
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, want := r.Header.Get("Authorization"), "Bearer "+openaiKey.Load().(string)
		ok := `{"choices":[{"message":{"content":"from the model"},"finish_reason":"stop"}],"usage":{"prompt_tokens":7,"completion_tokens":3}}`
		if strings.HasSuffix(r.URL.Path, "/v1/messages") {
			got, want = r.Header.Get("X-Api-Key"), s.keys["the anthropic key"]
			ok = `{"content":[{"type":"text","text":"from the deep model"}],"stop_reason":"end_turn","usage":{"input_tokens":5,"output_tokens":2}}`
		}
		seenMu.Lock()
		if got == want {
			seen[strings.TrimPrefix(want, "Bearer ")]++
		} else {
			seen["wrong"]++
		}
		seenMu.Unlock()
		echo := strings.TrimPrefix(got, "Bearer ")
		refuse := func(status int) {
			w.Header().Set("WWW-Authenticate", `Bearer realm="planted", error="invalid_key", key="`+echo+`"`)
			w.Header().Set("X-Echo-Key", echo)
			w.WriteHeader(status)
			fmt.Fprintf(w, `{"error":{"message":"the key %s was refused","key":%q}}`, echo, base64.StdEncoding.EncodeToString([]byte(echo)))
		}
		switch {
		case got != want:
			refuse(http.StatusUnauthorized)
		case mode.Load() == "reject":
			refuse(http.StatusUnauthorized)
		case mode.Load() == "limit":
			w.Header().Set("Retry-After", "1")
			refuse(http.StatusTooManyRequests)
		case mode.Load() == "fail":
			refuse(http.StatusInternalServerError)
		case mode.Load() == "hang":
			select {
			case <-release:
			case <-time.After(10 * time.Second):
			}
		default:
			_, _ = w.Write([]byte(ok))
		}
	}))
	t.Cleanup(provider.Close)
	t.Cleanup(func() { close(release) })

	// Two running agents of the organization; b answers requests from a.
	vm := func(agent string, inode uint64) controlplane.VMCaller {
		t.Helper()
		_ = l.store.RegisterPlacement(ctx, agent, "local")
		p, err := l.store.ClaimPlacement(ctx, agent, "local", "worker", time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		id := fmt.Sprintf("%016x", inode)
		if err = l.store.ConfirmPlacement(ctx, agent, "local", "worker", p.Generation, id); err != nil {
			t.Fatal(err)
		}
		return controlplane.VMCaller{AgentID: agent, HostID: "local", VMID: id, Generation: p.Generation}
	}
	s.agentA, s.agentB = apiActiveTenantAgent(t, l, owner, "alpha"), apiActiveTenantAgent(t, l, owner, "beta")
	db, err := pgxpool.New(ctx, l.dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	if _, err = db.Exec(ctx, "UPDATE agents SET discoverable=true,inbound_mode='auto' WHERE id=$1", s.agentB); err != nil {
		t.Fatal(err)
	}
	callerA, callerB := vm(s.agentA, 0xa1), vm(s.agentB, 0xb1)

	// Bob invokes a, with his delegation JWT; an auditor technical account
	// reads the trail with its service token; the platform lists the
	// organizations with its credential.
	bob := apiAddMember(t, l, owner, "bob", "agent_user")
	do("POST", "/v1/agents/"+s.agentA+"/assignments", owner, "asg-bob", `{"principal_id":"`+bob.PrincipalID+`","permissions":["read_metadata","invoke","read_content"]}`, 201)
	s.tokens["bob's JWT"] = l.sign(t, at, "bob-invoke", "bob", invokeScopes)
	var account controlplane.ServiceAccount
	if err = json.Unmarshal(do("POST", "/v1/service-accounts", owner, "svc", `{"name":"audit-bot","role":"auditor"}`, 201).Body.Bytes(), &account); err != nil {
		t.Fatal(err)
	}
	var issued controlplane.IssuedServiceToken
	body := `{"scopes":["audit:read"],"expires_at":"` + time.Now().Add(time.Hour).UTC().Format(time.RFC3339) + `"}`
	r := call(t, l.server, "POST", "/v1/service-accounts/"+account.ID+"/tokens", owner, "svc-token", body)
	if r.Code != 201 || json.Unmarshal(r.Body.Bytes(), &issued) != nil || issued.Token == "" {
		t.Fatal("service token", r.Code, r.Body.String())
	}
	s.tokens["the service token"] = issued.Token

	// The organization registers its providers and aliases, with a hard
	// budget on the second alias.
	var p controlplane.LLMProvider
	if err = json.Unmarshal(do("POST", "/v1/llm/providers", owner, "p1", `{"name":"main","kind":"openai_compatible","base_url":"`+provider.URL+`/v1","secret":"`+s.keys["the provider key"]+`"}`, 201).Body.Bytes(), &p); err != nil {
		t.Fatal(err)
	}
	s.provID = p.ID
	var deep controlplane.LLMProvider
	if err = json.Unmarshal(do("POST", "/v1/llm/providers", owner, "p2", `{"name":"deep","kind":"anthropic","base_url":"`+provider.URL+`","secret":"`+s.keys["the anthropic key"]+`"}`, 201).Body.Bytes(), &deep); err != nil {
		t.Fatal(err)
	}
	do("POST", "/v1/llm/aliases", owner, "a1", `{"alias":"fast","provider_id":"`+p.ID+`","upstream_model":"m"}`, 201)
	do("POST", "/v1/llm/aliases", owner, "a2", `{"alias":"deep","provider_id":"`+deep.ID+`","upstream_model":"d"}`, 201)
	do("POST", "/v1/llm/budgets", owner, "b1", `{"alias":"deep","period":"day","limit_tokens":200,"mode":"hard"}`, 201)

	svc, err := llmservice.New(l.server.accounts, llmgateway.NewForTests(llmgateway.Config{Timeout: 5 * time.Second, MaxAttempts: 2, Backoff: time.Millisecond},
		llmgateway.TestOptions{Loopback: true}))
	if err != nil {
		t.Fatal(err)
	}
	vocabulary := map[string][]string{"event": worker.LLMEvents()}
	for k, v := range worker.LLMEventCodes() {
		vocabulary[k] = v
	}
	svc.Observe(worker.NewLLMTelemetry(workerMetrics, telemetry.NewLogger(workerLog, vocabulary), l.store.LLMUnresolvedCalls))
	a := newGuest(t, &guestBridge{caller: callerA, store: l.store, transit: transit, llm: svc})
	b := newGuest(t, &guestBridge{caller: callerB, store: l.store, transit: transit, llm: svc})

	// Bob's invocation reaches a, which takes it up (working).
	mock, err := vmruntime.NewMock(ctx, t.TempDir(), s.agentA, s.agentB)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(mock.Close)
	mock.SetHandler(func(_ context.Context, target string, e harnessstore.Event, _ harnessstore.SQL) ([]byte, error) {
		if _, err := capsuleprotocol.DecodeInvocation(e, target); err == nil {
			return capsuleprotocol.WorkingResult(), nil
		}
		if _, err := capsuleprotocol.DecodePeerEvent(e, target); err != nil {
			return nil, err
		}
		return []byte(`{"received":true}`), nil
	})
	rt := &a2aRuntime{MockRuntime: mock, events: map[string][][]byte{}}
	var inv controlplane.Invocation
	if err = json.Unmarshal(do("POST", "/v1/agents/"+s.agentA+"/invocations", s.tokens["bob's JWT"], "inv", `{"content":[{"type":"text","text":"Plan the trip with beta."}]}`, 202).Body.Bytes(), &inv); err != nil {
		t.Fatal(err)
	}
	head, err := l.store.HeadDelivery(ctx, s.agentA)
	if err != nil {
		t.Fatal(err)
	}
	if err = transit.DispatchMailbox(ctx, head, time.Minute, rt); err != nil {
		t.Fatal(err)
	}
	delivered, err := capsuleprotocol.DecodeInvocation(harnessstore.Event{ID: head, Subjects: []string{"agent/" + s.agentA, "event/" + head}, Body: rt.events[s.agentA][0]}, s.agentA)
	if err != nil {
		t.Fatal(err)
	}

	// a calls its models: answered, then refused, rate limited, failing,
	// without an answer, over budget; its native requests are forwarded.
	question := capsuleprotocol.LLMMessage{Role: "user", Content: "Which city first?"}
	complete := func(key, alias string, max int, want string) {
		t.Helper()
		res, err := a.client.CompleteLLM(ctx, key, capsuleprotocol.LLMRequest{Alias: alias, Messages: []capsuleprotocol.LLMMessage{question}, MaxTokens: max})
		a.note(res, err)
		if got := a.code(err); got != want || want == "" && res.Text == "" {
			t.Fatal("model call", key, got, want)
		}
	}
	forward := func(key, alias, dialect, want string) {
		t.Helper()
		res, err := a.client.ForwardLLM(ctx, key, capsuleprotocol.LLMForward{Alias: alias, Dialect: dialect,
			Body: []byte(`{"model":"x","messages":[{"role":"user","content":"Which city first?"}],"max_tokens":16}`)})
		a.note(res, err)
		if got := a.code(err); got != want {
			t.Fatal("forwarded call", key, got, want)
		}
	}
	complete("m1", "fast", 32, "")
	forward("f1", "fast", "openai", "")
	if _, err = svc.Call(ctx, l.org.ID, s.agentA, "fast", "direct-1", llmgateway.Request{Messages: []llmgateway.Message{{Role: "user", Content: "Which city first?"}}, MaxTokens: 32}); err != nil {
		t.Fatal("direct model call", err)
	}
	do("POST", "/v1/llm/providers/"+p.ID+"/rotate", owner, "rotate", `{"secret":"`+s.keys["the rotated provider key"]+`"}`, 200)
	openaiKey.Store(s.keys["the rotated provider key"])
	complete("m2", "fast", 32, "")
	for _, c := range []struct{ mode, want string }{{"reject", "rejected"}, {"limit", "rate_limited"}, {"fail", "unavailable"}, {"hang", "outcome_unknown"}} {
		mode.Store(c.mode)
		complete("m-"+c.mode, "fast", 32, c.want)
	}
	mode.Store("reject")
	forward("f-reject", "fast", "openai", "rejected")
	mode.Store("ok")
	forward("f2", "deep", "anthropic", "")
	complete("m-quota", "deep", 500, "quota_exceeded")
	seenMu.Lock()
	if seen["wrong"] != 0 || seen[s.keys["the provider key"]] < 3 || seen[s.keys["the rotated provider key"]] < 6 || seen[s.keys["the anthropic key"]] != 1 {
		t.Fatal("the provider did not receive its current key on each call", seen["wrong"], seen[s.keys["the provider key"]],
			seen[s.keys["the rotated provider key"]], seen[s.keys["the anthropic key"]])
	}
	seenMu.Unlock()

	// a asks b, b answers; a reads b's description and its request's status,
	// then completes bob's invocation.
	a.note(a.client.DescribeAgent(ctx, s.agentB))
	sent, err := a.client.Submit(ctx, "ask-b", capsuleprotocol.Submission{RecipientAgentID: s.agentB, MandateID: delivered.Mandate.ID, Subject: "Trip",
		ExpiresAt: time.Now().Add(time.Hour).UTC().Truncate(time.Microsecond), Payload: &capsuleprotocol.PeerPayload{Content: []capsuleprotocol.TextContent{{Type: "text", Text: "Which city first?"}}}})
	a.note(sent, err)
	if err != nil {
		t.Fatal("request between agents", err)
	}
	mailbox := func(kind string) string {
		t.Helper()
		var id string
		if err := db.QueryRow(ctx, "SELECT id FROM agent_mailboxes WHERE ref_id=$1 AND kind=$2", sent.RequestID, kind).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	if err = transit.DispatchMailbox(ctx, mailbox("request"), time.Minute, rt); err != nil {
		t.Fatal(err)
	}
	replied, err := b.client.Reply(ctx, sent.RequestID, "answer", capsuleprotocol.Reply{Outcome: "completed",
		Payload: &capsuleprotocol.PeerPayload{Content: []capsuleprotocol.TextContent{{Type: "text", Text: "Lyon, then Paris."}}}})
	b.note(replied, err)
	if err != nil {
		t.Fatal("reply between agents", err)
	}
	if err = transit.DispatchMailbox(ctx, mailbox("reply"), time.Minute, rt); err != nil {
		t.Fatal(err)
	}
	status, err := a.client.RequestStatus(ctx, sent.RequestID)
	a.note(status, err)
	if err != nil || status.Reply == nil || status.Reply.Content[0].Text != "Lyon, then Paris." {
		t.Fatal("the request's status", status, err)
	}
	done, err := a.client.CompleteInvocation(ctx, "done", capsuleprotocol.InvocationCompletion{OperationID: inv.ID, Outcome: "completed",
		Content: []capsuleprotocol.TextContent{{Type: "text", Text: "Lyon, then Paris."}}})
	a.note(done, err)
	if err != nil {
		t.Fatal("completion", err)
	}
	for agent, events := range rt.events {
		for i, e := range events {
			s.a2a[fmt.Sprintf("event %d delivered to %s", i, agent)] = string(e)
		}
	}
	s.a2a["a's platform channel"], s.a2a["b's platform channel"] = a.received.String(), b.received.String()
	if !strings.Contains(s.a2a["event 0 delivered to "+s.agentB], "Which city first?") || len(rt.events[s.agentA]) != 2 {
		t.Fatal("the A2A messages were not captured", len(rt.events[s.agentA]), len(rt.events[s.agentB]))
	}

	// What the organization reads over HTTP: its result, usage, calls of
	// unknown outcome (one is settled), providers, budgets and audit.
	do("GET", "/v1/invocations/"+inv.ID+"/result", s.tokens["bob's JWT"], "", "", 200)
	do("GET", "/v1/llm/usage?period=day", owner, "", "", 200)
	var unresolved struct {
		Items []struct {
			ID string `json:"id"`
		} `json:"items"`
	}
	if err = json.Unmarshal(do("GET", "/v1/llm/calls/unresolved", owner, "", "", 200).Body.Bytes(), &unresolved); err != nil || len(unresolved.Items) != 1 {
		t.Fatal("unresolved calls", unresolved, err)
	}
	do("POST", "/v1/llm/calls/"+unresolved.Items[0].ID+"/settle", owner, "settle", `{"input_tokens":7,"output_tokens":3}`, 200)
	for _, path := range []string{"/v1/llm/providers", "/v1/llm/aliases", "/v1/llm/budgets", "/v1/audit?limit=200"} {
		do("GET", path, owner, "", "", 200)
	}
	do("GET", "/v1/audit?limit=200", s.tokens["the service token"], "", "", 200)
	from, to := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339), time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	do("GET", "/v1/audit/export?from="+from+"&to="+to, owner, "", "", 200)
	do("GET", "/v1/organizations", l.platform, "", "", 200)

	// A volume archive of each agent, of what its guest received, signed by
	// the restore authority whose volume keys the key authority holds.
	archives, err := volumearchive.New(filepath.Join(t.TempDir(), "archives"))
	if err != nil {
		t.Fatal(err)
	}
	archived := 0
	for i, g := range map[string]*guest{s.agentA: a, s.agentB: b} {
		archived++
		var volume string
		if err = db.QueryRow(ctx, "SELECT volume_id FROM store_enrollments WHERE agent_id=$1", i).Scan(&volume); err != nil {
			t.Fatal(err)
		}
		binding, err := authority.catalog.Register(ctx, i, volume)
		if err != nil {
			t.Fatal(err)
		}
		if err = authority.keys.Ensure(ctx, i, volume); err != nil {
			t.Fatal(err)
		}
		image := append(bytes.Clone(g.received.Bytes()), bytes.Join(rt.events[i], []byte("\n"))...)
		if _, err = archives.Capture(ctx, volumearchive.Spec{ID: fmt.Sprintf("arc_%032x", archived), Binding: binding, HarnessDigest: "sha256:" + strings.Repeat("a", 64),
			Size: int64(len(image))}, bytes.NewReader(image), authority.catalog); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = authority.catalog.Snapshot(ctx, authority.keys, authority.unlock.Recipient(), filepath.Join(authority.dir, "after-the-calls.sqlite")); err != nil {
		t.Fatal("snapshot of the authorities", err)
	}
	if !strings.Contains(a.received.String(), "from the model") || !strings.Contains(a.received.String(), "from the deep model") {
		t.Fatal("the guest's answers were not recorded")
	}

	// Everything the platform wrote.
	rows, err := db.Query(ctx, "SELECT tablename FROM pg_tables WHERE schemaname=current_schema() ORDER BY tablename")
	if err != nil {
		t.Fatal(err)
	}
	tables, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil || len(tables) < 50 {
		t.Fatal("tables", len(tables), err)
	}
	for _, table := range tables {
		var dump string
		if err = db.QueryRow(ctx, "SELECT coalesce(string_agg(x::text, E'\\n'),'') FROM "+pgx.Identifier{table}.Sanitize()+" x").Scan(&dump); err != nil {
			t.Fatal(table, err)
		}
		s.written["table "+table] = dump
	}
	for name, registry := range map[string]*telemetry.Registry{"the API's metrics": apiMetrics, "the worker's metrics": workerMetrics} {
		var b strings.Builder
		if _, err = registry.WriteTo(&b); err != nil {
			t.Fatal(err)
		}
		s.written[name] = b.String()
	}
	s.written["the API's log"], s.written["the worker's log"], s.written["the process log"] = apiLog.String(), workerLog.String(), stdLog.String()
	s.written["the HTTP answers"] = answers.String()
	for _, root := range []string{archives.Root(), authority.dir} {
		err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || d.Type()&fs.ModeSocket != 0 {
				return err
			}
			b, err := os.ReadFile(path)
			s.written["file "+path] = string(b)
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	// The search reads what it should: the rows, logs, metrics, archives and
	// the snapshot hold what the calls and the exchange did.
	for place, want := range map[string]string{
		"table llm_providers":       s.provID,
		"table llm_usage":           "fast",
		"table agent_requests":      sent.RequestID,
		"the API's log":             `"route":"/v1/llm/providers/{id}/rotate"`,
		"the worker's log":          `"event":"llm_call_refused","reason":"budget_tokens"`,
		"the worker's metrics":      `agentcapsule_llm_calls_total{provider="openai_compatible",outcome="unknown"} 1`,
		"the API's metrics":         `route="/v1/llm/providers"`,
		"the HTTP answers":          "llm.provider.created",
		"a's platform channel":      "from the model",
		"archived volume manifests": s.agentA,
		"the authorities' snapshot": s.agentA,
	} {
		text := s.written[place]
		switch place {
		case "a's platform channel":
			text = s.a2a[place]
		case "archived volume manifests", "the authorities' snapshot":
			suffix := map[string]string{"archived volume manifests": "manifest.json", "the authorities' snapshot": "after-the-calls.sqlite"}[place]
			for path, b := range s.written {
				if strings.HasSuffix(path, suffix) {
					text += b
				}
			}
		}
		if !strings.Contains(text, want) {
			t.Fatalf("%s lacks %q: the search would not see what is written", place, want)
		}
	}
	for _, secret := range []string{s.keys["the provider key"], s.tokens["bob's JWT"]} {
		for name, form := range secretForms(secret) {
			if leak("…"+form+"…", secret) == "" {
				t.Fatal("the search misses the form", name)
			}
		}
	}
	if !strings.Contains(answers.String(), "/v1/llm/providers/"+p.ID+"/rotate 200") {
		t.Fatal("the rotation was not answered")
	}
	size := 0
	for _, text := range s.written {
		size += len(text)
	}
	t.Logf("searched %d places (%d tables), %d bytes, and %d A2A messages and channels", len(s.written), len(tables), size, len(s.a2a))
	return s
}

// LLM-003: a provider key the organization registers never reaches what the
// platform writes, whatever the provider answers: neither PostgreSQL (every
// row of every table), nor the API's and the worker's logs and metrics, nor
// the answers, nor what a guest receives and its archived volume, nor the
// authorities' files and their snapshot. Only the provider receives it.
func TestProviderKeysReachOnlyTheProvider(t *testing.T) {
	s := newSecretScenario(t)
	s.check(t, s.keys, s.written)
	s.check(t, s.keys, s.a2a)
}

// LLM-008: during real gateway calls and an exchange between two agents,
// no secret reaches the A2A messages (the events delivered to the agents,
// the answers to their A2A reads) or the logs and metrics: no provider key,
// bearer token or delegation JWT.
func TestNoSecretInA2AMessagesOrLogsAroundAModelCall(t *testing.T) {
	s := newSecretScenario(t)
	secrets := map[string]string{}
	for name, v := range s.keys {
		secrets[name] = v
	}
	for name, v := range s.tokens {
		secrets[name] = v
	}
	s.check(t, secrets, s.a2a)
	logs := map[string]string{}
	for _, place := range []string{"the API's log", "the worker's log", "the process log", "the API's metrics", "the worker's metrics"} {
		logs[place] = s.written[place]
	}
	s.check(t, secrets, logs)
	// The rows hold no bearer token or JWT either: only hashes and IDs.
	s.check(t, s.tokens, s.written)
}
