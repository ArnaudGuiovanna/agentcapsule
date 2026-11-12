package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"iter"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/a2aproject/a2a-go/v2/a2aclient"
	"github.com/a2aproject/a2a-go/v2/a2asrv"
	"github.com/a2aproject/a2a-go/v2/a2asrv/taskstore"
	a2aslimrpc "github.com/agntcy/slim-a2a-go/a2aslimrpc/v1"
	slim "github.com/agntcy/slim-bindings-go/v3"
	slimrpc "github.com/agntcy/slim-bindings-go/v3/slim_rpc"
)

// A delivery crosses SLIM as one A2A message with a single raw part: the
// nonce and the event, as JSON. The receipt comes back as the task's artifact,
// one raw part with the receipt as JSON. Raw parts carry bytes unchanged.
const (
	deliveryType = "application/vnd.agentcapsule.delivery+json"
	receiptType  = "application/vnd.agentcapsule.receipt+json"
	probeType    = "application/vnd.agentcapsule.probe"
)

type delivery struct {
	Nonce string `json:"nonce"`
	Event Event  `json:"event"`
}

// ErrNodeLost ends the process: SLIM clients do not reconnect after the node
// restarts, only a new process does. The supervisor starts it again.
var ErrNodeLost = errors.New("slim node lost")

// served is an agent's name the bridge answers on.
type served struct {
	app    *slim.App
	server *slimrpc.Server
	last   time.Time
}

type Bridge struct {
	cfg    Config
	probe  string // the name only the probe uses: <name>.probe
	secret string
	// out sends, in answers: two SLIM services with a connection each, so
	// that every message crosses the node. Within one service, SLIM routes
	// between applications locally, without the node.
	out, in         *slim.Service
	outConn, inConn uint64
	self            *slim.App
	worker          *http.Client
	healthy         atomic.Bool
	mu              sync.Mutex
	names           map[string]*served
}

// Connect opens the bridge's two connections to the node. The bridge sends as
// its own name, and answers on the agents' names and on <name>.probe, for its
// probe only: an application calling itself over SLIM RPC gets no answer.
func Connect(cfg Config, secret string) (*Bridge, error) {
	slim.InitializeWithDefaults()
	client := slim.NewSecureClientConfig(cfg.Node)
	client.Tls.CaSource = slim.CaSourceFile{Path: cfg.CA}
	client.Tls.IncludeSystemCaCertsPool = false
	client.Tls.Source = slim.TlsSourceFile{Cert: cfg.Cert, Key: cfg.Key}
	b := &Bridge{cfg: cfg, secret: secret, out: slim.GetGlobalService(), in: slim.NewService("agentcapsule-slim-bridge-in"), names: map[string]*served{},
		worker: &http.Client{Transport: &http.Transport{DialContext: dialWorker(cfg.WorkerSocket, uint32(cfg.WorkerUID)), MaxIdleConns: 8,
			IdleConnTimeout: 30 * time.Second, DisableCompression: true}}}
	var err error
	if b.outConn, err = b.out.ConnectAsync(client); err != nil {
		return nil, fmt.Errorf("connect: %w", err)
	}
	if b.inConn, err = b.in.ConnectAsync(client); err != nil {
		return nil, fmt.Errorf("connect: %w", err)
	}
	if b.self, _, err = b.app(b.out, b.outConn, cfg.Name); err != nil {
		return nil, err
	}
	b.probe = cfg.Name + ".probe"
	app, server, err := b.answer(b.probe, probeAnswer{name: cfg.Name})
	if err != nil {
		return nil, err
	}
	b.names[b.probe] = &served{app: app, server: server, last: time.Now()}
	return b, nil
}

// app creates the application for name in svc and subscribes it on conn.
func (b *Bridge) app(svc *slim.Service, conn uint64, name string) (*slim.App, *slim.Name, error) {
	n, err := slim.NameFromString(name)
	if err != nil {
		return nil, nil, err
	}
	app, err := svc.CreateAppWithSecret(n, b.secret)
	if err != nil {
		return nil, nil, fmt.Errorf("app %s: %w", name, err)
	}
	if err = app.SubscribeAsync(app.Name(), &conn); err != nil {
		app.Destroy()
		return nil, nil, fmt.Errorf("subscribe %s: %w", name, err)
	}
	return app, n, nil
}

// answer creates the application for name and serves A2A on it.
func (b *Bridge) answer(name string, executor a2asrv.AgentExecutor) (*slim.App, *slimrpc.Server, error) {
	app, n, err := b.app(b.in, b.inConn, name)
	if err != nil {
		return nil, nil, err
	}
	server := slimrpc.ServerNewWithConnection(app, n, &b.inConn)
	a2aslimrpc.NewHandler(a2asrv.NewHandler(executor, a2asrv.WithTaskStore(newRotatingStore(10*time.Minute)))).RegisterWith(server)
	go func() { _ = server.ServeBlocking() }()
	return app, server, nil
}

// Serve makes the bridge answer on an agent's name, or keeps it answering.
func (b *Bridge) Serve(name string) error {
	if !validName(name) || len(name) >= len(platformNamespace) && name[:len(platformNamespace)] == platformNamespace {
		return errInvalid
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if s := b.names[name]; s != nil {
		s.last = time.Now()
		return nil
	}
	app, server, err := b.answer(name, deliveries{b: b, name: name})
	if err != nil {
		return err
	}
	b.names[name] = &served{app: app, server: server, last: time.Now()}
	return nil
}

// Release stops answering on names nobody delivered to for idle.
func (b *Bridge) Release(idle time.Duration) int {
	b.mu.Lock()
	var gone []*served
	for name, s := range b.names {
		if name != b.probe && time.Since(s.last) > idle {
			gone = append(gone, s)
			delete(b.names, name)
		}
	}
	b.mu.Unlock()
	for _, s := range gone {
		s.server.ShutdownBlocking()
		s.app.Destroy()
	}
	return len(gone)
}

var errInvalid = errors.New("invalid")

// call sends one A2A message to name over SLIM and returns the task.
func (b *Bridge) call(ctx context.Context, name string, part *a2a.Part) (*a2a.Task, error) {
	card := &a2a.AgentCard{Name: name, Description: "Agent Capsule delivery endpoint", Version: "1",
		SupportedInterfaces: []*a2a.AgentInterface{a2a.NewAgentInterface(name, a2aslimrpc.SLIMProtocol)},
		DefaultInputModes:   []string{deliveryType}, DefaultOutputModes: []string{receiptType}}
	client, err := a2aclient.NewFactory(a2aclient.WithDefaultsDisabled(), a2aslimrpc.WithSLIMRPCTransport(b.self, &b.outConn)).CreateFromCard(ctx, card)
	if err != nil {
		return nil, err
	}
	defer client.Destroy()
	result, err := client.SendMessage(ctx, &a2a.SendMessageRequest{Message: a2a.NewMessage(a2a.MessageRoleUser, part)})
	if err != nil {
		return nil, err
	}
	task, ok := result.(*a2a.Task)
	if !ok {
		return nil, errors.New("the recipient answered without a task")
	}
	return task, nil
}

// Send carries one delivery to the bridge answering on to, and returns the
// receipt that bridge's worker gave, or a refusal code with its HTTP status.
func (b *Bridge) Send(ctx context.Context, in SendRequest) (Receipt, int, string) {
	if !validName(in.To) || in.Nonce == "" || in.Event.ID == "" {
		return Receipt{}, http.StatusBadRequest, codeInvalid
	}
	payload, err := json.Marshal(delivery{Nonce: in.Nonce, Event: in.Event})
	if err != nil {
		return Receipt{}, http.StatusBadRequest, codeInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, b.cfg.Call())
	defer cancel()
	task, err := b.call(ctx, in.To, &a2a.Part{Content: a2a.Raw(payload), MediaType: deliveryType})
	if err != nil {
		return Receipt{}, http.StatusBadGateway, codeUnreachable
	}
	switch task.Status.State {
	case a2a.TaskStateCompleted:
		for _, artifact := range task.Artifacts {
			for _, p := range artifact.Parts {
				if raw, ok := p.Content.(a2a.Raw); ok && p.MediaType == receiptType {
					var r Receipt
					if json.Unmarshal(raw, &r) == nil {
						return r, http.StatusOK, ""
					}
				}
			}
		}
		return Receipt{}, http.StatusBadGateway, codeFailed
	case a2a.TaskStateRejected:
		return Receipt{}, http.StatusForbidden, codeRefused
	default:
		return Receipt{}, http.StatusBadGateway, codeFailed
	}
}

// Probe sends the bridge a message through the node and waits for its answer.
func (b *Bridge) Probe(ctx context.Context) error {
	task, err := b.call(ctx, b.probe, &a2a.Part{Content: a2a.Raw("probe"), MediaType: probeType})
	if err != nil {
		return err
	}
	if task.Status.State != a2a.TaskStateCompleted {
		return errors.New("probe not answered")
	}
	return nil
}

// probeWithin bounds a probe on the Go side too: once the node is gone, a
// native call can outlive its deadline. A stuck probe counts as failed.
func (b *Bridge) probeWithin(ctx context.Context, d time.Duration) error {
	done := make(chan error, 1)
	go func() {
		probe, cancel := context.WithTimeout(ctx, d)
		defer cancel()
		done <- b.Probe(probe)
	}()
	select {
	case err := <-done:
		return err
	case <-time.After(d + 2*time.Second):
		return errors.New("probe stuck")
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Watch probes until the node is lost three times in a row, or ctx ends.
func (b *Bridge) Watch(ctx context.Context) error {
	failures := 0
	for {
		err := b.probeWithin(ctx, 10*time.Second)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err == nil {
			failures = 0
			b.healthy.Store(true)
		} else {
			failures++
			b.healthy.Store(false)
			if failures >= 3 {
				return ErrNodeLost
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(b.cfg.Probe()):
		}
	}
}

func events(ec *a2asrv.ExecutorContext, state a2a.TaskState, note string, parts ...*a2a.Part) iter.Seq2[a2a.Event, error] {
	return func(yield func(a2a.Event, error) bool) {
		list := []a2a.Event{a2a.NewSubmittedTask(ec, ec.Message)}
		if len(parts) > 0 {
			list = append(list, a2a.NewArtifactEvent(ec, parts...))
		}
		var msg *a2a.Message
		if note != "" {
			msg = a2a.NewMessage(a2a.MessageRoleAgent, a2a.NewTextPart(note))
		}
		list = append(list, a2a.NewStatusUpdateEvent(ec, state, msg))
		for _, e := range list {
			if !yield(e, nil) {
				return
			}
		}
	}
}

func cancelled(_ context.Context, ec *a2asrv.ExecutorContext) iter.Seq2[a2a.Event, error] {
	return func(yield func(a2a.Event, error) bool) {
		yield(a2a.NewStatusUpdateEvent(ec, a2a.TaskStateCanceled, nil), nil)
	}
}

func rawPart(m *a2a.Message, mediaType string) ([]byte, bool) {
	if m == nil || len(m.Parts) != 1 || m.Parts[0].MediaType != mediaType {
		return nil, false
	}
	raw, ok := m.Parts[0].Content.(a2a.Raw)
	return raw, ok
}

// probeAnswer answers the probes of the bridge named name, and nothing else.
type probeAnswer struct{ name string }

func (p probeAnswer) Execute(ctx context.Context, ec *a2asrv.ExecutorContext) iter.Seq2[a2a.Event, error] {
	caller, ok := a2aslimrpc.CallerFromContext(ctx)
	// SLIM names an application's instance <name>_<suffix>.
	if _, probe := rawPart(ec.Message, probeType); !probe || !ok || !hasPrefix(caller.Subject, p.name+"_") {
		return events(ec, a2a.TaskStateRejected, codeRefused)
	}
	return events(ec, a2a.TaskStateCompleted, "")
}

func (probeAnswer) Cancel(ctx context.Context, ec *a2asrv.ExecutorContext) iter.Seq2[a2a.Event, error] {
	return cancelled(ctx, ec)
}

func hasPrefix(s, p string) bool { return len(s) >= len(p) && s[:len(p)] == p }

// deliveries answers on an agent's name: it hands each delivery to the
// worker with the caller's identity as SLIM verified it, and returns the
// worker's receipt. The worker decides; the bridge only carries.
type deliveries struct {
	b    *Bridge
	name string
}

func (d deliveries) Execute(ctx context.Context, ec *a2asrv.ExecutorContext) iter.Seq2[a2a.Event, error] {
	caller, ok := a2aslimrpc.CallerFromContext(ctx)
	raw, isDelivery := rawPart(ec.Message, deliveryType)
	var in delivery
	if !ok || !isDelivery || json.Unmarshal(raw, &in) != nil {
		return events(ec, a2a.TaskStateRejected, codeInvalid)
	}
	d.b.mu.Lock()
	if s := d.b.names[d.name]; s != nil {
		s.last = time.Now()
	}
	d.b.mu.Unlock()
	body, err := json.Marshal(DeliverRequest{To: d.name, Caller: caller.Subject, Nonce: in.Nonce, Event: in.Event})
	if err != nil {
		return events(ec, a2a.TaskStateRejected, codeInvalid)
	}
	ctx, cancel := context.WithTimeout(ctx, d.b.cfg.Call())
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://worker"+deliverPath, bytes.NewReader(body))
	if err != nil {
		return events(ec, a2a.TaskStateFailed, codeFailed)
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := d.b.worker.Do(req)
	if err != nil {
		return events(ec, a2a.TaskStateFailed, codeUnavailable)
	}
	defer res.Body.Close()
	data, err := io.ReadAll(io.LimitReader(res.Body, maxBody+1))
	switch {
	case err != nil:
		return events(ec, a2a.TaskStateFailed, codeFailed)
	case res.StatusCode == http.StatusOK:
		return events(ec, a2a.TaskStateCompleted, "", &a2a.Part{Content: a2a.Raw(data), MediaType: receiptType})
	case res.StatusCode == http.StatusForbidden || res.StatusCode == http.StatusGone:
		return events(ec, a2a.TaskStateRejected, codeRefused)
	default:
		return events(ec, a2a.TaskStateFailed, codeFailed)
	}
}

func (deliveries) Cancel(ctx context.Context, ec *a2asrv.ExecutorContext) iter.Seq2[a2a.Event, error] {
	return cancelled(ctx, ec)
}

// rotatingStore keeps tasks for one to two periods: every delivery completes
// within its own call, and an unbounded store would grow with each one.
type rotatingStore struct {
	mu        sync.Mutex
	cur, prev *taskstore.InMemory
	since     time.Time
	period    time.Duration
}

func newRotatingStore(period time.Duration) *rotatingStore {
	return &rotatingStore{cur: taskstore.NewInMemory(nil), prev: taskstore.NewInMemory(nil), since: time.Now(), period: period}
}

func (s *rotatingStore) stores() (*taskstore.InMemory, *taskstore.InMemory) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if time.Since(s.since) > s.period {
		s.prev, s.cur, s.since = s.cur, taskstore.NewInMemory(nil), time.Now()
	}
	return s.cur, s.prev
}

func (s *rotatingStore) Create(ctx context.Context, t *a2a.Task) (taskstore.TaskVersion, error) {
	cur, _ := s.stores()
	return cur.Create(ctx, t)
}

func (s *rotatingStore) Update(ctx context.Context, u *taskstore.UpdateRequest) (taskstore.TaskVersion, error) {
	cur, prev := s.stores()
	v, err := cur.Update(ctx, u)
	if errors.Is(err, a2a.ErrTaskNotFound) {
		return prev.Update(ctx, u)
	}
	return v, err
}

func (s *rotatingStore) Get(ctx context.Context, id a2a.TaskID) (*taskstore.StoredTask, error) {
	cur, prev := s.stores()
	t, err := cur.Get(ctx, id)
	if errors.Is(err, a2a.ErrTaskNotFound) {
		return prev.Get(ctx, id)
	}
	return t, err
}

func (s *rotatingStore) List(ctx context.Context, r *a2a.ListTasksRequest) (*a2a.ListTasksResponse, error) {
	cur, _ := s.stores()
	return cur.List(ctx, r)
}
