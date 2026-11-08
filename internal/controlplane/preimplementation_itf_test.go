package controlplane

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// P1 replay drives actual PostgreSQL transactions and durable SQLite stores.
// Initial placement is a fixture; per-boot mTLS channels use production code.
// Physical VM transitions are excluded from this SQL/SQLite/transport projection.
var p1Cases = map[string]bool{
	"delete-shared-recipient-four-requests": true, "expiration-preserves-neighbor-request": true,
	"shared-mandate-two-admissions": true, "mandate-expires-before-commit": true,
	"aborted-admission-releases-locks": true, "shared-agents-block-second-admission": true,
	"fifo-uses-commit-order": true, "lost-ack-competing-lease": true,
	"writer-blocks-revocation": true, "revoked-reply-gets-fresh-status": true,
	"worker-crash-before-business-commit": true, "manual-consent": true, "manual-decline": true,
	"dedup-survives-generation-change": true, "old-channel-after-replacement": true,
	"old-caller-after-replacement": true, "sql-commit-after-physical-death": true,
	"writer-crash-then-restricted-fencing": true, "confirmed-unpublished-boot-cleanup": true,
	"expired-start-lease-cleanup": true, "publication-after-stop-intent": true,
	"manual-consent-while-vm-sleeps": true,
}
var p1Routes = [4][2]int{{0, 1}, {2, 1}, {2, 0}, {0, 2}}

func p1Agent(n int) string   { return []string{"a", "b", "c"}[n] }
func p1Int(v any) int        { return int(v.(float64)) }
func p1Variant(v any) string { return v.(map[string]any)["variant"].(string) }
func p1Event(v any) string {
	x := v.(map[string]any)["tuple"].([]any)
	return fmt.Sprintf("request/%d/%s", p1Int(x[0]), []string{"request", "reply", "status"}[p1Int(x[1])])
}

type p1Call struct {
	kind                     string
	request, caller, mandate int
	identity                 VMCaller
	key                      string
	store                    *Store
	pid, gatePID             int
	gate                     pgx.Tx
	cancel                   context.CancelFunc
	done                     chan protocolAPIResult
	admitted                 bool
}
type p1RPC struct {
	attempt   DeliveryAttempt
	boot      *p1Boot
	release   chan struct{}
	cancel    context.CancelFunc
	done      chan error
	early     *error
	executing bool
}
type p1Replay struct {
	s          *Store
	boots      [3]*p1Boot
	restricted [3]bool
	root       string
	requests   [4]string
	callers    [3]VMCaller
	calls      [2]*p1Call
	rpc        [2]*p1RPC
	events     map[string]string
	tokens     map[string]map[int]string
	finals     [4]string
	// Only the privileged seal projection supplies this callback. It must
	// revalidate the host and publish its actual receipt on every invocation.
	seal   func(*testing.T, int) error
	sealed [3]bool
}

func newP1Replay(t *testing.T, manual bool) *p1Replay {
	t.Helper()
	s, _ := freshStore(t, "auto", 2)
	if manual {
		if _, err := s.pool.Exec(t.Context(), "UPDATE agents SET inbound_mode='manual' WHERE id='b'"); err != nil {
			t.Fatal(err)
		}
	}
	// Admission gates live only in this test schema and do not change business
	// writes. Each key has its own gate; shared agent locks remain production SQL.
	if _, err := s.pool.Exec(t.Context(), `CREATE FUNCTION hold_p1_admission() RETURNS trigger LANGUAGE plpgsql AS $$
 BEGIN PERFORM pg_advisory_xact_lock(hashtextextended(current_schema()::text || NEW.key,91)); RETURN NEW; END $$;
 CREATE TRIGGER hold_p1_admission BEFORE INSERT ON idempotency_keys FOR EACH ROW EXECUTE FUNCTION hold_p1_admission()`); err != nil {
		t.Fatal(err)
	}
	a := &p1Replay{s: s, root: t.TempDir(), events: map[string]string{}, tokens: map[string]map[int]string{}}
	for i := range 3 {
		a.callers[i] = confirmedCaller(t, s, p1Agent(i))
		a.boots[i] = a.launchLocal(t, i, false)
	}
	t.Cleanup(func() {
		for i, c := range a.calls {
			if c != nil {
				a.cancelCall(t, i, false)
			}
		}
		for _, r := range a.rpc {
			if r != nil && r.cancel != nil {
				r.cancel()
				if r.done != nil {
					select {
					case <-r.done:
					case <-time.After(6 * time.Second):
						t.Error("SQLite writer did not stop")
					}
				}
			}
		}
	})
	return a
}
func (a *p1Replay) startCall(t *testing.T, slot int) {
	t.Helper()
	c := a.calls[slot]
	if c == nil || c.done != nil {
		t.Fatal("invalid call admission")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	c.cancel = cancel
	cfg := a.s.pool.Config().Copy()
	cfg.MaxConns = 1
	cfg.MinConns = 0
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	c.store = &Store{pool: pool}
	if err = pool.QueryRow(ctx, "SELECT pg_backend_pid()").Scan(&c.pid); err != nil {
		t.Fatal(err)
	}
	c.gate, err = a.s.begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err = c.gate.QueryRow(ctx, "SELECT pg_backend_pid(),pg_advisory_xact_lock(hashtextextended(current_schema()::text || $1,91))", c.key).Scan(&c.gatePID, new(any)); err != nil {
		t.Fatal(err)
	}
	c.done = make(chan protocolAPIResult, 1)
	done := c.done
	requestID := a.requests[c.request]
	go func() {
		var r Receipt
		var err error
		switch c.kind {
		case "SubmitCall":
			in := submission()
			in.RecipientAgentID = p1Agent(p1Routes[c.request][1])
			in.MandateID = "mandate-" + p1Agent(c.mandate)
			r, err = c.store.SubmitFromVM(ctx, c.identity, c.key, in)
		case "ReplyCall":
			r, err = c.store.ReplyFromVM(ctx, c.identity, requestID, c.key, completedReply())
		case "AcceptCall":
			r, err = c.store.Accept(ctx, "user-"+p1Agent(c.caller), requestID, c.key)
		case "DeclineCall":
			r, err = c.store.DeclineRequest(ctx, "user-"+p1Agent(c.caller), requestID, c.key)
		default:
			err = fmt.Errorf("unsupported call kind %s", c.kind)
		}
		done <- protocolAPIResult{r, err}
	}()
}
func (a *p1Replay) admitted(t *testing.T, slot int) {
	t.Helper()
	a.startCall(t, slot)
	c := a.calls[slot]
	waitUntil(t, func() bool {
		select {
		case r := <-c.done:
			c.done = nil
			t.Fatalf("call returned before admission gate: %v", r.err)
		default:
		}
		var blocked bool
		if err := a.s.pool.QueryRow(t.Context(), "SELECT $1=ANY(pg_blocking_pids($2))", c.gatePID, c.pid).Scan(&blocked); err != nil {
			t.Fatal(err)
		}
		return blocked
	})
	c.admitted = true
}
func (a *p1Replay) finishCall(t *testing.T, slot int) error {
	t.Helper()
	c := a.calls[slot]
	if c == nil || c.done == nil || !c.admitted {
		t.Fatal("commit without admission")
	}
	rollback(c.gate)
	c.gate = nil
	var result protocolAPIResult
	select {
	case result = <-c.done:
	case <-time.After(6 * time.Second):
		t.Fatal("SQL commit did not finish")
	}
	c.done = nil
	c.cancel()
	c.store.Close()
	c.store = nil
	if result.err == nil && c.kind == "SubmitCall" {
		a.requests[c.request] = result.receipt.RequestID
	}
	a.calls[slot] = nil
	return result.err
}
func (a *p1Replay) cancelCall(t *testing.T, slot int, crash bool) {
	t.Helper()
	c := a.calls[slot]
	if c == nil {
		return
	}
	if c.done != nil {
		if crash {
			var killed bool
			if err := a.s.pool.QueryRow(t.Context(), "SELECT pg_terminate_backend($1)", c.pid).Scan(&killed); err != nil || !killed {
				t.Fatal("transaction crash injection", err)
			}
		} else {
			c.cancel()
		}
		select {
		case r := <-c.done:
			if r.err == nil {
				t.Error("aborted call committed")
			}
		case <-time.After(6 * time.Second):
			t.Error("aborted SQL call did not stop")
		}
		c.done = nil
	}
	if c.cancel != nil {
		c.cancel()
	}
	if c.gate != nil {
		rollback(c.gate)
	}
	if c.store != nil {
		c.store.Close()
	}
	a.calls[slot] = nil
}
func (a *p1Replay) subject(v any) string {
	x := v.(map[string]any)
	switch x["variant"] {
	case "AgentSubject":
		return "agent/" + p1Agent(p1Int(x["value"]))
	case "RequestSubject":
		return "request/" + a.requests[p1Int(x["value"])]
	case "EventSubject":
		return "event/" + a.events[p1Event(x["value"])]
	default:
		panic("unknown fence subject")
	}
}
func (a *p1Replay) beginEffect(t *testing.T, slot int) error {
	t.Helper()
	r := a.rpc[slot]
	if r == nil {
		t.Fatal("missing RPC")
	}
	entered := make(chan struct{})
	r.release = make(chan struct{})
	r.done = make(chan error, 1)
	ctx, cancel := context.WithCancel(t.Context())
	r.cancel = cancel
	release, done := r.release, r.done
	r.boot.mu.Lock()
	r.boot.gates[r.attempt.ID] = &p1EffectGate{entered: entered, release: release}
	r.boot.mu.Unlock()
	go func() {
		_, err := r.boot.client.Send(ctx, r.attempt.Envelope)
		done <- err
	}()
	select {
	case <-entered:
		r.executing = true
		return nil
	case err := <-r.done:
		r.early = &err
		r.done = nil
		r.executing = err == nil
		return err // durable dedup bypasses the handler
	case <-time.After(6 * time.Second):
		t.Fatal("SQLite effect did not start")
		return nil
	}
}
func (a *p1Replay) step(t *testing.T, op protocolAction) error {
	t.Helper()
	n := func(i int) int { return p1Int(op.Args[i]) }
	switch op.Name {
	case "receive":
		slot, r := n(0), n(1)
		if a.calls[slot] != nil {
			t.Fatal("occupied call slot")
		}
		kind := p1Variant(op.Args[2])
		caller := p1Routes[r][1]
		if kind == "SubmitCall" {
			caller = p1Routes[r][0]
		}
		a.calls[slot] = &p1Call{kind: kind, request: r, caller: caller, mandate: n(3), identity: a.callers[caller], key: fmt.Sprintf("p1-%d-%s", r, kind)}
	case "admit":
		a.admitted(t, n(0))
	case "commitCall":
		return a.finishCall(t, n(0))
	case "abortCall":
		a.cancelCall(t, n(0), false)
	case "expireMandate":
		_, err := a.s.pool.Exec(t.Context(), "UPDATE mandates SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1", "mandate-"+p1Agent(n(0)))
		return err
	case "claim":
		label := p1Event(op.Args[1])
		id := a.events[label]
		if id == "" {
			t.Fatal("mailbox not bound", label)
		}
		attempt, err := a.s.ClaimDelivery(t.Context(), id, time.Hour)
		if err != nil {
			return err
		}
		a.rpc[n(0)] = &p1RPC{attempt: attempt, boot: a.boots[p1AgentNumber(attempt.Destination)]}
		var counter int
		if err = a.s.pool.QueryRow(t.Context(), "SELECT attempts FROM agent_mailboxes WHERE id=$1", id).Scan(&counter); err != nil {
			return err
		}
		if a.tokens[label] == nil {
			a.tokens[label] = map[int]string{}
		}
		for _, old := range a.tokens[label] {
			if old == attempt.Token {
				t.Fatal("lease token reused")
			}
		}
		a.tokens[label][counter] = attempt.Token
	case "authorize":
		r := a.rpc[n(0)]
		return a.s.AuthorizeDispatch(t.Context(), r.attempt.ID, r.attempt.Token)
	case "beginEffect":
		return a.beginEffect(t, n(0))
	case "commitEffect":
		r := a.rpc[n(0)]
		if r == nil || r.release == nil {
			t.Fatal("effect not open")
		}
		close(r.release)
		r.release = nil
		r.executing = false
		if r.early != nil {
			return *r.early
		}
		select {
		case err := <-r.done:
			r.done = nil
			return err
		case <-time.After(6 * time.Second):
			t.Fatal("SQLite effect did not commit")
		}
	case "acknowledge":
		r := a.rpc[n(0)]
		err := a.s.AcknowledgeDelivery(t.Context(), r.attempt.ID, r.attempt.Token)
		if err == nil {
			if r.cancel != nil {
				r.cancel()
			}
			a.rpc[n(0)] = nil
		}
		return err
	case "loseRPC":
		r := a.rpc[n(0)]
		if r.cancel != nil {
			r.cancel()
		}
		a.rpc[n(0)] = nil
	case "expireLease":
		expireLease(t, a.s, a.events[p1Event(op.Args[0])])
	case "requestDelete":
		return a.s.RequestDeletion(t.Context(), "user-"+p1Agent(n(0)), p1Agent(n(0)))
	case "commitDelete":
		return a.s.commitRevocation(t.Context(), p1Agent(n(0)))
	case "fenceStore":
		if a.sealed[n(0)] {
			return a.seal(t, n(0))
		}
		return a.boots[n(0)].client.Fence(t.Context(), a.subject(op.Args[1]))
	case "sealStore":
		if a.seal == nil {
			t.Fatal("permanent seal requires the privileged host adapter")
		}
		if err := a.seal(t, n(0)); err != nil {
			return err
		}
		a.sealed[n(0)] = true
	case "recordFence":
		subject := op.Args[1].(map[string]any)
		switch subject["variant"] {
		case "AgentSubject":
			return a.s.recordFence(t.Context(), p1Agent(p1Int(subject["value"])), p1Agent(n(0)))
		case "RequestSubject":
			return a.s.recordRequestFence(t.Context(), a.requests[p1Int(subject["value"])], p1Agent(n(0)))
		default:
			t.Fatal("unsupported barrier receipt")
		}
	case "closeRequest":
		id := a.requests[n(0)]
		switch p1Variant(op.Args[1]) {
		case "CancelRequest":
			return a.s.RequestCancellation(t.Context(), "user-"+p1Agent(p1Routes[n(0)][0]), id)
		case "ExpireRequest":
			// Logical model expiry is mapped to the real database clock predicate.
			if _, err := a.s.pool.Exec(t.Context(), "UPDATE agent_requests SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1", id); err != nil {
				return err
			}
			return a.s.RequestExpiration(t.Context(), id)
		default:
			t.Fatal("unsupported closure")
		}
	case "commitClose":
		return a.s.commitRequestClosure(t.Context(), a.requests[n(0)])
	case "crashWorker":
		for i := range a.calls {
			a.cancelCall(t, i, true)
		}
	case "recoverWorker":
		if err := a.s.pool.Ping(t.Context()); err != nil {
			return err
		}
	default:
		if handled, err := a.lifecycleStep(t, op); handled {
			return err
		}
		t.Fatalf("unsupported P1 action %s", op.Name)
	}
	return nil
}

func TestPreimplementationP1ITF(t *testing.T) {
	if len(p1Cases) != 22 {
		t.Fatal("unexpected local P1 inventory")
	}
	runP1ITF(t, p1Cases, nil)
}

// A separate privileged test adds the host seal without changing the frozen
// trace or making host observations prerequisites for ordinary local replays.
type p1ITFHooks struct {
	state func(*testing.T, json.RawMessage, int)
	final func(*testing.T)
}

func runP1ITF(t *testing.T, selected map[string]bool, prepare func(*testing.T, *p1Replay) p1ITFHooks) {
	t.Helper()
	dir := "testdata/preimplementation-concurrency"
	read := func(name, hash string) []byte {
		t.Helper()
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if hash != "" && fmt.Sprintf("%x", sha256.Sum256(b)) != hash {
			t.Fatal("changed P1 evidence", name)
		}
		return b
	}
	var manifest struct {
		ModelSHA string `json:"model_sha256"`
		Cases    []struct {
			Name, Trace, Driver, Observations string
			Manual                            bool
			TraceSHA                          string `json:"trace_sha256"`
			DriverSHA                         string `json:"driver_sha256"`
			ObservationsSHA                   string `json:"observations_sha256"`
			Actions                           []protocolAction
			Refused                           []struct {
				Action  protocolAction
				Outcome string `json:"go_outcome"`
			} `json:"refused_actions"`
		}
	}
	if err := json.Unmarshal(read("manifest.json", "4fa7f026183e9f86d9e24edab051cd1d4acffec0337f8239779643a6980f9c3f"), &manifest); err != nil {
		t.Fatal(err)
	}
	read("sources/concurrent_protocol.qnt", manifest.ModelSHA)
	if len(manifest.Cases) != 24 {
		t.Fatal("unexpected P1 coverage inventory")
	}
	executed := 0
	for _, c := range manifest.Cases {
		if !selected[c.Name] {
			t.Log("outside this projection:", c.Name)
			continue
		}
		executed++
		t.Run(c.Name, func(t *testing.T) {
			read(c.Driver, c.DriverSHA)
			var trace struct{ States []json.RawMessage }
			if err := json.Unmarshal(read(c.Trace, c.TraceSHA), &trace); err != nil {
				t.Fatal(err)
			}
			var projections struct {
				States []struct {
					Index        int
					Action       *protocolAction
					Observations p1Observation
				}
			}
			if err := json.Unmarshal(read(c.Observations, c.ObservationsSHA), &projections); err != nil {
				t.Fatal(err)
			}
			if len(trace.States) != len(c.Actions)+1 || len(projections.States) != len(trace.States) {
				t.Fatal("trace/projection/action length mismatch")
			}
			a := newP1Replay(t, c.Manual)
			var hooks p1ITFHooks
			if prepare != nil {
				hooks = prepare(t, a)
			}
			for i, p := range projections.States {
				if p.Index != i {
					t.Fatal("projection index mismatch")
				}
				if i > 0 {
					got, _ := json.Marshal(p.Action)
					want, _ := json.Marshal(c.Actions[i-1])
					if string(got) != string(want) {
						t.Fatal("projection action mismatch")
					}
					if err := a.step(t, c.Actions[i-1]); err != nil {
						t.Fatalf("step %d %s: %v", i, c.Actions[i-1].Name, err)
					}
				}
				a.compareP1(t, p.Observations, i, true)
				if hooks.state != nil {
					hooks.state(t, trace.States[i], i)
				}
			}
			last := projections.States[len(projections.States)-1].Observations
			for _, refusal := range c.Refused {
				a.refuseP1(t, refusal.Action, refusal.Outcome)
				a.compareP1(t, last, len(c.Actions), false)
			}
			if hooks.final != nil {
				hooks.final(t)
				a.compareP1(t, last, len(c.Actions), false)
			}
			t.Logf("replayed %d transitions, %d states, %d refusals; PostgreSQL/SQLite, transaction-lock and local mTLS projection; physical runtime excluded", len(c.Actions), len(trace.States), len(c.Refused))
		})
	}
	if executed != len(selected) {
		t.Fatal("selected P1 case absent from manifest")
	}
}
