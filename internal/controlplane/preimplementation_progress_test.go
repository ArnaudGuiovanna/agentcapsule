package controlplane

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"syscall"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnessstore"
	"github.com/jackc/pgx/v5"
)

// This is a projection of P3's macrosteps, not a refinement proof or a test of
// physical capacity/fairness. P3 destination is the outcome recipient (the Go
// request sender). The opposite agent executes the request. This binding does
// not implement P3's selective deletion semantics and must not be used for it.
var p3Cases = map[string]bool{
	"successful-request-observed-and-notified":  true,
	"hung-handler-terminated-by-deadline":       true,
	"queued-request-deadline":                   true,
	"terminal-notification-failure-keeps-inbox": true,
	"notification-retry-success":                true,
	"fifo-shared-notification-queue":            true,
	"two-repeatable-arrivals":                   true,
	"restore-recovery-before-closing":           true,
	"unavailable-store-is-not-a-fence":          true,
	"worker-crash-recovery":                     true,
	"authority-recovery-enables-observation":    true,
	"observe-requires-current-authority":        true,
}

type p3Binding struct {
	id         string
	incoming   string
	notice     string
	observed   bool // set only after a successful production owner lookup
	lastNotice harnessstore.Event
}

type p3Replay struct {
	s           *Store
	local       *p1Replay
	transit     *Transit
	catalog     *AgentCatalog
	principals  [2]Principal
	bound       [3]p3Binding
	history     []p3Binding
	serial      int
	dsn         string
	lookup      *Store
	lookupProxy *p3SQLProxy
	sqlWorker   *p3SQLWorker
}

func p3Sender(slot int) int {
	if slot == 0 {
		return 0
	}
	return 1
}

func newP3Replay(t *testing.T, scenario string) *p3Replay {
	t.Helper()
	s, dsn := freshStore(t, "auto", 10)
	// Initial environment: exactly two stores and a two-attempt notification
	// budget, matching this finite instance. No requests/results are seeded.
	if _, err := s.pool.Exec(t.Context(), `DELETE FROM mandates WHERE agent_id='c'; DELETE FROM agents WHERE id='c'; ALTER TABLE agent_mailboxes ALTER COLUMN attempt_limit SET DEFAULT 2`); err != nil {
		t.Fatal(err)
	}
	a := &p3Replay{s: s, dsn: dsn, lookup: s}
	a.local = &p1Replay{s: s, root: t.TempDir(), events: map[string]string{}, tokens: map[string]map[int]string{}}
	accounts, err := NewAccounts(s, bytes.Repeat([]byte{0x74}, 32))
	if err != nil {
		t.Fatal(err)
	}
	secret, err := s.BootstrapService(t.Context(), "progress-admin", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	admin, err := s.Authenticate(t.Context(), secret)
	if err != nil {
		t.Fatal(err)
	}
	for i := range 2 {
		u := createAccount(t, accounts, admin, "owner-"+p1Agent(i), "Progress owner "+p1Agent(i))
		token := issueAccountToken(t, accounts, admin, u, "token-"+p1Agent(i))
		a.principals[i], err = s.Authenticate(t.Context(), token.Token)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = s.pool.Exec(t.Context(), "UPDATE agents SET owner_user_id=$2 WHERE id=$1", p1Agent(i), u.ID); err != nil {
			t.Fatal(err)
		}
		a.local.callers[i] = confirmedCaller(t, s, p1Agent(i))
		a.local.boots[i] = a.local.launchLocal(t, i, false)
	}
	a.transit, err = NewTransit(s, "progress", map[string][]byte{"progress": bytes.Repeat([]byte{0x75}, 32)}, 7*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err = a.transit.ActivateKeys(t.Context()); err != nil {
		t.Fatal(err)
	}
	a.catalog, err = NewAgentCatalogWithTransit(accounts, "host", a.transit)
	if err != nil {
		t.Fatal(err)
	}
	if scenario == "authority-recovery-enables-observation" || scenario == "observe-requires-current-authority" {
		a.setupLookupOutage(t)
	}
	if scenario == "worker-crash-recovery" {
		a.sqlWorker = startP3SQLWorker(t, dsn)
	}
	t.Cleanup(func() {
		for _, r := range a.local.rpc {
			if r != nil && r.cancel != nil {
				r.cancel()
			}
		}
		for i := range 2 {
			a.local.stopLocal(t, i)
		}
	})
	return a
}

func (a *p3Replay) claim(t *testing.T, id string) (DeliveryAttempt, error) {
	t.Helper()
	if a.sqlWorker != nil {
		return a.sqlWorker.exchange(t, &p3WorkerCommand{Op: "claim", Mailbox: id}).Attempt, nil
	}
	r, err := a.s.ClaimDelivery(t.Context(), id, time.Hour)
	if err != nil {
		return r, err
	}
	if err = a.s.AuthorizeDispatch(t.Context(), id, r.Token); err != nil {
		return r, err
	}
	r.Envelope, err = a.transit.resolveDelivery(t.Context(), r)
	return r, err
}

func (a *p3Replay) begin(t *testing.T, attempt DeliveryAttempt) error {
	t.Helper()
	if a.local.rpc[0] != nil {
		t.Fatal("overlapping callback outside this projection")
	}
	a.local.rpc[0] = &p1RPC{attempt: attempt, boot: a.local.boots[p1AgentNumber(attempt.Destination)]}
	return a.local.beginEffect(t, 0)
}

func (a *p3Replay) commit(t *testing.T) error {
	t.Helper()
	r := a.local.rpc[0]
	if r == nil {
		t.Fatal("missing local writer")
	}
	if err := a.local.step(t, protocolAction{Name: "commitEffect", Args: []any{float64(0)}}); err != nil {
		return err
	}
	if a.sqlWorker != nil {
		a.sqlWorker.exchange(t, &p3WorkerCommand{Op: "ack", Mailbox: r.attempt.ID, Token: r.attempt.Token})
	} else {
		if err := a.s.acknowledgeDelivery(t.Context(), r.attempt.ID, r.attempt.Token, a.transit); err != nil {
			return err
		}
	}
	r.cancel()
	a.local.rpc[0] = nil
	return nil
}

type p3Fences struct{ replay *p3Replay }

func (f p3Fences) Fence(ctx context.Context, target, subject string) error {
	return f.replay.local.boots[p1AgentNumber(target)].client.Fence(ctx, subject)
}

func (a *p3Replay) step(t *testing.T, op protocolAction) error {
	t.Helper()
	if op.Name == "stabilize" {
		return nil
	} // environment assumption; no Go assertion
	if handled, err := a.availabilityStep(t, op); handled {
		return err
	}
	i := p1Int(op.Args[0])
	b := &a.bound[i]
	sender, recipient := p3Sender(i), 1-p3Sender(i)
	switch op.Name {
	case "arrive":
		if b.id != "" {
			t.Fatal("occupied logical slot")
		}
		a.serial++
		r, err := a.transit.SubmitFromVM(t.Context(), a.local.callers[sender], fmt.Sprintf("progress-%d", a.serial), capsuleprotocol.Submission{
			RecipientAgentID: p1Agent(recipient), MandateID: "mandate-" + p1Agent(sender), ExpiresAt: time.Now().Add(time.Hour),
			Payload: &capsuleprotocol.PeerPayload{Content: []capsuleprotocol.TextContent{{Type: "text", Text: "progress request"}}},
		})
		if err != nil {
			return err
		}
		for _, old := range a.history {
			if old.id == r.RequestID {
				t.Fatal("reused a historical UUID")
			}
		}
		b.id = r.RequestID
		b.incoming = mailboxFor(t, a.s, b.id, "request")
		if a.sqlWorker != nil {
			a.sqlWorker.exchange(t, &p3WorkerCommand{Op: "discover"})
		}
	case "admit":
		r, err := a.claim(t, b.incoming)
		if err != nil {
			return err
		}
		return a.begin(t, r)
	case "complete":
		if err := a.commit(t); err != nil {
			return err
		}
		reply := capsuleprotocol.Reply{
			Outcome: "completed", Payload: &capsuleprotocol.PeerPayload{Content: []capsuleprotocol.TextContent{{Type: "text", Text: "progress result"}}},
		}
		if a.sqlWorker != nil {
			a.sqlWorker.exchange(t, &p3WorkerCommand{Op: "reply", Caller: a.local.callers[recipient], RequestID: b.id, Reply: reply})
		} else {
			if _, err := a.transit.ReplyFromVM(t.Context(), a.local.callers[recipient], b.id, "progress-reply", reply); err != nil {
				return err
			}
		}
		b.notice = mailboxFor(t, a.s, b.id, "reply")
	case "deadline":
		// Model time is an environment input. Only the deadline is aged; the
		// production clock guard and closure transaction are executed normally.
		if _, err := a.s.pool.Exec(t.Context(), "UPDATE agent_requests SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1", b.id); err != nil {
			return err
		}
		return a.s.RequestExpiration(t.Context(), b.id)
	case "releaseExecution":
		// Cancel/drain the real local writer before reopening SQLite. This is
		// not a VMM retirement or a physical forced-stop observation.
		a.local.stopLocal(t, recipient)
		a.local.boots[recipient] = a.local.launchLocal(t, recipient, false)
	case "fence":
		store := p1Int(op.Args[1])
		if err := a.local.boots[store].client.Fence(t.Context(), "request/"+b.id); err != nil {
			return err
		}
		return a.s.recordRequestFence(t.Context(), b.id, p1Agent(store))
	case "commitClose":
		if err := a.s.commitRequestClosure(t.Context(), b.id); err != nil {
			return err
		}
		b.notice = mailboxFor(t, a.s, b.id, "status")
	case "notify":
		r, err := a.claim(t, b.notice)
		if err != nil {
			return err
		}
		b.lastNotice = r.Envelope
		if !op.Args[1].(bool) {
			// A real failed TCP connection, after durable dispatch permission.
			// The unknown RPC outcome remains pending until lease expiry/fence.
			bad, err := capsuleprotocol.NewClient(a.local.boots[sender].host, func(ctx context.Context) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "tcp", "127.0.0.1:0")
			})
			if err != nil {
				return err
			}
			_, err = bad.Send(t.Context(), r.Envelope)
			if !errors.Is(err, syscall.ECONNREFUSED) {
				t.Fatal("expected actual connection refusal", err)
			}
			expireLease(t, a.s, b.notice)
			return nil
		}
		if err := a.begin(t, r); err != nil {
			return err
		}
		return a.commit(t)
	case "retireNotification":
		if err := a.s.RetireDelivery(t.Context(), b.notice, p3Fences{a}); err != nil {
			return err
		}
		// The final failure must revoke a delayed copy too; merely removing
		// the queue head is not sufficient.
		_, err := a.local.boots[sender].client.Send(t.Context(), b.lastNotice)
		if !errors.Is(err, harnessstore.ErrFenced) {
			t.Fatal("retired event still accepted", err)
		}
	case "observe":
		v, err := a.catalog.Request(t.Context(), a.principals[sender], b.id)
		if err != nil {
			return err
		}
		if active(v.State) {
			t.Fatal("owner lookup returned nonterminal result")
		}
		if v.State == "REPLIED" && (v.Reply == nil || len(v.Reply.Content) != 1 || v.Reply.Content[0].Text != "progress result") {
			t.Fatal("owner result unavailable")
		}
		b.observed = true
	case "recycle":
		// Rebind the finite model slot only. No DELETE, UPDATE of UUIDs or
		// removal of durable history is allowed in the implementation.
		var notified bool
		if err := a.s.pool.QueryRow(t.Context(), "SELECT sender_notified FROM agent_requests WHERE id=$1", b.id).Scan(&notified); err != nil {
			return err
		}
		if !b.observed || !notified {
			t.Fatal("cannot recycle this projection before observation and ACK")
		}
		a.history = append(a.history, *b)
		*b = p3Binding{}
	default:
		t.Fatalf("unimplemented P3 transition %s", op.Name)
	}
	return nil
}

type p3RequestObservation struct {
	Slot          int
	Stage, Result string
	Inbox         bool `json:"durable_inbox"`
	Notification  string
	Attempts      int
	Fences        []int `json:"fenced_stores"`
	Effect        bool  `json:"effect_committed"`
}
type p3Observation struct {
	Requests []p3RequestObservation
	Queues   struct{ Admission, Execution, Notification []int }
	Watched  struct{ Accepted, Observed bool }
	Capacity struct {
		Available   []int `json:"available_stores"`
		WorkerUp    bool  `json:"worker_up"`
		AuthorityUp bool  `json:"authority_up"`
	}
}

func (a *p3Replay) sqliteCount(t *testing.T, agent int, table, column, id string) int {
	t.Helper()
	p := filepath.Join(a.local.root, fmt.Sprintf("%x", sha256.Sum256([]byte(p1Agent(agent)))), "harness.db")
	db, err := sql.Open("sqlite3", p)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var exists, n int
	if err = db.QueryRowContext(t.Context(), "SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?", table).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if exists == 0 {
		return 0
	}
	// Names are fixed test constants, never trace/user content.
	if err = db.QueryRowContext(t.Context(), "SELECT count(*) FROM "+table+" WHERE "+column+"=?", id).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func (a *p3Replay) compare(t *testing.T, w p3Observation, index int) {
	t.Helper()
	eq := func(label string, got, want any) {
		t.Helper()
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("P3 state %d %s: got %#v; model %#v", index, label, got, want)
		}
	}
	bound := 0
	for _, expected := range w.Requests {
		i := expected.Slot
		b := a.bound[i]
		got := p3RequestObservation{Slot: i, Stage: "Vacant", Result: "NoResult", Notification: "Uncreated", Fences: []int{}}
		if b.id != "" {
			bound++
			var state, closure string
			var authorized, notified bool
			if err := a.s.pool.QueryRow(t.Context(), `SELECT r.state,m.dispatch_authorized,r.sender_notified,coalesce(c.phase,'')
 FROM agent_requests r JOIN agent_mailboxes m ON m.ref_id=r.id AND m.kind='request'
 LEFT JOIN request_closures c ON c.request_id=r.id WHERE r.id=$1`, b.id).Scan(&state, &authorized, &notified, &closure); err != nil {
				t.Fatal(err)
			}
			got.Stage = "Accepted"
			if authorized {
				got.Stage = "Executing"
			}
			if closure == "FENCING" {
				got.Stage = "Closing"
			}
			if !active(state) {
				got.Stage = "Terminal"
				if b.observed {
					got.Stage = "Observable"
				}
				got.Result = "Aborted"
				if state == "REPLIED" {
					got.Result = "Success"
				}
				if err := a.s.pool.QueryRow(t.Context(), "SELECT EXISTS(SELECT 1 FROM inbox_items WHERE ref_id=$1 AND kind='request_update' AND user_id=$2)", b.id, a.principals[p3Sender(i)].ID).Scan(&got.Inbox); err != nil {
					t.Fatal(err)
				}
			}
			effects := a.sqliteCount(t, 1-p3Sender(i), "received", "event_id", b.incoming)
			if effects > 1 {
				t.Fatal("repeated business effect")
			}
			got.Effect = effects == 1
			rows, err := a.s.pool.Query(t.Context(), "SELECT store_agent_id FROM request_closure_targets WHERE request_id=$1 AND acknowledged ORDER BY store_agent_id", b.id)
			if err != nil {
				t.Fatal(err)
			}
			for rows.Next() {
				var store string
				if err = rows.Scan(&store); err != nil {
					t.Fatal(err)
				}
				got.Fences = append(got.Fences, p1AgentNumber(store))
			}
			rows.Close()
			if err = rows.Err(); err != nil {
				t.Fatal(err)
			}
			for _, store := range got.Fences {
				eq("persisted fence", a.sqliteCount(t, store, "capsule_fences", "subject", "request/"+b.id), 1)
			}
			var notice, stateNotice string
			var exhausted bool
			err = a.s.pool.QueryRow(t.Context(), `SELECT id,delivery_state,attempts,attempts>=attempt_limit AND (lease_until IS NULL OR lease_until<=clock_timestamp()) FROM agent_mailboxes WHERE ref_id=$1 AND kind IN ('reply','status')`, b.id).Scan(&notice, &stateNotice, &got.Attempts, &exhausted)
			if err == nil {
				eq("notice binding", notice, b.notice)
				switch stateNotice {
				case "PENDING":
					got.Notification = "Pending"
					if exhausted {
						got.Notification = "RetiringDead"
					}
				case "DELIVERED":
					got.Notification = "Acked"
				case "DEAD":
					got.Notification = "Dead"
				case "CANCELED":
					got.Notification = "Cancelled"
				default:
					t.Fatal("unknown notification state", stateNotice)
				}
				var outbox bool
				if err = a.s.pool.QueryRow(t.Context(), "SELECT EXISTS(SELECT 1 FROM outbox WHERE mailbox_id=$1)", notice).Scan(&outbox); err != nil {
					t.Fatal(err)
				}
				eq("notice outbox", outbox, stateNotice == "PENDING")
				eq("sender reception", notified, stateNotice == "DELIVERED")
				wantEffects := 0
				if stateNotice == "DELIVERED" {
					wantEffects = 1
				}
				eq("notification local effect", a.sqliteCount(t, p3Sender(i), "received", "event_id", notice), wantEffects)
			} else if !errors.Is(err, pgx.ErrNoRows) {
				t.Fatal(err)
			}
		}
		eq(fmt.Sprintf("request/%d", i), got, expected)
	}
	eq("retained UUID census", count(t, a.s, "agent_requests"), bound+len(a.history))
	for _, old := range a.history {
		var state, sender, recipient string
		var notified bool
		if err := a.s.pool.QueryRow(t.Context(), "SELECT state,sender_notified,sender_agent_id,recipient_agent_id FROM agent_requests WHERE id=$1", old.id).Scan(&state, &notified, &sender, &recipient); err != nil {
			t.Fatal(err)
		}
		eq("historical result", state, "REPLIED")
		eq("historical notice", notified, true)
		eq("historical business effect", a.sqliteCount(t, p1AgentNumber(recipient), "received", "event_id", old.incoming), 1)
		eq("historical notification effect", a.sqliteCount(t, p1AgentNumber(sender), "received", "event_id", old.notice), 1)
	}
	// SQL queues are reconstructed from rows, never advanced by the adapter.
	// Notification comparisons exercise FIFO for a shared destination only;
	// this does not assert a global FIFO across different agents.
	admission := []int{}
	execution := []int{}
	notification := []int{}
	rows, err := a.s.pool.Query(t.Context(), `SELECT r.id,m.dispatch_authorized FROM agent_requests r
 JOIN agent_mailboxes m ON m.ref_id=r.id AND m.kind='request'
 WHERE r.state IN ('DELIVERING','PROCESSING') AND NOT EXISTS(SELECT 1 FROM request_closures c WHERE c.request_id=r.id)
 ORDER BY r.created_at,r.id`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var id string
		var auth bool
		if err = rows.Scan(&id, &auth); err != nil {
			t.Fatal(err)
		}
		slot := a.slot(t, id)
		if auth {
			execution = append(execution, slot)
		} else {
			admission = append(admission, slot)
		}
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		t.Fatal(err)
	}
	rows, err = a.s.pool.Query(t.Context(), `SELECT m.ref_id FROM agent_mailboxes m JOIN outbox o ON o.mailbox_id=m.id WHERE m.kind IN ('reply','status') AND m.delivery_state='PENDING' ORDER BY o.available_at,m.seq`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		notification = append(notification, a.slot(t, id))
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		t.Fatal(err)
	}
	eq("admission projection", admission, w.Queues.Admission)
	eq("execution projection", execution, w.Queues.Execution)
	eq("notification queue", notification, w.Queues.Notification)
	// Use the production head selector for the actual queue guard too.
	for _, slot := range notification {
		var head string
		head, err = a.s.HeadDelivery(t.Context(), p1Agent(p3Sender(slot)))
		if err != nil {
			t.Fatal(err)
		}
		first := -1
		for _, candidate := range notification {
			if p3Sender(candidate) == p3Sender(slot) {
				first = candidate
				break
			}
		}
		eq("terminal FIFO head", head, a.bound[first].notice)
	}
	eq("tagged acceptance", a.bound[0].id != "", w.Watched.Accepted)
	eq("tagged owner observation", a.bound[0].observed, w.Watched.Observed)
	a.compareAvailability(t, w, index)
}

func (a *p3Replay) slot(t *testing.T, id string) int {
	t.Helper()
	for i, b := range a.bound {
		if b.id == id {
			return i
		}
	}
	t.Fatal("unbound active request in SQL queue")
	return -1
}

func TestPreimplementationP3ITF(t *testing.T) {
	dir := "testdata/preimplementation-progress"
	read := func(name, hash string) []byte {
		t.Helper()
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if fmt.Sprintf("%x", sha256.Sum256(b)) != hash {
			t.Fatal("changed P3 evidence", name)
		}
		return b
	}
	var manifest struct {
		ModelSHA string `json:"model_sha256"`
		Cases    []struct {
			Name, Trace, Driver, Observations string
			TraceSHA                          string `json:"trace_sha256"`
			DriverSHA                         string `json:"driver_sha256"`
			ObservationsSHA                   string `json:"observations_sha256"`
			Actions                           []protocolAction
			Refused                           []struct{ Action protocolAction } `json:"refused_actions"`
		}
	}
	if err := json.Unmarshal(read("manifest.json", "dcc99c0810e31f721895b44f7202749ec7e15865dcf8857bddee52afafa9fb84"), &manifest); err != nil {
		t.Fatal(err)
	}
	read("sources/service_progress.qnt", manifest.ModelSHA)
	if len(manifest.Cases) != 20 || len(p3Cases) != 12 {
		t.Fatal("P3 coverage inventory changed")
	}
	executed := []string{}
	for _, c := range manifest.Cases {
		if !p3Cases[c.Name] {
			t.Log("P3 pending additional adapter:", c.Name)
			continue
		}
		executed = append(executed, c.Name)
		t.Run(c.Name, func(t *testing.T) {
			read(c.Driver, c.DriverSHA)
			var trace struct{ States []json.RawMessage }
			if err := json.Unmarshal(read(c.Trace, c.TraceSHA), &trace); err != nil {
				t.Fatal(err)
			}
			var projected struct {
				States []struct {
					Index        int
					Action       *protocolAction
					Observations p3Observation
				}
			}
			if err := json.Unmarshal(read(c.Observations, c.ObservationsSHA), &projected); err != nil {
				t.Fatal(err)
			}
			if len(trace.States) != len(c.Actions)+1 || len(projected.States) != len(trace.States) {
				t.Fatal("P3 trace shape/refusal scope changed")
			}
			a := newP3Replay(t, c.Name)
			for i, p := range projected.States {
				if p.Index != i {
					t.Fatal("P3 state index changed")
				}
				if i > 0 {
					if p.Action == nil || !reflect.DeepEqual(*p.Action, c.Actions[i-1]) {
						t.Fatal("P3 action/projection mismatch")
					}
					if err := a.step(t, c.Actions[i-1]); err != nil {
						t.Fatalf("step %d %s: %v", i, c.Actions[i-1].Name, err)
					}
				}
				a.compare(t, p.Observations, i)
			}
			for _, r := range c.Refused {
				a.refuse(t, r.Action)
				a.compare(t, projected.States[len(projected.States)-1].Observations, len(c.Actions))
			}
			t.Logf("replayed %d transitions, %d states, %d refusals; SQL/SQLite/local mTLS outcome, notification and availability projection; physical capacity, scheduling fairness and VM lifecycle excluded", len(c.Actions), len(trace.States), len(c.Refused))
		})
	}
	sort.Strings(executed)
	if len(executed) != len(p3Cases) {
		t.Fatal("selected P3 scenario missing")
	}
}
