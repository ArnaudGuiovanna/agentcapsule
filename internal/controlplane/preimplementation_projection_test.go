package controlplane

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type p1Observation struct {
	SQL struct {
		Agents []struct {
			ID               int
			Phase, Placement string
			Generation       int
			FenceOnly        bool `json:"fence_only"`
		}
		Requests []struct {
			ID, Sender, Recipient int
			State                 string
			Final                 string `json:"final_state"`
			Closure               *string
			Notified              bool `json:"sender_notified"`
		}
		Mailboxes []struct {
			ID          string
			Request     int
			Kind        string
			Destination int
			Sequence    *int
			State       string `json:"delivery_state"`
			Attempts    int
			Lease       bool `json:"lease_current"`
			Token       *int `json:"abstract_lease_token"`
			Permitted   bool `json:"dispatch_authorized"`
			Closing     bool
		}
		Mandates []struct {
			Agent, Remaining int
			Valid            bool
		}
		Acks []struct {
			Store   int
			Subject string
		} `json:"acknowledged_barriers"`
	}
	SQLite []struct {
		Agent        int
		Fences, Seen []string
		Effects      map[string]int
	}
	Calls []struct {
		Slot            int
		Phase, Kind     string
		Request, Caller int
		Generation      int   `json:"received_generation"`
		Held            []int `json:"held_agents"`
	} `json:"sql_transactions"`
}

func p1Equal(t *testing.T, step int, label string, got, want any) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("P1 step %d %s: got %#v; model %#v", step, label, got, want)
	}
}
func (a *p1Replay) canonicalSubject(t *testing.T, subject string) string {
	t.Helper()
	for i := range 3 {
		if subject == "agent/"+p1Agent(i) {
			return fmt.Sprintf("agent/%d", i)
		}
	}
	for i, id := range a.requests {
		if id != "" && subject == "request/"+id {
			return fmt.Sprintf("request/%d", i)
		}
	}
	for label, id := range a.events {
		if subject == "event/"+id {
			return "event/" + label
		}
	}
	t.Fatal("unbound fence subject", subject)
	return ""
}
func (a *p1Replay) compareP1(t *testing.T, w p1Observation, step int, transactions bool) {
	t.Helper()
	eq := func(label string, got, want any) { t.Helper(); p1Equal(t, step, label, got, want) }
	eq("agent census", count(t, a.s, "agents"), len(w.SQL.Agents))
	for _, agent := range w.SQL.Agents {
		var phase, state string
		var generation int
		var fenceOnly bool
		if err := a.s.pool.QueryRow(t.Context(), `SELECT a.phase,p.state,p.generation,p.fence_only FROM agents a JOIN agent_placements p ON p.agent_id=a.id WHERE a.id=$1`, p1Agent(agent.ID)).Scan(&phase, &state, &generation, &fenceOnly); err != nil {
			t.Fatal(err)
		}
		eq(fmt.Sprintf("agent/%d", agent.ID), []any{phase, state, generation, fenceOnly}, []any{agent.Phase, agent.Placement, agent.Generation, agent.FenceOnly})
	}
	present := 0
	for _, r := range w.SQL.Requests {
		state, final, sender, recipient, closure := "ABSENT", "ABSENT", "", "", ""
		notified := false
		if id := a.requests[r.ID]; id != "" {
			err := a.s.pool.QueryRow(t.Context(), `SELECT r.state,r.sender_agent_id,r.recipient_agent_id,r.sender_notified,coalesce(c.final_state,'') FROM agent_requests r LEFT JOIN request_closures c ON c.request_id=r.id WHERE r.id=$1`, id).Scan(&state, &sender, &recipient, &notified, &closure)
			if err != nil {
				t.Fatal(err)
			}
			present++
			eq("request sender", sender, p1Agent(r.Sender))
			eq("request recipient", recipient, p1Agent(r.Recipient))
			if !active(state) {
				if a.finals[r.ID] != "" {
					eq("terminal state stability", state, a.finals[r.ID])
				} else {
					a.finals[r.ID] = state
				}
			}
			if a.finals[r.ID] != "" {
				final = a.finals[r.ID]
			}
		}
		expectedClosure := ""
		if r.Closure != nil {
			expectedClosure = *r.Closure
		}
		eq(fmt.Sprintf("request/%d", r.ID), []any{state, final, closure, notified}, []any{r.State, r.Final, expectedClosure, r.Notified})
	}
	eq("request census", count(t, a.s, "agent_requests"), present)
	for _, m := range w.SQL.Mandates {
		var remaining int
		var valid bool
		if err := a.s.pool.QueryRow(t.Context(), "SELECT remaining,valid AND expires_at>clock_timestamp() FROM mandates WHERE id=$1", "mandate-"+p1Agent(m.Agent)).Scan(&remaining, &valid); err != nil {
			t.Fatal(err)
		}
		eq(fmt.Sprintf("mandate/%d", m.Agent), []any{remaining, valid}, []any{m.Remaining, m.Valid})
	}
	pending, mailboxes := 0, 0
	for _, m := range w.SQL.Mailboxes {
		var id, dest, state, token string
		var sequence, attempts int
		var leased, permitted, closing bool
		err := a.s.pool.QueryRow(t.Context(), `SELECT id,dest_agent_id,seq,delivery_state,attempts,COALESCE(lease_until>clock_timestamp(),false) AND delivery_state='PENDING',lease_token,dispatch_authorized,closing FROM agent_mailboxes WHERE ref_id=$1 AND kind=$2`, a.requests[m.Request], m.Kind).Scan(&id, &dest, &sequence, &state, &attempts, &leased, &token, &permitted, &closing)
		if m.State == "ABSENT" {
			if !errors.Is(err, pgx.ErrNoRows) {
				t.Fatal("unexpected mailbox or query failure", m.ID, err)
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		mailboxes++
		a.events[m.ID] = id
		if m.Sequence == nil {
			t.Fatal("missing model mailbox sequence")
		}
		eq(m.ID, []any{dest, sequence, state, attempts, leased, permitted, closing}, []any{p1Agent(m.Destination), *m.Sequence, m.State, m.Attempts, m.Lease, m.Permitted, m.Closing})
		if m.Token != nil {
			eq(m.ID+"/opaque token", token, a.tokens[m.ID][*m.Token])
		}
		if state == "PENDING" {
			pending++
		}
	}
	eq("mailbox census", count(t, a.s, "agent_mailboxes"), mailboxes)
	eq("outbox census", count(t, a.s, "outbox"), pending)
	// FIFO heads are independently read through the production selector, not
	// inferred from the order in which this adapter happens to send events.
	for target := range 3 {
		first, seq := "", int(^uint(0)>>1)
		for _, m := range w.SQL.Mailboxes {
			if m.Destination == target && m.State == "PENDING" && m.Sequence != nil && *m.Sequence < seq {
				first = a.events[m.ID]
				seq = *m.Sequence
			}
		}
		got, err := a.s.HeadDelivery(t.Context(), p1Agent(target))
		if first == "" {
			if !errors.Is(err, ErrNoDelivery) {
				t.Fatal("unexpected FIFO head", got, err)
			}
		} else {
			if err != nil {
				t.Fatal(err)
			}
			eq("FIFO head", got, first)
		}
	}
	acks := []string{}
	rows, err := a.s.pool.Query(t.Context(), `SELECT store_agent_id,'agent/'||agent_id FROM deletion_targets WHERE acknowledged UNION ALL SELECT store_agent_id,'request/'||request_id FROM request_closure_targets WHERE acknowledged`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var store, subject string
		if err = rows.Scan(&store, &subject); err != nil {
			t.Fatal(err)
		}
		acks = append(acks, store+":"+a.canonicalSubject(t, subject))
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		t.Fatal(err)
	}
	wanted := []string{}
	for _, r := range w.SQL.Acks {
		wanted = append(wanted, p1Agent(r.Store)+":"+r.Subject)
	}
	sort.Strings(acks)
	sort.Strings(wanted)
	eq("acknowledged barriers", acks, wanted)
	for _, local := range w.SQLite {
		db, err := sql.Open("sqlite3", filepath.Join(a.root, fmt.Sprintf("%x", sha256.Sum256([]byte(p1Agent(local.Agent)))), "harness.db"))
		if err != nil {
			t.Fatal(err)
		}
		func() {
			defer db.Close()
			fences := []string{}
			rows, err := db.QueryContext(t.Context(), "SELECT subject FROM capsule_fences ORDER BY subject")
			if err != nil {
				t.Fatal(err)
			}
			for rows.Next() {
				var subject string
				if err = rows.Scan(&subject); err != nil {
					t.Fatal(err)
				}
				fences = append(fences, a.canonicalSubject(t, subject))
			}
			rows.Close()
			if err = rows.Err(); err != nil {
				t.Fatal(err)
			}
			sort.Strings(fences)
			wantFences := append([]string{}, local.Fences...)
			sort.Strings(wantFences)
			eq("SQLite fences", fences, wantFences)
			reverse := map[string]string{}
			for label, id := range a.events {
				reverse[id] = label
			}
			seen := []string{}
			rows, err = db.QueryContext(t.Context(), "SELECT event_id,result FROM capsule_inbox")
			if err != nil {
				t.Fatal(err)
			}
			for rows.Next() {
				var id string
				var result []byte
				if err = rows.Scan(&id, &result); err != nil {
					t.Fatal(err)
				}
				label, ok := reverse[id]
				if !ok {
					t.Fatal("unbound local effect")
				}
				seen = append(seen, label)
				eq("local replay result", string(result), "durable")
			}
			rows.Close()
			if err = rows.Err(); err != nil {
				t.Fatal(err)
			}
			sort.Strings(seen)
			wantSeen := append([]string{}, local.Seen...)
			sort.Strings(wantSeen)
			eq("SQLite dedup", seen, wantSeen)
			var table int
			if err = db.QueryRowContext(t.Context(), "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='received'").Scan(&table); err != nil {
				t.Fatal(err)
			}
			actual := map[string]int{}
			for label := range local.Effects {
				actual[label] = 0
			}
			if table != 0 {
				rows, err = db.QueryContext(t.Context(), "SELECT event_id,count(*) FROM received GROUP BY event_id")
				if err != nil {
					t.Fatal(err)
				}
				for rows.Next() {
					var id string
					var n int
					if err = rows.Scan(&id, &n); err != nil {
						t.Fatal(err)
					}
					label, ok := reverse[id]
					if !ok {
						t.Fatal("unbound application effect")
					}
					actual[label] = n
				}
				rows.Close()
				if err = rows.Err(); err != nil {
					t.Fatal(err)
				}
			}
			eq("SQLite effects", actual, local.Effects)
		}()
	}
	if transactions {
		a.compareP1Calls(t, w, step)
	}
}
func (a *p1Replay) compareP1Calls(t *testing.T, w p1Observation, step int) {
	t.Helper()
	held := map[int]bool{}
	for _, call := range w.Calls {
		c := a.calls[call.Slot]
		if call.Phase == "EmptyCall" {
			if c != nil {
				t.Fatal("unexpected live call")
			}
			continue
		}
		if c == nil {
			t.Fatal("missing live call")
		}
		phase := "ReceivedCall"
		if c.admitted {
			phase = "AdmittedCall"
		}
		p1Equal(t, step, "call", []any{phase, c.kind, c.request, c.caller, int(c.identity.Generation)}, []any{call.Phase, call.Kind, call.Request, call.Caller, call.Generation})
		if c.admitted {
			var blocked bool
			if err := a.s.pool.QueryRow(t.Context(), "SELECT $1=ANY(pg_blocking_pids($2))", c.gatePID, c.pid).Scan(&blocked); err != nil {
				t.Fatal(err)
			}
			p1Equal(t, step, "admitted transaction still open", blocked, true)
		}
		for _, id := range call.Held {
			held[id] = true
		}
	}
	for id := range 3 {
		tx, err := a.s.begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		var got string
		err = tx.QueryRow(t.Context(), "SELECT id FROM agents WHERE id=$1 FOR NO KEY UPDATE NOWAIT", p1Agent(id)).Scan(&got)
		rollback(tx)
		blocked := false
		if err != nil {
			var pgerr *pgconn.PgError
			if !errors.As(err, &pgerr) || pgerr.Code != "55P03" {
				t.Fatal("lock probe", err)
			}
			blocked = true
		}
		p1Equal(t, step, fmt.Sprintf("actual agent row lock/%d", id), blocked, held[id])
	}
}
func (a *p1Replay) refuseP1(t *testing.T, op protocolAction, outcome string) {
	t.Helper()
	switch op.Name {
	case "commitCall":
		if err := a.finishCall(t, p1Int(op.Args[0])); !errors.Is(err, ErrMandate) {
			t.Fatal("expired mandate did not roll back", err)
		}
	case "admit":
		slot := p1Int(op.Args[0])
		a.startCall(t, slot)
		c := a.calls[slot]
		if strings.HasPrefix(outcome, "ErrPlacement;") {
			select {
			case r := <-c.done:
				c.done = nil
				if !errors.Is(r.err, ErrPlacement) {
					t.Fatal("stale caller admitted", r.err)
				}
			case <-time.After(6 * time.Second):
				t.Fatal("stale caller was not rejected")
			}
			a.cancelCall(t, slot, false)
			break
		}
		blocker := 0
		for i, other := range a.calls {
			if i != slot && other != nil && other.admitted {
				blocker = other.pid
			}
		}
		if blocker == 0 {
			t.Fatal("missing live blocking transaction")
		}
		waitUntil(t, func() bool {
			select {
			case r := <-c.done:
				c.done = nil
				t.Fatalf("competing admission completed: %v", r.err)
			default:
			}
			var waits bool
			if err := a.s.pool.QueryRow(t.Context(), "SELECT $1=ANY(pg_blocking_pids($2))", blocker, c.pid).Scan(&waits); err != nil {
				t.Fatal(err)
			}
			return waits
		})
		a.cancelCall(t, slot, false)
	case "fenceStore":
		ctx, cancel := context.WithTimeout(t.Context(), 150*time.Millisecond)
		defer cancel()
		err := a.boots[p1Int(op.Args[0])].client.Fence(ctx, a.subject(op.Args[1]))
		if err == nil || ctx.Err() == nil {
			t.Fatal("fence did not wait for the open writer", err)
		}
	case "beginEffect":
		r := a.rpc[p1Int(op.Args[0])]
		current := a.boots[p1AgentNumber(r.attempt.Destination)]
		if r.boot == current {
			t.Fatal("old-channel scenario did not replace the boot")
		}
		if err := current.client.Health(t.Context()); err != nil {
			t.Fatal("replacement channel unavailable", err)
		}
		// First exercise the captured, retired channel, then deliberately dial
		// the live replacement with those same old credentials. A closed port
		// alone would not establish authentication rejects a stale generation.
		if _, err := r.boot.client.Send(t.Context(), r.attempt.Envelope); !errors.Is(err, capsuleprotocol.ErrTransport) {
			t.Fatal("retired channel accepted", err)
		}
		stale, err := capsuleprotocol.NewClient(r.boot.host, current.dial)
		if err != nil {
			t.Fatal(err)
		}
		_, err = stale.Send(t.Context(), r.attempt.Envelope)
		var certificateError *tls.CertificateVerificationError
		if !errors.Is(err, capsuleprotocol.ErrTransport) || !errors.As(err, &certificateError) {
			t.Fatal("old credentials did not fail TLS verification on live replacement", err)
		}
		if err := current.client.Health(t.Context()); err != nil {
			t.Fatal("replacement channel lost after refusal", err)
		}
	default:
		t.Fatal("unsupported refusal", op.Name)
	}
	// Go rolls back a refused transaction; the disabled formal action leaves
	// its volatile admission record unchanged. Durable projections must agree.
	t.Log("observed refusal/wait:", op.Name, strings.Join([]string{"durable", "projection", "unchanged"}, " "))
}
