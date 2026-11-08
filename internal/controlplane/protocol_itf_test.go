package controlplane

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnessstore"
	vmruntime "github.com/ArnaudGuiovanna/agentcapsule/internal/runtime"
	"github.com/jackc/pgx/v5"
)

type protocolAction struct {
	Name string
	Args []any
}

// This adapter observes the SQL/SQLite projection, including placement generations
// and platform transaction admission. Physical host lifecycle, mTLS identities
// and the full state refinement are excluded.
type protocolReplay struct {
	s             *Store
	m             *vmruntime.MockRuntime
	root, request string
	attempt       DeliveryAttempt
	release       chan struct{}
	finished      chan error
	early         *error
	callers       map[string]VMCaller
	gate          pgx.Tx
	gatePID       int
	apiDone       chan protocolAPIResult
}

type protocolAPIResult struct {
	receipt Receipt
	err     error
}

// A test-schema trigger waits immediately after authorizeVM, before any durable
// business changes. PostgreSQL still owns the actual agent and placement locks.
func (a *protocolReplay) admit(t *testing.T, reply bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	t.Cleanup(cancel)
	gate, err := a.s.begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { rollback(gate) })
	a.gate = gate
	if err := gate.QueryRow(ctx, "SELECT pg_backend_pid(),pg_advisory_xact_lock(hashtextextended(current_schema()::text,91))").Scan(&a.gatePID, new(any)); err != nil {
		t.Fatal(err)
	}
	a.apiDone = make(chan protocolAPIResult, 1)
	go func() {
		var r Receipt
		var err error
		if reply {
			r, err = a.s.ReplyFromVM(ctx, a.callers["b"], a.request, "reply", completedReply())
		} else {
			r, err = a.s.SubmitFromVM(ctx, a.callers["a"], "request", submission())
		}
		a.apiDone <- protocolAPIResult{r, err}
	}()
	waitUntil(t, func() bool {
		var held bool
		if err := a.s.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid)) AND query LIKE '%INSERT INTO idempotency_keys%')`, a.gatePID).Scan(&held); err != nil {
			t.Fatal(err)
		}
		return held
	})
}

func (a *protocolReplay) step(t *testing.T, op protocolAction) {
	t.Helper()
	var err error
	switch op.Name {
	case "cacheCaller": // TLS/physical identity covered separately; fixture binds this SQL generation.
	case "admitSubmit", "admitReply":
		a.admit(t, op.Name == "admitReply")
	case "submit", "reply":
		rollback(a.gate)
		a.gate = nil
		select {
		case result := <-a.apiDone:
			err = result.err
			if op.Name == "submit" {
				a.request = result.receipt.RequestID
			}
		case <-time.After(5 * time.Second):
			t.Fatal("platform SQL commit did not finish")
		}
	case "claim":
		id := mailboxFor(t, a.s, a.request, []string{"request", "reply", "status"}[int(op.Args[1].(float64))])
		a.attempt, err = a.s.ClaimDelivery(t.Context(), id, time.Hour)
	case "authorize":
		err = a.s.AuthorizeDispatch(t.Context(), a.attempt.ID, a.attempt.Token)
	case "beginEffect":
		entered := make(chan struct{})
		a.release, a.finished, a.early = make(chan struct{}), make(chan error, 1), nil
		release, finished, attempt := a.release, a.finished, a.attempt
		ctx, cancel := context.WithCancel(t.Context())
		t.Cleanup(cancel)
		a.m.SetHandler(func(ctx context.Context, target string, event harnessstore.Event, tx harnessstore.SQL) ([]byte, error) {
			result, err := recordDelivery(ctx, target, event, tx)
			close(entered)
			if err != nil {
				return nil, err
			}
			select {
			case <-release:
				return result, nil
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		})
		go func() { _, err := a.m.Send(ctx, attempt.Destination, attempt.Envelope); finished <- err }()
		select {
		case <-entered: // Writer transaction remains open across model steps.
		case result := <-finished:
			// A duplicate is a local stutter; SQLite need not call the handler.
			a.early = &result
			err = result
		case <-time.After(5 * time.Second):
			t.Fatal("local transaction did not start")
		}
	case "commitEffect":
		close(a.release)
		if a.early != nil {
			err = *a.early
		} else {
			select {
			case err = <-a.finished:
			case <-time.After(5 * time.Second):
				t.Fatal("local transaction did not commit")
			}
		}
	case "acknowledge":
		err = a.s.AcknowledgeDelivery(t.Context(), a.attempt.ID, a.attempt.Token)
	case "loseRPC":
		a.attempt = DeliveryAttempt{} // No SQL ACK; the durable attempt remains.
	case "expireLease":
		expireLease(t, a.s, mailboxFor(t, a.s, a.request, []string{"request", "reply", "status"}[int(op.Args[0].(float64))]))
	case "requestDelete":
		err = a.s.RequestDeletion(t.Context(), "user-b", "b")
	case "fenceStore":
		err = a.m.Fence(t.Context(), op.Args[0].(string), op.Args[1].(string))
	case "recordFence":
		err = a.s.recordFence(t.Context(), "b", op.Args[0].(string))
	case "commitDelete":
		err = a.s.commitRevocation(t.Context(), "b")
	default:
		t.Fatalf("unsupported protocol action %q", op.Name)
	}
	if err != nil {
		t.Fatalf("%s: %v", op.Name, err)
	}
}

func (a *protocolReplay) compare(t *testing.T, model map[string]any, step int) {
	t.Helper()
	equal := func(label string, got, want any) {
		t.Helper()
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("step %d %s: got %#v, model %#v", step, label, got, want)
		}
	}
	var phase string
	if err := a.s.pool.QueryRow(t.Context(), "SELECT phase FROM agents WHERE id='b'").Scan(&phase); err != nil {
		t.Fatal(err)
	}
	equal("phase", phase, model["phase"])
	state, notified := "ABSENT", false
	if a.request != "" {
		if err := a.s.pool.QueryRow(t.Context(), "SELECT state,sender_notified FROM agent_requests WHERE id=$1", a.request).Scan(&state, &notified); err != nil {
			t.Fatal(err)
		}
	}
	equal("request", state, model["request"])
	equal("notified", notified, model["notified"])
	for _, target := range []string{"a", "b", "c"} {
		equal("budget/"+target, remaining(t, a.s, "mandate-"+target), model["budgets"].(map[string]any)[target])
		var placement string
		var generation int
		if err := a.s.pool.QueryRow(t.Context(), "SELECT state,generation FROM agent_placements WHERE agent_id=$1", target).Scan(&placement, &generation); err != nil {
			t.Fatal(err)
		}
		equal("placement/"+target, placement, model["placement"].(map[string]any)[target])
		equal("generation/"+target, generation, model["boots"].(map[string]any)[target].(map[string]any)["gen"])
	}
	var locked bool
	if a.gate != nil {
		if err := a.s.pool.QueryRow(t.Context(), "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid)))", a.gatePID).Scan(&locked); err != nil {
			t.Fatal(err)
		}
	}
	equal("platform SQL admission held", locked, strings.HasPrefix(model["api"].(string), "AUTH_"))
	acks := []any{}
	rows, err := a.s.pool.Query(t.Context(), "SELECT store_agent_id FROM deletion_targets WHERE agent_id='b' AND acknowledged ORDER BY store_agent_id")
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var target string
		if err := rows.Scan(&target); err != nil {
			t.Fatal(err)
		}
		acks = append(acks, target)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	wantAcks := model["deleteAcks"].([]any)
	sort.Slice(wantAcks, func(i, j int) bool { return wantAcks[i].(string) < wantAcks[j].(string) })
	equal("deleteAcks", acks, wantAcks)
	ids := map[string]string{}
	pending := 0
	for i, kind := range []string{"request", "reply", "status"} {
		key := fmt.Sprint(i)
		event := model["events"].(map[string]any)[key].(map[string]any)
		var id, status string
		var attempts int
		var lease, permitted, closing bool
		err := a.s.pool.QueryRow(t.Context(), `SELECT id,delivery_state,attempts,
            COALESCE(lease_until>clock_timestamp(),false) AND delivery_state='PENDING',dispatch_authorized,closing
            FROM agent_mailboxes WHERE ref_id=$1 AND kind=$2`, a.request, kind).Scan(&id, &status, &attempts, &lease, &permitted, &closing)
		if event["state"] == "ABSENT" {
			if err == nil {
				t.Fatalf("unexpected mailbox %s", kind)
			}
			// Require absence, not an arbitrary database failure.
			var n int
			if err := a.s.pool.QueryRow(t.Context(), "SELECT count(*) FROM agent_mailboxes WHERE ref_id=$1 AND kind=$2", a.request, kind).Scan(&n); err != nil || n != 0 {
				t.Fatalf("absent mailbox: %d %v", n, err)
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		ids[key] = id
		for label, pair := range map[string][2]any{"state": {status, event["state"]}, "attempts": {attempts, event["attempts"]}, "lease": {lease, event["lease"]}, "permitted": {permitted, event["permitted"]}, "closing": {closing, event["closing"]}} {
			equal(kind+"/"+label, pair[0], pair[1])
		}
		if status == "PENDING" {
			pending++
		}
	}
	equal("outbox", count(t, a.s, "outbox"), pending)
	for _, target := range []string{"a", "b", "c"} {
		db, err := sql.Open("sqlite3", filepath.Join(a.root, fmt.Sprintf("%x", sha256.Sum256([]byte(target))), "harness.db"))
		if err != nil {
			t.Fatal(err)
		}
		func() {
			defer db.Close()
			var table int
			if err := db.QueryRowContext(t.Context(), "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='received'").Scan(&table); err != nil {
				t.Fatal(err)
			}
			fences := []any{}
			rows, err := db.QueryContext(t.Context(), "SELECT subject FROM capsule_fences ORDER BY subject")
			if err != nil {
				t.Fatal(err)
			}
			for rows.Next() {
				var subject string
				if err := rows.Scan(&subject); err != nil {
					t.Fatal(err)
				}
				fences = append(fences, subject)
			}
			rows.Close()
			if err := rows.Err(); err != nil {
				t.Fatal(err)
			}
			want := model["fences"].(map[string]any)[target].([]any)
			sort.Slice(want, func(i, j int) bool { return want[i].(string) < want[j].(string) })
			equal("fences/"+target, fences, want)
			for key, id := range ids {
				if (key == "0" && target != "b") || (key != "0" && target != "a") {
					continue
				}
				var effects, seen int
				if table != 0 {
					if err := db.QueryRowContext(t.Context(), "SELECT count(*) FROM received WHERE event_id=?", id).Scan(&effects); err != nil {
						t.Fatal(err)
					}
				}
				if err := db.QueryRowContext(t.Context(), "SELECT count(*) FROM capsule_inbox WHERE event_id=?", id).Scan(&seen); err != nil {
					t.Fatal(err)
				}
				equal("effects/"+key, effects, model["effects"].(map[string]any)[key])
				equal("inbox/"+key, seen != 0, model["seen"].(map[string]any)[key].(int) != -1)
			}
		}()
	}
}

func TestProtocolITFMicrosteps(t *testing.T) {
	dir := "testdata/protocol-itf"
	read := func(name, hash string) []byte {
		t.Helper()
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if hash != "" && fmt.Sprintf("%x", sha256.Sum256(b)) != hash {
			t.Fatalf("changed trace input: %s", name)
		}
		return b
	}
	var manifest struct {
		SourceSHA string `json:"source_sha256"`
		Cases     []struct {
			Name, Trace, Driver, SHA256 string
			DriverSHA                   string `json:"driver_sha256"`
			Actions                     []protocolAction
		}
	}
	if err := json.Unmarshal(read("manifest.json", ""), &manifest); err != nil {
		t.Fatal(err)
	}
	read("protocol_composition.qnt", manifest.SourceSHA)
	if len(manifest.Cases) != 3 {
		t.Fatal("expected three protocol schedules")
	}
	for _, c := range manifest.Cases {
		t.Run(c.Name, func(t *testing.T) {
			read(c.Driver, c.DriverSHA)
			var trace struct{ States []map[string]any }
			if err := json.Unmarshal(read(c.Trace, c.SHA256), &trace); err != nil {
				t.Fatal(err)
			}
			if len(trace.States) != len(c.Actions)+1 {
				t.Fatal("trace/action length mismatch")
			}
			s, _ := freshStore(t, "auto", 1)
			root := t.TempDir()
			m := mockStores(t, root, "a", "b", "c")
			callers := map[string]VMCaller{}
			for _, id := range []string{"a", "b", "c"} {
				callers[id] = confirmedCaller(t, s, id)
			}
			if _, err := s.pool.Exec(t.Context(), `CREATE FUNCTION hold_protocol_admission() RETURNS trigger LANGUAGE plpgsql AS $$
              BEGIN PERFORM pg_advisory_xact_lock(hashtextextended(current_schema()::text,91)); RETURN NEW; END $$;
              CREATE TRIGGER hold_protocol_admission BEFORE INSERT ON idempotency_keys FOR EACH ROW EXECUTE FUNCTION hold_protocol_admission()`); err != nil {
				t.Fatal(err)
			}
			a := protocolReplay{s: s, m: m, root: root, callers: callers}
			for i, raw := range trace.States {
				if i > 0 {
					a.step(t, c.Actions[i-1])
				}
				var state map[string]any
				for key, value := range raw {
					if strings.HasSuffix(key, "::s") {
						state = decodeITF(value).(map[string]any)
					}
				}
				if state == nil {
					t.Fatal("missing model state")
				}
				a.compare(t, state, i)
			}
		})
	}
}
