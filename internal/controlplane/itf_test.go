package controlplane

import (
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	vmruntime "github.com/ArnaudGuiovanna/agentcapsule/internal/runtime"
)

type traceEvent struct {
	Key, Body, State string
	Attempts         int
}
type traceIdem struct {
	State, Body string
	Seq         int
}
type deliveryProjection struct {
	Events       map[int]traceEvent
	Idem         map[string]traceIdem
	NextSeq      int
	Responses    map[string][]int
	PendingWrite map[string]int
	Seen         []int
	Effects      map[int]int
	Log          []int
}

func emptyProjection() deliveryProjection {
	return deliveryProjection{Events: map[int]traceEvent{}, Idem: map[string]traceIdem{
		"k1": {State: "Absent", Seq: -1}, "k2": {State: "Absent", Seq: -1}},
		Responses: map[string][]int{"k1": {}, "k2": {}}, PendingWrite: map[string]int{"k1": -1, "k2": -1},
		Seen: []int{}, Effects: map[int]int{}, Log: []int{}}
}

// Decode only the documented ITF forms used by this model. Malformed/unknown
// values fail the test; a broken adapter must never count as rejecting a mutant.
func decodeITF(v any) any {
	switch x := v.(type) {
	case []any:
		out := make([]any, len(x))
		for i, item := range x {
			out[i] = decodeITF(item)
		}
		return out
	case map[string]any:
		if n, ok := x["#bigint"]; ok {
			value, err := strconv.Atoi(n.(string))
			if err != nil {
				panic(err)
			}
			return value
		}
		if entries, ok := x["#map"]; ok {
			out := map[string]any{}
			for _, pair := range entries.([]any) {
				p := pair.([]any)
				out[fmt.Sprint(decodeITF(p[0]))] = decodeITF(p[1])
			}
			return out
		}
		if values, ok := x["#set"]; ok {
			return decodeITF(values)
		}
		out := map[string]any{}
		for key, value := range x {
			out[key] = decodeITF(value)
		}
		return out
	default:
		return v
	}
}

func ints(v any) []int {
	result := []int{}
	for _, n := range v.([]any) {
		result = append(result, n.(int))
	}
	return result
}

func modelProjection(state map[string]any) deliveryProjection {
	values := map[string]any{}
	for name, value := range state {
		parts := strings.Split(name, "::")
		values[parts[len(parts)-1]] = value
	}
	p := emptyProjection()
	p.NextSeq = values["nextSeq"].(int)
	for seq, entry := range values["events"].(map[string]any) {
		e := entry.(map[string]any)
		n, err := strconv.Atoi(seq)
		if err != nil {
			panic(err)
		}
		p.Events[n] = traceEvent{e["key"].(string), e["body"].(string), e["state"].(map[string]any)["tag"].(string), e["attempts"].(int)}
	}
	for key, entry := range values["idem"].(map[string]any) {
		i := entry.(map[string]any)
		p.Idem[key] = traceIdem{i["state"].(map[string]any)["tag"].(string), i["body"].(string), i["seq"].(int)}
	}
	for key, entry := range values["responses"].(map[string]any) {
		p.Responses[key] = ints(entry)
		sort.Ints(p.Responses[key])
	}
	for key, entry := range values["pendingWrite"].(map[string]any) {
		p.PendingWrite[key] = entry.(int)
	}
	p.Seen, p.Log = ints(values["seen"]), ints(values["log"])
	sort.Ints(p.Seen)
	for key, count := range values["effects"].(map[string]any) {
		n, err := strconv.Atoi(key)
		if err != nil {
			panic(err)
		}
		p.Effects[n] = count.(int)
	}
	return p
}

type deliveryReplay struct {
	s         *Store
	m         *vmruntime.MockRuntime
	root      string
	deadline  time.Time
	responses map[string][]int // client observer: only responses actually received
}

func (a *deliveryReplay) project(t *testing.T) deliveryProjection {
	t.Helper()
	p := emptyProjection()
	p.Responses = a.responses
	if err := a.s.pool.QueryRow(t.Context(), "SELECT next_seq FROM agents WHERE id='b'").Scan(&p.NextSeq); err != nil {
		t.Fatal(err)
	}
	rows, err := a.s.pool.Query(t.Context(), `SELECT m.id,m.seq,r.payload_ref,m.delivery_state,m.attempts,i.key
        FROM agent_mailboxes m JOIN agent_requests r ON r.id=m.ref_id
        JOIN idempotency_keys i ON i.response_ref=r.id AND i.operation='submit' AND i.actor='agent/a'
        WHERE m.dest_agent_id='b' AND m.kind='request' ORDER BY m.seq`)
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]int{}
	for rows.Next() {
		var id, body, state, key string
		var seq, attempts int
		if err := rows.Scan(&id, &seq, &body, &state, &attempts, &key); err != nil {
			t.Fatal(err)
		}
		seq-- // PostgreSQL sequences start at 1; the model starts at 0.
		ids[id] = seq
		state = map[string]string{"PENDING": "Pending", "DELIVERED": "Delivered", "DEAD": "Dead", "CANCELED": "Canceled"}[state]
		p.Events[seq] = traceEvent{key, body, state, attempts}
		p.Idem[key] = traceIdem{State: "Done", Body: body, Seq: seq}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite3", filepath.Join(a.root, fmt.Sprintf("%x", sha256.Sum256([]byte("b"))), "harness.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	seen, err := db.QueryContext(t.Context(), "SELECT event_id FROM capsule_inbox")
	if err != nil {
		t.Fatal(err)
	}
	for seen.Next() {
		var id string
		if err := seen.Scan(&id); err != nil {
			t.Fatal(err)
		}
		seq, exists := ids[id]
		if !exists {
			t.Fatalf("unknown harness inbox event %s", id)
		}
		p.Seen = append(p.Seen, seq)
	}
	seen.Close()
	if err := seen.Err(); err != nil {
		t.Fatal(err)
	}
	sort.Ints(p.Seen)
	for _, id := range received(t, a.root, "b") {
		seq, exists := ids[id]
		if !exists {
			t.Fatalf("unknown effect %s", id)
		}
		if p.Effects[seq] == 0 {
			p.Log = append(p.Log, seq)
		}
		p.Effects[seq]++
	}
	return p
}

func pick(state map[string]any, name string) any {
	value := state["mbt::nondetPicks"].(map[string]any)[name].(map[string]any)
	if value["tag"] != "Some" {
		panic("missing nondeterministic pick: " + name)
	}
	return value["value"]
}

func (a *deliveryReplay) step(t *testing.T, state map[string]any) error {
	t.Helper()
	action := state["mbt::actionTaken"].(string)
	switch action {
	case "apiNewAtomic", "apiNewStep1", "apiReplay":
		key, body := pick(state, "k").(string), pick(state, "b").(string)
		input := submission()
		input.PayloadRef, input.PayloadHash, input.ExpiresAt = body, sha256.Sum256([]byte(body)), a.deadline
		r, err := a.s.Submit(t.Context(), "a", key, input)
		if err != nil {
			return err
		}
		if _, err := a.s.pool.Exec(t.Context(), "UPDATE agent_mailboxes SET attempt_limit=2 WHERE ref_id=$1 AND attempts=0", r.RequestID); err != nil {
			return err
		}
		lost := action == "apiNewStep1" || (action == "apiNewAtomic" && pick(state, "lost").(bool))
		if !lost {
			var seq int
			if err := a.s.pool.QueryRow(t.Context(), "SELECT seq FROM agent_mailboxes WHERE ref_id=$1 AND kind='request'", r.RequestID).Scan(&seq); err != nil {
				return err
			}
			seq--
			found := false
			for _, n := range a.responses[key] {
				found = found || n == seq
			}
			if !found {
				a.responses[key] = append(a.responses[key], seq)
				sort.Ints(a.responses[key])
			}
		}
		return nil
	case "deliver":
		seq := pick(state, "s").(int)
		outcome := pick(state, "o").(map[string]any)["tag"].(string)
		var id string
		if err := a.s.pool.QueryRow(t.Context(), "SELECT id FROM agent_mailboxes WHERE dest_agent_id='b' AND seq=$1", seq+1).Scan(&id); err != nil {
			return err
		}
		attempt, err := a.s.ClaimDelivery(t.Context(), id, time.Minute)
		if err != nil {
			return err
		}
		if outcome == "Ok" || outcome == "LostAck" {
			if err := a.s.AuthorizeDispatch(t.Context(), id, attempt.Token); err != nil {
				return err
			}
			if _, err := a.m.Send(t.Context(), "b", attempt.Envelope); err != nil {
				return err
			}
		} else if outcome != "Fail" {
			t.Fatalf("unknown delivery outcome %s", outcome)
		}
		if outcome == "Ok" {
			return a.s.AcknowledgeDelivery(t.Context(), id, attempt.Token)
		}
		expireLease(t, a.s, id)
		var attempts int
		if err := a.s.pool.QueryRow(t.Context(), "SELECT attempts FROM agent_mailboxes WHERE id=$1", id).Scan(&attempts); err != nil {
			return err
		}
		if attempts == 2 {
			return a.s.RetireDelivery(t.Context(), id, a.m)
		}
		return nil
	default:
		t.Fatalf("unsupported ITF action %q; adapter failure is not a negative result", action)
		return nil
	}
}

func differingFields(a, b deliveryProjection) []string {
	var fields []string
	x, y := reflect.ValueOf(a), reflect.ValueOf(b)
	for i := range x.NumField() {
		if !reflect.DeepEqual(x.Field(i).Interface(), y.Field(i).Interface()) {
			fields = append(fields, x.Type().Field(i).Name)
		}
	}
	return fields
}

func TestDeliveryITFConformance(t *testing.T) {
	// Force a real database even before reading fixtures. Missing integration
	// configuration is reported consistently with the rest of the package.
	databaseURL(t)
	dir := "testdata/delivery-itf"
	var manifest struct {
		SourceSHA string `json:"source_sha256"`
		Cases     []struct {
			Name, Module, Trace, SHA256 string
			Negative                    bool
		}
	}
	data, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	source, err := os.ReadFile(filepath.Join(dir, "delivery.qnt"))
	if err != nil || fmt.Sprintf("%x", sha256.Sum256(source)) != manifest.SourceSHA {
		t.Fatal("ITF model source hash mismatch", err)
	}
	if len(manifest.Cases) != 12 {
		t.Fatalf("expected eight conforming and four adversarial traces, got %d", len(manifest.Cases))
	}
	for _, c := range manifest.Cases {
		t.Run(c.Name, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(dir, c.Trace))
			if err != nil || fmt.Sprintf("%x", sha256.Sum256(data)) != c.SHA256 {
				t.Fatal("ITF trace hash mismatch", err)
			}
			var trace struct{ States []map[string]any }
			if err := json.Unmarshal(data, &trace); err != nil || len(trace.States) < 2 {
				t.Fatal("invalid ITF trace", err)
			}
			s, _ := freshStore(t, "auto", 3)
			root := t.TempDir()
			m := mockStores(t, root, "a", "b", "c")
			m.SetHandler(recordDelivery)
			db, err := sql.Open("sqlite3", filepath.Join(root, fmt.Sprintf("%x", sha256.Sum256([]byte("b"))), "harness.db"))
			if err != nil {
				t.Fatal(err)
			}
			_, err = db.ExecContext(t.Context(), "CREATE TABLE received (position INTEGER PRIMARY KEY,event_id TEXT NOT NULL,seq INTEGER NOT NULL)")
			db.Close()
			if err != nil {
				t.Fatal(err)
			}
			a := deliveryReplay{s, m, root, time.Now().Add(time.Hour).UTC().Truncate(time.Microsecond), emptyProjection().Responses}
			for i, raw := range trace.States {
				state := decodeITF(raw).(map[string]any)
				want := modelProjection(state)
				if i > 0 {
					err := a.step(t, state)
					if c.Module == "deliveryNoFifo" && errors.Is(err, ErrNotHead) {
						t.Logf("unsafe transition blocked at ITF state %d: FIFO head guard", i)
						return
					}
					if err != nil {
						t.Fatalf("ITF state %d operation failed: %v", i, err)
					}
				}
				got := a.project(t)
				fields := differingFields(got, want)
				if len(fields) != 0 {
					allowed := map[string][]string{"deliveryNoDedup": {"Effects"}, "deliveryNoDeadLetter": {"Events"}, "deliveryNonAtomicIdem": {"Idem", "PendingWrite"}}[c.Module]
					if c.Negative && reflect.DeepEqual(fields, allowed) {
						t.Logf("unsafe state %d prevented: differs in %v", i, fields)
						return
					}
					t.Fatalf("ITF state %d mismatch %v\ngot=%+v\nwant=%+v", i, fields, got, want)
				}
			}
			if c.Negative {
				t.Fatal("implementation reproduced the entire broken-model trace")
			}
			t.Logf("matched all %d ITF states against PostgreSQL and SQLite", len(trace.States))
		})
	}
}

// Keep the interface assertion close to the trace adapter: this is the same
// MockRuntime used by the worker, not an independent in-memory implementation.
var _ DeliveryRuntime = (*vmruntime.MockRuntime)(nil)
