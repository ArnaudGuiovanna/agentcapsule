package controlplane

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	vmruntime "github.com/ArnaudGuiovanna/agentcapsule/internal/runtime"
)

type messagingAction struct {
	Name, U, R, Mode string
	B                bool
	M, ID            int
}

var messagingFields = []string{"discoverable", "ads", "mode", "deleted", "mandates", "nextMandate", "requests", "nextReq", "acceptIntent", "lastSearch"}

func plainEnums(v any) any {
	switch x := v.(type) {
	case map[string]any:
		if tag, ok := x["tag"]; ok {
			return tag
		}
		m := map[string]any{}
		for key, value := range x {
			m[key] = plainEnums(value)
		}
		return m
	case []any:
		out := make([]any, len(x))
		for i, value := range x {
			out[i] = plainEnums(value)
		}
		return out
	default:
		return v
	}
}

func modelMessaging(raw map[string]any) map[string]any {
	state := map[string]any{}
	for full, value := range raw {
		parts := strings.Split(full, "::")
		state[parts[len(parts)-1]] = plainEnums(decodeITF(value))
	}
	for _, key := range []string{"ads", "acceptIntent"} {
		x := state[key].([]any)
		sort.Slice(x, func(i, j int) bool { return fmt.Sprint(x[i]) < fmt.Sprint(x[j]) })
	}
	search := state["lastSearch"].(map[string]any)
	for _, key := range []string{"results", "visible"} {
		x := search[key].([]any)
		sort.Slice(x, func(i, j int) bool { return fmt.Sprint(x[i]) < fmt.Sprint(x[j]) })
	}
	return state
}

type messagingReplay struct {
	s              *Store
	m              *vmruntime.MockRuntime
	mandates, reqs []string
	ads            map[string]bool // actual asynchronous directory test adapter
	intents        map[int]bool    // adversarial caller's earlier acceptance reads
	wasTerminal    map[string]bool // history observer computed from concrete states
	lastSearch     map[string]any  // client-visible search snapshot
	deadline       time.Time
}

func keysTrue(m map[string]bool) []string {
	keys := []string{}
	for key, value := range m {
		if value {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	return keys
}

func (a *messagingReplay) project(t *testing.T) map[string]any {
	t.Helper()
	discoverable, modes, deleted := map[string]any{}, map[string]any{}, map[string]any{}
	rows, err := a.s.pool.Query(t.Context(), "SELECT id,discoverable,inbound_mode,phase FROM agents")
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var id, mode, phase string
		var visible bool
		if err := rows.Scan(&id, &visible, &mode, &phase); err != nil {
			t.Fatal(err)
		}
		discoverable[id], modes[id], deleted[id] = visible, map[string]string{"manual": "Manual", "auto": "Auto"}[mode], phase == "DELETING" || phase == "DELETED"
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	mandateIDs, requestIDs := map[string]int{}, map[string]int{}
	for i, id := range a.mandates {
		mandateIDs[id] = i
	}
	for i, id := range a.reqs {
		requestIDs[id] = i
	}
	mandates, requests := map[string]any{}, map[string]any{}
	rows, err = a.s.pool.Query(t.Context(), "SELECT id,agent_id,remaining,valid FROM mandates")
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var id, owner string
		var remaining int
		var valid bool
		if err := rows.Scan(&id, &owner, &remaining, &valid); err != nil {
			t.Fatal(err)
		}
		i, found := mandateIDs[id]
		if !found {
			t.Fatalf("unexpected concrete mandate %s", id)
		}
		mandates[fmt.Sprint(i)] = map[string]any{"owner": owner, "remaining": remaining, "valid": valid}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	rows, err = a.s.pool.Query(t.Context(), `SELECT id,sender_agent_id,recipient_agent_id,mandate_id,state,
        via_auto,accepted,delivered,recipient_visible_at_submit,sender_notified FROM agent_requests`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var id, sender, recipient, mandate, state string
		var auto, accepted, delivered, visible, notified bool
		if err := rows.Scan(&id, &sender, &recipient, &mandate, &state, &auto, &accepted, &delivered, &visible, &notified); err != nil {
			t.Fatal(err)
		}
		i, found := requestIDs[id]
		if !found {
			t.Fatalf("unexpected concrete request %s", id)
		}
		md, found := mandateIDs[mandate]
		if !found {
			t.Fatalf("unknown concrete request mandate %s", mandate)
		}
		a.wasTerminal[id] = a.wasTerminal[id] || !active(state)
		state = map[string]string{"PENDING_APPROVAL": "PendingApproval", "DELIVERING": "Delivering", "PROCESSING": "Processing", "REPLIED": "Replied", "DECLINED": "Declined", "CANCELED": "Canceled", "EXPIRED": "Expired", "FAILED": "Failed"}[state]
		requests[fmt.Sprint(i)] = map[string]any{"sender": sender, "recipient": recipient, "mandate": md, "state": state,
			"viaAuto": auto, "accepted": accepted, "delivered": delivered, "recipientVisibleAtSubmit": visible, "wasTerminal": a.wasTerminal[id], "senderNotified": notified}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	intents := []int{}
	for i, pending := range a.intents {
		if pending {
			intents = append(intents, i)
		}
	}
	sort.Ints(intents)
	return map[string]any{"discoverable": discoverable, "mode": modes, "deleted": deleted, "ads": keysTrue(a.ads),
		"mandates": mandates, "nextMandate": len(mandates), "requests": requests, "nextReq": len(requests),
		"acceptIntent": intents, "lastSearch": a.lastSearch}
}

func (a *messagingReplay) deliver(t *testing.T, requestID string, notify bool) error {
	var id string
	err := a.s.pool.QueryRow(t.Context(), `SELECT id FROM agent_mailboxes WHERE ref_id=$1 AND delivery_state='PENDING'
        AND (($2 AND kind IN ('reply','status')) OR (NOT $2 AND kind='request')) ORDER BY seq LIMIT 1`, requestID, notify).Scan(&id)
	if err != nil {
		return err
	}
	attempt, err := a.s.ClaimDelivery(t.Context(), id, time.Minute)
	if err != nil {
		return err
	}
	if err := a.s.AuthorizeDispatch(t.Context(), id, attempt.Token); err != nil {
		return err
	}
	if _, err := a.m.Send(t.Context(), attempt.Destination, attempt.Envelope); err != nil {
		return err
	}
	return a.s.AcknowledgeDelivery(t.Context(), id, attempt.Token)
}

func (a *messagingReplay) step(t *testing.T, op messagingAction) error {
	ctx := t.Context()
	switch op.Name {
	case "setVisibility":
		return a.s.UpdatePreferences(ctx, "user-"+op.U, op.U, &op.B, nil)
	case "setMode":
		mode := strings.ToLower(op.Mode)
		return a.s.UpdatePreferences(ctx, "user-"+op.U, op.U, nil, &mode)
	case "syncAds":
		visible, err := a.s.DirectoryVisibility(ctx, op.U)
		if err == nil {
			a.ads[op.U] = visible
		}
		return err
	case "search":
		results, err := a.s.SearchDirectory(ctx, op.U, keysTrue(a.ads))
		if err != nil {
			return err
		}
		rows, err := a.s.pool.Query(ctx, "SELECT id FROM agents WHERE discoverable AND phase='LIVE' ORDER BY id")
		if err != nil {
			return err
		}
		visible := []string{}
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return err
			}
			visible = append(visible, id)
		}
		rows.Close()
		a.lastSearch = map[string]any{"who": op.U, "results": results, "visible": visible}
		return rows.Err()
	case "instruct":
		id, err := a.s.GrantMandate(ctx, "user-"+op.U, op.U, fmt.Sprintf("owner-instruction-%d", len(a.mandates)), 2, a.deadline)
		if err == nil {
			a.mandates = append(a.mandates, id)
		}
		return err
	case "expireMandate":
		var owner string
		if err := a.s.pool.QueryRow(ctx, "SELECT agent_id FROM mandates WHERE id=$1", a.mandates[op.M]).Scan(&owner); err != nil {
			return err
		}
		return a.s.RevokeMandate(ctx, "user-"+owner, a.mandates[op.M])
	case "submit":
		input := Submission{RecipientAgentID: op.R, MandateID: a.mandates[op.M], PayloadRef: fmt.Sprintf("opaque-transit-%d", len(a.reqs)), PayloadHash: sha256.Sum256([]byte("message")), ExpiresAt: a.deadline}
		r, err := a.s.Submit(ctx, op.U, fmt.Sprintf("request-%d", len(a.reqs)), input)
		if err == nil {
			a.reqs = append(a.reqs, r.RequestID)
		}
		return err
	case "deleteUser":
		if err := a.s.RequestDeletion(ctx, "user-"+op.U, op.U); err != nil {
			return err
		}
		return a.s.ReconcileRevocation(ctx, op.U, a.m)
	}
	id := a.reqs[op.ID]
	var sender, recipient, state string
	if err := a.s.pool.QueryRow(ctx, "SELECT sender_agent_id,recipient_agent_id,state FROM agent_requests WHERE id=$1", id).Scan(&sender, &recipient, &state); err != nil {
		return err
	}
	switch op.Name {
	case "acceptRead":
		if state != "PENDING_APPROVAL" {
			return ErrTransition
		}
		a.intents[op.ID] = true
		return nil
	case "accept", "acceptWrite":
		_, err := a.s.Accept(ctx, "user-"+recipient, id, "accept")
		if err == nil {
			delete(a.intents, op.ID)
		}
		return err
	case "decline":
		_, err := a.s.DeclineRequest(ctx, "user-"+recipient, id, "decline")
		return err
	case "cancel":
		if err := a.s.RequestCancellation(ctx, "user-"+sender, id); err != nil {
			return err
		}
		return a.s.ReconcileRequestClosure(ctx, id, a.m)
	case "expire":
		// The source model has nondeterministic time; make the actual DB deadline
		// due before calling the production expiration path, never bypass its guard.
		if _, err := a.s.pool.Exec(ctx, "UPDATE agent_requests SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1", id); err != nil {
			return err
		}
		if err := a.s.RequestExpiration(ctx, id); err != nil {
			return err
		}
		return a.s.ReconcileRequestClosure(ctx, id, a.m)
	case "deliver":
		return a.deliver(t, id, false)
	case "notifySender":
		return a.deliver(t, id, true)
	case "deliverFail":
		mailbox := mailboxFor(t, a.s, id, "request")
		for range 3 {
			if _, err := a.s.ClaimDelivery(ctx, mailbox, time.Minute); err != nil {
				return err
			}
			expireLease(t, a.s, mailbox)
		}
		return a.s.RetireDelivery(ctx, mailbox, a.m)
	case "reply", "autoDecline":
		input := completedReply()
		if op.Name == "autoDecline" {
			input = Reply{Outcome: "declined"}
		}
		_, err := a.s.ReplyToRequest(ctx, recipient, id, "reply", input)
		return err
	default:
		t.Fatalf("unsupported model action %s", op.Name)
		return nil
	}
}

func messagingDiff(got, want map[string]any) []string {
	fields := []string{}
	for _, key := range messagingFields {
		g, ge := json.Marshal(got[key])
		w, we := json.Marshal(want[key])
		if ge != nil || we != nil {
			panic("projection serialization failed")
		}
		if string(g) != string(w) {
			fields = append(fields, key)
		}
	}
	return fields
}

func TestMessagingITFConformance(t *testing.T) {
	databaseURL(t)
	dir := "testdata/messaging-itf"
	var manifest struct {
		SourceSHA string `json:"source_sha256"`
		Cases     []struct {
			Name, Module, Trace, SHA256, Driver, Certificate string
			DriverSHA                                        string `json:"driver_sha256"`
			Negative                                         bool
			Actions                                          []messagingAction
		}
	}
	read := func(name string) []byte {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	if err := json.Unmarshal(read("manifest.json"), &manifest); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprintf("%x", sha256.Sum256(read("messaging.qnt"))) != manifest.SourceSHA {
		t.Fatal("model hash mismatch")
	}
	if len(manifest.Cases) != 16 {
		t.Fatalf("expected 11 conforming and 5 certified adversarial traces, got %d", len(manifest.Cases))
	}
	for _, c := range manifest.Cases {
		t.Run(c.Name, func(t *testing.T) {
			data := read(c.Trace)
			if fmt.Sprintf("%x", sha256.Sum256(data)) != c.SHA256 {
				t.Fatal("trace hash mismatch")
			}
			if !c.Negative && fmt.Sprintf("%x", sha256.Sum256(read(c.Driver))) != c.DriverSHA {
				t.Fatal("driver hash mismatch")
			}
			var trace struct{ States []map[string]any }
			if err := json.Unmarshal(data, &trace); err != nil || len(trace.States) != len(c.Actions)+1 {
				t.Fatal("invalid trace/action sequence", err)
			}
			if c.Negative {
				var cert struct {
					Passed     bool
					TraceSteps int               `json:"trace_steps"`
					SourceSHA  map[string]string `json:"source_sha256"`
					Shorter    struct {
						Passed bool
						Steps  int
					} `json:"shorter_check"`
				}
				if err := json.Unmarshal(read(c.Certificate), &cert); err != nil {
					t.Fatal(err)
				}
				if !cert.Passed || !cert.Shorter.Passed || cert.TraceSteps != len(c.Actions) || cert.Shorter.Steps != len(c.Actions)-1 {
					t.Fatal("missing minimality certificate")
				}
				for name, digest := range cert.SourceSHA {
					if fmt.Sprintf("%x", sha256.Sum256(read(filepath.Join(filepath.Dir(c.Certificate), "sources", name)))) != digest {
						t.Fatal("certificate source hash mismatch")
					}
				}
			}
			s, _ := freshStore(t, "manual", 3)
			if _, err := s.pool.Exec(t.Context(), "DELETE FROM mandates; DELETE FROM agents"); err != nil {
				t.Fatal(err)
			}
			for _, u := range []string{"arnaud", "marc", "zoe"} {
				if _, err := s.pool.Exec(t.Context(), "INSERT INTO agents(id,owner_user_id) VALUES ($1,$2)", u, "user-"+u); err != nil {
					t.Fatal(err)
				}
			}
			m := mockStores(t, t.TempDir(), "arnaud", "marc", "zoe")
			m.SetHandler(recordDelivery)
			a := messagingReplay{s: s, m: m, ads: map[string]bool{}, intents: map[int]bool{}, wasTerminal: map[string]bool{},
				lastSearch: map[string]any{"who": "", "results": []string{}, "visible": []string{}}, deadline: time.Now().Add(time.Hour).UTC().Truncate(time.Microsecond)}
			for i, raw := range trace.States {
				if i > 0 {
					err := a.step(t, c.Actions[i-1])
					blocked := (c.Module == "messagingSendChecksAds" && errors.Is(err, ErrNotFound)) ||
						(c.Module == "messagingNoMandateOwner" && errors.Is(err, ErrMandate)) ||
						(c.Module == "messagingRacyAccept" && c.Actions[i-1].Name == "acceptWrite" && (errors.Is(err, ErrTransition) || errors.Is(err, ErrUnavailable)))
					if c.Negative && blocked {
						t.Logf("certified unsafe transition blocked at state %d: %v", i, err)
						return
					}
					if err != nil {
						t.Fatalf("state %d action %s: %v", i, c.Actions[i-1].Name, err)
					}
				}
				got, want := a.project(t), modelMessaging(raw)
				fields := messagingDiff(got, want)
				if len(fields) > 0 {
					if c.Negative && c.Module == "messagingNoPostcheck" && len(fields) == 1 && fields[0] == "lastSearch" {
						t.Logf("certified stale-directory leak prevented at state %d", i)
						return
					}
					g, _ := json.Marshal(got)
					w, _ := json.Marshal(want)
					t.Fatalf("state %d differs in %v\ngot=%s\nwant=%s", i, fields, g, w)
				}
			}
			if c.Negative {
				t.Fatal("implementation reproduced the broken-model trace")
			}
			t.Logf("matched all %d messaging ITF states", len(trace.States))
		})
	}
}
