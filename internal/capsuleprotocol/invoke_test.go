package capsuleprotocol

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnessstore"
)

func invocation(t *testing.T) harnessstore.Event {
	t.Helper()
	body, err := json.Marshal(Invocation{Kind: "message.user", OperationID: "op_one", Mandate: InstructionMandate{ID: "mdt_one", MaxAgentRequests: 3, ExpiresAt: time.Now().Add(time.Hour)}, Content: []TextContent{{Type: "text", Text: "hello"}}})
	if err != nil {
		t.Fatal(err)
	}
	return harnessstore.Event{ID: "instruction", Subjects: []string{"agent/a", "event/instruction"}, Body: body}
}
func TestInvocationRouteAuthorityLostACKAndFence(t *testing.T) {
	h, g := credentialPair(t, "a", "0123456789abcdef")
	var drop atomic.Bool
	drop.Store(true)
	c, _ := serverFixture(t, h, g, func(w http.ResponseWriter) {
		if drop.Swap(false) {
			conn, _, err := w.(http.Hijacker).Hijack()
			if err == nil {
				conn.Close()
			}
		}
	})
	e := invocation(t)
	if _, err := c.Send(t.Context(), e); !errors.Is(err, ErrProtocol) {
		t.Fatal("instruction accepted as generic event", err)
	}
	if _, err := c.call(t.Context(), "/v1/invoke", &request{Event: func() *harnessstore.Event { e := event("generic"); return &e }()}); !errors.Is(err, ErrProtocol) {
		t.Fatal("generic event gained invocation authority", err)
	}
	bad := e
	bad.Subjects = []string{"agent/a", "event/other"}
	if _, err := c.call(t.Context(), "/v1/invoke", &request{Event: &bad}); !errors.Is(err, ErrProtocol) {
		t.Fatal("misbound invocation", err)
	}
	if _, err := c.Invoke(t.Context(), e); !errors.Is(err, ErrTransport) {
		t.Fatal("lost ACK succeeded", err)
	}
	r, err := c.Invoke(t.Context(), e)
	if err != nil || !r.Replayed || string(r.Result) != "1" {
		t.Fatal("invoke repeated effect", r, err)
	}
	if err = c.Fence(t.Context(), "event/"+e.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = c.Invoke(t.Context(), e); !errors.Is(err, harnessstore.ErrFenced) {
		t.Fatal("fenced invocation", err)
	}
	h, g, err = NewCredentials(Identity{Incarnation: 1, AgentID: "a", Generation: 2, VMID: "0123456789abcdee", FenceOnly: true}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	c, _ = serverFixture(t, h, g, nil)
	if _, err = c.Invoke(t.Context(), e); !errors.Is(err, ErrFenceOnly) {
		t.Fatal("restricted boot executed instruction", err)
	}
}

func TestInvocationInvalidResultRollsBackLocalEffect(t *testing.T) {
	_, g := credentialPair(t, "a", "0123456789abcdef")
	store, err := harnessstore.Open(t.Context(), filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	invalid := true
	s, err := NewServer(g, ShutdownClean, store, func(ctx context.Context, e harnessstore.Event, tx harnessstore.SQL) ([]byte, error) {
		if _, err := tx.ExecContext(ctx, "CREATE TABLE IF NOT EXISTS effects(id TEXT PRIMARY KEY)"); err != nil {
			return nil, err
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO effects VALUES(?)", e.ID); err != nil {
			return nil, err
		}
		if invalid {
			return []byte("invalid json"), nil
		}
		return []byte(`{"ok":true}`), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	e := invocation(t)
	body, err := json.Marshal(request{Protocol: Version, Identity: g.Identity, Event: &e})
	if err != nil {
		t.Fatal(err)
	}
	call := func() *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "/v1/invoke", strings.NewReader(string(body)))
		// Authentication fixture for the SQL rollback boundary; real mTLS above.
		r.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{{}}}}
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		return w
	}
	if w := call(); w.Code == 200 {
		t.Fatal("invalid result committed")
	}
	invalid = false
	w := call()
	var result response
	if err = json.Unmarshal(w.Body.Bytes(), &result); err != nil || w.Code != 200 || result.Receipt == nil || result.Receipt.Replayed {
		t.Fatal("failed transaction retained effect/dedup", w.Code, err)
	}
}
