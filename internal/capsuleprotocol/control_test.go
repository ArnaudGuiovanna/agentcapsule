package capsuleprotocol

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnessstore"
)

func credentialPair(t *testing.T, agent, vm string) (Credentials, Credentials) {
	t.Helper()
	h, g, err := NewCredentials(Identity{Incarnation: 1, AgentID: agent, Generation: 1, VMID: vm}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return h, g
}
func serverFixture(t *testing.T, host, guest Credentials, hook func(http.ResponseWriter)) (*Client, func(context.Context) (net.Conn, error)) {
	t.Helper()
	root := t.TempDir()
	store, err := harnessstore.Open(t.Context(), filepath.Join(root, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewServer(guest, ShutdownClean, store, func(ctx context.Context, e harnessstore.Event, tx harnessstore.SQL) ([]byte, error) {
		if bytes.Equal(e.Body, []byte("fail")) {
			return nil, errors.New("private SQL payload/password must never cross the wire")
		}
		if _, err := tx.ExecContext(ctx, "CREATE TABLE IF NOT EXISTS effects (n INTEGER PRIMARY KEY AUTOINCREMENT)"); err != nil {
			return nil, err
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO effects DEFAULT VALUES"); err != nil {
			return nil, err
		}
		var n int
		if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM effects").Scan(&n); err != nil {
			return nil, err
		}
		return json.Marshal(n)
	})
	if err != nil {
		t.Fatal(err)
	}
	server.afterCommit = hook
	// TCP is confined to loopback for portable unit tests; KVM tests use actual vsock.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx, l) }()
	t.Cleanup(func() { cancel(); <-done; store.Close() })
	dial := func(ctx context.Context) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", l.Addr().String())
	}
	c, err := NewClient(host, dial)
	if err != nil {
		t.Fatal(err)
	}
	return c, dial
}
func event(id string) harnessstore.Event {
	return harnessstore.Event{ID: id, Subjects: []string{"agent/a", "request/r", "event/" + id}, Body: []byte("body")}
}

func TestAuthenticatedControlLostACKAndDurableFence(t *testing.T) {
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
	if err := c.Health(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Send(t.Context(), event("one")); !errors.Is(err, ErrTransport) {
		t.Fatalf("lost ACK returned success: %v", err)
	}
	r, err := c.Send(t.Context(), event("one"))
	if err != nil || !r.Replayed || string(r.Result) != "1" {
		t.Fatalf("replay: %+v %v", r, err)
	}
	r, err = c.Send(t.Context(), event("two"))
	if err != nil || r.Replayed || string(r.Result) != "2" {
		t.Fatalf("effect repeated after lost ACK: %+v %v", r, err)
	}
	changed := event("two")
	changed.Body = []byte("different")
	if _, err = c.Send(t.Context(), changed); !errors.Is(err, harnessstore.ErrConflict) {
		t.Fatal(err)
	}
	if err = c.Fence(t.Context(), "request/r"); err != nil {
		t.Fatal(err)
	}
	if _, err = c.Send(t.Context(), event("two")); !errors.Is(err, harnessstore.ErrFenced) {
		t.Fatalf("fenced replay accepted: %v", err)
	}
	if _, err = c.Send(t.Context(), event("three")); !errors.Is(err, harnessstore.ErrFenced) {
		t.Fatalf("fenced new effect accepted: %v", err)
	}
}

func TestControlRejectsWrongAgentGenerationAndCertificateRole(t *testing.T) {
	h, g := credentialPair(t, "a", "0123456789abcdef")
	good, dial := serverFixture(t, h, g, nil)
	if err := good.Health(t.Context()); err != nil {
		t.Fatal(err)
	}
	foreign, _ := credentialPair(t, "b", "fedcba9876543210")
	for name, credentials := range map[string]Credentials{"other_agent": foreign, "guest_key_as_client": g} {
		t.Run(name, func(t *testing.T) {
			bad, err := NewClient(credentials, dial)
			if err != nil {
				t.Fatal(err)
			}
			if err = bad.Health(t.Context()); err == nil {
				t.Fatal("foreign/guest client authenticated")
			}
		})
	}
	t.Run("missing_client_certificate", func(t *testing.T) {
		cfg, err := h.TLS(false)
		if err != nil {
			t.Fatal(err)
		}
		cfg.Certificates = nil
		conn, err := dial(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(2 * time.Second))
		c := tls.Client(conn, cfg)
		if err = c.HandshakeContext(t.Context()); err == nil {
			// TLS 1.3 rejection may be observed when reading the first application response.
			_, err = io.WriteString(c, "GET /v1/health HTTP/1.1\r\nHost: test\r\n\r\n")
			if err == nil {
				var b [1]byte
				_, err = c.Read(b[:])
			}
		}
		if err == nil {
			t.Fatal("unauthenticated connection accepted")
		}
	})
	for _, alter := range []func(*Identity){func(i *Identity) { i.AgentID = "b" }, func(i *Identity) { i.Generation++ }, func(i *Identity) { i.VMID = "1111111111111111" }} {
		bad, err := NewClient(h, dial)
		if err != nil {
			t.Fatal(err)
		}
		alter(&bad.identity)
		_, err = bad.call(t.Context(), "/v1/events", &request{Event: func() *harnessstore.Event { e := event("forged"); return &e }()})
		if !errors.Is(err, ErrIdentity) {
			t.Fatalf("forged channel identity accepted: %v", err)
		}
	}
}

func TestControlBoundsAndErrorRedaction(t *testing.T) {
	h, g := credentialPair(t, "a", "0123456789abcdef")
	c, _ := serverFixture(t, h, g, nil)
	sendRaw := func(body string) (int, string) {
		r, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://"+h.Identity.serverName()+"/v1/events", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		resp, err := c.http.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		return resp.StatusCode, string(b)
	}
	in := request{Protocol: Version, Identity: h.Identity}
	e := event("bad")
	in.Event = &e
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{string(b) + " {}", strings.TrimSuffix(string(b), "}") + `,"sender_agent_id":"other"}`, `{"padding":"` + strings.Repeat("x", MaxMessageBytes) + `"}`} {
		if status, _ := sendRaw(bad); status != http.StatusBadRequest {
			t.Fatalf("invalid JSON accepted: %d", status)
		}
	}
	e.Subjects = []string{"agent/b"}
	b, _ = json.Marshal(in)
	if status, _ := sendRaw(string(b)); status != http.StatusBadRequest {
		t.Fatalf("omitted target fence: %d", status)
	}
	e = event("fail")
	e.Body = []byte("fail")
	b, _ = json.Marshal(in)
	status, body := sendRaw(string(b))
	if status != http.StatusServiceUnavailable || strings.Contains(body, "private") || strings.Contains(body, "SQL") || strings.Contains(body, "password") {
		t.Fatalf("unexpected error body: %s", body)
	}
	r, err := c.Send(t.Context(), event("ok"))
	if err != nil || string(r.Result) != "1" {
		t.Fatalf("failed operation left an effect: %+v %v", r, err)
	}
}

func TestControlFenceOnlyBootAndLostFenceACK(t *testing.T) {
	h, g, err := NewCredentials(Identity{Incarnation: 1, AgentID: "a", Generation: 2, VMID: "0123456789abcdef", FenceOnly: true}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
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
	if err = c.Health(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err = c.Send(t.Context(), event("forbidden")); !errors.Is(err, ErrFenceOnly) {
		t.Fatalf("barrier-only guest executed work: %v", err)
	}
	if err = c.Fence(t.Context(), "request/r"); !errors.Is(err, ErrTransport) {
		t.Fatalf("fence ACK not dropped: %v", err)
	}
	if err = c.Fence(t.Context(), "request/r"); err != nil {
		t.Fatal(err)
	}
	c.identity.FenceOnly = false
	if _, err = c.Send(t.Context(), event("forged-mode")); !errors.Is(err, ErrIdentity) {
		t.Fatalf("mode upgrade accepted: %v", err)
	}
}
