package api

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
)

// The daily receipt keys (docs/adr/006-authority-service.md §7, wave 6), as
// a client sees them. A replay whose day's key is gone, after a failover
// that lost a key the primary created alone, answers 409
// idempotency_receipt_unreadable, and the request does not run again. A new
// request whose day's key the authority service does not give answers 503
// authority_unavailable before it runs.
func TestHTTPReceiptsOfTheDailyKeys(t *testing.T) {
	server, store, admin, _ := apiLab(t)
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	daily := func(_ context.Context, _ time.Time) ([]byte, error) { return bytes.Clone(key), nil }
	if err := server.accounts.UseDailyReceiptKeys(daily); err != nil {
		t.Fatal(err)
	}
	created := call(t, server, "POST", "/v1/users", admin, "create", `{"display_name":"Ada"}`)
	if created.Code != 201 {
		t.Fatal(created.Code, created.Body.String())
	}
	replay := call(t, server, "POST", "/v1/users", admin, "create", `{"display_name":"Ada"}`)
	if replay.Code != 201 || replay.Body.String() != created.Body.String() || replay.Header().Get("Idempotency-Replayed") != "true" {
		t.Fatal("the replay of a daily receipt", replay.Code, replay.Body.String())
	}
	other := func(source controlplane.ReceiptKeySource) *Server {
		t.Helper()
		a, err := controlplane.NewAccounts(store, bytes.Repeat([]byte{0x36}, 32))
		if err != nil {
			t.Fatal(err)
		}
		if err = a.UseDailyReceiptKeys(source); err != nil {
			t.Fatal(err)
		}
		s, err := NewForHost(store, a, "local")
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	gone := other(func(context.Context, time.Time) ([]byte, error) {
		return nil, errors.Join(controlplane.ErrReceiptKeyGone, errors.New("key_revoked"))
	})
	r := call(t, gone, "POST", "/v1/users", admin, "create", `{"display_name":"Ada"}`)
	if r.Code != 409 || !strings.Contains(r.Body.String(), `"code":"idempotency_receipt_unreadable"`) {
		t.Fatal("the replay of a receipt whose key is gone", r.Code, r.Body.String())
	}
	down := other(func(context.Context, time.Time) ([]byte, error) { return nil, errors.New("no answer") })
	r = call(t, down, "POST", "/v1/users", admin, "new", `{"display_name":"Grace"}`)
	if r.Code != 503 || !strings.Contains(r.Body.String(), `"code":"authority_unavailable"`) || r.Header().Get("Retry-After") == "" {
		t.Fatal("a new request without its day's key", r.Code, r.Body.String())
	}
	listed := call(t, server, "GET", "/v1/users", admin, "", "")
	var page struct {
		Items []controlplane.User `json:"items"`
	}
	if listed.Code != 200 || json.Unmarshal(listed.Body.Bytes(), &page) != nil || len(page.Items) != 1 {
		t.Fatal("a refused request ran", listed.Code, listed.Body.String())
	}
}
