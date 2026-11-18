//go:build linux && cgo

package authorityclient

import (
	"bytes"
	"testing"
	"time"

	svc "github.com/ArnaudGuiovanna/agentcapsule/internal/authorityservice"
)

// A receipt key's answer is the last thing the service does for its
// request: the client's next request on the same connection is the next
// request, never one that breaks the protocol and ends the connection. The
// service used to write the key from the operation, before the request
// ended: a next request that arrived first closed the connection, and the
// client saw an outage (EOF). It showed once, under load, in
// TestServiceTendsTheDailyReceiptKeys; here the end of the operation is
// delayed, so that the next request always arrives first.
func TestReceiptKeysBackToBack(t *testing.T) {
	keys, catalog := authorities(t, t.TempDir())
	k := &dayClock{t: date(16, 10, 0)}
	delay := func(c *svc.Config) {
		c.AfterOperation = func(op string) {
			if op == svc.OpReceiptKey {
				time.Sleep(100 * time.Millisecond)
			}
		}
	}
	l := serve(t, keys, catalog, receiptDays(k, &lockedBuffer{}), delay)
	api := l.apiClient(t)
	ctx := t.Context()
	first, err := api.ReceiptKey(ctx, date(16, 0, 0))
	if err != nil {
		t.Fatal(err)
	}
	for i := range 5 {
		if _, err = api.Status(ctx); err != nil {
			t.Fatal("the request after a receipt key", i, err)
		}
		key, err := api.ReceiptKey(ctx, date(16, 0, 0))
		if err != nil || !bytes.Equal(key, first) {
			t.Fatal("receipt key", i, err)
		}
	}
}
