//go:build linux && cgo

package authorityclient

import (
	"context"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/keymem"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/keymem/keymemtest"
)

// released waits until every key buffer handed out since before is
// released, in the service and in its clients, which share this process.
func released(t *testing.T, before int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for keymem.InUse() != before {
		if time.Now().After(deadline) {
			t.Fatal("key buffers not released", keymem.InUse(), before)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// FIX-1 (L-18 continued): the volume key a hold gives the worker lies in a
// page of its own, outside the Go heap, locked in RAM (lo) and left out of
// core dumps (dd); once the hold returned, the page is cleared and
// unlocked, and the service released its own buffer.
func TestAHeldKeyLivesInLockedMemoryOnTheClientSide(t *testing.T) {
	keys, catalog := authorities(t, t.TempDir())
	l := serve(t, keys, catalog)
	c := l.client(t)
	ctx := t.Context()
	b, err := c.Register(ctx, agent, volume)
	if err != nil {
		t.Fatal(err)
	}
	if err = c.Ensure(ctx, agent, volume); err != nil {
		t.Fatal(err)
	}
	before := keymem.InUse()
	var page []byte // a test-only reference, to observe the release
	var addr uintptr
	if err = c.HoldKey(ctx, b, func(_ context.Context, key []byte) error {
		page, addr = key, uintptr(unsafe.Pointer(&key[0]))
		if keymemtest.Zero(key) || !keymemtest.Locked(t, key) {
			t.Errorf("the held key's mapping has flags %q: not locked, or dumped", keymemtest.Flags(t, key))
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(keymemtest.FlagsAt(t, addr), " lo ") || !keymemtest.Zero(page) {
		t.Fatal("the released page is still locked, or holds the key")
	}
	released(t, before)
}

// The API's receipt key comes in a locked page too, which its caller
// releases (keymem.Release); the service released the copy it sent.
func TestAReceiptKeyLivesInLockedMemoryOnTheClientSide(t *testing.T) {
	keys, catalog := authorities(t, t.TempDir())
	l := serve(t, keys, catalog)
	api := l.apiClient(t)
	before := keymem.InUse()
	key, err := api.ReceiptKey(t.Context(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(key) != 32 || keymemtest.Zero(key) || !keymemtest.Locked(t, key) {
		t.Fatalf("the receipt key's mapping has flags %q: not locked, or dumped", keymemtest.Flags(t, key))
	}
	addr := uintptr(unsafe.Pointer(&key[0]))
	keymem.Release(key)
	if strings.Contains(keymemtest.FlagsAt(t, addr), " lo ") || !keymemtest.Zero(key) {
		t.Fatal("the released page is still locked, or holds the key")
	}
	released(t, before)
}
