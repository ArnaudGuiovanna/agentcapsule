//go:build linux && cgo

package restoreauthority

import (
	"strings"
	"testing"
	"unsafe"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/keymem"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/keymem/keymemtest"
)

// FIX-1 (L-18 continued): the authority service sends a receipt key from
// the copy Local.ReceiptKey gives it. That copy lies in a page of its own,
// outside the Go heap, locked in RAM (lo) and left out of core dumps (dd);
// keymem.Release clears and unlocks it.
func TestAReceiptKeyCopyLivesInLockedMemory(t *testing.T) {
	keys, catalog := primary(t, t.TempDir())
	local := Local{Catalog: catalog, Keys: keys}
	if err := local.EnsureReceiptKey(t.Context(), receiptDay); err != nil {
		t.Fatal(err)
	}
	before := keymem.InUse()
	key, err := local.ReceiptKey(t.Context(), receiptDay)
	if err != nil || len(key) != 32 || keymemtest.Zero(key) {
		t.Fatal("the receipt key", err)
	}
	if !keymemtest.Locked(t, key) {
		t.Fatalf("the receipt key's mapping has flags %q: not locked, or dumped", keymemtest.Flags(t, key))
	}
	addr := uintptr(unsafe.Pointer(&key[0]))
	keymem.Release(key)
	if strings.Contains(keymemtest.FlagsAt(t, addr), " lo ") || !keymemtest.Zero(key) || keymem.InUse() != before {
		t.Fatal("the released page is still locked, holds the key, or is still counted")
	}
}
