//go:build linux

package keymem_test

import (
	"errors"
	"os"
	"strings"
	"testing"
	"unsafe"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/keymem"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/keymem/keymemtest"
)

// A buffer lies in a page of its own, locked and left out of core dumps;
// released, the page is cleared and unlocked, and a second release does
// nothing.
func TestABufferIsLockedThenClearedAtItsRelease(t *testing.T) {
	before := keymem.InUse()
	b, err := keymem.Copy([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	if !keymemtest.Locked(t, b) || len(b) != 32 || cap(b) != 32 {
		t.Fatal("the buffer is not in a locked page left out of dumps", keymemtest.Flags(t, b), len(b), cap(b))
	}
	if keymem.InUse() != before+1 {
		t.Fatal("the buffer is not counted", keymem.InUse(), before)
	}
	addr := uintptr(unsafe.Pointer(&b[0]))
	keymem.Release(b)
	if strings.Contains(keymemtest.FlagsAt(t, addr), " lo ") || !keymemtest.Zero(b) {
		t.Fatal("the released page is still locked, or holds the key")
	}
	if keymem.InUse() != before {
		t.Fatal("the released buffer is still counted")
	}
	keymem.Release(b)
	keymem.Release(nil)
	keymem.Release(make([]byte, 32))
	if keymem.InUse() != before {
		t.Fatal("a second release changed the count")
	}
}

func TestABufferHoldsOneByteToAPage(t *testing.T) {
	for _, n := range []int{0, -1, os.Getpagesize() + 1} {
		if _, err := keymem.Buffer(n); !errors.Is(err, keymem.ErrSize) {
			t.Fatal(n, err)
		}
	}
	b, err := keymem.Buffer(os.Getpagesize())
	if err != nil || !keymemtest.Zero(b) {
		t.Fatal(err)
	}
	keymem.Release(b)
}
