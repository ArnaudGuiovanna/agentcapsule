//go:build linux

package controlplane

import (
	"context"
	"crypto/cipher"
	"crypto/rand"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/keymem"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/keymem/keymemtest"
)

// FIX-1 (L-18 continued): the authority service's client gives a receipt
// key in a locked page (internal/keymem). The ring makes its cipher, then
// releases the page: cleared, unlocked, and counted no more.
func TestTheReceiptKeyRingReleasesTheKeyItFetched(t *testing.T) {
	var fetched []byte
	ring := &receiptKeyRing{now: func() time.Time { return receiptDay16 }, keys: map[time.Time]cipher.AEAD{},
		fetch: func(context.Context, time.Time) ([]byte, error) {
			key, err := keymem.Buffer(32)
			if err != nil {
				return nil, err
			}
			_, _ = rand.Read(key)
			fetched = key
			return key, nil
		}}
	before := keymem.InUse()
	if _, err := ring.aead(t.Context(), receiptDay16); err != nil {
		t.Fatal(err)
	}
	if keymem.InUse() != before || !keymemtest.Zero(fetched) {
		t.Fatal("the fetched key's page was not released, or holds the key", keymem.InUse(), before)
	}
}
