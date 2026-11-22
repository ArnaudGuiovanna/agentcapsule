//go:build linux && cgo

package restoreauthority

import (
	"context"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/keyauthority"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/keymem"
)

// The daily receipt keys (docs/adr/006-authority-service.md §7, wave 6;
// internal/keyauthority/receipt_keys_linux.go). The key authority keeps
// them under a reserved binding; the stream gives them their own kinds
// (Catalog.Append): their creation continues in degraded mode, their
// destruction waits for the replica, and neither names a store, so no seal.
// The authority service decides when a day's key is created and destroyed.

// EnsureReceiptKey creates day's receipt key, if it does not exist. Armed,
// it returns once the replica holds the key, except in degraded mode: the
// creation of a receipt key continues there, and the key is then on this
// host alone until the standby returns (ADR 006, answer 4(b)). A destroyed
// day's key is never created again (keyauthority.ErrRevoked).
func (l Local) EnsureReceiptKey(ctx context.Context, day time.Time) error {
	if l.Keys == nil {
		return keyauthority.ErrInput
	}
	return l.Keys.Ensure(ctx, keyauthority.ReceiptKeyAgent, keyauthority.ReceiptKeyVolume(day))
}

// ReceiptKey returns a copy of day's receipt key, in a locked page outside
// the Go heap (internal/keymem) that the caller releases with
// keymem.Release. It reads the key authority only, under the key's shared
// lock, and opens no catalogue transaction: reading a key that exists
// changes nothing, so it does not wait for the standby.
// keyauthority.ErrRevoked once the key is destroyed;
// keyauthority.ErrUnavailable while it does not exist.
func (l Local) ReceiptKey(ctx context.Context, day time.Time) ([]byte, error) {
	if l.Keys == nil {
		return nil, keyauthority.ErrInput
	}
	var key []byte
	err := l.Keys.WithKey(ctx, keyauthority.ReceiptKeyAgent, keyauthority.ReceiptKeyVolume(day), func(k []byte) error {
		var err error
		if key, err = keymem.Copy(k); err != nil {
			return keyauthority.ErrUnavailable
		}
		return nil
	})
	if err != nil {
		keymem.Release(key)
		return nil, err
	}
	return key, nil
}

// DestroyReceiptKey destroys day's receipt key. It has no store, so it
// needs no seal: the caller destroys it once every receipt of its day has
// expired. Armed, it waits for the replica, in degraded mode too, and the
// replica deletes its wrapped copy in the same write.
func (l Local) DestroyReceiptKey(ctx context.Context, day time.Time) error {
	if l.Keys == nil {
		return keyauthority.ErrInput
	}
	return l.Keys.Revoke(ctx, keyauthority.ReceiptKeyAgent, keyauthority.ReceiptKeyVolume(day))
}

// ReceiptKeys lists the days whose receipt key the key authority holds.
func (l Local) ReceiptKeys() ([]keyauthority.ReceiptKey, error) {
	keys, ok := l.Keys.(interface {
		ReceiptKeys() ([]keyauthority.ReceiptKey, error)
	})
	if !ok {
		return nil, keyauthority.ErrInput
	}
	return keys.ReceiptKeys()
}
