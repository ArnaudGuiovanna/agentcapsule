package controlplane

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"sync"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/keymem"
)

// The daily receipt keys (docs/adr/006-authority-service.md §7, wave 6;
// docs/adr/005-keys-outside-restored-domain.md, Decision). With the
// authority service, the API encrypts each new idempotency receipt with the
// key of the day it writes it, and records that day with the receipt. The
// service destroys a day's key once every receipt of the day has expired, so
// a backup of the database holds no token secret anyone can read once two
// midnights (UTC) have passed. The API keeps today's and yesterday's keys in
// memory, and asks the service for a key it does not hold.
//
// A receipt written before the daily keys, or by an API without the service
// (development), names no day: the installation's receipt key encrypts it,
// as before, until it expires. The installation's key also stays the root of
// the LLM credential key and of the download link key: neither rotates.

// ReceiptKeySource fetches the receipt key of day from the authority
// service: 32 bytes, which the caller clears and releases (keymem.Release:
// the service's client gives them in a locked page). An error that wraps
// ErrReceiptKeyGone means that the key no longer exists, for good.
type ReceiptKeySource func(ctx context.Context, day time.Time) ([]byte, error)

var (
	// ErrReceiptKeyGone means that the key of a day no longer exists: it was
	// destroyed, or lost with a primary that held it alone (ADR 006, answer
	// 4(b)).
	ErrReceiptKeyGone = errors.New("the receipt key of that day no longer exists")
	// ErrReceiptUnreadable means that an idempotency receipt can no longer
	// be read: the key of its day is gone. The request it answers took
	// effect, and does not run again.
	ErrReceiptUnreadable = errors.New("idempotency receipt unreadable: the key of its day is gone")
	// ErrReceiptKeyUnavailable means that the authority service did not give
	// a day's key now. It is also ErrAuthorityUnavailable: try again in a
	// moment.
	ErrReceiptKeyUnavailable error = receiptKeyUnavailable{}
)

type receiptKeyUnavailable struct{}

func (receiptKeyUnavailable) Error() string {
	return "the authority service did not give the receipt key of the day: try again"
}
func (receiptKeyUnavailable) Is(target error) bool { return target == ErrAuthorityUnavailable }

// receiptFetch bounds one question to the authority service, within the
// request's own deadline.
const receiptFetch = 5 * time.Second

// receiptKeyRing holds the daily receipt keys the API has in memory.
type receiptKeyRing struct {
	fetch ReceiptKeySource
	now   func() time.Time
	mu    sync.Mutex
	keys  map[time.Time]cipher.AEAD
}

// receiptDay is the day of t, in UTC.
func receiptDay(t time.Time) time.Time {
	y, m, d := t.UTC().Date()
	return time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
}

// aead returns the cipher of day's key: from memory, or from the service.
// The ring forgets the keys of days before yesterday, and treats them as
// gone without asking: their receipts have expired.
func (r *receiptKeyRing) aead(ctx context.Context, day time.Time) (cipher.AEAD, error) {
	day = receiptDay(day)
	yesterday := receiptDay(r.now()).AddDate(0, 0, -1)
	r.mu.Lock()
	for d := range r.keys {
		if d.Before(yesterday) {
			delete(r.keys, d)
		}
	}
	c, ok := r.keys[day]
	r.mu.Unlock()
	switch {
	case ok:
		return c, nil
	case day.Before(yesterday):
		return nil, ErrReceiptKeyGone
	}
	ctx, cancel := context.WithTimeout(ctx, receiptFetch)
	defer cancel()
	key, err := r.fetch(ctx, day)
	// The service's client gives the key in a locked page (internal/keymem):
	// clear it, then give the page back. The cipher keeps its own copy of
	// the key schedule, on the Go heap, as long as the ring holds the day.
	defer keymem.Release(key)
	defer clear(key)
	switch {
	case errors.Is(err, ErrReceiptKeyGone):
		return nil, ErrReceiptKeyGone
	case err != nil || len(key) != 32:
		return nil, ErrReceiptKeyUnavailable
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if c, err = cipher.NewGCM(block); err != nil {
		return nil, err
	}
	r.mu.Lock()
	r.keys[day] = c
	r.mu.Unlock()
	return c, nil
}

// UseDailyReceiptKeys makes the API encrypt every new receipt with the key
// of its day, from source: the authority service. Call it once, before
// serving. Without it, receipts use the installation's receipt key, as
// before: development without the authority service only.
func (a *Accounts) UseDailyReceiptKeys(source ReceiptKeySource) error {
	return a.useDailyReceiptKeys(source, time.Now)
}

func (a *Accounts) useDailyReceiptKeys(source ReceiptKeySource, now func() time.Time) error {
	if source == nil || now == nil {
		return ErrInput
	}
	if !a.days.CompareAndSwap(nil, &receiptKeyRing{fetch: source, now: now, keys: map[time.Time]cipher.AEAD{}}) {
		return ErrConflict
	}
	return nil
}

// receiptSealer returns the cipher for a new receipt, and the day to record
// with it: today's key, or the installation's key (no day) without the
// authority service. A key the service does not give fails the request
// before anything runs (ErrReceiptKeyUnavailable): nothing is committed.
func (a *Accounts) receiptSealer(ctx context.Context) (cipher.AEAD, *time.Time, error) {
	ring := a.days.Load()
	if ring == nil {
		return a.cipher, nil, nil
	}
	day := receiptDay(ring.now())
	c, err := ring.aead(ctx, day)
	if err != nil {
		return nil, nil, ErrReceiptKeyUnavailable
	}
	return c, &day, nil
}

// openReceipt decrypts a stored receipt with the key it names: its day's,
// or the installation's when it names none. A day whose key is gone, or
// whose key is not the one that sealed it (created again after a failover
// lost the first), makes the receipt unreadable: ErrReceiptUnreadable.
func (a *Accounts) openReceipt(ctx context.Context, ciphertext []byte, day *time.Time, aad []byte, kind string) ([]byte, error) {
	c := a.cipher
	if day != nil {
		ring := a.days.Load()
		if ring == nil {
			return nil, ErrReceiptKeyUnavailable // only the authority service has the daily keys
		}
		var err error
		if c, err = ring.aead(ctx, *day); errors.Is(err, ErrReceiptKeyGone) {
			return nil, ErrReceiptUnreadable
		} else if err != nil {
			return nil, err
		}
	}
	n := c.NonceSize()
	if len(ciphertext) < n+c.Overhead() {
		return nil, errors.New("invalid encrypted " + kind + " receipt")
	}
	plain, err := c.Open(nil, ciphertext[:n], ciphertext[n:], aad)
	switch {
	case err != nil && day != nil:
		return nil, ErrReceiptUnreadable
	case err != nil:
		return nil, errors.New(kind + " receipt cannot be decrypted")
	}
	return plain, nil
}
