//go:build linux && cgo

package authorityservice

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"strconv"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/keyauthority"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/restoreauthority"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/telemetry"
)

// The daily receipt keys (docs/adr/006-authority-service.md §7, wave 6;
// docs/adr/005-keys-outside-restored-domain.md, Decision). The API encrypts
// each idempotency receipt, the secrets of the tokens it issues included,
// with the key of the day it writes it, and keeps today's and yesterday's
// keys in memory. A receipt lives 24 hours, so the last receipt of a day
// expires by the end of the next day: the service destroys the day's key
// then, with a margin for the clocks. A backup of the database then holds
// receipts that nothing can decrypt once two midnights have passed.
//
// The service creates each key a day ahead, while the standby answers, so
// that it is on the replica before its day. If the standby is away when a
// day comes and its key is missing, the service creates it on the primary
// alone: the creation of a receipt key continues in degraded mode (answer
// 4(b)). Its destruction waits for the standby, as a volume key's does.

// OpReceiptKey gives the API the receipt key of a day, on the API socket
// only: its frame, then the key's 32 raw bytes, never inside JSON.
const OpReceiptKey = "receipt_key"

const (
	// ReceiptKeyEvery is how often the service looks after the keys.
	ReceiptKeyEvery = time.Minute
	// ReceiptKeyGrace is how long a day's key outlives the last receipt
	// it can have encrypted, for the clocks of the API, PostgreSQL and the
	// service.
	ReceiptKeyGrace = time.Hour
	// receiptKeyStep bounds one creation or destruction of a pass: one
	// that waits for the standby is tried again at the next pass.
	receiptKeyStep = 30 * time.Second
)

// ReceiptKeyDestroyedAt is when the service destroys day's key: 24 hours
// after the day ends, when every receipt of the day has expired, and the
// grace.
func ReceiptKeyDestroyedAt(day time.Time) time.Time {
	return keyauthority.ReceiptDay(day).AddDate(0, 0, 2).Add(ReceiptKeyGrace)
}

type (
	// ReceiptKeyArgs names the day, YYYY-MM-DD in UTC.
	ReceiptKeyArgs struct {
		Day string `json:"day"`
	}
	// ReceiptKeyResult is the frame before the key's bytes.
	ReceiptKeyResult struct {
		Day string `json:"day"`
	}
)

// keyAnswer is the result of an operation that answers with a key: the
// request writes its frame, then the key's bytes, once the operation has
// ended, and clears the key. The operation must not write it itself: the
// client's next request may arrive before the operation ends, and would
// then be taken for a broken protocol.
type keyAnswer struct {
	result any
	key    []byte
}

func init() {
	operations[OpReceiptKey] = operation{api: true, apiOnly: true, run: func(ctx context.Context, s *Server, raw json.RawMessage, h *hold) (any, error) {
		a, err := decode[ReceiptKeyArgs](raw)
		if err != nil {
			return nil, err
		}
		day, err := time.Parse(time.DateOnly, a.Day)
		if err != nil || day.Format(time.DateOnly) != a.Day {
			return nil, keyauthority.ErrInput
		}
		key, err := s.receiptKey(ctx, day)
		if err != nil {
			return nil, err
		}
		return keyAnswer{ReceiptKeyResult{Day: a.Day}, key}, nil
	}}
}

// sendKey writes the result's frame, then the key's raw bytes.
func sendKey(conn *net.UnixConn, result any, key []byte) bool {
	b, err := json.Marshal(result)
	if err != nil || len(key) != KeySize {
		return false
	}
	conn.SetWriteDeadline(time.Now().Add(writeTimeout))
	if writeFrame(conn, Response{Result: b}) != nil {
		return false
	}
	_, err = conn.Write(key)
	return err == nil
}

func (s *Server) now() time.Time {
	if s.c.Now != nil {
		return s.c.Now()
	}
	return time.Now()
}

// receiptKey is receipt_key: day's key, for the API. By the service's
// clock it gives yesterday's, today's and tomorrow's keys only: tomorrow's
// for an API whose clock runs a little ahead. Reading a key that exists
// waits for nothing. Today's key is created when it is missing, without
// the standby in degraded mode (answer 4(b)); another day's never is. A
// day older than yesterday is gone (keyauthority.ErrRevoked), even while
// its destruction waits for the standby; so is yesterday's when the
// service does not hold it, as after a failover that lost a key created on
// the old primary alone.
func (s *Server) receiptKey(ctx context.Context, day time.Time) ([]byte, error) {
	today := keyauthority.ReceiptDay(s.now())
	day = keyauthority.ReceiptDay(day)
	switch {
	case day.After(today.AddDate(0, 0, 1)):
		return nil, keyauthority.ErrInput
	case day.Before(today.AddDate(0, 0, -1)):
		return nil, keyauthority.ErrRevoked
	}
	key, err := s.local.ReceiptKey(ctx, day)
	if err == nil || errors.Is(err, keyauthority.ErrRevoked) {
		return key, err
	}
	held, usable, lerr := s.receiptKeyHeld(day)
	switch {
	case lerr != nil:
		return nil, err
	case day.Equal(today):
		if err = s.createReceiptKey(ctx, day, usable); err != nil {
			return nil, err
		}
		return s.local.ReceiptKey(ctx, day)
	case day.Before(today) && !held:
		return nil, keyauthority.ErrRevoked
	}
	return nil, err
}

// receiptKeyHeld reports whether the key authority holds day's key, and
// whether its creation completed.
func (s *Server) receiptKeyHeld(day time.Time) (held, usable bool, err error) {
	keys, err := s.local.ReceiptKeys()
	for _, k := range keys {
		if k.Day.Equal(day) {
			return true, k.Usable, err
		}
	}
	return false, false, err
}

// createReceiptKey creates day's key, and says so when it was missing.
func (s *Server) createReceiptKey(ctx context.Context, day time.Time, usable bool) error {
	err := s.local.EnsureReceiptKey(ctx, day)
	switch {
	case err != nil:
		s.c.Logger.Event("receipt_key_failed", telemetry.Code("step", "create"), dayField(day))
	case !usable:
		s.c.Events.Event("receipt_key_created", dayField(day))
	}
	return err
}

func dayField(day time.Time) telemetry.Field {
	n, _ := strconv.ParseInt(day.Format("20060102"), 10, 64)
	return telemetry.Int("day", n)
}

// KeepReceiptKeys looks after the daily receipt keys until ctx ends: a pass
// at once, then every ReceiptKeyEvery. The primary role runs it.
func (s *Server) KeepReceiptKeys(ctx context.Context) {
	for {
		_ = s.TendReceiptKeys(ctx)
		timer := time.NewTimer(ReceiptKeyEvery)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

// TendReceiptKeys is one pass: it creates today's key if it is missing,
// tomorrow's a day ahead while the standby answers, and destroys each key
// whose receipts have all expired (ReceiptKeyDestroyedAt). In degraded
// mode, and while a restarted service waits for its standby, tomorrow's
// key waits: created then, it would be on the primary alone a day early.
// Each step is bounded; one that fails, or waits for the standby, is tried
// again at the next pass. It returns the first failure.
func (s *Server) TendReceiptKeys(ctx context.Context) error {
	now := s.now()
	today := keyauthority.ReceiptDay(now)
	keys, err := s.local.ReceiptKeys()
	if err != nil {
		return err
	}
	usable := map[time.Time]bool{}
	for _, k := range keys {
		usable[k.Day] = k.Usable
	}
	var first error
	step := func(do func(context.Context) error) {
		ctx, cancel := context.WithTimeout(ctx, receiptKeyStep)
		defer cancel()
		if err := do(ctx); err != nil && first == nil {
			first = err
		}
	}
	if !usable[today] {
		step(func(ctx context.Context) error { return s.createReceiptKey(ctx, today, false) })
	}
	tomorrow := today.AddDate(0, 0, 1)
	if mode, _ := s.c.Catalog.ReplicationMode(); !usable[tomorrow] && (mode == restoreauthority.ModeSynchronous || mode == restoreauthority.ModeStandalone) {
		step(func(ctx context.Context) error { return s.createReceiptKey(ctx, tomorrow, false) })
	}
	for _, k := range keys {
		if now.Before(ReceiptKeyDestroyedAt(k.Day)) {
			continue
		}
		step(func(ctx context.Context) error {
			err := s.local.DestroyReceiptKey(ctx, k.Day)
			if err != nil {
				s.c.Logger.Event("receipt_key_failed", telemetry.Code("step", "destroy"), dayField(k.Day))
				return err
			}
			s.c.Events.Event("receipt_key_destroyed", dayField(k.Day))
			return nil
		})
	}
	s.observeReceiptKeys(now)
	return first
}

// observeReceiptKeys sets the metrics from the keys held now.
func (s *Server) observeReceiptKeys(now time.Time) {
	keys, err := s.local.ReceiptKeys()
	if err != nil {
		return
	}
	today := keyauthority.ReceiptDay(now)
	ready := map[string]bool{}
	overdue := 0
	for _, k := range keys {
		switch {
		case !now.Before(ReceiptKeyDestroyedAt(k.Day)):
			overdue++
		case k.Day.Equal(today):
			ready["today"] = k.Usable
		case k.Day.Equal(today.AddDate(0, 0, 1)):
			ready["tomorrow"] = k.Usable
		}
	}
	s.c.Metrics.receiptKeys(ready["today"], ready["tomorrow"], overdue)
}

// receiptMetrics are the daily receipt keys' metrics.
type receiptMetrics struct {
	ready, overdue *telemetry.Gauge
}

func newReceiptMetrics(r *telemetry.Registry) receiptMetrics {
	m := receiptMetrics{
		ready: r.Gauge("agentcapsule_authority_receipt_key_ready",
			"1 when the authority service holds the daily receipt key of the day, today or tomorrow, and its creation completed.",
			telemetry.Label{Name: "day", Values: []string{"today", "tomorrow"}}),
		overdue: r.Gauge("agentcapsule_authority_receipt_keys_overdue",
			"Daily receipt keys the authority service still holds after their destruction time: their destruction waits for the standby, or fails."),
	}
	m.ready.Set(0, "today")
	m.ready.Set(0, "tomorrow")
	m.overdue.Set(0)
	return m
}

func (m *Metrics) receiptKeys(today, tomorrow bool, overdue int) {
	if m == nil {
		return
	}
	value := func(b bool) float64 {
		if b {
			return 1
		}
		return 0
	}
	m.receipt.ready.Set(value(today), "today")
	m.receipt.ready.Set(value(tomorrow), "tomorrow")
	m.receipt.overdue.Set(float64(overdue))
}
