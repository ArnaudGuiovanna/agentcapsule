//go:build linux && cgo

package authorityclient

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authoritylog"
	svc "github.com/ArnaudGuiovanna/agentcapsule/internal/authorityservice"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/keyauthority"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/restoreauthority"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/telemetry"
)

// The daily receipt keys (docs/adr/006-authority-service.md §7, wave 6).

// dayClock is the service's clock of days; it moves when a test says.
type dayClock struct {
	mu sync.Mutex
	t  time.Time
}

func (k *dayClock) now() time.Time {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.t
}

func (k *dayClock) set(t time.Time) {
	k.mu.Lock()
	k.t = t
	k.mu.Unlock()
}

// lockedBuffer is a log the service writes while the test reads it.
type lockedBuffer struct {
	mu sync.Mutex
	b  strings.Builder
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// receiptDays runs the service on k's days, and logs its events to log.
func receiptDays(k *dayClock, log *lockedBuffer) option {
	return func(c *svc.Config) {
		c.Now = k.now
		c.Events = telemetry.NewLogger(log, svc.Vocabulary())
		c.Logger = c.Events
	}
}

func date(d int, hour, minute int) time.Time {
	return time.Date(2026, 11, d, hour, minute, 0, 0, time.UTC)
}

func held(t *testing.T, keys *keyauthority.Files) []string {
	t.Helper()
	got, err := keys.ReceiptKeys()
	if err != nil {
		t.Fatal(err)
	}
	var days []string
	for _, k := range got {
		s := k.Day.Format(time.DateOnly)
		if !k.Usable {
			s += " (pending)"
		}
		days = append(days, s)
	}
	return days
}

func hasLines(t *testing.T, text string, lines ...string) {
	t.Helper()
	for _, line := range lines {
		if !strings.Contains(text, line) {
			t.Fatalf("missing %q in\n%s", line, text)
		}
	}
}

// The API asks the service for a day's key on its socket. Today's is
// created on demand; yesterday's and tomorrow's never are; a day before
// yesterday is gone, a day after tomorrow refused. The worker's socket
// does not serve receipt keys.
func TestAPIGetsTheDailyReceiptKeys(t *testing.T) {
	keys, catalog := authorities(t, t.TempDir())
	k := &dayClock{t: date(16, 10, 0)}
	l := serve(t, keys, catalog, receiptDays(k, &lockedBuffer{}))
	api := l.apiClient(t)
	ctx := t.Context()
	today := date(16, 0, 0)
	key, err := api.ReceiptKey(ctx, today)
	if err != nil || len(key) != 32 || bytes.Equal(key, make([]byte, 32)) {
		t.Fatal("today's key", err)
	}
	if again, err := api.ReceiptKey(ctx, date(16, 23, 59)); err != nil || !bytes.Equal(again, key) {
		t.Fatal("the same day gave another key", err)
	}
	for name, c := range map[string]struct {
		day  time.Time
		want error
	}{
		"yesterday, never held":    {today.AddDate(0, 0, -1), keyauthority.ErrRevoked},
		"tomorrow, not yet":        {today.AddDate(0, 0, 1), keyauthority.ErrUnavailable},
		"the day before yesterday": {today.AddDate(0, 0, -2), keyauthority.ErrRevoked},
		"the day after tomorrow":   {today.AddDate(0, 0, 2), keyauthority.ErrInput},
	} {
		if got, err := api.ReceiptKey(ctx, c.day); !errors.Is(err, c.want) || got != nil {
			t.Fatal(name, err)
		}
	}
	if got := held(t, keys); len(got) != 1 || got[0] != "2026-11-16" {
		t.Fatal("the service created", got)
	}
	// The control plane's source says when a key is gone for good.
	if _, err = api.ReceiptKeys()(ctx, today.AddDate(0, 0, -1)); !errors.Is(err, controlplane.ErrReceiptKeyGone) {
		t.Fatal("a gone key, in the control plane's terms", err)
	}
	if _, err = l.client(t).receiptKey(ctx, today); !errors.Is(err, svc.ErrRole) {
		t.Fatal("the worker socket gave a receipt key", err)
	}
}

// The service creates tomorrow's key a day ahead, keeps yesterday's, and
// destroys each day's key an hour after its last receipt expired: two
// midnights after its day began, and the grace.
func TestServiceTendsTheDailyReceiptKeys(t *testing.T) {
	keys, catalog := authorities(t, t.TempDir())
	k := &dayClock{t: date(16, 10, 0)}
	var log lockedBuffer
	l := serve(t, keys, catalog, receiptDays(k, &log))
	api := l.apiClient(t)
	ctx := t.Context()
	if err := l.server.TendReceiptKeys(ctx); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(held(t, keys), ","); got != "2026-11-16,2026-11-17" {
		t.Fatal("held", got)
	}
	hasLines(t, l.scrape(t), `agentcapsule_authority_receipt_key_ready{day="today"} 1`,
		`agentcapsule_authority_receipt_key_ready{day="tomorrow"} 1`, "agentcapsule_authority_receipt_keys_overdue 0")
	first, err := api.ReceiptKey(ctx, date(16, 0, 0))
	if err != nil {
		t.Fatal(err)
	}
	k.set(date(17, 10, 0))
	if err = l.server.TendReceiptKeys(ctx); err != nil {
		t.Fatal(err)
	}
	if again, err := api.ReceiptKey(ctx, date(16, 0, 0)); err != nil || !bytes.Equal(again, first) {
		t.Fatal("yesterday's key", err)
	}
	// After the second midnight the API no longer gets the key; the service
	// keeps it for the grace, then destroys it.
	k.set(date(18, 0, 30))
	if err = l.server.TendReceiptKeys(ctx); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(held(t, keys), ","); got != "2026-11-16,2026-11-17,2026-11-18,2026-11-19" {
		t.Fatal("held within the grace", got)
	}
	if _, err = api.ReceiptKey(ctx, date(16, 0, 0)); !errors.Is(err, keyauthority.ErrRevoked) {
		t.Fatal("the API got a key older than yesterday", err)
	}
	if !svc.ReceiptKeyDestroyedAt(date(16, 23, 0)).Equal(date(18, 1, 0)) {
		t.Fatal("destroyed at", svc.ReceiptKeyDestroyedAt(date(16, 23, 0)))
	}
	k.set(date(18, 1, 0))
	if err = l.server.TendReceiptKeys(ctx); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(held(t, keys), ","); got != "2026-11-17,2026-11-18,2026-11-19" {
		t.Fatal("held after the destruction", got)
	}
	if err = keys.WithKey(ctx, keyauthority.ReceiptKeyAgent, keyauthority.ReceiptKeyVolume(date(16, 0, 0)), func([]byte) error { return nil }); !errors.Is(err, keyauthority.ErrRevoked) {
		t.Fatal("the destroyed key is readable", err)
	}
	hasLines(t, log.String(), `"event":"receipt_key_created","day":20261116`, `"event":"receipt_key_created","day":20261117`,
		`"event":"receipt_key_created","day":20261118`, `"event":"receipt_key_created","day":20261119`,
		`"event":"receipt_key_destroyed","day":20261116`)
	if strings.Contains(log.String(), "receipt_key_failed") || strings.Count(log.String(), "receipt_key_created") != 4 {
		t.Fatal("events", log.String())
	}
}

// Answer 4(b): the standby is away when a day comes. Its key is created on
// the primary alone, on demand and by the next pass, and the API gets it;
// tomorrow's waits for the standby, and so does the destruction of an
// expired key, which the metrics show. When the standby returns, both run,
// and the replica holds every key.
func TestReceiptKeyOfANewDayIsCreatedWithoutTheStandby(t *testing.T) {
	dir := t.TempDir()
	keys, catalog := authorities(t, dir)
	_, recipient, err := authoritylog.GenerateUnlockKey()
	if err != nil {
		t.Fatal(err)
	}
	snapshot := filepath.Join(dir, "snapshot.sqlite")
	if _, err = catalog.Snapshot(t.Context(), keys, recipient, snapshot); err != nil {
		t.Fatal(err)
	}
	replica, err := restoreauthority.InitializeReplica(t.Context(), filepath.Join(dir, "replica"), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { replica.Close() })
	link := &tap{target: replica}
	if err = svc.LinkTo(t.Context(), catalog, keys, link, authoritylog.MinDegradedAfter); err != nil {
		t.Fatal(err)
	}
	k := &dayClock{t: date(16, 10, 0)}
	var log lockedBuffer
	l := serve(t, keys, catalog, receiptDays(k, &log))
	api := l.apiClient(t)
	ctx := t.Context()
	mode := func() string {
		t.Helper()
		status, err := api.Status(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return status.Mode
	}
	for deadline := time.Now().Add(10 * time.Second); mode() != restoreauthority.ModeSynchronous; time.Sleep(20 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("no standby")
		}
	}
	worker := l.client(t)
	b, _ := fenced(t, worker, "store-a", "volume-a")
	if err = l.server.TendReceiptKeys(ctx); err != nil {
		t.Fatal(err)
	}
	position := func() uint64 {
		t.Helper()
		p, err := replica.Position(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return p.Seq
	}
	before := position()
	if before == 0 {
		t.Fatal("the keys created with the standby did not reach it")
	}
	link.set(true)
	if err = worker.RecordOutcome(within(t, 500*time.Millisecond), b, restoreauthority.Outcome{ID: "event-1", Digest: digest("one")}); !errors.Is(err, restoreauthority.ErrUnavailable) {
		t.Fatal("a write returned without the standby, before degraded mode", err)
	}
	for deadline := time.Now().Add(30 * time.Second); mode() != restoreauthority.ModeDegraded; time.Sleep(100 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("no degraded mode")
		}
	}
	if err = worker.RecordOutcome(ctx, b, restoreauthority.Outcome{ID: "event-1", Digest: digest("one")}); err != nil {
		t.Fatal(err)
	}
	before = position() // the outcome is a degraded write: the replica lacks it
	if state, err := catalog.Replication(ctx); err != nil || state.Committed.Seq <= before {
		t.Fatal("no degraded write", state, err)
	}
	// Two days later, at 01:30: the 16th's key is due for destruction, the
	// 18th's is missing.
	k.set(date(18, 1, 30))
	key, err := api.ReceiptKey(within(t, 10*time.Second), date(18, 0, 0))
	if err != nil || len(key) != 32 {
		t.Fatal("the key of a new day waited for the standby", err)
	}
	if err = l.server.TendReceiptKeys(within(t, 2*time.Second)); !errors.Is(err, restoreauthority.ErrWaitsForReplica) {
		t.Fatal("the destruction did not wait for the standby", err)
	}
	if got := strings.Join(held(t, keys), ","); got != "2026-11-16,2026-11-17,2026-11-18" {
		t.Fatal("held while the standby is away", got)
	}
	hasLines(t, l.scrape(t), `agentcapsule_authority_receipt_key_ready{day="today"} 1`,
		`agentcapsule_authority_receipt_key_ready{day="tomorrow"} 0`, "agentcapsule_authority_receipt_keys_overdue 1")
	hasLines(t, log.String(), `"event":"receipt_key_failed","step":"destroy","day":20261116`)
	if position() != before {
		t.Fatal("the replica applied a record while it was away")
	}
	link.set(false)
	for deadline := time.Now().Add(30 * time.Second); mode() != restoreauthority.ModeSynchronous; time.Sleep(50 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the standby did not return")
		}
	}
	if err = l.server.TendReceiptKeys(ctx); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(held(t, keys), ","); got != "2026-11-17,2026-11-18,2026-11-19" {
		t.Fatal("held once the standby returned", got)
	}
	hasLines(t, l.scrape(t), `agentcapsule_authority_receipt_key_ready{day="tomorrow"} 1`, "agentcapsule_authority_receipt_keys_overdue 0")
	state, err := catalog.Replication(ctx)
	if err != nil || position() != state.Committed.Seq {
		t.Fatal("the replica lacks what the primary committed", position(), state.Committed, err)
	}
	if again, err := api.ReceiptKey(ctx, date(18, 0, 0)); err != nil || !bytes.Equal(again, key) {
		t.Fatal("the key of the 18th changed", err)
	}
}

// The receipt key reaches the API as 32 raw bytes after its frame, never
// inside JSON, as a volume key reaches the worker.
func TestReceiptKeyNeverTravelsInJSON(t *testing.T) {
	keys, catalog := authorities(t, t.TempDir())
	k := &dayClock{t: date(16, 10, 0)}
	l := serve(t, keys, catalog, receiptDays(k, &lockedBuffer{}))
	var rec recorder
	relay := filepath.Join(socketDir(t), "relay.sock")
	rec.relay(t, relay, l.api)
	api, err := NewAPI(relay, catalog.Identity(), keys.Identity())
	if err != nil {
		t.Fatal(err)
	}
	defer api.Close()
	key, err := api.ReceiptKey(t.Context(), date(16, 0, 0))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = api.Status(t.Context()); err != nil {
		t.Fatal("the connection did not serve the next request", err)
	}
	api.Close()
	encodings := [][]byte{key, []byte(base64.StdEncoding.EncodeToString(key)), []byte(base64.RawStdEncoding.EncodeToString(key)),
		[]byte(base64.URLEncoding.EncodeToString(key)), []byte(hex.EncodeToString(key))}
	rec.mu.Lock()
	fromService, toService := bytes.Clone(rec.fromService.Bytes()), bytes.Clone(rec.toService.Bytes())
	rec.mu.Unlock()
	for _, e := range encodings {
		if bytes.Contains(toService, e) {
			t.Fatal("the API sent the key back")
		}
	}
	stream, seen := bytes.NewReader(fromService), 0
	for stream.Len() > 0 {
		var size uint32
		if err = binary.Read(stream, binary.BigEndian, &size); err != nil {
			t.Fatal(err)
		}
		frame := make([]byte, size)
		if _, err = io.ReadFull(stream, frame); err != nil {
			t.Fatal(err)
		}
		for _, e := range encodings {
			if bytes.Contains(frame, e) {
				t.Fatal("a JSON frame carried the key:", string(frame))
			}
		}
		var r svc.Response
		if err = json.Unmarshal(frame, &r); err != nil {
			t.Fatal(err)
		}
		var result svc.ReceiptKeyResult
		if json.Unmarshal(r.Result, &result) == nil && result.Day == "2026-11-16" {
			raw := make([]byte, svc.KeySize)
			if _, err = io.ReadFull(stream, raw); err != nil || !bytes.Equal(raw, key) {
				t.Fatal("the key did not follow its frame", err)
			}
			seen++
		}
	}
	if seen != 1 {
		t.Fatal("keys seen", seen)
	}
}
