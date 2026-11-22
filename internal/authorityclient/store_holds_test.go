//go:build linux && cgo

package authorityclient

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/restoreauthority"
)

// A key hold of one agent's boot, which lasts through LUKS formatting or
// the guest's cryptsetup open, no longer stops the service for every other
// agent (S-15): another store's binding check, outcome, scan, fences and
// reservation are served while it lasts, and the held store's reservation
// still waits for it.
func TestKeyHoldOfOneStoreLeavesOtherStoresServed(t *testing.T) {
	keys, catalog := authorities(t, t.TempDir())
	l := serve(t, keys, catalog)
	c := l.client(t)
	ctx := t.Context()
	a, err := c.Register(ctx, agent, volume)
	if err != nil {
		t.Fatal(err)
	}
	if err = c.Ensure(ctx, agent, volume); err != nil {
		t.Fatal(err)
	}
	other := "agt_" + strings.Repeat("c", 32)
	b, err := c.Register(ctx, other, "vol_"+strings.Repeat("d", 32))
	if err != nil {
		t.Fatal(err)
	}
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	holder := l.client(t)
	go func() {
		done <- holder.HoldKey(ctx, a, func(context.Context, []byte) error { close(entered); <-release; return nil })
	}()
	<-entered
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	served := within(t, 5*time.Second)
	if err = c.CheckBinding(served, b); err != nil {
		t.Fatal("check of another store", err)
	}
	if err = c.RecordOutcome(served, b, restoreauthority.Outcome{ID: "outcome-b", Digest: [32]byte{2}}); err != nil {
		t.Fatal("outcome of another store", err)
	}
	if err = c.BeginRevocations(served, []restoreauthority.Scope{{Subject: "event/b", Stores: []string{other}}}); err != nil {
		t.Fatal("revocation of another store", err)
	}
	r, err := c.Scan(served, b)
	if err != nil || len(r.Subjects) != 1 {
		t.Fatal("scan of another store", r.Subjects, err)
	}
	if err = c.RecordVerifiedFence(served, r); err != nil {
		t.Fatal(err)
	}
	if err = c.HoldFences(served, r, func(context.Context) error { return nil }); err != nil {
		t.Fatal("fences of another store", err)
	}
	if _, err = c.ReserveIncarnation(served, b, "restore-b"); err != nil {
		t.Fatal("reservation of another store", err)
	}
	if _, err = c.ReserveIncarnation(within(t, 200*time.Millisecond), a, "restore-a"); !errors.Is(err, restoreauthority.ErrUnavailable) {
		t.Fatal("the held store's reservation overtook its key hold", err)
	}
	close(release)
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	if _, err = c.ReserveIncarnation(ctx, a, "restore-a"); err != nil {
		t.Fatal(err)
	}
}

// A guest boot no longer receives subjects outside its store's scope, and a
// scan across the socket pages a scope that would not fit one frame: each
// page goes back in a request frame (S-01).
func TestScanAcrossTheSocketIsScopedAndPaged(t *testing.T) {
	keys, catalog := authorities(t, t.TempDir())
	l := serve(t, keys, catalog)
	c := l.client(t)
	ctx := t.Context()
	a, err := c.Register(ctx, agent, volume)
	if err != nil {
		t.Fatal(err)
	}
	other := "agt_" + strings.Repeat("c", 32)
	if _, err = c.Register(ctx, other, "vol_"+strings.Repeat("d", 32)); err != nil {
		t.Fatal(err)
	}
	var mine, theirs []restoreauthority.Scope
	for i := range restoreauthority.ScanPage + 5 {
		mine = append(mine, restoreauthority.Scope{Subject: fmt.Sprintf("event/mine-%s%06d", strings.Repeat("x", 400), i), Stores: []string{agent}})
		theirs = append(theirs, restoreauthority.Scope{Subject: fmt.Sprintf("event/theirs-%06d", i), Stores: []string{other}})
	}
	if err = c.BeginRevocations(ctx, append(mine, theirs...)); err != nil {
		t.Fatal(err)
	}
	pages, fenced := 0, 0
	for {
		r, err := c.Scan(ctx, a)
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range r.Subjects {
			if !strings.HasPrefix(s, "event/mine-") {
				t.Fatal("another organization's subject reached the receipt", s)
			}
		}
		fenced += len(r.Subjects)
		pages++
		if err = c.RecordVerifiedFence(ctx, r); err != nil {
			t.Fatal("a page did not go back in a request frame", err)
		}
		if !r.More {
			if err = c.HoldFences(ctx, r, func(context.Context) error { return nil }); err != nil {
				t.Fatal(err)
			}
			break
		}
	}
	if fenced != len(mine) || pages < 2 {
		t.Fatal(fenced, pages)
	}
}

// A worker of the previous protocol knows neither Base nor More: its scan
// covers its store's whole scope from the first revision, in a receipt of
// the format it knows, which it can record.
func TestPreviousProtocolScansTheWholeScope(t *testing.T) {
	keys, catalog := authorities(t, t.TempDir())
	l := serve(t, keys, catalog)
	c := l.client(t)
	ctx := t.Context()
	a, err := c.Register(ctx, agent, volume)
	if err != nil {
		t.Fatal(err)
	}
	if err = c.BeginRevocations(ctx, []restoreauthority.Scope{{Subject: "event/one", Stores: []string{agent}}}); err != nil {
		t.Fatal(err)
	}
	r, err := c.Scan(ctx, a)
	if err != nil {
		t.Fatal(err)
	}
	if err = c.RecordVerifiedFence(ctx, r); err != nil {
		t.Fatal(err)
	}
	if err = c.BeginRevocations(ctx, []restoreauthority.Scope{{Subject: "event/two", Stores: []string{agent}}}); err != nil {
		t.Fatal(err)
	}
	if r, err = c.Scan(ctx, a); err != nil || r.Base == 0 || len(r.Subjects) != 1 {
		t.Fatal("the current protocol scans what the store lacks", r.Base, r.Subjects, err)
	}
	old := l.client(t)
	old.hello.Protocol = 1
	r, err = old.Scan(ctx, a)
	if err != nil || r.Base != 0 || r.More || len(r.Subjects) != 2 {
		t.Fatal("previous protocol", r.Base, r.More, r.Subjects, err)
	}
	if err = old.RecordVerifiedFence(ctx, r); err != nil {
		t.Fatal(err)
	}
	if err = old.HoldFences(ctx, r, func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
}
