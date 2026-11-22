//go:build linux && cgo

package worker

import (
	"context"
	"fmt"
	"slices"
	"sync/atomic"
	"testing"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnessstore"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/restoreauthority"
)

// countingAuthority counts the calls of a boot's synchronization.
type countingAuthority struct {
	restoreauthority.Authority
	begins, scans, subjects atomic.Int64
}

func (c *countingAuthority) BeginRevocation(ctx context.Context, subject string) (uint64, error) {
	c.begins.Add(1)
	return c.Authority.BeginRevocation(ctx, subject)
}

func (c *countingAuthority) BeginRevocations(ctx context.Context, scopes []restoreauthority.Scope) error {
	c.begins.Add(1)
	return c.Authority.BeginRevocations(ctx, scopes)
}

func (c *countingAuthority) Scan(ctx context.Context, b restoreauthority.Binding) (restoreauthority.Receipt, error) {
	c.scans.Add(1)
	r, err := c.Authority.Scan(ctx, b)
	c.subjects.Add(int64(len(r.Subjects)))
	return r, err
}

func TestBootCostIgnoresOtherOrganizationsRevocations(t *testing.T) {
	forEachAuthority(t, testBootCostIgnoresOtherOrganizationsRevocations)
}

// S-01: a boot's synchronization costs the same with 3000 revocations of
// another organization's stores as with none: no begin, one scan, and only
// the store's own subject sent to its guest. The other organization's
// subjects never reach the guest, and do not make the boot stale.
func testBootCostIgnoresOtherOrganizationsRevocations(t *testing.T, implementation string) {
	b := newBootLab(t)
	a := b.withAuthority(t, implementation, true)
	own := "request/own-store"
	if err := a.BeginRevocations(t.Context(), []restoreauthority.Scope{{Subject: own, Stores: []string{b.e.AgentID}}}); err != nil {
		t.Fatal(err)
	}
	theirs := func(from, n int) {
		t.Helper()
		var scopes []restoreauthority.Scope
		for i := from; i < from+n; i++ {
			scopes = append(scopes, restoreauthority.Scope{Subject: fmt.Sprintf("event/other-organization-%06d", i), Stores: []string{"agt_" + fmt.Sprintf("%032x", i)}})
		}
		for chunk := range slices.Chunk(scopes, restoreauthority.MaxScopes) {
			if err := a.BeginRevocations(t.Context(), chunk); err != nil {
				t.Fatal(err)
			}
		}
		for i := from; i < from+n; i++ {
			if _, err := b.db.Exec(t.Context(), "INSERT INTO revocation_catalogue(subject) VALUES($1)", fmt.Sprintf("event/other-organization-%06d", i)); err != nil {
				t.Fatal(err)
			}
		}
	}
	theirs(0, 3000)
	counting := &countingAuthority{Authority: a}
	b.w.authority = counting
	run := b.claim(t)
	client, local := bootClientHarness(t, b.e.AgentID, run, func(capsuleprotocol.VolumeBoot, []byte) error { return nil }, false, nil, nil)
	if err := b.opts.PrepareGuest(t.Context(), b.e.AgentID, run, client); err != nil {
		t.Fatal(err)
	}
	if begins, scans, subjects := counting.begins.Load(), counting.scans.Load(), counting.subjects.Load(); begins != 0 || scans != 1 || subjects != 1 {
		t.Fatal("first boot's synchronization", begins, scans, subjects)
	}
	assertLocalBarrier(t, local, own)
	// The other organization's subject is not fenced in this guest.
	effect := func(context.Context, harnessstore.SQL) ([]byte, error) { return []byte("{}"), nil }
	if _, err := local.Apply(t.Context(), harnessstore.Event{ID: "theirs", Subjects: []string{"event/other-organization-000007"}}, effect); err != nil {
		t.Fatal("another organization's subject reached the guest", err)
	}
	// More of their revocations, between the scan and the confirmation, do
	// not make it stale, and the next boot's scan names nothing.
	theirs(3000, 1000)
	if err := b.opts.Confirm(t.Context(), b.e.AgentID, run); err != nil {
		t.Fatal("another organization's revocation made the boot stale", err)
	}
	next, err := counting.Scan(t.Context(), enrollmentBinding(b.e))
	if err != nil || len(next.Subjects) != 0 || next.More {
		t.Fatal("the next boot's scan", next.Subjects, err)
	}
}
