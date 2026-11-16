package controlplane

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"
)

func TestTransitRotationBindingAndRetention(t *testing.T) {
	s, c, old, _, owner, e := instructionLab(t)
	r, err := c.Instruct(t.Context(), owner, e.AgentID, "one", privateInstruction("first private payload"))
	one := acceptedOperation(t, r, err)
	r, err = c.Instruct(t.Context(), owner, e.AgentID, "two", privateInstruction("second private payload"))
	two := acceptedOperation(t, r, err)
	first, second := instructionRef(t, s, one.OperationID), instructionRef(t, s, two.OperationID)
	key1, key2 := bytes.Repeat([]byte{0x73}, 32), bytes.Repeat([]byte{0x29}, 32)
	missing, err := NewTransit(s, "v2", map[string][]byte{"v2": key2}, 7*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err = missing.ActivateKeys(t.Context()); !errors.Is(err, ErrTransitKey) {
		t.Fatal("rotation discarded key for live payload", err)
	}
	wrong, err := NewTransit(s, "v1", map[string][]byte{"v1": key2}, 7*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err = wrong.ActivateKeys(t.Context()); !errors.Is(err, ErrTransitKey) {
		t.Fatal("key ID rebound", err)
	}
	current, err := NewTransit(s, "v2", map[string][]byte{"v1": key1, "v2": key2}, 7*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err = current.ActivateKeys(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err = current.CheckKeys(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err = old.CheckKeys(t.Context()); !errors.Is(err, ErrTransitKey) {
		t.Fatal("old writer accepted new active key", err)
	}
	if _, err = c.Instruct(t.Context(), owner, e.AgentID, "stale-writer", privateInstruction("blocked")); !errors.Is(err, ErrTransitKey) {
		t.Fatal("old writer published after rotation", err)
	}
	if count(t, s, "owner_instructions") != 2 {
		t.Fatal("failed stale writer left an instruction")
	}
	if _, err = current.ReadForOwner(t.Context(), owner, first); err != nil {
		t.Fatal("rotation lost old data", err)
	}
	var original []byte
	if err = s.pool.QueryRow(t.Context(), "SELECT ciphertext FROM transit_payloads WHERE id=$1", first).Scan(&original); err != nil {
		t.Fatal(err)
	}
	if _, err = s.pool.Exec(t.Context(), "UPDATE transit_payloads SET ciphertext=(SELECT ciphertext FROM transit_payloads WHERE id=$2) WHERE id=$1", first, second); err != nil {
		t.Fatal(err)
	}
	if _, err = current.ReadForOwner(t.Context(), owner, first); !errors.Is(err, ErrTransitPayload) {
		t.Fatal("swapped ciphertext authenticated", err)
	}
	if _, err = s.pool.Exec(t.Context(), "UPDATE transit_payloads SET ciphertext=$2 WHERE id=$1", first, original); err != nil {
		t.Fatal(err)
	}
	if _, err = current.ReadForOwner(t.Context(), owner, first); err != nil {
		t.Fatal(err)
	}
	tx, err := s.begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err = current.delivered(t.Context(), tx, first); err != nil {
		rollback(tx)
		t.Fatal(err)
	}
	if err = commit(t.Context(), tx); err != nil {
		t.Fatal(err)
	}
	var deadline time.Time
	if err = s.pool.QueryRow(t.Context(), "SELECT purge_after FROM transit_payloads WHERE id=$1", first).Scan(&deadline); err != nil {
		t.Fatal(err)
	}
	tx, err = s.begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err = current.delivered(t.Context(), tx, first); err != nil {
		rollback(tx)
		t.Fatal(err)
	}
	if err = commit(t.Context(), tx); err != nil {
		t.Fatal(err)
	}
	var replayDeadline time.Time
	if err = s.pool.QueryRow(t.Context(), "SELECT purge_after FROM transit_payloads WHERE id=$1", first).Scan(&replayDeadline); err != nil || !replayDeadline.Equal(deadline) {
		t.Fatal("replay extended retention", err)
	}
	if _, err = s.pool.Exec(t.Context(), "UPDATE transit_payloads SET purge_after=clock_timestamp()-interval '1 second' WHERE id=$1", first); err != nil {
		t.Fatal(err)
	}
	if _, err = current.ReadForOwner(t.Context(), owner, first); !errors.Is(err, ErrNotFound) {
		t.Fatal("expired content exposed before purge", err)
	}
	if n, err := current.PurgeExpired(t.Context(), 10); err != nil || n != 1 {
		t.Fatal("expiry purge", n, err)
	}
	if _, err = current.ReadForOwner(t.Context(), owner, second); err != nil {
		t.Fatal("purge affected undelivered content", err)
	}
	if err = s.RequestDeletion(t.Context(), owner.ID, e.AgentID); err != nil {
		t.Fatal(err)
	}
	if err = missing.ActivateKeys(t.Context()); err != nil {
		t.Fatal("purged key still required by current ciphertext", err)
	}
}

func TestTransitRotationWaitsForOldWriterBeforeCoverageCheck(t *testing.T) {
	s, _, old, _, _, e := instructionLab(t)
	tx, err := s.begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer rollback(tx)
	if _, err = old.put(t.Context(), tx, "instruction", "isolated-payload-fixture", []string{e.AgentID}, []byte("committing old-key body")); err != nil {
		t.Fatal(err)
	}
	next, err := NewTransit(s, "v2", map[string][]byte{"v2": bytes.Repeat([]byte{0x39}, 32)}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- next.ActivateKeys(ctx) }()
	// The open writer holds FOR SHARE on the active-key row. Rotation cannot
	// finish its coverage census until that writer has committed or rolled back.
	select {
	case err := <-done:
		t.Fatal("rotation bypassed the active writer", err)
	case <-time.After(50 * time.Millisecond):
	}
	if err = commit(t.Context(), tx); err != nil {
		t.Fatal(err)
	}
	if err = <-done; !errors.Is(err, ErrTransitKey) {
		t.Fatal("late old-key commit absent from rotation census", err)
	}
	if err = old.CheckKeys(t.Context()); err != nil {
		t.Fatal("failed rotation changed active key", err)
	}
}

// An attachment is sealed with a transit key too. A rotation cannot drop the
// key of a live attachment, and a process configured without that key does
// not start, as for a request or a result. Once the attachment is purged, the
// key is no longer needed.
func TestTransitRotationKeepsTheKeyOfALiveAttachment(t *testing.T) {
	il := newInvocationLab(t)
	alice := il.invoker(t, "alice")
	if _, _, err := il.upload(t, alice, "u1", "notes.txt", []byte("a file sealed with v1"), 60); err != nil {
		t.Fatal(err)
	}
	v1, v2 := bytes.Repeat([]byte{0x73}, 32), bytes.Repeat([]byte{0x29}, 32)
	without, err := NewTransit(il.s, "v2", map[string][]byte{"v2": v2}, 7*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err = without.ActivateKeys(t.Context()); !errors.Is(err, ErrTransitKey) {
		t.Fatal("a rotation dropped the key of a live attachment", err)
	}
	with, err := NewTransit(il.s, "v2", map[string][]byte{"v1": v1, "v2": v2}, 7*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err = with.ActivateKeys(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err = without.CheckKeys(t.Context()); !errors.Is(err, ErrTransitKey) {
		t.Fatal("a process without the key of a live attachment starts", err)
	}
	later := time.Now().Add(time.Hour)
	if n, err := il.s.PurgeAttachments(t.Context(), &later, 10); err != nil || n != 1 {
		t.Fatal("expired attachment not purged", n, err)
	}
	if err = without.CheckKeys(t.Context()); err != nil {
		t.Fatal("a purged attachment still needs its key", err)
	}
}

// The usage of each transit key tells the operator when an old key can leave
// the configuration: once no live content is sealed with it. Content without
// a purge date yet (not delivered, or attached to a running invocation) keeps
// the key for an unknown time; the rest gives the latest purge date.
func TestTransitKeyUsageSaysWhenAnOldKeyCanGo(t *testing.T) {
	il := newInvocationLab(t)
	alice := il.invoker(t, "alice")
	inv, err := il.invokeWith(t, alice, "i1")
	if err != nil {
		t.Fatal(err)
	}
	payload := instructionRef(t, il.s, inv.ID)
	att, _, err := il.upload(t, alice, "u1", "notes.txt", []byte("a file sealed with v1"), 600)
	if err != nil {
		t.Fatal(err)
	}
	v1, v2 := bytes.Repeat([]byte{0x73}, 32), bytes.Repeat([]byte{0x29}, 32)
	next, err := NewTransit(il.s, "v2", map[string][]byte{"v1": v1, "v2": v2}, 7*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err = next.ActivateKeys(t.Context()); err != nil {
		t.Fatal(err)
	}
	usage := func() map[string]TransitKeyUse {
		t.Helper()
		keys, err := il.s.TransitKeyUsage(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		byID := map[string]TransitKeyUse{}
		for _, k := range keys {
			byID[k.ID] = k
		}
		if len(byID) != len(keys) {
			t.Fatal("a key listed twice", keys)
		}
		return byID
	}
	u := usage()
	if k := u["v1"]; k.Active || k.Payloads != 1 || k.Attachments != 1 || k.Undated != 1 || k.PurgeBy == nil || !k.PurgeBy.Equal(att.ExpiresAt) {
		t.Fatal("old key in use", k)
	}
	if k := u["v2"]; !k.Active || k.Payloads != 0 || k.Attachments != 0 || k.Undated != 0 || k.PurgeBy != nil {
		t.Fatal("new active key", k)
	}
	// Delivered, the instruction gets its purge date: the latest of both.
	tx, err := il.s.begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err = next.delivered(t.Context(), tx, payload); err != nil {
		rollback(tx)
		t.Fatal(err)
	}
	if err = commit(t.Context(), tx); err != nil {
		t.Fatal(err)
	}
	var purgeAfter time.Time
	if err = il.s.pool.QueryRow(t.Context(), "SELECT purge_after FROM transit_payloads WHERE id=$1", payload).Scan(&purgeAfter); err != nil {
		t.Fatal(err)
	}
	if k := usage()["v1"]; k.Undated != 0 || k.PurgeBy == nil || !k.PurgeBy.Equal(purgeAfter) {
		t.Fatal("purge date of the old key", k, purgeAfter)
	}
	// Once both are purged, nothing needs v1 any more.
	if _, err = il.s.pool.Exec(t.Context(), "UPDATE transit_payloads SET purge_after=clock_timestamp()-interval '1 second' WHERE id=$1", payload); err != nil {
		t.Fatal(err)
	}
	if n, err := next.PurgeExpired(t.Context(), 10); err != nil || n != 1 {
		t.Fatal("expiry purge", n, err)
	}
	later := time.Now().Add(time.Hour)
	if n, err := il.s.PurgeAttachments(t.Context(), &later, 10); err != nil || n != 1 {
		t.Fatal("expired attachment not purged", n, err)
	}
	if k := usage()["v1"]; k.Payloads != 0 || k.Attachments != 0 || k.Undated != 0 || k.PurgeBy != nil {
		t.Fatal("a purged key still in use", k)
	}
	without, err := NewTransit(il.s, "v2", map[string][]byte{"v2": v2}, 7*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err = without.CheckKeys(t.Context()); err != nil {
		t.Fatal("a key with no live content is still required", err)
	}
}
