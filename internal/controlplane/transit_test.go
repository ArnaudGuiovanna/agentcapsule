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
