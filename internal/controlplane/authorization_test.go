package controlplane

import (
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestOwnerInstructionGrantIsIdempotentAndNeverRefills(t *testing.T) {
	s, _ := freshStore(t, "auto", 3)
	deadline := time.Now().Add(time.Hour).UTC().Truncate(time.Microsecond)
	if _, err := s.GrantMandate(t.Context(), "user-b", "a", "instruction", 2, deadline); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	type result struct {
		id  string
		err error
	}
	results := make(chan result, 12)
	for range 12 {
		go func() {
			id, err := s.GrantMandate(t.Context(), "user-a", "a", "instruction", 2, deadline)
			results <- result{id, err}
		}()
	}
	id := ""
	for range 12 {
		r := <-results
		if r.err != nil {
			t.Fatal(r.err)
		}
		if id == "" {
			id = r.id
		}
		if r.id != id {
			t.Fatal("instruction replay created a second grant")
		}
	}
	input := submission()
	input.MandateID = id
	if _, err := s.Submit(t.Context(), "a", "spend", input); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GrantMandate(t.Context(), "user-a", "a", "instruction", 2, deadline); err != nil {
		t.Fatal(err)
	}
	if remaining(t, s, id) != 1 {
		t.Fatal("instruction replay refilled mandate")
	}
	if _, err := s.GrantMandate(t.Context(), "user-a", "a", "instruction", 3, deadline); !errors.Is(err, ErrConflict) {
		t.Fatal(err)
	}
	if err := s.RevokeMandate(t.Context(), "user-b", id); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	if err := s.RevokeMandate(t.Context(), "user-a", id); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GrantMandate(t.Context(), "user-a", "a", "instruction", 2, deadline); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Submit(t.Context(), "a", "after-revocation", input); !errors.Is(err, ErrMandate) {
		t.Fatal(err)
	}
}

func TestDirectoryPostcheckAndPreferenceOwnership(t *testing.T) {
	s, _ := freshStore(t, "manual", 3)
	hidden := false
	if err := s.UpdatePreferences(t.Context(), "user-a", "b", &hidden, nil); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	if err := s.UpdatePreferences(t.Context(), "user-b", "b", &hidden, nil); err != nil {
		t.Fatal(err)
	}
	results, err := s.SearchDirectory(t.Context(), "a", []string{"b", "b", "a", "c", "missing"})
	if err != nil || fmt.Sprint(results) != "[c]" {
		t.Fatalf("stale candidates leaked: %v %v", results, err)
	}
	if err := s.RequestDeletion(t.Context(), "user-c", "c"); err != nil {
		t.Fatal(err)
	}
	results, err = s.SearchDirectory(t.Context(), "a", []string{"c"})
	if err != nil || len(results) != 0 {
		t.Fatalf("quiescing agent leaked: %v %v", results, err)
	}
	visible := true
	if err := s.UpdatePreferences(t.Context(), "user-c", "c", &visible, nil); !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
	if _, err := s.SearchDirectory(t.Context(), "missing", []string{"a"}); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
}
