package harnessstore

import (
	"path/filepath"
	"testing"
)

func TestOutcomeFingerprintSurvivesReopenAndCanonicalReplay(t *testing.T) {
	path := filepath.Join(t.TempDir(), "history.sqlite")
	s := openTest(t, path)
	e := Event{ID: "same-id", Subjects: []string{"agent/b", "agent/a", "agent/a"}}
	r, err := s.Apply(t.Context(), e, increment)
	if err != nil {
		t.Fatal(err)
	}
	id, digest, err := OutcomeFingerprint("store-a", e, r.Result)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	s = openTest(t, path)
	e.Subjects, e.Body = []string{"agent/a", "agent/b"}, []byte{}
	r, err = s.Apply(t.Context(), e, increment)
	if err != nil || !r.Replayed {
		t.Fatal("canonical replay", r, err)
	}
	again, same, err := OutcomeFingerprint("store-a", e, r.Result)
	if err != nil || again != id || same != digest {
		t.Fatal("replay changed history commitment", err)
	}
	var storedID string
	var envelope, result []byte
	if err = s.db.QueryRow("SELECT event_id,envelope_hash,result FROM capsule_inbox").Scan(&storedID, &envelope, &result); err != nil {
		t.Fatal(err)
	}
	if len(envelope) != 32 {
		t.Fatal("stored hash length")
	}
	again, same, err = StoredOutcomeFingerprint("store-a", storedID, [32]byte(envelope), result)
	if err != nil || again != id || same != digest {
		t.Fatal("persisted data cannot reconstruct commitment", err)
	}
	other, changed, _ := OutcomeFingerprint("store-b", e, r.Result)
	if other == id || changed == digest {
		t.Fatal("stores collide")
	}
	other, changed, _ = OutcomeFingerprint("store-a", e, []byte("changed-result"))
	if other != id || changed == digest {
		t.Fatal("result conflict not visible")
	}
	e.Body = []byte("changed-body")
	other, changed, _ = OutcomeFingerprint("store-a", e, r.Result)
	if other != id || changed == digest {
		t.Fatal("envelope conflict not visible")
	}
	assertCounts(t, s, 1, 1)
}
