//go:build linux

package keyauthority

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeJournal stands for the replication stream: it keeps each change and
// fails on demand after the local write, as a standby that does not answer.
type fakeJournal struct {
	fail    error
	changes []Change
}

func (j *fakeJournal) Append(_ context.Context, write func() (*Change, error)) error {
	change, err := write()
	if change != nil {
		kept := *change
		kept.Key = bytes.Clone(change.Key)
		j.changes = append(j.changes, kept)
		clear(change.Key)
	}
	if err != nil {
		return err
	}
	return j.fail
}

var errStandby = errors.New("standby unreachable")

func TestJournaledKeyIsUsableOnlyOnceReplicated(t *testing.T) {
	s := fixture(t)
	j := &fakeJournal{fail: errStandby}
	s.SetJournal(j)
	if err := s.Ensure(t.Context(), testAgent, testVolume); !errors.Is(err, errStandby) {
		t.Fatal(err)
	}
	if len(j.changes) != 1 || j.changes[0].Revoke || len(j.changes[0].Key) != 32 {
		t.Fatal("creation not handed to the journal", j.changes)
	}
	if err := s.WithKey(t.Context(), testAgent, testVolume, func([]byte) error { t.Error("unreplicated key used"); return nil }); err == nil {
		t.Fatal("unreplicated key usable")
	}
	// The retry records the same key, never a new one.
	j.fail = nil
	if err := s.Ensure(t.Context(), testAgent, testVolume); err != nil {
		t.Fatal(err)
	}
	if len(j.changes) != 2 || !bytes.Equal(j.changes[0].Key, j.changes[1].Key) {
		t.Fatal("a retry changed the key")
	}
	if keyHash(t, s) != sha256.Sum256(j.changes[0].Key) {
		t.Fatal("the journal received another key")
	}
	if err := s.Ensure(t.Context(), testAgent, testVolume); err != nil || len(j.changes) != 2 {
		t.Fatal("a replicated key was recorded again", err)
	}
	// Destruction: the tombstone denies at once, the file goes once replicated.
	j.fail = errStandby
	if err := s.Revoke(t.Context(), testAgent, testVolume); !errors.Is(err, errStandby) {
		t.Fatal(err)
	}
	if err := s.WithKey(t.Context(), testAgent, testVolume, func([]byte) error { return nil }); !errors.Is(err, ErrRevoked) {
		t.Fatal(err)
	}
	path := filepath.Join(s.root, "records", testVolume)
	if _, err := os.Lstat(path); err != nil {
		t.Fatal("key removed before the replica destroyed its copy", err)
	}
	j.fail = nil
	if err := s.Revoke(t.Context(), testAgent, testVolume); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("replicated destruction left the key", err)
	}
	if last := j.changes[len(j.changes)-1]; !last.Revoke || last.Key != nil {
		t.Fatal("destruction not recorded", last)
	}
	if err := s.Ensure(t.Context(), testAgent, testVolume); !errors.Is(err, ErrRevoked) {
		t.Fatal(err)
	}
}

func TestArmedAuthorityRefusesWritesWithoutItsJournal(t *testing.T) {
	s := fixture(t)
	if err := s.Ensure(t.Context(), testAgent, testVolume); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkReplicated(); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkReplicated(); err != nil {
		t.Fatal("arming is not repeatable", err)
	}
	other := "vol_" + strings.Repeat("c", 32)
	if err := s.Ensure(t.Context(), testAgent, other); !errors.Is(err, ErrUnavailable) {
		t.Fatal("armed authority wrote without its journal", err)
	}
	if err := s.Revoke(t.Context(), testAgent, testVolume); !errors.Is(err, ErrUnavailable) {
		t.Fatal("armed authority destroyed without its journal", err)
	}
	keyHash(t, s) // reads stay available
	reopened, err := Open(s.root, s.Identity())
	if err != nil {
		t.Fatal(err)
	}
	if armed, err := reopened.Replicated(); err != nil || !armed {
		t.Fatal("arming lost", err)
	}
}

func TestExportAndInstallCarryEveryVolume(t *testing.T) {
	s := fixture(t)
	revoked, unused := "vol_"+strings.Repeat("c", 32), "vol_"+strings.Repeat("d", 32)
	for _, v := range []string{testVolume, revoked} {
		if err := s.Ensure(t.Context(), testAgent, v); err != nil {
			t.Fatal(err)
		}
	}
	for _, v := range []string{revoked, unused} {
		if err := s.Revoke(t.Context(), testAgent, v); err != nil {
			t.Fatal(err)
		}
	}
	var entries []Entry
	err := s.Export(t.Context(), func(e Entry) error {
		e.Key = bytes.Clone(e.Key)
		entries = append(entries, e)
		return nil
	})
	if err != nil || len(entries) != 3 {
		t.Fatal(entries, err)
	}
	if e := entries[0]; e.Volume != testVolume || e.Key == nil || !e.Allocated || e.Revoked {
		t.Fatal("live key", e)
	}
	if e := entries[1]; e.Volume != revoked || e.Key != nil || !e.Allocated || !e.Revoked {
		t.Fatal("destroyed key", e)
	}
	if e := entries[2]; e.Volume != unused || e.Key != nil || e.Allocated || !e.Revoked {
		t.Fatal("unused tombstone", e)
	}
	root := filepath.Join(t.TempDir(), "promoted")
	installed, err := Install(t.Context(), root, s.Identity(), entries)
	if err != nil || installed.Identity() != s.Identity() {
		t.Fatal(err)
	}
	if _, err = Install(t.Context(), root, s.Identity(), entries); err != nil {
		t.Fatal("install is not repeatable", err)
	}
	if keyHash(t, installed) != keyHash(t, s) {
		t.Fatal("installed key differs")
	}
	for _, v := range []string{revoked, unused} {
		if err = installed.Ensure(t.Context(), testAgent, v); !errors.Is(err, ErrRevoked) {
			t.Fatal("a tombstone was lost", v, err)
		}
	}
	changed := []Entry{{Agent: testAgent, Volume: testVolume, Key: bytes.Repeat([]byte{1}, 32), Allocated: true}}
	if _, err = Install(t.Context(), root, s.Identity(), changed); !errors.Is(err, ErrConflict) {
		t.Fatal("install replaced a key", err)
	}
	if _, err = Install(t.Context(), root, "keyauth_"+strings.Repeat("e", 32), nil); !errors.Is(err, ErrConflict) {
		t.Fatal("install replaced an identity", err)
	}
	if _, err = Install(t.Context(), s.root, "keyauth_"+strings.Repeat("e", 32), nil); !errors.Is(err, ErrConflict) {
		t.Fatal("install over another authority", err)
	}
	if armed, err := installed.Replicated(); err != nil || armed {
		t.Fatal("a promoted authority starts armed", err)
	}
}
