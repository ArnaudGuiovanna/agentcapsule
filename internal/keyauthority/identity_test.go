//go:build linux

package keyauthority

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestAuthorityInitializationIsConcurrentAndIdentityIsPinned(t *testing.T) {
	root := filepath.Join(t.TempDir(), "authority")
	type outcome struct {
		s   *Files
		err error
	}
	results := make(chan outcome, 8)
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() { s, err := Initialize(t.Context(), root); results <- outcome{s, err} })
	}
	wg.Wait()
	close(results)
	var id string
	for o := range results {
		if o.err != nil {
			t.Fatal(o.err)
		}
		if id == "" {
			id = o.s.Identity()
		}
		if o.s.Identity() != id {
			t.Fatal("concurrent initialization assigned different identities")
		}
	}
	s, err := Open(root, id)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Ensure(t.Context(), testAgent, testVolume); err != nil {
		t.Fatal(err)
	}
	other := fixture(t)
	if _, err = Open(root, other.Identity()); !errors.Is(err, ErrUnavailable) {
		t.Fatal("wrong installation accepted", err)
	}
}

func TestMissingOrReplacedAuthorityFailsClosed(t *testing.T) {
	s := fixture(t)
	if err := s.Ensure(t.Context(), testAgent, testVolume); err != nil {
		t.Fatal(err)
	}
	oldHash := keyHash(t, s)
	retained := s.root + ".retained"
	if err := os.Rename(s.root, retained); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(s.root, s.Identity()); err == nil {
		t.Fatal("missing authority opened")
	}
	if _, err := os.Lstat(s.root); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("worker opening recreated missing authority", err)
	}
	if err := s.Ensure(t.Context(), testAgent, testVolume); !errors.Is(err, ErrUnavailable) {
		t.Fatal("stale provider recreated missing authority", err)
	}
	replacement, err := Initialize(t.Context(), s.root)
	if err != nil {
		t.Fatal(err)
	}
	if replacement.Identity() == s.Identity() {
		t.Fatal("replacement identity reused")
	}
	if _, err = Open(s.root, s.Identity()); !errors.Is(err, ErrUnavailable) {
		t.Fatal("replacement authority opened with old pin", err)
	}
	for _, op := range []func() error{
		func() error { return s.Ensure(t.Context(), testAgent, testVolume) },
		func() error {
			return s.WithKey(t.Context(), testAgent, testVolume, func([]byte) error { t.Error("replacement authority exposed secret"); return nil })
		},
		func() error { return s.Revoke(t.Context(), testAgent, testVolume) },
	} {
		if err = op(); !errors.Is(err, ErrUnavailable) {
			t.Fatal("old handle used replacement authority", err)
		}
	}
	for _, dir := range []string{"records", "revoked", "locks"} {
		entries, err := os.ReadDir(filepath.Join(s.root, dir))
		if err != nil || len(entries) != 0 {
			t.Fatal("old handle mutated replacement authority", err)
		}
	}
	original, err := Open(retained, s.Identity())
	if err != nil {
		t.Fatal(err)
	}
	if keyHash(t, original) != oldHash {
		t.Fatal("original key changed")
	}
}

func TestAuthorityIdentityCannotBeRecreatedOverExistingState(t *testing.T) {
	for _, revoked := range []bool{false, true} {
		name := "key"
		if revoked {
			name = "revocation"
		}
		t.Run(name, func(t *testing.T) {
			s := fixture(t)
			if revoked {
				if err := s.Revoke(t.Context(), testAgent, testVolume); err != nil {
					t.Fatal(err)
				}
			} else if err := s.Ensure(t.Context(), testAgent, testVolume); err != nil {
				t.Fatal(err)
			}
			identityPath := filepath.Join(s.root, "identity")
			if err := os.Remove(identityPath); err != nil {
				t.Fatal(err)
			}
			if _, err := Initialize(t.Context(), s.root); !errors.Is(err, ErrUnavailable) {
				t.Fatal("identity silently regenerated over prior state", err)
			}
			if _, err := os.Lstat(identityPath); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("identity file recreated", err)
			}
			if err := s.Ensure(t.Context(), testAgent, testVolume); !errors.Is(err, ErrUnavailable) {
				t.Fatal("unbound key operation allowed", err)
			}
		})
	}
}
