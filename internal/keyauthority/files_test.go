//go:build linux

package keyauthority

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

var testAgent = "agt_" + strings.Repeat("a", 32)
var testVolume = "vol_" + strings.Repeat("b", 32)

func fixture(t *testing.T) *Files {
	t.Helper()
	s, err := Initialize(t.Context(), filepath.Join(t.TempDir(), "authority"))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func keyHash(t *testing.T, s *Files) [32]byte {
	t.Helper()
	var digest [32]byte
	if err := s.WithKey(t.Context(), testAgent, testVolume, func(key []byte) error {
		if len(key) != 32 {
			return errors.New("unexpected key length")
		}
		digest = sha256.Sum256(key)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return digest
}

func TestConcurrentCreationPreservesKeyAndBinding(t *testing.T) {
	s := fixture(t)
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for range 8 {
		wg.Go(func() { errs <- s.Ensure(t.Context(), testAgent, testVolume) })
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	first := keyHash(t, s)
	reopened, err := Open(s.root, s.Identity())
	if err != nil {
		t.Fatal(err)
	}
	if err = reopened.Ensure(t.Context(), testAgent, testVolume); err != nil {
		t.Fatal(err)
	}
	if keyHash(t, reopened) != first {
		t.Fatal("reopen replaced key")
	}
	other := "agt_" + strings.Repeat("c", 32)
	if err = s.Ensure(t.Context(), other, testVolume); !errors.Is(err, ErrConflict) {
		t.Fatal("rebound key", err)
	}
	if err = s.WithKey(t.Context(), other, testVolume, func([]byte) error { t.Error("wrong agent received key"); return nil }); err == nil {
		t.Fatal("wrong binding accepted")
	}
	if err = s.Revoke(t.Context(), other, testVolume); !errors.Is(err, ErrConflict) {
		t.Fatal("wrong agent revoked key", err)
	}
	if keyHash(t, s) != first {
		t.Fatal("binding rejection changed key")
	}
}

func TestKeyBorrowClearsBufferAndRevocationWaits(t *testing.T) {
	s := fixture(t)
	if err := s.Ensure(t.Context(), testAgent, testVolume); err != nil {
		t.Fatal(err)
	}
	var borrowed []byte // Test-only reference to observe cleanup, never a copy.
	callbackError := errors.New("callback failed")
	if err := s.WithKey(t.Context(), testAgent, testVolume, func(key []byte) error {
		borrowed = key
		return callbackError
	}); !errors.Is(err, callbackError) {
		t.Fatal("callback error lost", err)
	}
	if !bytes.Equal(borrowed, make([]byte, 32)) {
		t.Fatal("borrowed buffer retained secret")
	}
	entered, release, finished := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		finished <- s.WithKey(t.Context(), testAgent, testVolume, func([]byte) error {
			close(entered)
			<-release
			return nil
		})
	}()
	<-entered
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	err := s.Revoke(ctx, testAgent, testVolume)
	cancel()
	close(release)
	if useErr := <-finished; useErr != nil {
		t.Fatal(useErr)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("revocation bypassed active key borrower", err)
	}
	keyHash(t, s) // Cancelled revocation must not have published a tombstone.
	if err = s.Revoke(t.Context(), testAgent, testVolume); err != nil {
		t.Fatal(err)
	}
	if err = s.WithKey(t.Context(), testAgent, testVolume, func([]byte) error { t.Error("revoked key exposed"); return nil }); !errors.Is(err, ErrRevoked) {
		t.Fatal(err)
	}
}

func TestRevocationSurvivesRestoredKeyAndPrecedesCreation(t *testing.T) {
	s := fixture(t)
	if err := s.Ensure(t.Context(), testAgent, testVolume); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(s.root, "records", testVolume)
	backup, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(backup)
	if err = s.Revoke(t.Context(), testAgent, testVolume); err != nil {
		t.Fatal(err)
	}
	// Restore only key material, never the independent revocation catalogue.
	if err = os.WriteFile(path, backup, 0600); err != nil {
		t.Fatal(err)
	}
	if err = s.Ensure(t.Context(), testAgent, testVolume); !errors.Is(err, ErrRevoked) {
		t.Fatal("restored key resurrected", err)
	}
	if err = s.WithKey(t.Context(), testAgent, testVolume, func([]byte) error { t.Error("restored revoked key exposed"); return nil }); !errors.Is(err, ErrRevoked) {
		t.Fatal(err)
	}
	if err = s.Revoke(t.Context(), testAgent, testVolume); err != nil {
		t.Fatal("repeat revoke", err)
	}
	if _, err = os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("restored managed key not removed", err)
	}
	volume := "vol_" + strings.Repeat("d", 32)
	if err = s.Revoke(t.Context(), testAgent, volume); err != nil {
		t.Fatal(err)
	}
	if err = s.Ensure(t.Context(), testAgent, volume); !errors.Is(err, ErrRevoked) {
		t.Fatal("revoked unused identity allocated", err)
	}
}

func TestLostOrDamagedPublishedKeyIsNeverRecreated(t *testing.T) {
	for _, damage := range []string{"missing", "truncated", "checksum", "permissions", "symlink"} {
		t.Run(damage, func(t *testing.T) {
			s := fixture(t)
			if err := s.Ensure(t.Context(), testAgent, testVolume); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(s.root, "records", testVolume)
			var err error
			switch damage {
			case "missing":
				err = os.Remove(path)
			case "truncated":
				err = os.Truncate(path, 16)
			case "checksum":
				var b []byte
				b, err = os.ReadFile(path)
				if err == nil {
					b[80] ^= 1
					err = os.WriteFile(path, b, 0600)
					clear(b)
				}
			case "permissions":
				err = os.Chmod(path, 0644)
			case "symlink":
				err = os.Rename(path, path+".external")
				if err == nil {
					err = os.Symlink(path+".external", path)
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			if err = s.Ensure(t.Context(), testAgent, testVolume); err == nil {
				t.Fatal("damaged published key regenerated")
			}
			if err = s.WithKey(t.Context(), testAgent, testVolume, func([]byte) error { t.Error("damaged key exposed"); return nil }); err == nil {
				t.Fatal("damaged key accepted")
			}
			if damage == "missing" {
				if _, err = os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("missing key replaced", err)
				}
			}
		})
	}
}

func TestPrivateDirectoriesAndRestoreSeparation(t *testing.T) {
	s := fixture(t)
	for _, path := range []string{s.root, filepath.Dir(s.root), filepath.Join(s.root, "future-data")} {
		if err := s.SeparateFrom(path); !errors.Is(err, ErrInput) {
			t.Fatal("overlapping restore domain", err)
		}
	}
	alias := filepath.Join(filepath.Dir(s.root), "alias")
	if err := os.Symlink(s.root, alias); err != nil {
		t.Fatal(err)
	}
	if err := s.SeparateFrom(filepath.Join(alias, "not-created")); !errors.Is(err, ErrInput) {
		t.Fatal("symlink bypassed separation", err)
	}
	if err := s.SeparateFrom(filepath.Join(filepath.Dir(s.root), "data")); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(alias, s.Identity()); !errors.Is(err, ErrUnavailable) {
		t.Fatal("symlink authority accepted", err)
	}
	if err := os.Chmod(s.root, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(s.root, s.Identity()); !errors.Is(err, ErrUnavailable) {
		t.Fatal("public authority directory accepted", err)
	}
}

type crashInput struct{ Root, Boundary, AuthorityID string }

func TestKeyAuthorityProcessCrashRecovery(t *testing.T) {
	for _, boundary := range []string{"key_written", "key_linked", "key_published", "revocation_linked", "revocation_published"} {
		t.Run(boundary, func(t *testing.T) {
			s := fixture(t)
			revoking := strings.HasPrefix(boundary, "revocation_")
			if revoking {
				if err := s.Ensure(t.Context(), testAgent, testVolume); err != nil {
					t.Fatal(err)
				}
				// Simulate a raw-key alias left by an earlier interrupted publish.
				if err := os.Link(filepath.Join(s.root, "records", testVolume), filepath.Join(s.root, "records", ".pending-"+testVolume+"-orphan")); err != nil {
					t.Fatal(err)
				}
			}
			input, err := json.Marshal(crashInput{s.root, boundary, s.Identity()})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestKeyAuthorityCrashChild$")
			cmd.Env = append(os.Environ(), "AGENTCAPSULE_KEY_CHILD=1")
			cmd.Stdin = bytes.NewReader(input)
			if output, err := cmd.CombinedOutput(); err == nil || cmd.ProcessState == nil || cmd.ProcessState.ExitCode() != 93 || len(output) != 0 {
				t.Fatalf("child failed to stop at %s (output withheld): %v", boundary, err)
			}
			path := filepath.Join(s.root, "records", testVolume)
			before, err := os.ReadFile(path)
			if err != nil && !(boundary == "key_written" && errors.Is(err, os.ErrNotExist)) {
				t.Fatal(err)
			}
			defer clear(before)
			if revoking {
				if err = s.WithKey(t.Context(), testAgent, testVolume, func([]byte) error { t.Error("incomplete revoke exposed key"); return nil }); !errors.Is(err, ErrRevoked) {
					t.Fatal(err)
				}
				if err = s.Revoke(t.Context(), testAgent, testVolume); err != nil {
					t.Fatal("revoke cannot resume", err)
				}
				if err = s.Ensure(t.Context(), testAgent, testVolume); !errors.Is(err, ErrRevoked) {
					t.Fatal("revoked key recreated", err)
				}
				if _, err = os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("managed key survived revocation", err)
				}
			} else {
				if err = s.WithKey(t.Context(), testAgent, testVolume, func([]byte) error { t.Error("unfinished allocation exposed key"); return nil }); err == nil {
					t.Fatal("unfinished allocation accepted")
				}
				if err = s.Ensure(t.Context(), testAgent, testVolume); err != nil {
					t.Fatal("allocation cannot resume", err)
				}
				keyHash(t, s)
				if before != nil {
					after, err := os.ReadFile(path)
					if err != nil {
						t.Fatal(err)
					}
					same := bytes.Equal(before, after)
					clear(after)
					if !same {
						t.Fatal("published key changed after crash")
					}
				}
			}
			for _, dir := range []string{"records", "revoked"} {
				entries, err := os.ReadDir(filepath.Join(s.root, dir))
				if err != nil {
					t.Fatal(err)
				}
				for _, e := range entries {
					if strings.HasPrefix(e.Name(), ".pending-") {
						t.Fatal("private alias survived completed recovery")
					}
				}
			}
		})
	}
}

func TestKeyAuthorityCrashChild(t *testing.T) {
	if os.Getenv("AGENTCAPSULE_KEY_CHILD") != "1" {
		return
	}
	var input crashInput
	if err := json.NewDecoder(os.Stdin).Decode(&input); err != nil {
		os.Exit(94)
	}
	s, err := Open(input.Root, input.AuthorityID)
	if err != nil {
		os.Exit(95)
	}
	s.hook = func(boundary string) {
		if boundary == input.Boundary {
			os.Exit(93)
		}
	}
	if strings.HasPrefix(input.Boundary, "revocation_") {
		err = s.Revoke(context.Background(), testAgent, testVolume)
	} else {
		err = s.Ensure(context.Background(), testAgent, testVolume)
	}
	if err != nil {
		os.Exit(96)
	}
	os.Exit(97)
}
