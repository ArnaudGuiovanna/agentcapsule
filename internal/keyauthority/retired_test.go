//go:build linux

package keyauthority

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"unsafe"
)

// lockFile is the volume's lock file, and whether it exists.
func lockExists(t *testing.T, s *Files, volume string) bool {
	t.Helper()
	_, err := os.Lstat(filepath.Join(s.root, "locks", volume))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	return err == nil
}

// L-18: a revocation removes the volume's lock file with its key. Later
// calls on the revoked volume answer as before (ErrRevoked, or nothing to
// do for a repeated revocation) and leave no lock file.
func TestRevocationRemovesTheVolumesLock(t *testing.T) {
	for _, journaled := range []bool{false, true} {
		t.Run(map[bool]string{false: "standalone", true: "journaled"}[journaled], func(t *testing.T) {
			s := fixture(t)
			if journaled {
				s.SetJournal(&fakeJournal{})
			}
			if err := s.Ensure(t.Context(), testAgent, testVolume); err != nil {
				t.Fatal(err)
			}
			keyHash(t, s)
			if !lockExists(t, s, testVolume) {
				t.Fatal("no lock file while the key lives")
			}
			if err := s.Revoke(t.Context(), testAgent, testVolume); err != nil {
				t.Fatal(err)
			}
			if lockExists(t, s, testVolume) {
				t.Fatal("the revocation left the lock file")
			}
			if err := s.WithKey(t.Context(), testAgent, testVolume, func([]byte) error { t.Error("revoked key exposed"); return nil }); !errors.Is(err, ErrRevoked) {
				t.Fatal(err)
			}
			if err := s.Ensure(t.Context(), testAgent, testVolume); !errors.Is(err, ErrRevoked) {
				t.Fatal(err)
			}
			if err := s.Revoke(t.Context(), testAgent, testVolume); err != nil {
				t.Fatal("a repeated revocation:", err)
			}
			if lockExists(t, s, testVolume) {
				t.Fatal("a call after the revocation left a lock file")
			}
		})
	}
}

// L-18: borrowers racing a revocation: each one either borrowed the key, or
// got ErrRevoked; none borrows it once the revocation returned, none holds a
// lock whose file the revocation removed, and no lock file remains.
func TestBorrowersRacingARevocationNeverShareARemovedLock(t *testing.T) {
	for round := range 20 {
		s := fixture(t)
		volume := fmt.Sprintf("vol_%032d", round)
		if err := s.Ensure(t.Context(), testAgent, volume); err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		var mu sync.Mutex
		revoked := false
		late := 0
		for range 8 {
			wg.Go(func() {
				for range 5 {
					err := s.WithKey(t.Context(), testAgent, volume, func([]byte) error {
						mu.Lock()
						defer mu.Unlock()
						if revoked {
							late++
						}
						return nil
					})
					if err != nil && !errors.Is(err, ErrRevoked) {
						t.Error(err)
					}
				}
			})
		}
		if err := s.Revoke(t.Context(), testAgent, volume); err != nil {
			t.Fatal(err)
		}
		mu.Lock()
		revoked = true
		mu.Unlock()
		wg.Wait()
		if late != 0 {
			t.Fatalf("round %d: %d borrowers got the key after its revocation", round, late)
		}
		if lockExists(t, s, volume) {
			t.Fatalf("round %d: a borrower left a lock file", round)
		}
	}
}

// L-18: Open removes the lock files that revocations left before: a revoked
// volume whose key is gone loses it, a live volume keeps its own.
func TestOpenRemovesTheLocksOfRevokedVolumes(t *testing.T) {
	s := fixture(t)
	live := "vol_" + strings.Repeat("c", 32)
	for _, v := range []string{testVolume, live} {
		if err := s.Ensure(t.Context(), testAgent, v); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Revoke(t.Context(), testAgent, testVolume); err != nil {
		t.Fatal(err)
	}
	// As a revocation before this version left it.
	if err := os.WriteFile(filepath.Join(s.root, "locks", testVolume), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(s.root, s.Identity())
	if err != nil {
		t.Fatal(err)
	}
	if lockExists(t, reopened, testVolume) || !lockExists(t, reopened, live) {
		t.Fatal("Open kept a revoked volume's lock, or removed a live one's")
	}
	if err = reopened.WithKey(t.Context(), testAgent, live, func([]byte) error { return nil }); err != nil {
		t.Fatal(err)
	}
}

// mapping returns the VmFlags of the mapping of this process that holds
// addr, from /proc/self/smaps, or "" when none does.
func mapping(t *testing.T, addr uintptr) string {
	t.Helper()
	f, err := os.Open("/proc/self/smaps")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	inside := false
	lines := bufio.NewScanner(f)
	for lines.Scan() {
		line := lines.Text()
		if fields := strings.Fields(line); len(fields) > 1 && strings.Contains(fields[0], "-") && !strings.HasSuffix(fields[0], ":") {
			start, end, _ := strings.Cut(fields[0], "-")
			a, err1 := strconv.ParseUint(start, 16, 64)
			b, err2 := strconv.ParseUint(end, 16, 64)
			inside = err1 == nil && err2 == nil && uint64(addr) >= a && uint64(addr) < b
			continue
		}
		if flags, ok := strings.CutPrefix(line, "VmFlags:"); ok && inside {
			return " " + strings.TrimSpace(flags) + " "
		}
	}
	return ""
}

// L-18: the key a callback borrows lies in a page of its own, outside the Go
// heap, locked in RAM (lo) and left out of core dumps (dd); once the
// callback returned, the page is cleared and unlocked. A key the authority
// makes is handled the same way: Ensure leaves none behind.
func TestBorrowedKeysLiveInLockedMemory(t *testing.T) {
	s := fixture(t)
	if err := s.Ensure(t.Context(), testAgent, testVolume); err != nil {
		t.Fatal(err)
	}
	var addr uintptr
	var page []byte // a test-only reference, to observe the release
	if err := s.WithKey(t.Context(), testAgent, testVolume, func(key []byte) error {
		addr = uintptr(unsafe.Pointer(&key[0]))
		page = key
		if flags := mapping(t, addr); !strings.Contains(flags, " lo ") || !strings.Contains(flags, " dd ") {
			t.Errorf("the borrowed key's mapping has flags %q: not locked, or dumped", flags)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if flags := mapping(t, addr); strings.Contains(flags, " lo ") {
		t.Errorf("the released page is still locked: %q", flags)
	}
	for _, b := range page {
		if b != 0 {
			t.Fatal("the released page holds the key")
		}
	}
}
