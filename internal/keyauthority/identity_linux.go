//go:build linux

package keyauthority

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

// Identity is public configuration, not an encryption key. Pin it separately
// from the data restore domain. It detects an accidentally replaced authority;
// it cannot detect rollback of an authority backup carrying the same identity.
func (s *Files) Identity() string { return s.identity }

func readIdentity(root string) (string, error) {
	f, err := os.OpenFile(filepath.Join(root, "identity"), os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return "", err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm() != 0600 || st.Size() != 40 || st.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) {
		return "", ErrUnavailable
	}
	var b [40]byte
	if _, err = io.ReadFull(f, b[:]); err != nil {
		return "", ErrUnavailable
	}
	id := string(b[:])
	if !valid(id, "keyauth_") {
		return "", ErrUnavailable
	}
	return id, nil
}

func (s *Files) checkIdentity() error {
	id, err := readIdentity(s.root)
	if err != nil || s.identity == "" || id != s.identity {
		return ErrUnavailable
	}
	return nil
}

// Open requires an existing authority and an independently configured expected
// identity. It never creates directories, identities or keys on startup.
func Open(root, expectedIdentity string) (*Files, error) {
	if !valid(expectedIdentity, "keyauth_") {
		return nil, ErrInput
	}
	s, err := openDirectories(root, false)
	if err != nil {
		return nil, err
	}
	s.identity = expectedIdentity
	if err = s.checkIdentity(); err != nil {
		return nil, err
	}
	return s, nil
}

// Initialize is an explicit administrative operation for a new installation.
// The returned identity must be pinned in worker configuration before use.
// Repeated calls preserve the identity, but never repair its disappearance from
// an authority that already contains volume allocations, locks or revocations.
func Initialize(ctx context.Context, root string) (*Files, error) {
	s, err := openDirectories(root, true)
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(s.root, "initialize.lock"), os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm() != 0600 || st.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) {
		return nil, ErrUnavailable
	}
	if err = lockFile(ctx, f, true); err != nil {
		return nil, err
	}
	id, err := readIdentity(s.root)
	if err == nil {
		if err = syncDir(s.root); err != nil {
			return nil, err
		}
		s.identity = id
		return s, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	for _, name := range []string{"locks", "records", "revoked"} {
		entries, err := os.ReadDir(filepath.Join(s.root, name))
		if err != nil || len(entries) != 0 {
			return nil, ErrUnavailable
		}
	}
	var random [16]byte
	_, _ = rand.Read(random[:])
	id = "keyauth_" + hex.EncodeToString(random[:])
	if err = publish(filepath.Join(s.root, "identity"), []byte(id), nil, nil); err != nil {
		return nil, err
	}
	s.identity = id
	return s, nil
}
