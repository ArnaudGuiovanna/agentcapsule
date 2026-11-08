//go:build linux

// Package keyauthority holds per-volume unlock secrets outside the data restore
// domain. The file provider does not attest forensic media erasure or removal of
// external copies; physical retirement of key holders is a worker obligation.
package keyauthority

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

var (
	ErrInput       = errors.New("invalid key binding")
	ErrUnavailable = errors.New("key authority material unavailable or inconsistent")
	ErrRevoked     = errors.New("volume key is revoked")
	ErrConflict    = errors.New("volume key belongs to a different binding")
)

// Provider deliberately exposes no unscoped key-returning API. A consumer must
// not retain the key after use. Revoke waits for active callbacks, but cannot
// retire a VM or clear copies made by a consumer outside this contract.
type Provider interface {
	Ensure(context.Context, string, string) error
	WithKey(context.Context, string, string, func([]byte) error) error
	Revoke(context.Context, string, string) error
}

type Files struct {
	root     string
	identity string
	hook     func(string)
}

const recordSize = 144 // magic(8), agent(36), volume(36), key(32), SHA-256(32)

// The parent hierarchy must be operator-controlled; root is kept outside every
// data backup/restore operation, and on a separate device when policy requires.
func openDirectories(root string, create bool) (*Files, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	for _, path := range []string{abs, filepath.Join(abs, "locks"), filepath.Join(abs, "records"), filepath.Join(abs, "revoked")} {
		if create {
			if err = os.MkdirAll(path, 0700); err != nil {
				return nil, err
			}
		}
		real, err := filepath.EvalSymlinks(path)
		if err != nil || real != path {
			return nil, ErrUnavailable
		}
		st, err := os.Stat(path)
		if err != nil || !st.IsDir() || st.Mode().Perm() != 0700 || st.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) {
			return nil, ErrUnavailable
		}
		if err = syncDir(filepath.Dir(path)); err != nil {
			return nil, err
		}
	}
	return &Files{root: abs}, nil
}

// SeparateFrom rejects a nested or identical data/authority path. Distinct paths
// alone are not proof of independent devices, snapshots, or operator backups.
func (s *Files) SeparateFrom(dataRoot string) error {
	abs, err := filepath.Abs(dataRoot)
	if err != nil {
		return err
	}
	// Resolve the existing ancestor even when the final data directory has not
	// been created yet. A symlink plus a missing suffix must not bypass nesting.
	base := abs
	for {
		if _, err = os.Lstat(base); err == nil {
			real, e := filepath.EvalSymlinks(base)
			if e != nil {
				return e
			}
			suffix, e := filepath.Rel(base, abs)
			if e != nil {
				return e
			}
			abs = filepath.Join(real, suffix)
			break
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		base = filepath.Dir(base)
	}
	for _, pair := range [][2]string{{s.root, abs}, {abs, s.root}} {
		rel, err := filepath.Rel(pair[0], pair[1])
		if err != nil || (rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator))) {
			return ErrInput
		}
	}
	return nil
}

func valid(id, prefix string) bool {
	if len(id) != len(prefix)+32 || !strings.HasPrefix(id, prefix) {
		return false
	}
	_, err := hex.DecodeString(id[len(prefix):])
	return err == nil && strings.ToLower(id) == id
}

func (s *Files) withLock(ctx context.Context, agent, volume string, exclusive bool, fn func() error) error {
	if !valid(agent, "agt_") || !valid(volume, "vol_") {
		return ErrInput
	}
	if err := s.checkIdentity(); err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Join(s.root, "locks", volume), os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm() != 0600 || st.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) {
		return ErrUnavailable
	}
	if err = lockFile(ctx, f, exclusive); err != nil {
		return err
	}
	if err = s.checkIdentity(); err != nil {
		return err
	}
	return fn()
}

func lockFile(ctx context.Context, f *os.File, exclusive bool) error {
	mode := syscall.LOCK_SH
	if exclusive {
		mode = syscall.LOCK_EX
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		err := syscall.Flock(int(f.Fd()), mode|syscall.LOCK_NB)
		if err == nil {
			break
		}
		if err != syscall.EWOULDBLOCK && err != syscall.EAGAIN {
			return err
		}
		timer := time.NewTimer(10 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
	return nil
}

func read(path, magic, agent, volume string) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm() != 0600 || st.Size() != recordSize || st.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) {
		return nil, ErrUnavailable
	}
	b := make([]byte, recordSize)
	if _, err = io.ReadFull(f, b); err != nil {
		clear(b)
		return nil, ErrUnavailable
	}
	h := sha256.Sum256(b[:112])
	if string(b[:8]) != magic || string(b[112:]) != string(h[:]) {
		clear(b)
		return nil, ErrUnavailable
	}
	if string(b[8:44]) != agent || string(b[44:80]) != volume {
		clear(b)
		return nil, ErrConflict
	}
	return b, nil
}

func record(magic, agent, volume string, key []byte) []byte {
	b := make([]byte, recordSize)
	copy(b[:8], magic)
	copy(b[8:44], agent)
	copy(b[44:80], volume)
	copy(b[80:112], key)
	h := sha256.Sum256(b[:112])
	copy(b[112:], h[:])
	return b
}

func syncDir(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

// Publish one complete record without overwriting an existing record. Temp
// files live in a private directory; interrupted ones are never adopted as keys.
func publish(path string, b []byte, afterSync, afterLink func()) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".pending-"+filepath.Base(path)+"-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if _, err = f.Write(b); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if afterSync != nil {
		afterSync()
	}
	if err = os.Link(f.Name(), path); err != nil {
		return err
	}
	if err = syncDir(filepath.Dir(path)); err != nil {
		return err
	}
	if afterLink != nil {
		afterLink()
	}
	return nil
}

func (s *Files) boundary(name string) {
	if s.hook != nil {
		s.hook(name)
	}
}

// Remove only this binding's incomplete private records while holding its
// exclusive lock. A crash after link publication can leave another name for
// the key inode; revocation must remove that name as well as the final record.
func (s *Files) cleanTemps(directory, volume string) error {
	dir := filepath.Join(s.root, directory)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), ".pending-"+volume+"-") &&
			!strings.HasPrefix(entry.Name(), ".pending-"+volume+".allocated-") {
			continue
		}
		st, err := entry.Info()
		if err != nil || !st.Mode().IsRegular() || st.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) {
			return ErrUnavailable
		}
		if err = os.Remove(filepath.Join(dir, entry.Name())); err != nil {
			return err
		}
	}
	return syncDir(dir)
}

func (s *Files) allocation(agent, volume string, create bool) error {
	path := filepath.Join(s.root, "records", volume+".allocated")
	b, err := read(path, "ACPALO01", agent, volume)
	clear(b)
	if err == nil {
		return nil
	}
	if !create || !errors.Is(err, os.ErrNotExist) {
		return ErrUnavailable
	}
	b = record("ACPALO01", agent, volume, nil)
	defer clear(b)
	return publish(path, b, nil, nil)
}

func (s *Files) revoked(agent, volume string) error {
	b, err := read(filepath.Join(s.root, "revoked", volume), "ACPREV01", agent, volume)
	clear(b)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	return ErrRevoked
}

func (s *Files) Ensure(ctx context.Context, agent, volume string) error {
	return s.withLock(ctx, agent, volume, true, func() error {
		if err := s.revoked(agent, volume); err != nil {
			return err
		}
		if err := s.cleanTemps("records", volume); err != nil {
			return err
		}
		path := filepath.Join(s.root, "records", volume)
		b, err := read(path, "ACPKEY01", agent, volume)
		if err == nil {
			clear(b)
			return s.allocation(agent, volume, true)
		}
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		// A separate permanent allocation marker prevents regeneration after a
		// published key disappears. Until key publication no volume can use it.
		allocated := filepath.Join(s.root, "records", volume+".allocated")
		if _, err := os.Lstat(allocated); err == nil || !errors.Is(err, os.ErrNotExist) {
			return ErrUnavailable
		}
		key := make([]byte, 32)
		_, _ = rand.Read(key)
		defer clear(key)
		b = record("ACPKEY01", agent, volume, key)
		defer clear(b)
		if err = publish(path, b, func() { s.boundary("key_written") }, func() { s.boundary("key_linked") }); err != nil {
			return err
		}
		s.boundary("key_published")
		return s.allocation(agent, volume, true)
	})
}

func (s *Files) WithKey(ctx context.Context, agent, volume string, use func([]byte) error) error {
	if use == nil {
		return ErrInput
	}
	return s.withLock(ctx, agent, volume, false, func() error {
		if err := s.revoked(agent, volume); err != nil {
			return err
		}
		if err := s.allocation(agent, volume, false); err != nil {
			return err
		}
		b, err := read(filepath.Join(s.root, "records", volume), "ACPKEY01", agent, volume)
		if err != nil {
			return ErrUnavailable
		}
		defer clear(b)
		if err = syncDir(filepath.Join(s.root, "records")); err != nil {
			return err
		}
		return use(b[80:112])
	})
}

// Revoke durably denies future access before unlinking the managed key. The
// tombstone must outlive all data backups. This is not proof that an external
// copy, a former key holder's memory, or raw storage cannot contain the key.
func (s *Files) Revoke(ctx context.Context, agent, volume string) error {
	return s.withLock(ctx, agent, volume, true, func() error {
		err := s.revoked(agent, volume)
		if err != nil && !errors.Is(err, ErrRevoked) {
			return err
		}
		path := filepath.Join(s.root, "records", volume)
		if b, e := read(path, "ACPKEY01", agent, volume); e == nil {
			clear(b)
		} else if !errors.Is(e, os.ErrNotExist) {
			return e
		}
		if err == nil {
			marker := record("ACPREV01", agent, volume, nil)
			defer clear(marker)
			if err = publish(filepath.Join(s.root, "revoked", volume), marker, nil, func() { s.boundary("revocation_linked") }); err != nil {
				return err
			}
		}
		// A previous call may have linked the tombstone but failed its directory
		// sync. A successful retry must durably establish it before removing keys.
		if err = syncDir(filepath.Join(s.root, "revoked")); err != nil {
			return err
		}
		s.boundary("revocation_published")
		if err = s.cleanTemps("records", volume); err != nil {
			return err
		}
		if err = s.cleanTemps("revoked", volume); err != nil {
			return err
		}
		if err = os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return syncDir(filepath.Dir(path))
	})
}
