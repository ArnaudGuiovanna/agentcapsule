//go:build linux && cgo

// Package volumearchive publishes coherent ciphertext and its authenticated
// manifest as one immutable directory. It stores no decryption key. The local
// archive root must be outside runtime, key and authority restore domains.
// Remove deletes an archive in one step, for local retention. Off-host
// replication is a separate storage integration.
package volumearchive

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/restoreauthority"
)

var ErrArchive = errors.New("encrypted archive is missing, inconsistent or incomplete")

type Store struct {
	root          string
	device, inode uint64
	hook          func(string) // real publication/crash boundaries in tests
}

type Spec struct {
	ID            string
	Binding       restoreauthority.Binding
	HarnessDigest string
	Size          int64
}

func New(root string) (*Store, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	if err = os.MkdirAll(abs, 0700); err != nil {
		return nil, err
	}
	real, err := filepath.EvalSymlinks(abs)
	if err != nil || real != abs {
		return nil, ErrArchive
	}
	st, err := os.Stat(abs)
	if err != nil {
		return nil, err
	}
	x := st.Sys().(*syscall.Stat_t)
	if !st.IsDir() || st.Mode().Perm() != 0700 || x.Uid != uint32(os.Geteuid()) {
		return nil, ErrArchive
	}
	if err = syncDir(filepath.Dir(abs)); err != nil {
		return nil, err
	}
	return &Store{root: abs, device: uint64(x.Dev), inode: x.Ino}, nil
}

func (s *Store) Root() string { return s.root }

func (s *Store) check() error {
	st, err := os.Lstat(s.root)
	if err != nil {
		return err
	}
	x := st.Sys().(*syscall.Stat_t)
	if !st.IsDir() || st.Mode().Perm() != 0700 || x.Uid != uint32(os.Geteuid()) || uint64(x.Dev) != s.device || x.Ino != s.inode {
		return ErrArchive
	}
	return nil
}

// ValidID checks the stable archive identifier before an operator action can
// stop a guest. Reuse the same ID only to retry the same capture operation.
func ValidID(id string) bool {
	if len(id) != 36 || !strings.HasPrefix(id, "arc_") || strings.ToLower(id) != id {
		return false
	}
	_, err := hex.DecodeString(id[4:])
	return err == nil
}

func syncDir(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

func privateFile(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	x := st.Sys().(*syscall.Stat_t)
	if !st.Mode().IsRegular() || st.Mode().Perm() != 0600 || x.Uid != uint32(os.Geteuid()) || x.Nlink != 1 {
		f.Close()
		return nil, ErrArchive
	}
	return f, nil
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r contextReader) Read(b []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(b)
}

// Manifest reads a published archive's manifest without authenticating it or
// hashing the ciphertext: enough to tell which agent an archive belongs to and
// its size, never enough to restore it (use Open). A missing archive is an
// error that matches os.ErrNotExist.
func (s *Store) Manifest(id string) (restoreauthority.Archive, error) {
	var a restoreauthority.Archive
	if !ValidID(id) {
		return a, ErrArchive
	}
	if err := s.check(); err != nil {
		return a, err
	}
	dir := filepath.Join(s.root, id)
	st, err := os.Lstat(dir)
	if err != nil {
		return a, err
	}
	if !st.IsDir() || st.Mode().Perm() != 0700 || st.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) {
		return a, ErrArchive
	}
	m, err := privateFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		return a, err
	}
	defer m.Close()
	info, err := m.Stat()
	if err != nil || info.Size() > 8192 {
		return a, ErrArchive
	}
	d := json.NewDecoder(io.LimitReader(m, 8193))
	d.DisallowUnknownFields()
	err = d.Decode(&a)
	var trailing any
	if err != nil || d.Decode(&trailing) != io.EOF || a.ID != id {
		return restoreauthority.Archive{}, ErrArchive
	}
	return a, nil
}

// Remove deletes a published archive. It first renames the archive out of
// its ID, in one step, so the archive is either whole or gone; the leftover
// is deleted at once, or by Sweep after a crash. A missing archive is not an
// error. Only a trusted retention policy calls it: it never checks that a
// newer archive exists.
func (s *Store) Remove(id string) error {
	if !ValidID(id) {
		return ErrArchive
	}
	if err := s.check(); err != nil {
		return err
	}
	final := filepath.Join(s.root, id)
	st, err := os.Lstat(final)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !st.IsDir() {
		return ErrArchive
	}
	nonce := make([]byte, 16)
	if _, err = rand.Read(nonce); err != nil {
		return err
	}
	removed := filepath.Join(s.root, removedPrefix+hex.EncodeToString(nonce))
	if err = os.Rename(final, removed); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if err = syncDir(s.root); err != nil {
		return err
	}
	return os.RemoveAll(removed)
}

const (
	pendingPrefix = ".pending-"
	removedPrefix = ".removed-"
)

// Sweep deletes what an interrupted capture or removal left in the root:
// staging directories untouched for staleAfter (a capture still writing
// touches its file), and archives already renamed for removal. It never
// touches a published archive.
func (s *Store) Sweep(staleAfter time.Duration) error {
	if staleAfter <= 0 {
		return ErrArchive
	}
	if err := s.check(); err != nil {
		return err
	}
	entries, err := os.ReadDir(s.root)
	if err != nil {
		return err
	}
	var result error
	for _, e := range entries {
		path := filepath.Join(s.root, e.Name())
		switch {
		case strings.HasPrefix(e.Name(), removedPrefix):
		case strings.HasPrefix(e.Name(), pendingPrefix):
			if latest, err := newest(path); err != nil || time.Since(latest) < staleAfter {
				result = errors.Join(result, err)
				continue
			}
		default:
			continue
		}
		result = errors.Join(result, os.RemoveAll(path))
	}
	return result
}

// newest is the latest modification time of a directory and its entries.
func newest(dir string) (time.Time, error) {
	st, err := os.Lstat(dir)
	if err != nil {
		return time.Time{}, err
	}
	latest := st.ModTime()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return latest, err
	}
	for _, e := range entries {
		if info, err := e.Info(); err == nil && info.ModTime().After(latest) {
			latest = info.ModTime()
		}
	}
	return latest, nil
}

// Open authenticates metadata and hashes the actual immutable local ciphertext.
// Its file descriptor remains on this inode. Untrusted remote objects must first
// be staged privately and verified; this is not a mutable remote-stream API.
func (s *Store) Open(ctx context.Context, id string, authority *restoreauthority.Catalog) (*os.File, restoreauthority.Archive, error) {
	if authority == nil {
		return nil, restoreauthority.Archive{}, ErrArchive
	}
	a, err := s.Manifest(id)
	if err != nil {
		return nil, restoreauthority.Archive{}, err
	}
	dir := filepath.Join(s.root, id)
	if err = authority.ValidateArchive(ctx, a); err != nil {
		return nil, restoreauthority.Archive{}, err
	}
	f, err := privateFile(filepath.Join(dir, "volume.luks"))
	if err != nil {
		return nil, restoreauthority.Archive{}, err
	}
	failed := true
	defer func() {
		if failed {
			f.Close()
		}
	}()
	info, err := f.Stat()
	if err != nil || info.Size() != a.Size {
		return nil, restoreauthority.Archive{}, ErrArchive
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(contextReader{ctx, f}, a.Size+1))
	if err != nil {
		return nil, restoreauthority.Archive{}, err
	}
	if n != a.Size || !bytes.Equal(h.Sum(nil), a.Digest[:]) {
		return nil, restoreauthority.Archive{}, ErrArchive
	}
	if err = authority.ValidateArchive(ctx, a); err != nil {
		return nil, restoreauthority.Archive{}, err
	}
	if err = s.check(); err != nil {
		return nil, restoreauthority.Archive{}, err
	}
	if _, err = f.Seek(0, io.SeekStart); err != nil {
		return nil, restoreauthority.Archive{}, err
	}
	failed = false
	return f, a, nil
}

// Capture requires a reader of a coherent, physically excluded ciphertext
// image. A stable ID makes a lost publication ACK retryable. Pending directories
// are never accepted as archives, and an existing complete archive is immutable.
func (s *Store) Capture(ctx context.Context, spec Spec, source io.Reader, authority *restoreauthority.Catalog) (restoreauthority.Archive, error) {
	var zero restoreauthority.Archive
	if !ValidID(spec.ID) || source == nil || authority == nil || spec.Size <= 0 || spec.Size > 32<<30 {
		return zero, ErrArchive
	}
	if err := s.check(); err != nil {
		return zero, err
	}
	replay := func() (restoreauthority.Archive, error) {
		f, a, err := s.Open(ctx, spec.ID, authority)
		if err != nil {
			return zero, err
		}
		f.Close()
		if a.Binding != spec.Binding || a.Size != spec.Size || a.HarnessDigest != spec.HarnessDigest {
			return zero, restoreauthority.ErrConflict
		}
		return a, nil
	}
	final := filepath.Join(s.root, spec.ID)
	if _, err := os.Lstat(final); err == nil {
		return replay()
	} else if !errors.Is(err, os.ErrNotExist) {
		return zero, err
	}
	stage, err := os.MkdirTemp(s.root, pendingPrefix)
	if err != nil {
		return zero, err
	}
	defer os.RemoveAll(stage)
	f, err := os.OpenFile(filepath.Join(stage, "volume.luks"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return zero, err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(contextReader{ctx, source}, spec.Size+1))
	if err == nil && n != spec.Size {
		err = ErrArchive
	}
	if err == nil {
		err = f.Sync()
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		return zero, err
	}
	if s.hook != nil {
		s.hook("image_synced")
	}
	a := restoreauthority.Archive{ID: spec.ID, Binding: spec.Binding, HarnessDigest: spec.HarnessDigest, Size: spec.Size}
	copy(a.Digest[:], h.Sum(nil))
	a, err = authority.SignArchive(ctx, a)
	if err != nil {
		return zero, err
	}
	data, err := json.Marshal(a)
	if err != nil {
		return zero, err
	}
	m, err := os.OpenFile(filepath.Join(stage, "manifest.json"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return zero, err
	}
	_, err = m.Write(append(data, '\n'))
	if err == nil {
		err = m.Sync()
	}
	err = errors.Join(err, m.Close())
	if err != nil {
		return zero, err
	}
	if err = syncDir(stage); err != nil {
		return zero, err
	}
	if s.hook != nil {
		s.hook("manifest_synced")
	}
	if err = ctx.Err(); err != nil {
		return zero, err
	}
	if err = s.check(); err != nil {
		return zero, err
	}
	// Rename cannot replace a complete (nonempty) archive directory. Concurrent
	// publication of this stable ID wins once and is then validated as a retry.
	if err = os.Rename(stage, final); err != nil {
		if _, statErr := os.Lstat(final); statErr == nil {
			return replay()
		}
		return zero, err
	}
	if s.hook != nil {
		s.hook("archive_published")
	}
	if err = syncDir(s.root); err != nil {
		return zero, err
	}
	if s.hook != nil {
		s.hook("archive_synced")
	}
	return a, nil
}
