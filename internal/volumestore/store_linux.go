//go:build linux && cgo

// Package volumestore creates encrypted regular-file containers. Filesystem
// initialization happens inside the guest; this package never mounts images.
package volumestore

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

var (
	ErrInput    = errors.New("invalid volume reservation or key")
	ErrConflict = errors.New("volume reservation does not match")
	ErrState    = errors.New("volume journal or file identity is inconsistent")
	ErrBusy     = errors.New("volume is in use")
	ErrLUKS     = errors.New("encrypted volume initialization or key validation failed")
	ErrRemoved  = errors.New("volume is permanently retired")
)

type Spec struct {
	AgentID  string `json:"agent_id"`
	VolumeID string `json:"volume_id"`
	SizeMiB  int64  `json:"size_mib"`
}

// Container means a checked LUKS2 header, not an initialized private filesystem
// or an activated agent. Device/Inode bind subsequent host registration.
type Container struct {
	Spec          Spec
	Path, UUID    string
	Device, Inode uint64
}

// journal is a volume's state, in the data domain: archives and backups copy
// it, and it outlives the key's destruction (L-18). Version 2 identifies the
// key by HMAC-SHA256 under a random salt of the volume, KeySalt and KeyMAC:
// they bind retries to the same key, reveal nothing else of it, and differ
// for two volumes of one key. Version 1, before, held the key's SHA-256 in
// KeyHash; Prepare replaces it with version 2's identifier. A removal clears
// the identifier: the key was revoked before.
type journal struct {
	Version       int    `json:"version"`
	Spec          Spec   `json:"spec"`
	KeyHash       string `json:"key_hash,omitempty"`
	KeySalt       string `json:"key_salt,omitempty"`
	KeyMAC        string `json:"key_mac,omitempty"`
	Stage         string `json:"stage"`
	Device, Inode uint64
}

// identify sets the version 2 identifier of key, under a new salt.
func (j *journal) identify(key []byte) {
	salt := make([]byte, 32)
	_, _ = rand.Read(salt)
	j.Version, j.KeyHash, j.KeySalt, j.KeyMAC = 2, "", hex.EncodeToString(salt), hex.EncodeToString(keyMAC(salt, key))
}

// forget clears the identifier of the key, of either version.
func (j *journal) forget() {
	j.Version, j.KeyHash, j.KeySalt, j.KeyMAC = 2, "", "", ""
}

// identifies reports whether key is the journal's.
func (j journal) identifies(key []byte) bool {
	switch j.Version {
	case 1:
		sum := sha256.Sum256(key)
		return subtle.ConstantTimeCompare([]byte(hex.EncodeToString(sum[:])), []byte(j.KeyHash)) == 1
	case 2:
		salt, err1 := hex.DecodeString(j.KeySalt)
		mac, err2 := hex.DecodeString(j.KeyMAC)
		return err1 == nil && err2 == nil && len(salt) == 32 && hmac.Equal(mac, keyMAC(salt, key))
	}
	return false
}

func keyMAC(salt, key []byte) []byte {
	m := hmac.New(sha256.New, salt)
	m.Write(key)
	return m.Sum(nil)
}

// identified: the journal holds a well-formed identifier of its version, or,
// once its volume is removed, none (version 2).
func (j journal) identified() bool {
	hex64 := func(s string) bool { b, err := hex.DecodeString(s); return err == nil && len(b) == 32 }
	removed := j.Stage == "REMOVING" || j.Stage == "REMOVED"
	switch j.Version {
	case 1:
		return hex64(j.KeyHash) && j.KeySalt == "" && j.KeyMAC == ""
	case 2:
		return j.KeyHash == "" && (hex64(j.KeySalt) && hex64(j.KeyMAC) || removed && j.KeySalt == "" && j.KeyMAC == "")
	}
	return false
}

type Store struct {
	root string
	// Tests interrupt the real process after durable boundaries.
	hook func(string)
}

// New requires a trusted parent hierarchy. The root and its managed directories
// must be private, owned by this process, and free of symlink indirection.
func New(root string) (*Store, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	for _, p := range []string{abs, filepath.Join(abs, "volumes"), filepath.Join(abs, "volume-state")} {
		if err = os.MkdirAll(p, 0700); err != nil {
			return nil, err
		}
		real, err := filepath.EvalSymlinks(p)
		if err != nil || real != p {
			return nil, ErrState
		}
		st, err := os.Stat(p)
		if err != nil {
			return nil, err
		}
		if !st.IsDir() || st.Mode().Perm() != 0700 || st.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) {
			return nil, ErrState
		}
		if err = syncDir(filepath.Dir(p)); err != nil {
			return nil, err
		}
	}
	return &Store{root: abs}, nil
}

func identifier(id, prefix string) bool {
	if len(id) != len(prefix)+32 || !strings.HasPrefix(id, prefix) {
		return false
	}
	_, err := hex.DecodeString(id[len(prefix):])
	return err == nil && strings.ToLower(id) == id
}

func (s Spec) uuid() string {
	h := s.VolumeID[4:]
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

func syncDir(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

func file(path string, create bool) (*os.File, error) {
	flags := os.O_RDWR | syscall.O_NOFOLLOW | syscall.O_NONBLOCK
	if create {
		flags |= os.O_CREATE | os.O_EXCL
	}
	f, err := os.OpenFile(path, flags, 0600)
	if err != nil {
		return nil, err
	}
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm() != 0600 {
		f.Close()
		return nil, ErrState
	}
	return f, nil
}

func flock(ctx context.Context, f *os.File, wait bool) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return nil
		}
		if err != syscall.EWOULDBLOCK && err != syscall.EAGAIN {
			return err
		}
		if !wait {
			return ErrBusy
		}
		timer := time.NewTimer(10 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func load(path string) (journal, error) {
	var j journal
	f, err := file(path, false)
	if err != nil {
		return j, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || st.Size() > 4096 || st.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) {
		return j, ErrState
	}
	d := json.NewDecoder(io.LimitReader(f, 4097))
	d.DisallowUnknownFields()
	if err = d.Decode(&j); err != nil {
		return j, ErrState
	}
	var extra any
	if d.Decode(&extra) != io.EOF || !j.identified() || (j.Stage != "PREPARING" && j.Stage != "READY" && j.Stage != "REMOVING" && j.Stage != "REMOVED") {
		return j, ErrState
	}
	return j, nil
}

func save(path string, j journal) error {
	b, err := json.Marshal(j)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".journal-")
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
	if err = os.Rename(f.Name(), path); err != nil {
		return err
	}
	return syncDir(filepath.Dir(path))
}

func (s *Store) boundary(name string) {
	if s.hook != nil {
		s.hook(name)
	}
}

func absence(path string) bool {
	_, err := os.Lstat(path)
	return errors.Is(err, os.ErrNotExist)
}

// Prepare requires the same durable, random 32-byte unlock secret on retries.
// Secret generation/wrapping belongs to the authority, before this operation.
// A cancellation during a native call is observed when it returns; it does not
// release locks while that call can still write. A process crash closes all
// native writers and locks together. No published file is ever formatted here.
func (s *Store) Prepare(ctx context.Context, spec Spec, key []byte) (Container, error) {
	var result Container
	if !identifier(spec.AgentID, "agt_") || !identifier(spec.VolumeID, "vol_") || spec.SizeMiB < 64 || spec.SizeMiB > 32768 || len(key) != 32 {
		return result, ErrInput
	}
	base := filepath.Join(s.root, "volume-state", spec.VolumeID)
	lock, err := file(base+".lock", true)
	if errors.Is(err, os.ErrExist) {
		lock, err = file(base+".lock", false)
	}
	if err != nil {
		return result, err
	}
	defer lock.Close()
	if err = flock(ctx, lock, true); err != nil {
		return result, err
	}
	path := filepath.Join(s.root, "volumes", spec.VolumeID+".luks")
	pending := filepath.Join(s.root, "volumes", spec.VolumeID+".pending")
	j, err := load(base + ".json")
	if errors.Is(err, os.ErrNotExist) {
		if !absence(path) || !absence(pending) {
			return result, ErrState
		}
		j = journal{Spec: spec, Stage: "PREPARING"}
		j.identify(key)
		err = save(base+".json", j)
	}
	if err != nil {
		return result, err
	}
	if j.Spec != spec {
		return result, ErrConflict
	}
	// A removed volume's journal no longer identifies its key.
	if j.Stage == "REMOVING" || j.Stage == "REMOVED" {
		return result, ErrRemoved
	}
	if !j.identifies(key) {
		return result, ErrConflict
	}
	if j.Version == 1 {
		// A journal written before the audit: the key's SHA-256 goes.
		j.identify(key)
		if err = save(base+".json", j); err != nil {
			return result, err
		}
	}
	s.boundary("reserved")
	// Publication may have reached disk before its final journal commit. Check
	// and adopt that exact inode; never treat its contents as a format candidate.
	final := !absence(path)
	if !final && j.Stage == "READY" {
		return result, ErrState
	}
	activePath := pending
	if final {
		activePath = path
	}
	f, err := file(activePath, false)
	if errors.Is(err, os.ErrNotExist) && !final && j.Inode == 0 {
		f, err = file(activePath, true)
	}
	if err != nil {
		return result, err
	}
	defer f.Close()
	if err = flock(ctx, f, false); err != nil {
		return result, err
	}
	st, err := f.Stat()
	if err != nil {
		return result, err
	}
	id := st.Sys().(*syscall.Stat_t)
	if (j.Inode != 0 && (j.Inode != id.Ino || j.Device != uint64(id.Dev))) || (final && j.Inode == 0) {
		return result, ErrState
	}
	if !final && j.Inode == 0 {
		if id.Uid != uint32(os.Geteuid()) || id.Nlink != 1 {
			return result, ErrState
		}
		if err = f.Truncate(spec.SizeMiB << 20); err != nil {
			return result, err
		}
		if err = f.Sync(); err != nil {
			return result, err
		}
		if err = syncDir(filepath.Dir(path)); err != nil {
			return result, err
		}
		j.Device, j.Inode = uint64(id.Dev), id.Ino
		if err = save(base+".json", j); err != nil {
			return result, err
		}
	}
	st, err = f.Stat()
	if err != nil || st.Size() != spec.SizeMiB<<20 {
		return result, ErrState
	}
	if err = ctx.Err(); err != nil {
		return result, err
	}
	s.boundary("allocated")
	// A committed container was checked before its publication; since then
	// its guest may have rewritten its header, or a restore installed an
	// archive's. libcryptsetup never reads that header in this process
	// (S-21): the journal, the inode and the key's identifier adopt it.
	if final && j.Stage == "READY" {
		return Container{Spec: spec, Path: path, UUID: spec.uuid(), Device: j.Device, Inode: j.Inode}, nil
	}
	if err = luks(activePath, spec.uuid(), key, false, nil); err != nil {
		if final {
			return result, err
		}
		// Only a reserved, unpublished inode can be restarted. No caller ever
		// receives its path until format, validation and publication complete.
		if err = f.Truncate(0); err != nil {
			return result, err
		}
		if err = f.Truncate(spec.SizeMiB << 20); err != nil {
			return result, err
		}
		if err = luks(activePath, spec.uuid(), key, true, func() { s.boundary("header_written") }); err != nil {
			return result, err
		}
		if err = luks(activePath, spec.uuid(), key, false, nil); err != nil {
			return result, err
		}
	}
	if err = f.Sync(); err != nil {
		return result, err
	}
	s.boundary("formatted")
	if err = ctx.Err(); err != nil {
		return result, err
	}
	if !final {
		// Link is atomic and refuses replacement. The temporary second name
		// refers to this same locked inode and is removed after directory sync.
		if err = os.Link(pending, path); err != nil {
			return result, err
		}
		if err = syncDir(filepath.Dir(path)); err != nil {
			return result, err
		}
	}
	s.boundary("published")
	if old, err := os.Lstat(pending); err == nil {
		x := old.Sys().(*syscall.Stat_t)
		if !old.Mode().IsRegular() || x.Ino != j.Inode || uint64(x.Dev) != j.Device {
			return result, ErrState
		}
		if err = os.Remove(pending); err != nil {
			return result, err
		}
		if err = syncDir(filepath.Dir(path)); err != nil {
			return result, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return result, err
	}
	j.Stage = "READY"
	if err = save(base+".json", j); err != nil {
		return result, err
	}
	s.boundary("committed")
	return Container{Spec: spec, Path: path, UUID: spec.uuid(), Device: j.Device, Inode: j.Inode}, nil
}

// Grow verifies the published inode and extends its reservation without changing
// its LUKS header. Only a retired volume under a recorded restore may be passed.
func (s *Store) Grow(ctx context.Context, spec Spec, target int64, device, inode uint64) error {
	if !identifier(spec.AgentID, "agt_") || !identifier(spec.VolumeID, "vol_") || spec.SizeMiB < 64 || target <= spec.SizeMiB || target > 32768 || inode == 0 {
		return ErrInput
	}
	base := filepath.Join(s.root, "volume-state", spec.VolumeID)
	lock, err := file(base+".lock", false)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err = flock(ctx, lock, true); err != nil {
		return err
	}
	j, err := load(base + ".json")
	if err != nil {
		return err
	}
	if j.Stage != "READY" || j.Spec.AgentID != spec.AgentID || j.Spec.VolumeID != spec.VolumeID || (j.Spec.SizeMiB != spec.SizeMiB && j.Spec.SizeMiB != target) || j.Device != device || j.Inode != inode {
		return ErrState
	}
	f, err := file(filepath.Join(s.root, "volumes", spec.VolumeID+".luks"), false)
	if err != nil {
		return err
	}
	defer f.Close()
	if err = flock(ctx, f, false); err != nil {
		return err
	}
	st, err := f.Stat()
	if err != nil {
		return err
	}
	id := st.Sys().(*syscall.Stat_t)
	if uint64(id.Dev) != device || id.Ino != inode || id.Nlink != 1 || (st.Size() != spec.SizeMiB<<20 && st.Size() != target<<20) {
		return ErrState
	}
	if err = f.Truncate(target << 20); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	j.Spec.SizeMiB = target
	return save(base+".json", j)
}
