//go:build linux

package runtime

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"
)

// The host registry (registry.json) is the durable record of the host's
// agents and their VM runs. Each worker process keeps the last version it
// read or wrote in memory and writes every change through, durably, under
// host.lock (ADR 014 §11). A version another process wrote is read again: the
// cached file stays open, so that its inode number cannot be given to another
// file, and any other inode, size or time means another version.
//
// host.lock is held only for short state transitions: no guest RPC, SQL,
// authority call, volume copy or boot wait runs under it. Those run under the
// agent's own lock (lockAgent), and admission under the agent's own queue
// (firecracker_admission_linux.go).

// registryVersion 3 moved the admission queue out of the registry, into a
// file of its own with one queue per agent. A worker that reads version 2
// cannot run beside one that writes version 3, and refuses the file.
const registryVersion = 3

// fileID tells two versions of a file apart.
type fileID struct {
	dev, ino     uint64
	size         int64
	mtime, ctime int64
}

func fileIdentity(st os.FileInfo) fileID {
	s := st.Sys().(*syscall.Stat_t)
	return fileID{dev: uint64(s.Dev), ino: s.Ino, size: st.Size(), mtime: s.Mtim.Nano(), ctime: s.Ctim.Nano()}
}

// registryCache is the version of registry.json last read or written. reg is
// never changed in place: readers clone it.
type registryCache struct {
	reg *hostRegistry
	raw []byte
	id  fileID
	pin *os.File // nil when the file did not exist
}

func (r *hostRegistry) clone() *hostRegistry {
	c := &hostRegistry{Version: r.Version, Agents: make(map[string]*HostAgent, len(r.Agents))}
	for id, a := range r.Agents {
		c.Agents[id] = a.clone()
	}
	return c
}

func (a *HostAgent) clone() *HostAgent {
	c := *a
	if a.SystemImage != nil {
		s := *a.SystemImage
		c.SystemImage = &s
	}
	if a.Run != nil {
		r := *a.Run
		c.Run = &r
	}
	if a.Harness != nil {
		h := *a.Harness
		h.Entrypoint = slices.Clone(a.Harness.Entrypoint)
		c.Harness = &h
	}
	c.Corpora = slices.Clone(a.Corpora)
	if a.Build != nil {
		b := *a.Build
		c.Build = &b
	}
	return &c
}

func (h *FirecrackerHost) registryPath() string { return filepath.Join(h.root, "registry.json") }

// flockWait takes a kernel lock that another process may hold. Within this
// process the caller's own lock already serializes the waiters, so a wait
// here is another process's short section: it is polled, bounded by ctx.
func flockWait(ctx context.Context, f *os.File, mode int) error {
	delay := time.Millisecond
	for {
		err := syscall.Flock(int(f.Fd()), mode|syscall.LOCK_NB)
		if err == nil {
			return nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
		}
		delay = min(2*delay, 20*time.Millisecond)
	}
}

// locked runs fn on a copy of the current registry under host.lock. fn
// persists its changes with save; a change it does not save is dropped.
func (h *FirecrackerHost) locked(ctx context.Context, fn func(*hostRegistry) error) error {
	h.registryMu.Lock()
	defer h.registryMu.Unlock()
	f, err := os.OpenFile(filepath.Join(h.root, "host.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	if err = flockWait(ctx, f, syscall.LOCK_EX); err != nil {
		return err
	}
	defer syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	r, err := h.loadRegistry()
	if err != nil {
		return err
	}
	return fn(r)
}

// loadRegistry runs under host.lock: the cached version when the file is
// still the one cached, otherwise the file read and checked again.
func (h *FirecrackerHost) loadRegistry() (*hostRegistry, error) {
	h.cacheMu.Lock()
	defer h.cacheMu.Unlock()
	c, err := h.currentRegistry()
	if err != nil {
		return nil, err
	}
	r := c.reg.clone()
	if c.migrated {
		if err = h.saveLocked(r); err != nil {
			return nil, err
		}
	}
	return r, nil
}

type loadedRegistry struct {
	reg      *hostRegistry
	migrated bool
}

// currentRegistry runs under cacheMu. It never writes; a registry that needs
// migration is returned with migrated set, for the caller holding host.lock.
func (h *FirecrackerHost) currentRegistry() (loadedRegistry, error) {
	st, err := os.Stat(h.registryPath())
	if errors.Is(err, os.ErrNotExist) {
		if h.registry == nil || h.registry.pin != nil {
			h.dropRegistryCache()
			h.registry = &registryCache{reg: &hostRegistry{Version: registryVersion, Agents: map[string]*HostAgent{}}}
		}
		return loadedRegistry{reg: h.registry.reg}, nil
	}
	if err != nil {
		return loadedRegistry{}, err
	}
	if h.registry != nil && h.registry.pin != nil && h.registry.id == fileIdentity(st) {
		return loadedRegistry{reg: h.registry.reg}, nil
	}
	f, err := os.OpenFile(h.registryPath(), os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return loadedRegistry{}, err
	}
	fst, err := f.Stat()
	if err != nil {
		f.Close()
		return loadedRegistry{}, err
	}
	b, err := io.ReadAll(f)
	if err != nil {
		f.Close()
		return loadedRegistry{}, err
	}
	r, migrated, err := h.decodeRegistry(b)
	if err != nil {
		f.Close()
		return loadedRegistry{}, err
	}
	h.dropRegistryCache()
	h.registry = &registryCache{reg: r, raw: b, id: fileIdentity(fst), pin: f}
	return loadedRegistry{reg: r, migrated: migrated}, nil
}

func (h *FirecrackerHost) dropRegistryCache() {
	if h.registry != nil && h.registry.pin != nil {
		h.registry.pin.Close()
	}
	h.registry = nil
}

// view returns the current registry without host.lock, for checks that must
// not wait behind a state transition: the platform channel's accept check and
// the host's monitor. Renaming makes every version whole. The registry
// returned must not be changed.
func (h *FirecrackerHost) view() (*hostRegistry, error) {
	h.cacheMu.Lock()
	defer h.cacheMu.Unlock()
	c, err := h.currentRegistry()
	if err != nil {
		return nil, err
	}
	if c.migrated {
		return nil, errors.New("runtime registry awaits its migration")
	}
	return c.reg, nil
}

// decodeRegistry checks a registry read from disk. Version 2 kept the
// admission queue in the registry: one whose waiters are all gone migrates to
// version 3; one with a live waiter belongs to an older worker that still
// runs, which must be stopped first.
func (h *FirecrackerHost) decodeRegistry(b []byte) (*hostRegistry, bool, error) {
	r := &hostRegistry{Version: registryVersion, Agents: map[string]*HostAgent{}}
	if err := json.Unmarshal(b, r); err != nil {
		return nil, false, err
	}
	migrated := false
	if r.Version == 1 || r.Version == 2 {
		for _, w := range append(slices.Clone(r.Admissions), r.LegacyBarriers...) {
			raw, err := hex.DecodeString(w.ID)
			if err != nil || len(raw) != 16 || strings.ToLower(w.ID) != w.ID {
				return nil, false, errors.New("invalid host admission queue")
			}
			alive, err := h.requestAlive(w.ID)
			if err != nil {
				return nil, false, err
			}
			if alive {
				return nil, false, ErrOlderWorker
			}
		}
		r.Admissions, r.LegacyBarriers, r.Version, migrated = nil, nil, registryVersion, true
	}
	if err := h.validRegistry(r); err != nil {
		return nil, false, err
	}
	return r, migrated, nil
}

// validRegistry checks every record, as read and before each write.
func (h *FirecrackerHost) validRegistry(r *hostRegistry) error {
	if r.Version != registryVersion || r.Agents == nil || len(r.Admissions) != 0 || len(r.LegacyBarriers) != 0 {
		return errors.New("invalid runtime registry")
	}
	for id, a := range r.Agents {
		if a == nil || a.ID != id || id == "" || a.UID < 10000 || filepath.Dir(a.Volume) != filepath.Join(h.root, "volumes") {
			return errors.New("invalid agent in runtime registry")
		}
		if a.Resources != (VMResources{}) && !a.Resources.valid() {
			return errors.New("invalid agent resources in runtime registry")
		}
		if a.SealID != "" {
			b, err := hex.DecodeString(a.SealID)
			if err != nil || len(b) != 16 || strings.ToLower(a.SealID) != a.SealID || !a.Fenced || a.Run != nil {
				return errors.New("invalid permanent store seal")
			}
		}
		if a.VolumeRemoved && a.SealID == "" {
			return errors.New("volume removal without permanent store seal")
		}
		if run := a.Run; run != nil {
			decoded, err := hex.DecodeString(run.ID)
			if err != nil || len(decoded) != 8 || run.ID != strings.ToLower(run.ID) || run.Generation == 0 || run.Generation != a.Generation ||
				(run.Phase != "STARTING" && run.Phase != "RUNNING") || run.Socket != filepath.Join(h.jail(run), "vsock") {
				return errors.New("invalid attempt in runtime registry")
			}
			if run.Phase == "RUNNING" && (run.PID <= 0 || run.StartTicks == "") {
				return errors.New("confirmed attempt lacks process identity")
			}
		}
	}
	return nil
}

// ErrOlderWorker: the host registry still holds the admission queue of a
// worker of an older version that runs. Stop it before this one starts.
var ErrOlderWorker = errors.New("an older worker still runs on this host: stop it first")

// save writes r through under host.lock, durably, and only when it differs
// from the version on disk (P-09). The lock-free readers (view) wait only for
// the cached version to be replaced, never for the write's fsyncs.
func (h *FirecrackerHost) save(r *hostRegistry) error {
	h.cacheMu.Lock()
	b, unchanged, err := h.encodeRegistry(r)
	h.cacheMu.Unlock()
	if err != nil || unchanged {
		return err
	}
	f, st, err := h.writeRegistry(b)
	if f == nil {
		return err
	}
	h.cacheMu.Lock()
	h.dropRegistryCache()
	h.registry = &registryCache{reg: r.clone(), raw: b, id: fileIdentity(st), pin: f}
	h.cacheMu.Unlock()
	return err
}

// saveLocked is save under cacheMu: a migration as the registry is read.
func (h *FirecrackerHost) saveLocked(r *hostRegistry) error {
	b, unchanged, err := h.encodeRegistry(r)
	if err != nil || unchanged {
		return err
	}
	f, st, err := h.writeRegistry(b)
	if f != nil {
		h.dropRegistryCache()
		h.registry = &registryCache{reg: r.clone(), raw: b, id: fileIdentity(st), pin: f}
	}
	return err
}

// encodeRegistry runs under cacheMu: r checked and encoded, and whether the
// file on disk holds it already.
func (h *FirecrackerHost) encodeRegistry(r *hostRegistry) ([]byte, bool, error) {
	r.Version = registryVersion
	if err := h.validRegistry(r); err != nil {
		return nil, false, err
	}
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return nil, false, err
	}
	b = append(b, '\n')
	if h.registry != nil && h.registry.pin != nil && string(h.registry.raw) == string(b) {
		if st, err := os.Stat(h.registryPath()); err == nil && fileIdentity(st) == h.registry.id {
			return b, true, nil
		}
	}
	return b, false, nil
}

// writeRegistry replaces registry.json with b, durably. Once renamed, the
// file is returned open with its identity, even if the directory's sync
// fails: it holds the version already, and the error is returned.
func (h *FirecrackerHost) writeRegistry(b []byte) (*os.File, os.FileInfo, error) {
	f, err := os.CreateTemp(h.root, "registry-*.tmp")
	if err != nil {
		return nil, nil, err
	}
	fail := func(err error) (*os.File, os.FileInfo, error) {
		f.Close()
		os.Remove(f.Name())
		return nil, nil, err
	}
	if _, err = f.Write(b); err != nil {
		return fail(err)
	}
	if err = f.Sync(); err != nil {
		return fail(err)
	}
	if err = os.Rename(f.Name(), h.registryPath()); err != nil {
		return fail(err)
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	return f, st, syncDir(h.root)
}
