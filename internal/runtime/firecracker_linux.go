//go:build linux

package runtime

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
)

var (
	ErrVolumeBusy = errors.New("agent volume is already in use")
	ErrGeneration = errors.New("stale runtime generation")
	ErrHostFenced = errors.New("agent is fenced on this host")
	ErrCapacity   = errors.New("host VM capacity exhausted")
)

// FirecrackerOptions are supplied by a trusted host worker, never an HTTP caller.
// Images and the writable volume must already have passed provisioning checks.
// This driver manages processes and boot-bound authenticated control. Private
// content resolution, volume encryption and filesystem repair are separate;
// callers supply the PostgreSQL placement transaction callbacks.
type FirecrackerOptions struct {
	Root                                                        string
	Firecracker, Jailer, Kernel, Initrd                         string
	FirecrackerSHA256, JailerSHA256, KernelSHA256, InitrdSHA256 string
	MaxActive                                                   int
	BootTimeout                                                 time.Duration
	// AuthenticatedControl injects per-boot credentials and uses capsule.v1 mTLS
	// readiness. Ready remains only for explicit laboratory/legacy probe images.
	AuthenticatedControl bool
	// ResolveIncarnation reads the installed storage identity before allocating
	// boot credentials. Product workers must validate it against independent
	// authority; absent callback is limited to preprovisioned/laboratory images.
	ResolveIncarnation func(context.Context, string) (uint64, error)
	// PrepareGuest opens/checks the guest volume through its authenticated boot
	// channel before readiness and SQL confirmation. It must not call the host
	// registry recursively: this callback runs under the host lifecycle lock.
	PrepareGuest func(context.Context, string, VMRun, *capsuleprotocol.Client) error
	// PlatformHandler supplies an API bound to this boot, never a payload identity.
	// The driver owns mTLS, per-boot Unix listener, process/UID checks and recovery.
	PlatformHandler func(string, VMRun) (http.Handler, error)
	// Ready probes capsule-init through the private vsock socket.
	Ready func(context.Context, string) error
	// Confirm must conditionally validate the caller's durable placement lease.
	// Failure kills this attempt, without touching a newer generation.
	Confirm func(context.Context, string, VMRun) error
	// Adopt revalidates a previously RUNNING placement against durable authority.
	// ErrGeneration means obsolete; any other error blocks reconciliation while
	// retaining the VMM, so a transient database outage is not mistaken for death.
	Adopt func(context.Context, string, VMRun) error
	// ObserveControl records compatibility for this exact boot after negotiation.
	// It is separate from the physical census and must never infer VMM absence.
	// Failure blocks application admission; callers may still retire the boot.
	ObserveControl func(context.Context, string, VMRun, bool) error
}

type HostAgent struct {
	ID            string `json:"id"`
	UID           uint32 `json:"uid"`
	Volume        string `json:"volume"`
	Device, Inode uint64
	Generation    uint64      `json:"generation"`
	Fenced        bool        `json:"fenced"`
	SealID        string      `json:"seal_id,omitempty"`
	VolumeRemoved bool        `json:"volume_removed,omitempty"`
	Run           *VMRun      `json:"run,omitempty"`
	Resources     VMResources `json:"resources,omitempty"`
	// Harness, when set, is a read-only harness filesystem from the registry
	// cache, attached as the second drive; otherwise the platform image's
	// built-in harness runs.
	Harness *HarnessImage `json:"harness,omitempty"`
}

// HarnessImage is a verified harness.ext4 shared read-only by every agent
// pinned to its release.
type HarnessImage struct {
	Path       string   `json:"path"`
	Digest     string   `json:"digest"`
	Entrypoint []string `json:"entrypoint"`
}

type VMRun struct {
	Incarnation uint64 `json:"incarnation"`
	ID          string `json:"id"`
	Generation  uint64 `json:"generation"`
	Phase       string `json:"phase"`
	PID         int    `json:"pid"`
	StartTicks  string `json:"start_ticks"`
	Socket      string `json:"socket"`
	FenceOnly   bool   `json:"fence_only,omitempty"`
}

type hostRegistry struct {
	Version        int                   `json:"version"`
	Agents         map[string]*HostAgent `json:"agents"`
	Admissions     []admissionWaiter     `json:"admissions,omitempty"`
	LegacyBarriers []admissionWaiter     `json:"barriers,omitempty"`
}

type FirecrackerHost struct {
	opts         FirecrackerOptions
	root, cgroup string
	// Tests can stop the worker at actual durable/process boundaries.
	hook           func(string, VMRun)
	admissionHook  func(string, string)
	platformMu     sync.Mutex
	platform       map[string]*platformService
	platformClosed bool
}

// NewFirecrackerHost requires a private root-owned state directory. The parent
// hierarchy and the supplied expected hashes are trusted operator configuration.
// The Firecracker digest MUST designate the AgentCapsule volume-lock build.
func NewFirecrackerHost(opts FirecrackerOptions) (*FirecrackerHost, error) {
	if os.Geteuid() != 0 {
		return nil, errors.New("host driver requires root for jailer/cgroups")
	}
	if (opts.Ready == nil && !opts.AuthenticatedControl) || opts.Confirm == nil || opts.Adopt == nil || opts.MaxActive < 1 {
		return nil, errors.New("readiness, placement confirmation and capacity are required")
	}
	if opts.PlatformHandler != nil && !opts.AuthenticatedControl {
		return nil, errors.New("platform requires authenticated boot configuration")
	}
	if opts.PrepareGuest != nil && !opts.AuthenticatedControl {
		return nil, errors.New("guest preparation requires authenticated boot configuration")
	}
	if opts.BootTimeout <= 0 {
		opts.BootTimeout = 30 * time.Second
	}
	root, err := filepath.Abs(opts.Root)
	if err != nil {
		return nil, err
	}
	if err = os.MkdirAll(root, 0700); err != nil {
		return nil, err
	}
	canonical, err := filepath.EvalSymlinks(root)
	if err != nil {
		return nil, err
	}
	if canonical != root {
		return nil, errors.New("runtime root must not contain symlinks")
	}
	st, err := os.Stat(root)
	if err != nil {
		return nil, err
	}
	sys := st.Sys().(*syscall.Stat_t)
	if !st.IsDir() || sys.Uid != 0 || st.Mode().Perm() != 0700 {
		return nil, errors.New("runtime root must be a root-owned 0700 directory")
	}
	if len(filepath.Join(root, "jails", "firecracker", strings.Repeat("x", 16), "root", "vsock_5001")) >= 108 {
		return nil, errors.New("runtime root too long for Unix socket")
	}
	hash := sha256.Sum256([]byte(root))
	h := &FirecrackerHost{opts: opts, root: root, cgroup: filepath.Join("/sys/fs/cgroup", "acp-runtime-"+hex.EncodeToString(hash[:8]))}
	for _, d := range []string{"bin", "volumes", "jails", "logs", "credentials", "platform", "admission"} {
		if err = os.MkdirAll(filepath.Join(root, d), 0700); err != nil {
			return nil, err
		}
	}
	// Serialize initialization with all other worker processes.
	err = h.locked(context.Background(), func(r *hostRegistry) error {
		for _, a := range []struct{ name, path, hash string }{{"firecracker", opts.Firecracker, opts.FirecrackerSHA256}, {"jailer", opts.Jailer, opts.JailerSHA256}, {"kernel", opts.Kernel, opts.KernelSHA256}, {"initrd", opts.Initrd, opts.InitrdSHA256}} {
			if err := pinFile(a.path, filepath.Join(root, "bin", a.name), a.hash); err != nil {
				return err
			}
		}
		if err := os.MkdirAll(h.cgroup, 0700); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(h.cgroup, "cgroup.subtree_control"), []byte("+cpu +memory +pids"), 0600); err != nil {
			return err
		}
		return h.save(r)
	})
	return h, err
}

func pinFile(source, destination, want string) error {
	if len(want) != 64 {
		return errors.New("SHA-256 digest required for every runtime artifact")
	}
	if old, err := os.ReadFile(destination); err == nil {
		got := sha256.Sum256(old)
		if hex.EncodeToString(got[:]) != want {
			return errors.New("pinned runtime artifact mismatch")
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()
	f, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0500)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		f.Close()
		if !ok {
			os.Remove(destination)
		}
	}()
	h := sha256.New()
	if _, err = io.Copy(io.MultiWriter(f, h), in); err != nil {
		return err
	}
	if hex.EncodeToString(h.Sum(nil)) != want {
		return errors.New("runtime artifact checksum mismatch")
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = syncDir(filepath.Dir(destination)); err != nil {
		return err
	}
	ok = true
	return nil
}

func syncDir(path string) error {
	f, e := os.Open(path)
	if e != nil {
		return e
	}
	defer f.Close()
	return f.Sync()
}

func (h *FirecrackerHost) locked(ctx context.Context, fn func(*hostRegistry) error) error {
	f, err := os.OpenFile(filepath.Join(h.root, "host.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	for {
		err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			break
		}
		if err != syscall.EWOULDBLOCK {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
	defer syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	r := &hostRegistry{Version: 2, Agents: map[string]*HostAgent{}}
	b, err := os.ReadFile(filepath.Join(h.root, "registry.json"))
	if err == nil {
		if err = json.Unmarshal(b, r); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	migrated := false
	if r.Version == 1 && len(r.Admissions) == 0 {
		r.Admissions, r.LegacyBarriers, r.Version = r.LegacyBarriers, nil, 2
		migrated = true
	}
	if r.Version != 2 || r.Agents == nil || len(r.LegacyBarriers) != 0 {
		return errors.New("invalid runtime registry")
	}
	seen := map[string]bool{}
	for _, w := range r.Admissions {
		b, err := hex.DecodeString(w.ID)
		if err != nil || len(b) != 16 || strings.ToLower(w.ID) != w.ID || seen[w.ID] || (w.Shared && w.Target != "") || (!w.Shared && r.Agents[w.Target] == nil) {
			return errors.New("invalid host admission queue")
		}
		seen[w.ID] = true
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
	if migrated {
		if err := h.save(r); err != nil {
			return err
		}
	}
	return fn(r)
}

func (h *FirecrackerHost) save(r *hostRegistry) error {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(h.root, "registry-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if _, err = f.Write(append(b, '\n')); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(f.Name(), filepath.Join(h.root, "registry.json")); err != nil {
		return err
	}
	return syncDir(h.root)
}

// Register enrolls an already provisioned regular file below Root/volumes. It
// refuses symlinks, inode aliases of other agents, reused UIDs and re-registration.
func (h *FirecrackerHost) Register(ctx context.Context, id, volume string, uid uint32) error {
	return h.locked(ctx, func(r *hostRegistry) error {
		if id == "" || uid < 10000 {
			return errors.New("agent ID and dedicated non-system UID required")
		}
		if _, ok := r.Agents[id]; ok {
			return errors.New("agent already registered")
		}
		abs, err := filepath.Abs(volume)
		if err != nil {
			return err
		}
		real, err := filepath.EvalSymlinks(abs)
		if err != nil {
			return err
		}
		if real != abs || filepath.Dir(abs) != filepath.Join(h.root, "volumes") {
			return errors.New("volume must be a direct regular file in the managed volume directory")
		}
		st, err := os.Stat(abs)
		if err != nil {
			return err
		}
		if !st.Mode().IsRegular() {
			return errors.New("block devices require a separate alias-safe exclusivity protocol")
		}
		s := st.Sys().(*syscall.Stat_t)
		for _, a := range r.Agents {
			if a.UID == uid || (a.Device == uint64(s.Dev) && a.Inode == s.Ino) {
				return errors.New("UID or volume inode already assigned")
			}
		}
		if err = os.Chown(abs, int(uid), int(uid)); err != nil {
			return err
		}
		if err = os.Chmod(abs, 0600); err != nil {
			return err
		}
		r.Agents[id] = &HostAgent{ID: id, UID: uid, Volume: abs, Device: uint64(s.Dev), Inode: s.Ino}
		return h.save(r)
	})
}

func (h *FirecrackerHost) jail(run *VMRun) string {
	return filepath.Join(h.root, "jails", "firecracker", run.ID, "root")
}
func (h *FirecrackerHost) group(run *VMRun) string { return filepath.Join(h.cgroup, run.ID) }

func populated(path string) (bool, error) {
	b, e := os.ReadFile(filepath.Join(path, "cgroup.events"))
	if errors.Is(e, os.ErrNotExist) {
		return false, nil
	}
	if e != nil {
		return false, e
	}
	for _, line := range strings.Split(string(b), "\n") {
		if line == "populated 1" {
			return true, nil
		}
		if line == "populated 0" {
			return false, nil
		}
	}
	return false, errors.New("missing populated cgroup field")
}

// cleanup is only called under host.lock. clone3 places every launcher in its
// attempt cgroup AT FORK, so no late launcher can escape an interrupted attempt.
func (h *FirecrackerHost) cleanup(run *VMRun) error {
	h.closePlatform(run.ID)
	group := h.group(run)
	busy, err := populated(group)
	if err != nil {
		return err
	}
	if busy {
		if err = os.WriteFile(filepath.Join(group, "cgroup.kill"), []byte("1"), 0600); err != nil {
			return err
		}
	}
	deadline := time.Now().Add(10 * time.Second)
	for busy {
		if time.Now().After(deadline) {
			return errors.New("attempt cgroup still populated; volume remains unavailable")
		}
		time.Sleep(10 * time.Millisecond)
		busy, err = populated(group)
		if err != nil {
			return err
		}
	}
	if err = os.Remove(group); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.RemoveAll(filepath.Dir(h.jail(run))); err != nil {
		return err
	}
	if err := os.Remove(h.credentialPath(run)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Remove(h.platformLockPath(run.ID)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return syncDir(filepath.Join(h.root, "credentials"))
}

func procIdentity(pid int) (string, error) {
	b, e := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if e != nil {
		return "", e
	}
	i := strings.LastIndex(string(b), ")")
	if i < 0 {
		return "", errors.New("invalid proc stat")
	}
	f := strings.Fields(string(b[i+1:]))
	if len(f) < 20 {
		return "", errors.New("short proc stat")
	}
	if f[0] == "Z" {
		return "", errors.New("process exited")
	}
	return f[19], nil
}

func (h *FirecrackerHost) identify(a *HostAgent) (int, string, error) {
	run := a.Run
	b, err := os.ReadFile(filepath.Join(h.jail(run), "firecracker.pid"))
	if err != nil {
		return 0, "", err
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil {
		return 0, "", err
	}
	ticks, err := procIdentity(pid)
	if err != nil {
		return 0, "", err
	}
	if run.PID != 0 && (pid != run.PID || ticks != run.StartTicks) {
		return 0, "", errors.New("PID was reused")
	}
	root, err := os.Stat(fmt.Sprintf("/proc/%d/root", pid))
	if err != nil {
		return 0, "", err
	}
	want, err := os.Stat(h.jail(run))
	if err != nil {
		return 0, "", err
	}
	if !os.SameFile(root, want) {
		return 0, "", errors.New("unexpected VMM root")
	}
	status, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return 0, "", err
	}
	uidLine := fmt.Sprintf("Uid:\t%d\t%d\t%d\t%d", a.UID, a.UID, a.UID, a.UID)
	if !strings.Contains(string(status), uidLine) {
		return 0, "", errors.New("unexpected VMM UID")
	}
	cgroup, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return 0, "", err
	}
	if strings.TrimSpace(string(cgroup)) != "0::"+strings.TrimPrefix(h.group(run), "/sys/fs/cgroup") {
		return 0, "", errors.New("unexpected VMM cgroup")
	}
	exe, err := os.Stat(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return 0, "", err
	}
	expected, err := os.Stat(filepath.Join(h.jail(run), "firecracker"))
	if err != nil {
		return 0, "", err
	}
	if !os.SameFile(exe, expected) {
		return 0, "", errors.New("unexpected VMM executable")
	}
	return pid, ticks, nil
}

// Check the lock on the VMM's actual backing descriptor before exposing RUNNING.
// A vanilla or incorrectly built Firecracker must not be accepted by this driver.
func ownedVolumeLock(pid int, volume string) error {
	want, err := os.Stat(volume)
	if err != nil {
		return err
	}
	entries, err := os.ReadDir(fmt.Sprintf("/proc/%d/fd", pid))
	if err != nil {
		return err
	}
	for _, entry := range entries {
		path := fmt.Sprintf("/proc/%d/fd/%s", pid, entry.Name())
		got, err := os.Stat(path)
		if err != nil || !os.SameFile(want, got) {
			continue
		}
		info, err := os.ReadFile(fmt.Sprintf("/proc/%d/fdinfo/%s", pid, entry.Name()))
		if err != nil {
			return err
		}
		for _, line := range strings.Split(string(info), "\n") {
			f := strings.Fields(line)
			if len(f) >= 6 && f[0] == "lock:" && f[2] == "FLOCK" && f[3] == "ADVISORY" && f[4] == "WRITE" {
				return nil
			}
		}
	}
	return errors.New("VMM does not own the required writable-volume flock")
}

// recover observes only a fully identified, previously confirmed VMM. Its
// authority check supports inventory, retirement and credential rotation without
// requiring a reachable/compatible harness. Start reuse and Control separately
// require the negotiated contract before admitting application use.
// An interrupted STARTING attempt is killed before its volume can be reused.
//
// Every agent is examined even when another one fails, so that one broken agent
// cannot leave the others unrecovered. Map order is random, so stopping at the
// first error would also make which agents were recovered arbitrary. The
// registry is saved after the pass, including the cleanups that did succeed, and
// the failures are returned together. A failing agent keeps its Run untouched:
// it is neither adopted nor cleaned until the cause is resolved.
func (h *FirecrackerHost) recover(ctx context.Context, r *hostRegistry) error {
	var failures []error
	for _, a := range r.Agents {
		if err := h.recoverAgent(ctx, a); err != nil {
			failures = append(failures, fmt.Errorf("agent %s: %w", a.ID, err))
		}
	}
	if err := h.save(r); err != nil {
		failures = append(failures, err)
	}
	return errors.Join(failures...)
}

func (h *FirecrackerHost) recoverAgent(ctx context.Context, a *HostAgent) error {
	if a.Run == nil {
		return nil
	}
	if a.Run.Phase == "RUNNING" && !a.Fenced {
		if _, _, e := h.identify(a); e == nil {
			if err := ownedVolumeLock(a.Run.PID, a.Volume); err != nil {
				return err
			}
			if err := h.opts.Adopt(ctx, a.ID, *a.Run); err == nil {
				return h.ensurePlatform(a)
			} else if !errors.Is(err, ErrGeneration) {
				return err
			}
		}
	}
	if err := h.cleanup(a.Run); err != nil {
		return err
	}
	a.Run = nil
	return nil
}

func (h *FirecrackerHost) Reconcile(ctx context.Context) (map[string]VMRun, error) {
	result := map[string]VMRun{}
	err := h.locked(ctx, func(r *hostRegistry) error {
		if err := h.recover(ctx, r); err != nil {
			return err
		}
		for id, a := range r.Agents {
			if a.Run != nil {
				result[id] = *a.Run
			}
		}
		return nil
	})
	return result, err
}

func (h *FirecrackerHost) Start(ctx context.Context, id string, generation uint64) (VMRun, error) {
	return h.start(ctx, id, generation, false)
}

// StartForFence boots a guest whose authenticated control identity permits only
// durable barriers and health checks. It cannot accept application work.
func (h *FirecrackerHost) StartForFence(ctx context.Context, id string, generation uint64) (VMRun, error) {
	if !h.opts.AuthenticatedControl {
		return VMRun{}, ErrNoControl
	}
	return h.start(ctx, id, generation, true)
}

func (h *FirecrackerHost) start(ctx context.Context, id string, generation uint64, fenceOnly bool) (VMRun, error) {
	var result VMRun
	err := h.WithApplication(ctx, func(ctx context.Context) error {
		var reusedClient *capsuleprotocol.Client
		registryErr := h.locked(ctx, func(r *hostRegistry) error {
			if err := h.checkStartAdmission(ctx, r, id); err != nil {
				return err
			}
			if err := h.recover(ctx, r); err != nil {
				return err
			}
			a := r.Agents[id]
			if a == nil {
				return errors.New("unregistered agent")
			}
			if a.Fenced {
				return ErrHostFenced
			}
			if a.Run != nil {
				if a.Run.Generation == generation && a.Run.FenceOnly == fenceOnly {
					result = *a.Run
					if h.opts.AuthenticatedControl {
						client, err := h.controlClient(a)
						if err != nil {
							return err
						}
						reusedClient = client
					}
					return nil
				}
				return ErrVolumeBusy
			}
			if generation <= a.Generation {
				return ErrGeneration
			}
			active := 0
			for _, other := range r.Agents {
				if other.Run != nil {
					active++
				}
			}
			if active >= h.opts.MaxActive {
				return ErrCapacity
			}
			st, err := os.Stat(a.Volume)
			if err != nil {
				return err
			}
			s := st.Sys().(*syscall.Stat_t)
			if !st.Mode().IsRegular() || uint64(s.Dev) != a.Device || s.Ino != a.Inode {
				return errors.New("registered volume identity changed")
			}
			// Fast rejection only. The VMM itself must acquire/retain the same inode
			// lock after this descriptor closes; this check is not the safety barrier.
			probe, err := os.OpenFile(a.Volume, os.O_RDWR, 0)
			if err != nil {
				return err
			}
			err = syscall.Flock(int(probe.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
			probe.Close()
			if err == syscall.EWOULDBLOCK {
				return ErrVolumeBusy
			}
			if err != nil {
				return err
			}
			nonce := make([]byte, 8)
			if _, err = rand.Read(nonce); err != nil {
				return err
			}
			incarnation := uint64(1)
			if h.opts.ResolveIncarnation != nil {
				incarnation, err = h.opts.ResolveIncarnation(ctx, id)
				if err != nil {
					return err
				}
			}
			if incarnation == 0 || incarnation > 1<<63-1 {
				return ErrGeneration
			}
			run := &VMRun{Incarnation: incarnation, ID: hex.EncodeToString(nonce), Generation: generation, Phase: "STARTING", FenceOnly: fenceOnly}
			run.Socket = filepath.Join(h.jail(run), "vsock")
			a.Generation = generation
			a.Run = run
			if err = h.save(r); err != nil {
				return err
			}
			if h.hook != nil {
				h.hook("intent", *run)
			}
			fail := func(e error) error {
				if clean := h.cleanup(run); clean != nil {
					return errors.Join(e, clean)
				}
				a.Run = nil
				return errors.Join(e, h.save(r))
			}
			if err = h.prepare(a); err != nil {
				return fail(err)
			}
			group, err := os.Open(h.group(run))
			if err != nil {
				return fail(err)
			}
			defer group.Close()
			log, err := os.OpenFile(filepath.Join(h.root, "logs", run.ID+".log"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
			if err != nil {
				return fail(err)
			}
			defer log.Close()
			cmd := exec.Command(filepath.Join(h.root, "bin", "jailer"), "--id", run.ID, "--exec-file", filepath.Join(h.root, "bin", "firecracker"), "--uid", strconv.Itoa(int(a.UID)), "--gid", strconv.Itoa(int(a.UID)), "--chroot-base-dir", filepath.Join(h.root, "jails"), "--new-pid-ns", "--cgroup-version", "2", "--parent-cgroup", strings.TrimPrefix(h.group(run), "/sys/fs/cgroup/"), "--resource-limit", "no-file=256", "--", "--no-api", "--config-file", "/config.json")
			cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(group.Fd()), Cloneflags: syscall.CLONE_NEWNET}
			cmd.Stdout = log
			cmd.Stderr = log
			if err = cmd.Start(); err != nil {
				return fail(err)
			}
			go func() { _ = cmd.Wait() }()
			if h.hook != nil {
				h.hook("spawned", *run)
			}
			boot, cancel := context.WithTimeout(ctx, h.opts.BootTimeout)
			defer cancel()
			for {
				pid, ticks, e := h.identify(a)
				if e == nil && h.opts.PrepareGuest != nil {
					// Do not hand an unlock secret to a process until it actually
					// owns the exclusive backing-volume lock. Startup may have
					// reached its PID file before opening the block backend.
					e = ownedVolumeLock(pid, a.Volume)
				}
				if e == nil {
					run.PID = pid
					run.StartTicks = ticks
					break
				}
				select {
				case <-boot.Done():
					return fail(errors.Join(boot.Err(), e))
				case <-time.After(20 * time.Millisecond):
				}
			}
			if h.opts.AuthenticatedControl {
				if h.opts.PrepareGuest != nil {
					var client *capsuleprotocol.Client
					client, err = h.controlClient(a)
					if err == nil {
						err = h.opts.PrepareGuest(boot, id, *run, client)
					}
				}
				if err == nil {
					err = h.controlReady(boot, a)
				}
			} else {
				err = h.opts.Ready(boot, run.Socket)
			}
			if err != nil {
				return fail(err)
			}
			if err = ownedVolumeLock(run.PID, a.Volume); err != nil {
				return fail(err)
			}
			if err = h.opts.Confirm(boot, id, *run); err != nil {
				return fail(err)
			}
			run.Phase = "RUNNING"
			if err = h.save(r); err != nil {
				return fail(err)
			}
			if h.opts.AuthenticatedControl && h.opts.ObserveControl != nil {
				if err = h.opts.ObserveControl(boot, id, *run, true); err != nil {
					return fail(err)
				}
			}
			if h.hook != nil {
				h.hook("confirmed", *run)
			}
			result = *run
			return nil
		})
		if registryErr != nil {
			if result.ID != "" && h.opts.AuthenticatedControl {
				return h.observeControlResult(ctx, id, result, registryErr)
			}
			return registryErr
		}
		if reusedClient != nil {
			// Retain the observed VMM on failure. This RPC runs outside host.lock
			// while the caller still owns host admission for the exact boot.
			return h.observeControlResult(ctx, id, result, checkControlContract(ctx, reusedClient))
		}
		return nil
	})
	return result, err
}

func (h *FirecrackerHost) prepare(a *HostAgent) error {
	run := a.Run
	root := h.jail(run)
	if err := os.MkdirAll(root, 0700); err != nil {
		return err
	}
	guest, err := h.prepareControl(a)
	if err != nil {
		return err
	}
	if err := h.ensurePlatform(a); err != nil {
		return err
	}
	for _, name := range []string{"kernel", "initrd"} {
		source, err := os.Open(filepath.Join(h.root, "bin", name))
		if err != nil {
			return err
		}
		f, err := os.OpenFile(filepath.Join(root, name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0444)
		if err != nil {
			source.Close()
			return err
		}
		_, err = io.Copy(f, source)
		source.Close()
		if err == nil && name == "initrd" && h.opts.AuthenticatedControl {
			err = appendControlConfig(f, guest, a.Harness)
		}
		if err == nil {
			err = f.Sync()
		}
		f.Close()
		if err != nil {
			return err
		}
	}
	if err := os.Link(a.Volume, filepath.Join(root, "data.ext4")); err != nil {
		return err
	}
	drives := []any{map[string]any{"drive_id": "data", "path_on_host": "/data.ext4", "is_root_device": false, "is_read_only": false, "cache_type": "Writeback", "io_engine": "Sync"}}
	if a.Harness != nil {
		if !h.opts.AuthenticatedControl {
			return errors.New("a registry harness needs the authenticated guest contract")
		}
		// One inode shared by every agent of the release; the VMM only reads it.
		if err := linkOrCopy(a.Harness.Path, filepath.Join(root, "harness.ext4")); err != nil {
			return err
		}
		drives = append(drives, map[string]any{"drive_id": "harness", "path_on_host": "/harness.ext4", "is_root_device": false, "is_read_only": true, "cache_type": "Unsafe", "io_engine": "Sync"})
	}
	resources := a.resources()
	config := map[string]any{"boot-source": map[string]any{"kernel_image_path": "/kernel", "initrd_path": "/initrd", "boot_args": "console=ttyS0 reboot=k panic=1 pci=off"}, "machine-config": map[string]any{"vcpu_count": resources.VCPUs, "mem_size_mib": resources.MemoryMiB}, "drives": drives, "vsock": map[string]any{"guest_cid": 3, "uds_path": "/vsock"}}
	b, err := json.Marshal(config)
	if err != nil {
		return err
	}
	if err = os.WriteFile(filepath.Join(root, "config.json"), b, 0444); err != nil {
		return err
	}
	if err = os.Mkdir(h.group(run), 0700); err != nil {
		return err
	}
	for name, value := range map[string]string{"memory.max": strconv.FormatInt(int64(resources.MemoryMiB+256)<<20, 10), "pids.max": "32", "cpu.max": fmt.Sprintf("%d 100000", resources.VCPUs*100000)} {
		if err = os.WriteFile(filepath.Join(h.group(run), name), []byte(value), 0600); err != nil {
			return err
		}
	}
	// A guest must not be able to exceed memory.max by spilling into host swap.
	// Kernels booted without swap accounting do not expose this file, in which
	// case there is nothing to limit, so a failure here is deliberately ignored.
	_ = os.WriteFile(filepath.Join(h.group(run), "memory.swap.max"), []byte("0"), 0600)
	return nil
}

func (h *FirecrackerHost) Stop(ctx context.Context, id string, generation uint64) error {
	return h.locked(ctx, func(r *hostRegistry) error {
		a := r.Agents[id]
		if a == nil {
			return errors.New("unregistered agent")
		}
		if a.Generation != generation {
			return ErrGeneration
		}
		if a.Run == nil {
			return nil
		}
		if err := h.cleanup(a.Run); err != nil {
			return err
		}
		a.Run = nil
		return h.save(r)
	})
}

// Retire neutralizes all local attempts up to generation and durably advances
// the admission watermark, including when an allocated generation has not yet
// reached this host. A delayed worker can no longer launch it after an absence
// report. It never stops a newer generation. Register/provisioning is required.
func (h *FirecrackerHost) Retire(ctx context.Context, id string, generation uint64) error {
	_, err := h.retire(ctx, id, generation, "")
	return err
}

// RetireMissing closes the snapshot race between scanning the host and reading
// PostgreSQL: a matching RUNNING attempt may have appeared in between. In that
// case it returns false without killing or retiring it. vmID comes from a
// RUNNING database placement; other states must use unconditional Retire.
func (h *FirecrackerHost) RetireMissing(ctx context.Context, id string, generation uint64, vmID string) (bool, error) {
	if vmID == "" {
		return false, errors.New("expected VMM identity required")
	}
	return h.retire(ctx, id, generation, vmID)
}

func (h *FirecrackerHost) retire(ctx context.Context, id string, generation uint64, preserveVM string) (bool, error) {
	retired := false
	err := h.locked(ctx, func(r *hostRegistry) error {
		a := r.Agents[id]
		if a == nil {
			return errors.New("unregistered agent")
		}
		if a.SealID != "" {
			// A permanent seal forbids every generation. Keep its attested
			// generation stable even when routine cleanup requests a larger one.
			retired = true
			return nil
		}
		if a.Generation > generation {
			return ErrGeneration
		}
		if a.Run != nil && a.Run.Generation == generation && a.Run.Phase == "RUNNING" && a.Run.ID == preserveVM {
			return nil
		}
		if a.Run != nil {
			if err := h.cleanup(a.Run); err != nil {
				return err
			}
			a.Run = nil
		}
		a.Generation = generation
		if err := h.save(r); err != nil {
			return err
		}
		retired = true
		return nil
	})
	return retired, err
}

// FenceAgent durably blocks future starts before neutralizing the current VMM.
// This is a host lifecycle fence, NOT a harness data barrier or key destruction.
func (h *FirecrackerHost) FenceAgent(ctx context.Context, id string) error {
	return h.locked(ctx, func(r *hostRegistry) error {
		a := r.Agents[id]
		if a == nil {
			return errors.New("unregistered agent")
		}
		a.Fenced = true
		if err := h.save(r); err != nil {
			return err
		}
		if a.Run != nil {
			if err := h.cleanup(a.Run); err != nil {
				return err
			}
			a.Run = nil
		}
		return h.save(r)
	})
}
