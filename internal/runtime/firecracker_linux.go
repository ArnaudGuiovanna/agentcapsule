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
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"slices"
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
	SystemImages                                                []BootImage
	MaxActive                                                   int
	// Provisioning hosts also enforce the CPU and memory budget reported to
	// the planner. Preprovisioned hosts without these limits use MaxActive.
	HostVCPUs     int
	HostMemoryMiB int64
	BootTimeout   time.Duration
	// DriveLimits caps the I/O of each VM's drives; zero means
	// DefaultDriveLimits (CAP-03, ADR 012).
	DriveLimits DriveLimits
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
	// SerialConsole gives each guest a serial console (console=ttyS0), whose
	// output joins the VMM's bounded log: for debugging only (S-20). Without
	// it the guest kernel has no serial port at all.
	SerialConsole bool
}

type BootImage struct {
	Kernel, Initrd, KernelSHA256, InitrdSHA256 string
}
type BootImageID struct {
	Kernel string `json:"kernel"`
	Initrd string `json:"initrd"`
}

type HostAgent struct {
	Rollout       string       `json:"rollout,omitempty"`
	SystemImage   *BootImageID `json:"system_image,omitempty"`
	ID            string       `json:"id"`
	UID           uint32       `json:"uid"`
	Volume        string       `json:"volume"`
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
	// Corpora are read-only corpus images, attached after the harness in
	// this order and mounted under /corpus (ADR 023 §5). Build, for the
	// builder agent only, are the drives of its current build.
	Corpora []CorpusImage `json:"corpora,omitempty"`
	Build   *BuildDrives  `json:"build,omitempty"`
}

// HarnessImage is a verified harness.ext4 shared read-only by every agent
// pinned to its release.
type HarnessImage struct {
	Path       string   `json:"path"`
	Digest     string   `json:"digest"`
	Entrypoint []string `json:"entrypoint"`
}

type VMRun struct {
	Rollout     string `json:"rollout,omitempty"`
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
	Version int                   `json:"version"`
	Agents  map[string]*HostAgent `json:"agents"`
	// Reservations hold, per agent, the slot its eviction frees for its boot
	// (ReserveSlot), while the evicting turn lasts.
	Reservations   map[string]slotReservation `json:"reservations,omitempty"`
	Admissions     []admissionWaiter          `json:"admissions,omitempty"`
	LegacyBarriers []admissionWaiter          `json:"barriers,omitempty"`
}

type FirecrackerHost struct {
	opts         FirecrackerOptions
	root, cgroup string
	// Tests can stop the worker at actual durable/process boundaries.
	hook          func(string, VMRun)
	admissionHook func(string, string)
	// census, when set, stands in for the physical census of a confirmed
	// VMM (confirmedVMM): tests without KVM.
	census func(*HostAgent) (bool, error)
	// peer, when set, stands in for the process identity check of a
	// platform connection's peer (platformPeer): tests without KVM.
	peer           func(*HostAgent, *syscall.Ucred) error
	platformMu     sync.Mutex
	platform       map[string]*platformService
	platformClosed bool
	// clients holds each boot's control client, whose connections stay
	// open between calls (P-09); platformMu guards it.
	clients map[string]*capsuleprotocol.Client
	monitor *hostMonitor
	// registryMu, then host.lock, guard registry.json; cacheMu guards the
	// cached version (firecracker_registry_linux.go).
	registryMu, cacheMu sync.Mutex
	registry            *registryCache
	// queueMu, then admission/queue.lock, guard the admission queues.
	queueMu sync.Mutex
	queue   *queueCache
	// lockMu guards agentLocks (firecracker_locks_linux.go).
	lockMu     sync.Mutex
	agentLocks map[string]*agentLock
	// uidMu guards uidsHeld, the UIDs of registrations under way
	// (RegisterProvisioned). ownVolume, when set, stands in for the chown
	// and fsync of a provisioned volume: tests without root.
	uidMu     sync.Mutex
	uidsHeld  map[uint32]bool
	ownVolume func(*os.File, uint32) error
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
	opts.DriveLimits = opts.DriveLimits.orDefault()
	if err := opts.DriveLimits.Validate(); err != nil {
		return nil, err
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
	for _, d := range []string{"bin", "volumes", "jails", "logs", "credentials", "platform", "admission", "locks"} {
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
			if a.name == "kernel" || a.name == "initrd" {
				if err := shareBootFile(filepath.Join(root, "bin", a.name)); err != nil {
					return err
				}
			}
		}
		// Versioned artifacts are installed under their verified content digests.
		// Existing agents keep using their pinned pair after a worker restart.
		for _, image := range opts.SystemImages {
			if err := cacheSystemImage(root, image); err != nil {
				return err
			}
		}
		if err := cacheSystemImage(root, BootImage{opts.Kernel, opts.Initrd, opts.KernelSHA256, opts.InitrdSHA256}); err != nil {
			return err
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

func cacheSystemImage(root string, img BootImage) error {
	for _, a := range []struct{ name, path, digest string }{{"kernel", img.Kernel, img.KernelSHA256}, {"initrd", img.Initrd, img.InitrdSHA256}} {
		if raw, err := hex.DecodeString(a.digest); err != nil || len(raw) != sha256.Size || strings.ToLower(a.digest) != a.digest {
			return errors.New("invalid system image digest")
		}
		if err := pinFile(a.path, filepath.Join(root, "bin", a.name+"-"+a.digest), a.digest); err != nil {
			return err
		}
		if err := shareBootFile(filepath.Join(root, "bin", a.name+"-"+a.digest)); err != nil {
			return err
		}
	}
	return nil
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

// The caller holds the registry lock and has reconciled exited runs. Include
// a VM whose startup is in progress and the same 256 MiB of VMM headroom per
// guest used by the cgroup limit and the deployment planner. A slot another
// agent's eviction reserved counts too, once its victim is stopped
// (ReserveSlot); booting's own reservation does not.
func (h *FirecrackerHost) hasBootCapacity(r *hostRegistry, requested VMResources, booting string) bool {
	slots, cpus, memory := 1, requested.VCPUs, int64(requested.MemoryMiB+256)
	count := func(a *HostAgent) {
		v := a.resources()
		slots++
		cpus += v.VCPUs
		memory += int64(v.MemoryMiB + 256)
	}
	for id, other := range r.Agents {
		if other.Run != nil && id != booting {
			count(other)
		}
	}
	for id, res := range r.Reservations {
		a, victim := r.Agents[id], r.Agents[res.Victim]
		if id == booting || a == nil || a.Run != nil || victim != nil && victim.Run != nil || !h.reservationLive(res) {
			continue
		}
		count(a)
	}
	return slots <= h.opts.MaxActive && (h.opts.HostVCPUs == 0 || cpus <= h.opts.HostVCPUs) &&
		(h.opts.HostMemoryMiB == 0 || memory <= h.opts.HostMemoryMiB)
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

// cleanup runs under the agent's lock, never under host.lock: the attempt's
// cgroup may take up to ten seconds to empty. clone3 places every launcher in
// its attempt cgroup AT FORK, so no late launcher can escape an interrupted
// attempt. The run stays in the registry, holding its slot, until cleanup
// returns.
func (h *FirecrackerHost) cleanup(run *VMRun) error {
	h.closePlatform(run.ID)
	h.dropClient(run.ID)
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
	// The VMM's log goes with its run (S-20). While debugging, it stays for
	// inspection; the census keeps the newest few (removeStaleLogs).
	if !h.opts.SerialConsole {
		if err := os.Remove(h.logPath(run.ID)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return syncDir(filepath.Join(h.root, "credentials"))
}

func (h *FirecrackerHost) identify(a *HostAgent) (int, string, error) {
	run := a.Run
	// The jail belongs to the VMM's user: its PID file is read without
	// following a link, at most a few bytes, never blocking (L-15).
	pid, err := readPIDFile(h.jail(run), "firecracker.pid")
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
	want, err := os.Lstat(h.jail(run))
	if err != nil {
		return 0, "", err
	}
	if !want.IsDir() || !os.SameFile(root, want) {
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
	expected, err := os.Lstat(filepath.Join(h.jail(run), "firecracker"))
	if err != nil {
		return 0, "", err
	}
	if !expected.Mode().IsRegular() || !os.SameFile(exe, expected) {
		return 0, "", errors.New("unexpected VMM executable")
	}
	return pid, ticks, nil
}

// recover observes only a fully identified, previously confirmed VMM. Its
// authority check supports inventory, retirement and credential rotation without
// requiring a reachable/compatible harness. Start reuse and Control separately
// require the negotiated contract before admitting application use.
// An interrupted STARTING attempt is killed before its volume can be reused.
//
// Every agent is examined even when another one fails, so that one broken agent
// cannot leave the others unrecovered. The registry is written for each run
// retired, and only then; the failures are returned together. A failing
// agent keeps its Run untouched: it is neither adopted nor cleaned until the
// cause is resolved.
//
// An agent in use is left to its user: one whose turn another caller holds,
// or whose lock another operation holds (a boot, a stop, a volume copy). Its
// run stays in the registry and keeps its slot. The census never waits for
// it, and holds no lock while it adopts a VM (S-03).
//
// recover is the census of the host: Reconcile, CredentialRotations and a
// boot's count of the running VMs. An operation on one agent's VM uses
// recoverOne instead.
func (h *FirecrackerHost) recover(ctx context.Context) error {
	logs, logsErr := h.listLogs()
	r, err := h.view()
	if err != nil {
		return err
	}
	ids := make([]string, 0, len(r.Agents))
	for id, a := range r.Agents {
		if a.Run != nil {
			ids = append(ids, id)
		}
	}
	slices.Sort(ids)
	var failures []error
	for _, id := range ids {
		err := h.TryBarrier(ctx, id, func(ctx context.Context) error {
			unlock, err := h.tryLockAgent(id)
			if err != nil {
				return err
			}
			defer unlock()
			return h.recoverOne(ctx, id)
		})
		if err != nil && !errors.Is(err, ErrAgentBusy) {
			failures = append(failures, err)
		}
	}
	// The logs of runs that are gone (a worker died before their cleanup)
	// go at the census (S-20).
	if logsErr == nil {
		logsErr = h.removeStaleLogs(ctx, logs)
	}
	return errors.Join(append(failures, logsErr)...)
}

// recoverOne is recover for one agent, whose lock the caller holds: the reuse
// of its VM and its control sessions (each delivery, each platform call)
// adopt that VM again before using it, so a stale or sealed binding retires
// it there. The host's other VMs wait for its next census: adopting them at
// every use made each delivery's cost grow with the number of running VMs.
// The registry is written only when the run is retired (P-09).
func (h *FirecrackerHost) recoverOne(ctx context.Context, id string) error {
	a, err := h.agent(ctx, id)
	if err != nil || a == nil || a.Run == nil {
		return err
	}
	retire, err := h.recoverAgent(ctx, a)
	if err != nil {
		return fmt.Errorf("agent %s: %w", id, err)
	}
	if retire {
		if err = h.retireRun(ctx, id, a.Run); err != nil {
			return fmt.Errorf("agent %s: %w", id, err)
		}
	}
	return nil
}

// recoverAgent adopts a's confirmed VMM, or tells that its run must be
// retired: the VMM is gone, obsolete or interrupted while starting.
func (h *FirecrackerHost) recoverAgent(ctx context.Context, a *HostAgent) (bool, error) {
	if a.Run.Phase == "RUNNING" && !a.Fenced {
		if alive, err := h.confirmedVMM(a); err != nil {
			return false, err
		} else if alive {
			if err := h.opts.Adopt(ctx, a.ID, *a.Run); err == nil {
				return false, h.ensurePlatform(a)
			} else if !errors.Is(err, ErrGeneration) {
				return false, err
			}
		}
	}
	return true, nil
}

// runs returns the VM runs of the registry.
func (h *FirecrackerHost) runs(only string) (map[string]VMRun, error) {
	result := map[string]VMRun{}
	r, err := h.view()
	if err != nil {
		return nil, err
	}
	for id, a := range r.Agents {
		if a.Run != nil && (only == "" || id == only) {
			result[id] = *a.Run
		}
	}
	return result, nil
}

// Reconcile adopts every confirmed VM of the host, retires the others and
// returns the runs that remain, those of agents in use among them.
func (h *FirecrackerHost) Reconcile(ctx context.Context) (map[string]VMRun, error) {
	if err := h.recover(ctx); err != nil {
		return map[string]VMRun{}, err
	}
	return h.runs("")
}

// ReconcileAgent is Reconcile for one agent: it adopts or retires that
// agent's VM alone, and returns its run only, if it has one.
func (h *FirecrackerHost) ReconcileAgent(ctx context.Context, id string) (map[string]VMRun, error) {
	unlock, err := h.lockAgent(ctx, id)
	if err != nil {
		return map[string]VMRun{}, err
	}
	defer unlock()
	if err = h.recoverOne(ctx, id); err != nil {
		return map[string]VMRun{}, err
	}
	return h.runs(id)
}

func (h *FirecrackerHost) Start(ctx context.Context, id string, generation uint64) (VMRun, error) {
	return h.start(ctx, id, generation, false)
}

// MaxActive is how many VMs this host may run at once.
func (h *FirecrackerHost) MaxActive() int { return h.opts.MaxActive }

// StartForFence boots a guest whose authenticated control identity permits only
// durable barriers and health checks. It cannot accept application work.
func (h *FirecrackerHost) StartForFence(ctx context.Context, id string, generation uint64) (VMRun, error) {
	if !h.opts.AuthenticatedControl {
		return VMRun{}, ErrNoControl
	}
	return h.start(ctx, id, generation, true)
}

// start reuses or boots agent id's VM under the agent's turn and its lock.
// host.lock is taken only to read the agent, to count the host's capacity
// and record the boot's intent (STARTING), and to publish RUNNING; the boot
// itself, from the jailer to the SQL confirmation, runs outside it (S-03).
// The STARTING record holds the boot's slot from its intent on: capacity
// stays host-wide, counted under host.lock.
func (h *FirecrackerHost) start(ctx context.Context, id string, generation uint64, fenceOnly bool) (VMRun, error) {
	var result VMRun
	err := h.WithApplication(ctx, id, func(ctx context.Context) error {
		var reusedClient *capsuleprotocol.Client
		bootErr := func() error {
			unlock, err := h.lockAgent(ctx, id)
			if err != nil {
				return err
			}
			defer unlock()
			if err := h.checkAdmission(ctx, id); err != nil {
				return err
			}
			// Reusing the agent's VM concerns that VM alone. A boot counts
			// the host's VMs below, once it has checked every one of them.
			if err := h.recoverOne(ctx, id); err != nil {
				return err
			}
			a, err := h.agent(ctx, id)
			if err != nil {
				return err
			}
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
			if err := h.recover(ctx); err != nil {
				return err
			}
			// A boot that has no room asks the authority nothing.
			if err := h.locked(ctx, func(r *hostRegistry) error {
				if current := r.Agents[id]; current != nil && !h.hasBootCapacity(r, current.resources(), id) {
					return ErrCapacity
				}
				return nil
			}); err != nil {
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
			nonce := make([]byte, 8)
			if _, err = rand.Read(nonce); err != nil {
				return err
			}
			run := &VMRun{Incarnation: incarnation, ID: hex.EncodeToString(nonce), Generation: generation, Phase: "STARTING", FenceOnly: fenceOnly}
			run.Socket = filepath.Join(h.jail(run), "vsock")
			if err = h.locked(ctx, func(r *hostRegistry) error {
				current := r.Agents[id]
				switch {
				case current == nil:
					return errors.New("unregistered agent")
				case current.Fenced:
					return ErrHostFenced
				case current.Run != nil:
					return ErrVolumeBusy
				case generation <= current.Generation:
					return ErrGeneration
				case !h.hasBootCapacity(r, current.resources(), id):
					return ErrCapacity
				}
				st, err := os.Stat(current.Volume)
				if err != nil {
					return err
				}
				s := st.Sys().(*syscall.Stat_t)
				if !st.Mode().IsRegular() || uint64(s.Dev) != current.Device || s.Ino != current.Inode {
					return errors.New("registered volume identity changed")
				}
				// Fast rejection only. The VMM itself must acquire/retain the same inode
				// lock after this descriptor closes; this check is not the safety barrier.
				probe, err := os.OpenFile(current.Volume, os.O_RDWR, 0)
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
				run.Rollout = current.Rollout
				current.Generation = generation
				current.Run = run
				a = current.clone()
				// The run holds the slot now; reservations whose turn ended go.
				delete(r.Reservations, id)
				h.pruneReservations(r)
				return h.save(r)
			}); err != nil {
				return err
			}
			if h.hook != nil {
				h.hook("intent", *run)
			}
			run = a.Run
			fail := func(e error) error {
				return errors.Join(e, h.retireRun(ctx, id, run))
			}
			if err = h.prepare(a); err != nil {
				return fail(err)
			}
			group, err := os.Open(h.group(run))
			if err != nil {
				return fail(err)
			}
			defer group.Close()
			log, err := h.openLog(run.ID)
			if err != nil {
				return fail(err)
			}
			defer log.Close()
			cmd := h.jailerCommand(run, a.UID, group)
			cmd.Stdout = log
			cmd.Stderr = log
			if err = cmd.Start(); err != nil {
				return fail(err)
			}
			go func() { _ = cmd.Wait() }()
			h.watch()
			if h.hook != nil {
				h.hook("spawned", *run)
			}
			boot, cancel := context.WithTimeout(ctx, h.opts.BootTimeout)
			defer cancel()
			// Once its VMM is identified, a failed attempt tells whether the
			// guest failed (ErrBootFailed) before it is cleaned up.
			failBoot := func(e error) error { return fail(h.bootFailure(ctx, a, e)) }
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
				return failBoot(err)
			}
			if err = ownedVolumeLock(run.PID, a.Volume); err != nil {
				return failBoot(err)
			}
			if err = h.opts.Confirm(boot, id, *run); err != nil {
				return failBoot(err)
			}
			if err = h.locked(boot, func(r *hostRegistry) error {
				current := r.Agents[id]
				if current == nil || current.Run == nil || current.Run.ID != run.ID {
					return ErrGeneration
				}
				current.Run.Phase, current.Run.PID, current.Run.StartTicks = "RUNNING", run.PID, run.StartTicks
				return h.save(r)
			}); err != nil {
				return failBoot(err)
			}
			run.Phase = "RUNNING"
			if h.opts.AuthenticatedControl && h.opts.ObserveControl != nil {
				if err = h.opts.ObserveControl(boot, id, *run, true); err != nil {
					return failBoot(err)
				}
			}
			if h.hook != nil {
				h.hook("confirmed", *run)
			}
			result = *run
			return nil
		}()
		if bootErr != nil {
			if result.ID != "" && h.opts.AuthenticatedControl {
				return h.observeControlResult(ctx, id, result, bootErr)
			}
			return bootErr
		}
		if reusedClient != nil {
			// Retain the observed VMM on failure. This RPC runs outside the
			// agent's lock while the caller still owns the agent's admission
			// for the exact boot.
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
	// Each drive has its own I/O ceiling (CAP-03, ADR 012), enforced by the VMM.
	limits := h.opts.DriveLimits.orDefault()
	// The drives after the data volume, in the order corpora.json gives the
	// guest (ADR 023 §5.1).
	extra, corpora, err := extraDrives(a, limits)
	if err != nil {
		return err
	}
	if len(extra) != 0 && !h.opts.AuthenticatedControl {
		return errors.New("a registry harness, corpora and build drives need the authenticated guest contract")
	}
	// The kernel is linked into the jail, the initrd cloned or copied with the
	// boot's configuration appended; neither is synced (P-12).
	var appendix func(*os.File) error
	if h.opts.AuthenticatedControl {
		appendix = func(f *os.File) error { return appendControlConfig(f, guest, a.Harness, corpora) }
	}
	if err = h.placeBootImages(a, root, appendix); err != nil {
		return err
	}
	if err := os.Link(a.Volume, filepath.Join(root, "data.ext4")); err != nil {
		return err
	}
	drives := []any{map[string]any{"drive_id": "data", "path_on_host": "/data.ext4", "is_root_device": false, "is_read_only": false, "cache_type": "Writeback", "io_engine": "Sync",
		"rate_limiter": limits.Volume.rateLimiter(0)}}
	for _, d := range extra {
		// One inode shared by every VM of the image; a read-only drive's
		// VMM holds it under LOCK_SH, a writable one under LOCK_EX.
		if err := d.share(d.source, filepath.Join(root, d.name)); err != nil {
			return err
		}
		drives = append(drives, map[string]any{"drive_id": d.id, "path_on_host": "/" + d.name, "is_root_device": false, "is_read_only": d.readOnly, "cache_type": d.cache, "io_engine": "Sync",
			"rate_limiter": d.rate.rateLimiter(d.burst)})
	}
	resources := a.resources()
	// No "network-interfaces": the VM has no network device (ADR 012).
	config := map[string]any{"boot-source": map[string]any{"kernel_image_path": "/kernel", "initrd_path": "/initrd", "boot_args": bootArgs(h.opts.SerialConsole)}, "machine-config": map[string]any{"vcpu_count": resources.VCPUs, "mem_size_mib": resources.MemoryMiB}, "drives": drives, "vsock": map[string]any{"guest_cid": 3, "uds_path": "/vsock"}}
	b, err := json.Marshal(config)
	if err != nil {
		return err
	}
	configPath := filepath.Join(root, "config.json")
	if err = os.WriteFile(configPath, b, 0600); err != nil {
		return err
	}
	if err = os.Chmod(configPath, 0444); err != nil {
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

// bootArgs is the guest kernel's command line. reboot=k: a guest that
// restarts resets its CPU through the keyboard controller, and Firecracker
// exits on that reset, so a guest ends its VMM (guestinit.EndCommand);
// panic=1 restarts a guest whose kernel panics. Without serial, the kernel
// registers no serial port (8250.nr_uarts=0) and its console is not on one:
// nothing the guest prints reaches the host (S-20).
func bootArgs(serial bool) string {
	if serial {
		return "console=ttyS0 reboot=k panic=1 pci=off"
	}
	return "reboot=k panic=1 pci=off 8250.nr_uarts=0"
}

// Stop removes the VM of generation, if any.
func (h *FirecrackerHost) Stop(ctx context.Context, id string, generation uint64) error {
	unlock, err := h.lockAgent(ctx, id)
	if err != nil {
		return err
	}
	defer unlock()
	a, err := h.agent(ctx, id)
	if err != nil {
		return err
	}
	if a == nil {
		return errors.New("unregistered agent")
	}
	if a.Generation != generation {
		return ErrGeneration
	}
	if a.Run == nil {
		return nil
	}
	return h.retireRun(ctx, id, a.Run)
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
	unlock, err := h.lockAgent(ctx, id)
	if err != nil {
		return false, err
	}
	defer unlock()
	a, err := h.agent(ctx, id)
	if err != nil {
		return false, err
	}
	if a == nil {
		return false, errors.New("unregistered agent")
	}
	if a.SealID != "" {
		// A permanent seal forbids every generation. Keep its attested
		// generation stable even when routine cleanup requests a larger one.
		return true, nil
	}
	if a.Generation > generation {
		return false, ErrGeneration
	}
	if a.Run != nil && a.Run.Generation == generation && a.Run.Phase == "RUNNING" && a.Run.ID == preserveVM {
		return false, nil
	}
	if a.Run != nil {
		if err := h.cleanup(a.Run); err != nil {
			return false, err
		}
	}
	record, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	err = h.locked(record, func(r *hostRegistry) error {
		current := r.Agents[id]
		if current == nil {
			return errors.New("unregistered agent")
		}
		if current.Generation > generation {
			return ErrGeneration
		}
		if current.Run != nil {
			if a.Run == nil || current.Run.ID != a.Run.ID {
				return ErrVolumeBusy
			}
			current.Run = nil
		}
		current.Generation = generation
		return h.save(r)
	})
	return err == nil, err
}

// FenceAgent durably blocks future starts before neutralizing the current VMM.
// This is a host lifecycle fence, NOT a harness data barrier or key destruction.
func (h *FirecrackerHost) FenceAgent(ctx context.Context, id string) error {
	unlock, err := h.lockAgent(ctx, id)
	if err != nil {
		return err
	}
	defer unlock()
	var run *VMRun
	if err = h.locked(ctx, func(r *hostRegistry) error {
		a := r.Agents[id]
		if a == nil {
			return errors.New("unregistered agent")
		}
		a.Fenced = true
		if a.Run != nil {
			run = a.Run
		}
		return h.save(r)
	}); err != nil || run == nil {
		return err
	}
	return h.retireRun(ctx, id, run)
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

// Check the lock on the VMM's actual backing descriptor before exposing RUNNING.
// A vanilla or incorrectly built Firecracker must not be accepted by this driver.
func ownedVolumeLock(pid int, volume string) error {
	_, locked, err := volumeLock(pid, volume)
	if err == nil && !locked {
		err = errVolumeLock
	}
	return err
}

var errVolumeLock = errors.New("VMM does not own the required writable-volume flock")

// volumeLock tells whether pid has volume open, and whether it holds the
// volume's exclusive lock through one of those descriptors.
func volumeLock(pid int, volume string) (open, locked bool, err error) {
	want, err := os.Stat(volume)
	if err != nil {
		return false, false, err
	}
	entries, err := os.ReadDir(fmt.Sprintf("/proc/%d/fd", pid))
	if err != nil {
		return false, false, err
	}
	for _, entry := range entries {
		path := fmt.Sprintf("/proc/%d/fd/%s", pid, entry.Name())
		got, err := os.Stat(path)
		if err != nil || !os.SameFile(want, got) {
			continue
		}
		info, err := os.ReadFile(fmt.Sprintf("/proc/%d/fdinfo/%s", pid, entry.Name()))
		if errors.Is(err, fs.ErrNotExist) {
			continue // closed since, as by a VMM that exits
		}
		if err != nil {
			return true, false, err
		}
		open = true
		for _, line := range strings.Split(string(info), "\n") {
			f := strings.Fields(line)
			if len(f) >= 6 && f[0] == "lock:" && f[2] == "FLOCK" && f[3] == "ADVISORY" && f[4] == "WRITE" {
				return true, true, nil
			}
		}
	}
	return open, false, nil
}

// confirmedVMM tells whether a's confirmed VMM still runs. A live VMM that
// has its volume open without its lock is an error, not an absence.
func (h *FirecrackerHost) confirmedVMM(a *HostAgent) (bool, error) {
	if h.census != nil {
		return h.census(a)
	}
	if _, _, err := h.identify(a); err != nil {
		return false, nil
	}
	return vmmWithVolume(a.Run.PID, a.Volume, func() bool { _, _, err := h.identify(a); return err == nil })
}

// vmmWithVolume tells whether a confirmed VMM, found alive, still runs with
// its volume; alive identifies it again.
//
// A VMM releases its volume as it exits: Firecracker closes its drive, which
// releases the lock, before its process ends (59 to 110 ms from "Vmm is
// stopping" to its last line, for guests of 256 MiB; longer for larger
// guests, whose memory it also unmaps). A guest that restarts ends its VMM
// so (ADR 012, question 6). A VMM with no descriptor of its volume left can
// no longer write it: it is gone, and the census's cleanup kills what is left
// of it and waits until its cgroup is empty before the volume is used again.
// So is a VMM that ended while it was examined. A VMM that has its volume
// open without the lock is an error: an unpatched VMM, or another writer.
func vmmWithVolume(pid int, volume string, alive func() bool) (bool, error) {
	open, locked, err := volumeLock(pid, volume)
	switch {
	case locked:
		return true, nil
	case !alive():
		return false, nil
	case err != nil:
		return true, err
	case !open:
		return false, nil
	}
	return true, errVolumeLock
}
