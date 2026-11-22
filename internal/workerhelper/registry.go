package workerhelper

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"strconv"
	"strings"
)

// RegistryVersion is the version of the worker's registry.json that this
// view reads (internal/runtime, registryVersion).
const RegistryVersion = 3

// Registry is the part of the worker's registry.json the helper reads: which
// agent has which UID, volume, run and drives. It is the worker's: it says
// which of the worker's VMs and files a request concerns, never what the
// helper may do as root (ADR 024 §4).
type Registry struct {
	Version int               `json:"version"`
	Agents  map[string]*Agent `json:"agents"`
}

// Agent is one agent of the registry (runtime.HostAgent).
type Agent struct {
	ID            string     `json:"id"`
	UID           uint32     `json:"uid"`
	Volume        string     `json:"volume"`
	Device        uint64     `json:"Device"`
	Inode         uint64     `json:"Inode"`
	Generation    uint64     `json:"generation"`
	Fenced        bool       `json:"fenced"`
	SealID        string     `json:"seal_id,omitempty"`
	VolumeRemoved bool       `json:"volume_removed,omitempty"`
	Run           *Run       `json:"run,omitempty"`
	Resources     Resources  `json:"resources,omitempty"`
	SystemImage   *BootImage `json:"system_image,omitempty"`
	Harness       *Image     `json:"harness,omitempty"`
	Corpora       []Image    `json:"corpora,omitempty"`
	Build         *Build     `json:"build,omitempty"`
}

// Run is an agent's VM run (runtime.VMRun).
type Run struct {
	ID         string `json:"id"`
	Generation uint64 `json:"generation"`
	Phase      string `json:"phase"`
	PID        int    `json:"pid"`
	StartTicks string `json:"start_ticks"`
	Socket     string `json:"socket"`
	FenceOnly  bool   `json:"fence_only,omitempty"`
}

// Resources are a VM's vCPUs and memory; zero means one vCPU and 256 MiB.
type Resources struct {
	VCPUs     int `json:"vcpus"`
	MemoryMiB int `json:"memory_mib"`
	VolumeMiB int `json:"volume_mib"`
}

// BootImage names an agent's pinned kernel and initrd by their digests.
type BootImage struct {
	Kernel string `json:"kernel"`
	Initrd string `json:"initrd"`
}

// Image is a harness or corpus image.
type Image struct {
	Path string `json:"path"`
}

// Build are a builder agent's drives (runtime.BuildDrives).
type Build struct {
	Enricher bool   `json:"enricher,omitempty"`
	Source   string `json:"source"`
	LFS      string `json:"lfs,omitempty"`
	Output   string `json:"output"`
}

// DecodeRegistry reads a registry.json. Fields this view does not name are
// ignored: they are the worker's alone.
func DecodeRegistry(b []byte) (*Registry, error) {
	r := &Registry{}
	if err := json.Unmarshal(b, r); err != nil {
		return nil, err
	}
	if r.Version != RegistryVersion {
		return nil, errors.New("worker registry of another version")
	}
	if r.Agents == nil {
		r.Agents = map[string]*Agent{}
	}
	for id, a := range r.Agents {
		if a == nil || a.ID != id {
			return nil, errors.New("invalid agent in the worker registry")
		}
	}
	return r, nil
}

// ValidRunID: a run's ID, 16 lowercase hexadecimal digits.
func ValidRunID(id string) bool {
	b, err := hex.DecodeString(id)
	return err == nil && len(b) == 8 && strings.ToLower(id) == id
}

func validDigest(d string) bool {
	b, err := hex.DecodeString(d)
	return err == nil && len(b) == sha256.Size && strings.ToLower(d) == d
}

// Layout is where a host's VMs live.
type Layout struct {
	// Root is the worker's runtime root.
	Root string `json:"root"`
	// Jails is the jailer's chroot base for new runs.
	Jails string `json:"jails"`
	// Bin holds the pinned jailer and Firecracker the helper executes.
	Bin string `json:"bin"`
	// Cgroup is the VMs' parent cgroup.
	Cgroup string `json:"cgroup"`
}

// CgroupFor is the VMs' parent cgroup of a runtime root, as the runtime has
// always named it.
func CgroupFor(root string) string {
	hash := sha256.Sum256([]byte(root))
	return filepath.Join("/sys/fs/cgroup", "acp-runtime-"+hex.EncodeToString(hash[:8]))
}

// LegacyJails is where a worker that ran as root put its jails: runs it
// started stay there until they end (ADR 024 §5).
func (l Layout) LegacyJails() string { return filepath.Join(l.Root, "jails") }

// Jail is the chroot of run runID under the chroot base base.
func Jail(base, runID string) string { return filepath.Join(base, "firecracker", runID, "root") }

// RunCgroup is a run's cgroup.
func (l Layout) RunCgroup(runID string) string { return filepath.Join(l.Cgroup, runID) }

// JailBase is the chroot base a run's recorded socket names: the layout's,
// or the legacy one. Any other socket is refused.
func (l Layout) JailBase(run *Run) (string, error) {
	if run == nil || !ValidRunID(run.ID) {
		return "", refuse("not a run")
	}
	for _, base := range []string{l.Jails, l.LegacyJails()} {
		if base != "" && run.Socket == filepath.Join(Jail(base, run.ID), "vsock") {
			return base, nil
		}
	}
	return "", refuse("the run's socket is outside the jails")
}

// The kinds of file a jail gets.
const (
	KindKernel  = "kernel"
	KindVolume  = "volume"
	KindHarness = "harness"
	KindCorpus  = "corpus"
	KindBuild   = "build"
)

// JailFile is a file of a jail: Name in the jail, Source on the host.
type JailFile struct {
	Name, Source, Kind string
}

// BootFiles names an agent's cached kernel and initrd under the runtime root:
// its pinned system image, or the host's.
func (l Layout) BootFiles(a *Agent) (kernel, initrd string, err error) {
	kernel, initrd = filepath.Join(l.Root, "bin", "kernel"), filepath.Join(l.Root, "bin", "initrd")
	if a.SystemImage != nil {
		if !validDigest(a.SystemImage.Kernel) || !validDigest(a.SystemImage.Initrd) {
			return "", "", errors.New("invalid system image digest")
		}
		kernel += "-" + a.SystemImage.Kernel
		initrd += "-" + a.SystemImage.Initrd
	}
	return kernel, initrd, nil
}

// JailFiles are the files of a's jail besides its initrd and config.json, in
// the order its VM's drives take them: the kernel, the data volume, the
// registry harness, the corpora in binding order, then the build drives
// (source, lfs, output). The names are those config.json gives the VMM
// (internal/runtime, extraDrives).
func (l Layout) JailFiles(a *Agent) ([]JailFile, error) {
	kernel, _, err := l.BootFiles(a)
	if err != nil {
		return nil, err
	}
	out := []JailFile{{"kernel", kernel, KindKernel}, {"data.ext4", a.Volume, KindVolume}}
	if a.Harness != nil {
		out = append(out, JailFile{"harness.ext4", a.Harness.Path, KindHarness})
	}
	for i, c := range a.Corpora {
		out = append(out, JailFile{"corpus" + strconv.Itoa(i) + ".ext4", c.Path, KindCorpus})
	}
	if b := a.Build; b != nil {
		for _, d := range []struct{ name, path string }{{"source.bin", b.Source}, {"lfs.bin", b.LFS}, {"output.ext4", b.Output}} {
			if d.path != "" {
				out = append(out, JailFile{d.name, d.path, KindBuild})
			}
		}
	}
	return out, nil
}

// Limits are the cgroup limits of a VM of these resources: its memory with
// 256 MiB of VMM headroom, 32 tasks and its vCPUs' worth of processor time
// (ADR 012). memory.swap.max, set apart, is 0.
func Limits(r Resources) map[string]string {
	if r == (Resources{}) {
		r = Resources{VCPUs: 1, MemoryMiB: 256}
	}
	return map[string]string{
		"memory.max": strconv.FormatInt(int64(r.MemoryMiB+256)<<20, 10),
		"pids.max":   "32",
		"cpu.max":    strconv.Itoa(r.VCPUs*100000) + " 100000",
	}
}
