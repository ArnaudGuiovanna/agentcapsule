//go:build linux

package workerhelper

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"syscall"
)

// Artifact is a pinned binary of the worker's configuration.
type Artifact struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// WorkerConfig is the part of the worker's configuration
// (/etc/agentcapsule/worker.json) that the helper reads: root's file, which
// the worker cannot change.
type WorkerConfig struct {
	Root         string   `json:"root"`
	Firecracker  Artifact `json:"firecracker"`
	Jailer       Artifact `json:"jailer"`
	Provisioning *struct {
		FirstUID uint32 `json:"first_uid"`
		LastUID  uint32 `json:"last_uid"`
	} `json:"provisioning"`
	Registry *struct {
		Cache         string `json:"cache"`
		InspectionUID uint32 `json:"inspection_uid"`
	} `json:"registry"`
	Corpus *struct {
		Cache   string `json:"cache"`
		Staging string `json:"staging"`
	} `json:"corpus"`
	Archives *struct {
		Root string `json:"root"`
	} `json:"archives"`
}

// ReadWorkerConfig reads the worker's configuration: a regular file of
// root's, at most 64 KiB, that neither its group nor others can write. The
// fields the helper does not use are the worker's.
func ReadWorkerConfig(path string) (WorkerConfig, error) {
	var w WorkerConfig
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return w, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return w, err
	}
	if !st.Mode().IsRegular() || st.Mode().Perm()&0o022 != 0 || st.Sys().(*syscall.Stat_t).Uid != 0 || st.Size() > 65536 {
		return w, errors.New("the worker configuration must be a bounded root-owned regular file without group/other write access")
	}
	b, err := io.ReadAll(io.LimitReader(f, 65537))
	if err != nil {
		return w, err
	}
	if err = json.Unmarshal(b, &w); err != nil {
		return w, err
	}
	return w, nil
}

// Paths is where the helper keeps its own files.
type Paths struct {
	// State is the helper's directory: bin/ (the pinned jailer and
	// Firecracker) and jails/. Root's, out of the worker's tree.
	State string
	// Executable is the worker's own executable, whose registered programs
	// a self run runs confined; empty: none.
	Executable string
	// Debugfs is the program a confined run may name; empty: none.
	Debugfs string
	// ArchiveFetch is the archive shipper's command; nil: no fetch.
	ArchiveFetch []string
}

// Config derives the helper's configuration from the worker's and the
// helper's paths, for the worker's account.
func (w WorkerConfig) Config(p Paths, workerUID, workerGID uint32, workerName string) (Config, error) {
	if !cleanAbs(w.Root) || !cleanAbs(p.State) {
		return Config{}, errors.New("the runtime root and the helper's directory must be absolute clean paths")
	}
	if w.Provisioning == nil {
		return Config{}, errors.New("the worker configuration has no provisioning range: the helper gives files to no other UID")
	}
	c := Config{
		Layout:    Layout{Root: w.Root, Jails: filepath.Join(p.State, "jails"), Bin: filepath.Join(p.State, "bin"), Cgroup: CgroupFor(w.Root)},
		WorkerUID: workerUID, WorkerGID: workerGID, WorkerName: workerName,
		FirstUID: w.Provisioning.FirstUID, LastUID: w.Provisioning.LastUID,
		ImageRoots: []string{w.Root}, DriveRoots: []string{w.Root},
		Debugfs: p.Debugfs, Executable: p.Executable, ArchiveFetch: p.ArchiveFetch,
	}
	c.Jailer, c.Firecracker = filepath.Join(c.Layout.Bin, "jailer"), filepath.Join(c.Layout.Bin, "firecracker")
	add := func(roots []string, dir string) []string {
		if dir == "" || slices.Contains(roots, dir) {
			return roots
		}
		if _, inside := within(w.Root, dir); inside {
			return roots
		}
		return append(roots, dir)
	}
	if w.Registry != nil {
		c.InspectionUID = w.Registry.InspectionUID
		c.ImageRoots = add(c.ImageRoots, w.Registry.Cache)
	}
	if w.Corpus != nil {
		c.ImageRoots = add(add(c.ImageRoots, w.Corpus.Cache), w.Corpus.Staging)
		c.DriveRoots = add(c.DriveRoots, w.Corpus.Staging)
	}
	for _, roots := range [][]string{c.ImageRoots, c.DriveRoots} {
		for _, r := range roots {
			if !cleanAbs(r) {
				return Config{}, errors.New("a cache or staging directory is not an absolute clean path")
			}
		}
	}
	if _, inside := within(w.Root, p.State); inside || w.Root == p.State {
		return Config{}, errors.New("the helper's directory must lie outside the worker's runtime root")
	}
	return c, nil
}
