//go:build linux

package runtime

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/workerhelper"
)

// CorpusImage is a verified corpus.ext4 of the host's corpus cache, shared
// read-only by every VM bound to it and mounted at /corpus/<Mount> in the
// guest (ADR 023 §5). UUID is the one its superblock carries, which the
// guest checks before it mounts the drive.
type CorpusImage struct {
	Parent string `json:"parent,omitempty"`
	Path   string `json:"path"`
	Digest string `json:"digest"`
	UUID   string `json:"uuid"`
	Mount  string `json:"mount"`
}

// BuildDrives are the raw drives of one corpus build, for the builder agent
// only: the source archive and the LFS objects, read-only, and the output
// drive the builder writes the image to. LFS is empty without LFS objects.
type BuildDrives struct {
	Enricher bool   `json:"enricher,omitempty"`
	Source   string `json:"source"`
	LFS      string `json:"lfs,omitempty"`
	Output   string `json:"output"`
}

// ErrCorpusFilesystem: a corpus image or a build drive is on another file
// system than the jails. It is shared by hard link only; copying it at each
// boot is refused (ADR 023 §5.1).
var ErrCorpusFilesystem = errors.New("corpus image or build drive outside the jails' file system: it is never copied")

// ErrDrivesInUse: the agent has a VM run; its corpora or build drives change
// only once that VM has stopped, at a later boot.
var ErrDrivesInUse = errors.New("drives in use by a running VM")

// minCorpusBytes is the smallest corpus image, as the smallest harness image.
const minCorpusBytes = 64 << 10

// drive is one drive of a VM after its data volume, in boot order.
type drive struct {
	id, source, name string // Firecracker drive_id, host path, file in the jail
	readOnly         bool
	cache            string
	rate             DriveRate
	burst            int64
}

// extraDrives lists a's drives after its data volume, in the order the guest
// expects them: the registry harness when there is one, the corpora in
// binding order, then the build drives (source, lfs, output). It returns the
// matching corpora.json, nil when the VM has neither corpora nor build
// drives.
func extraDrives(a *HostAgent, limits DriveLimits) ([]drive, *capsuleprotocol.GuestCorpora, error) {
	var out []drive
	if a.Harness != nil {
		st, err := os.Stat(a.Harness.Path)
		if err != nil {
			return nil, nil, err
		}
		out = append(out, drive{id: "harness", source: a.Harness.Path, name: "harness.ext4", readOnly: true, cache: "Unsafe",
			rate: limits.Harness, burst: st.Size()})
	}
	if len(a.Corpora) == 0 && a.Build == nil {
		return out, nil, nil
	}
	if err := checkCorpora(a.Corpora); err != nil {
		return nil, nil, err
	}
	if a.Build != nil && !a.Build.Enricher && len(a.Corpora) != 0 {
		return nil, nil, errors.New("the builder mounts no corpus")
	}
	first := capsuleprotocol.FirstExtraDrive(a.Harness != nil)
	next := first // the index of the next drive
	config := &capsuleprotocol.GuestCorpora{Schema: capsuleprotocol.CorporaSchema, Corpora: []capsuleprotocol.CorpusMount{}}
	for i, c := range a.Corpora {
		st, err := os.Stat(c.Path)
		if err != nil {
			return nil, nil, err
		}
		id := "corpus" + strconv.Itoa(i)
		out = append(out, drive{id: id, source: c.Path, name: id + ".ext4", readOnly: true, cache: "Unsafe",
			rate: limits.Corpus, burst: min(st.Size(), CorpusBurstBytes)})
		config.Corpora = append(config.Corpora, capsuleprotocol.CorpusMount{Index: next, Mount: c.Mount, UUID: c.UUID, Parent: c.Parent})
		next++
	}
	if b := a.Build; b != nil {
		build := &capsuleprotocol.GuestBuildDrives{Enricher: b.Enricher}
		for _, d := range []struct {
			id, path, name string
			readOnly       bool
			into           func(capsuleprotocol.BuildDrive)
		}{
			{"source", b.Source, "source.bin", true, func(d capsuleprotocol.BuildDrive) { build.Source = d }},
			{"lfs", b.LFS, "lfs.bin", true, func(d capsuleprotocol.BuildDrive) { build.LFS = &d }},
			{"output", b.Output, "output.ext4", false, func(d capsuleprotocol.BuildDrive) { build.Output = d }},
		} {
			if d.path == "" {
				continue
			}
			st, err := os.Stat(d.path)
			if err != nil {
				return nil, nil, err
			}
			cache := "Unsafe"
			if !d.readOnly {
				cache = "Writeback"
			}
			d.into(capsuleprotocol.BuildDrive{Index: next, Bytes: st.Size()})
			out = append(out, drive{id: d.id, source: d.path, name: d.name, readOnly: d.readOnly, cache: cache, rate: limits.Volume})
			next++
		}
		config.Build = build
	}
	if err := config.Validate(first); err != nil {
		return nil, nil, errors.New("invalid corpus or build drives")
	}
	return out, config, nil
}

// A corpus image or a build drive is shared with a jail by hard link only,
// never copied (ErrCorpusFilesystem); a harness image is linked, or copied
// from another file system (workerhelper.System.PrepareJail).

// CheckLinkable tells whether each path, a regular file or a directory, can
// be hard linked into the jails, as CheckLinkable below does, through root
// when this process is not (ADR 024): the jails are then the helper's. For a
// directory, a new empty file of this process in it is probed.
func (h *FirecrackerHost) CheckLinkable(ctx context.Context, paths ...string) error {
	if h.priv == nil {
		return CheckLinkable(h.jailBase(), paths...)
	}
	files := make([]string, 0, len(paths))
	for _, p := range paths {
		st, err := os.Lstat(p)
		if err != nil {
			return err
		}
		if st.IsDir() {
			f, err := os.CreateTemp(p, ".link-probe-")
			if err != nil {
				return err
			}
			f.Close()
			defer os.Remove(f.Name())
			p = f.Name()
		} else if !st.Mode().IsRegular() {
			return errors.New("not a regular file")
		}
		files = append(files, p)
	}
	return h.privileged().CheckLinkable(ctx, files...)
}

// CheckLinkable tells whether each path can be hard linked into dir, as a
// corpus image or a build drive is into a jail (dir: root/jails). A file is
// linked itself; for a directory, a new empty file in it. Each probe link is
// removed at once. Otherwise ErrCorpusFilesystem: link(2) refuses another
// file system, and another mount of the same one. The worker's preflight
// checks its corpus cache and staging with it.
func CheckLinkable(dir string, paths ...string) error {
	for _, p := range paths {
		if err := checkLinkable(dir, p); err != nil {
			return err
		}
	}
	return nil
}

func checkLinkable(dir, p string) error {
	st, err := os.Lstat(p)
	if err != nil {
		return err
	}
	if st.IsDir() {
		f, err := os.CreateTemp(p, ".link-probe-")
		if err != nil {
			return err
		}
		f.Close()
		defer os.Remove(f.Name())
		p = f.Name()
	} else if !st.Mode().IsRegular() {
		return errors.New("not a regular file")
	}
	nonce := make([]byte, 8)
	if _, err = rand.Read(nonce); err != nil {
		return err
	}
	probe := filepath.Join(dir, ".link-probe-"+hex.EncodeToString(nonce))
	if err = os.Link(p, probe); errors.Is(err, syscall.EXDEV) {
		return ErrCorpusFilesystem
	} else if err != nil {
		return err
	}
	return os.Remove(probe)
}

// cleanAbs: an absolute clean path.
func cleanAbs(p string) bool { return filepath.IsAbs(p) && filepath.Clean(p) == p }

// checkCorpora checks the record of a VM's corpora without reading them: at
// most MaxCorpora, each a valid mount, UUID and digest of a clean absolute
// path, each mount, UUID and path once.
func checkCorpora(corpora []CorpusImage) error {
	invalid := errors.New("invalid corpus image")
	var mounts []capsuleprotocol.CorpusMount
	paths := map[string]bool{}
	for _, c := range corpora {
		if !cleanAbs(c.Path) || !validDigest(c.Digest) || paths[c.Path] {
			return invalid
		}
		paths[c.Path] = true
		mounts = append(mounts, capsuleprotocol.CorpusMount{Parent: c.Parent, Mount: c.Mount, UUID: c.UUID})
	}
	if err := capsuleprotocol.ValidateCorpusMounts(mounts); err != nil {
		return invalid
	}
	return nil
}

func validDigest(d string) bool {
	if len(d) != 71 || !strings.HasPrefix(d, "sha256:") || strings.ToLower(d) != d {
		return false
	}
	for _, c := range d[7:] {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// verifyCorpora checks corpora before they are recorded for an agent of
// this host: the record (checkCorpora), then each image, a world-readable,
// write-protected regular file of whole 4 KiB blocks on the jails' file
// system, whose superblock carries the recorded UUID. A wrong record fails
// here, not at each boot against the agent's restart budget.
func (h *FirecrackerHost) verifyCorpora(ctx context.Context, corpora []CorpusImage) error {
	if err := checkCorpora(corpora); err != nil {
		return err
	}
	for _, c := range corpora {
		f, err := os.OpenFile(c.Path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		if err != nil {
			return err
		}
		st, err := f.Stat()
		if err == nil && (!st.Mode().IsRegular() || st.Mode().Perm()&0o004 == 0 || st.Mode().Perm()&0o222 != 0 || st.Size() < minCorpusBytes || st.Size()%4096 != 0) {
			err = errors.New("corpus image must be a world-readable, write-protected regular file of whole 4 KiB blocks")
		}
		if err == nil {
			var uuid string
			if uuid, err = capsuleprotocol.Ext4UUID(f); err == nil && uuid != c.UUID {
				err = errors.New("corpus image carries another UUID")
			}
		}
		f.Close()
		if err != nil {
			return err
		}
		if err = h.CheckLinkable(ctx, c.Path); err != nil {
			return err
		}
	}
	return nil
}

func sameCorpora(a, b []CorpusImage) bool { return slices.Equal(a, b) }

// CorporaOf returns the corpora recorded for an agent, in binding order.
func (h *FirecrackerHost) CorporaOf(ctx context.Context, id string) ([]CorpusImage, error) {
	var out []CorpusImage
	err := h.locked(ctx, func(r *hostRegistry) error {
		a := r.Agents[id]
		if a == nil {
			return errors.New("agent not registered on this host")
		}
		out = slices.Clone(a.Corpora)
		return nil
	})
	return out, err
}

// ReplaceCorpora records the corpora (in binding order, nil for none) a
// provisioned agent mounts from its next boot. Refused while a VM run
// exists, for a fenced, sealed or removed agent, and for a builder.
func (h *FirecrackerHost) ReplaceCorpora(ctx context.Context, id string, corpora []CorpusImage) error {
	if err := h.verifyCorpora(ctx, corpora); err != nil {
		return err
	}
	return h.locked(ctx, func(r *hostRegistry) error {
		a := r.Agents[id]
		switch {
		case a == nil:
			return errors.New("agent not registered on this host")
		case sameCorpora(a.Corpora, corpora):
			return nil
		case a.Fenced || a.SealID != "" || a.VolumeRemoved:
			return ErrHostFenced
		case a.Run != nil:
			return ErrDrivesInUse
		case a.Build != nil && len(corpora) != 0:
			return errors.New("the builder mounts no corpus")
		}
		a.Corpora = slices.Clone(corpora)
		return h.save(r)
	})
}

// SetBuildDrives records the build drives of a builder agent's next boot,
// nil for none. Each is a regular file of whole 4 KiB blocks on the jails'
// file system; they become the builder VMM's own: the source and the LFS
// objects readable only (0400), the output writable (0600). Refused while a
// VM run exists, and for an agent with corpora.
func (h *FirecrackerHost) SetBuildDrives(ctx context.Context, id string, b *BuildDrives) error {
	if b != nil && b.Enricher {
		return errors.New("use SetEnrichmentDrives for a reviewed base")
	}
	return h.setWorkDrives(ctx, id, b, nil)
}

// SetEnrichmentDrives installs one reviewed base and one private output
// together. Passing an empty output clears the stopped enricher's disks.
func (h *FirecrackerHost) SetEnrichmentDrives(ctx context.Context, id string, base CorpusImage, output string) error {
	if output == "" {
		return h.setWorkDrives(ctx, id, nil, []CorpusImage{})
	}
	if base.Parent != "" || base.Mount != "base" {
		return errors.New("invalid enrichment base")
	}
	bases := []CorpusImage{base}
	if err := h.verifyCorpora(ctx, bases); err != nil {
		return err
	}
	return h.setWorkDrives(ctx, id, &BuildDrives{Enricher: true, Output: output}, bases)
}

func (h *FirecrackerHost) setWorkDrives(ctx context.Context, id string, b *BuildDrives, bases []CorpusImage) error {
	var paths []string
	if b != nil {
		if !b.Enricher && b.Source == "" || b.Output == "" {
			return errors.New("invalid build drives")
		}
		paths = []string{b.Output}
		if b.Source != "" {
			paths = append(paths, b.Source)
		}
		if b.LFS != "" {
			paths = append(paths, b.LFS)
		}
		seen := map[string]bool{}
		for _, p := range paths {
			if !cleanAbs(p) || seen[p] {
				return errors.New("invalid build drives")
			}
			seen[p] = true
			st, err := os.Lstat(p)
			if err != nil {
				return err
			}
			if !st.Mode().IsRegular() || st.Size() < 4096 || st.Size()%4096 != 0 || st.Size() > capsuleprotocol.MaxBuildDriveBytes {
				return errors.New("a build drive must be a regular file of whole 4 KiB blocks")
			}
		}
		if err := h.CheckLinkable(ctx, paths...); err != nil {
			return err
		}
	}
	return h.locked(ctx, func(r *hostRegistry) error {
		a := r.Agents[id]
		switch {
		case a == nil:
			return errors.New("agent not registered on this host")
		case a.Fenced || a.SealID != "" || a.VolumeRemoved:
			return ErrHostFenced
		case a.Run != nil:
			return ErrDrivesInUse
		case bases == nil && len(a.Corpora) != 0 && b != nil:
			return errors.New("the builder mounts no corpus")
		}
		// The drives of the agent's last build go back to this process before
		// another build's, or none, are recorded: the output is read once the
		// builder stopped (ADR 024).
		if a.Build != nil {
			if err := h.privileged().ReclaimDrives(ctx, a); err != nil {
				return err
			}
		}
		if b != nil {
			drives := make([]workerhelper.Drive, 0, len(paths))
			for _, p := range paths {
				mode := uint32(0o400)
				if p == b.Output {
					mode = 0o600
				}
				drives = append(drives, workerhelper.Drive{Path: p, Mode: mode})
			}
			if err := h.privileged().GiveDrives(ctx, a, drives); err != nil {
				return err
			}
			c := *b
			b = &c
		}
		if bases != nil {
			a.Corpora = slices.Clone(bases)
		}
		a.Build = b
		return h.save(r)
	})
}

// CreateBuildOutput creates a build's output drive: a new sparse file of
// bytes, whole 4 KiB blocks, private to root until SetBuildDrives gives it
// to the builder.
func CreateBuildOutput(path string, bytes int64) error {
	if !cleanAbs(path) || bytes < 4096 || bytes%4096 != 0 || bytes > capsuleprotocol.MaxBuildDriveBytes {
		return errors.New("invalid build output drive")
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	if err = f.Truncate(bytes); err == nil {
		err = f.Sync()
	}
	return errors.Join(err, f.Close())
}

// CorpusImagesInUseAt reads the exact boot mounts of running VMs, under the
// same host lock used to install drives and change an agent's running state.
func CorpusImagesInUseAt(ctx context.Context, root string) (map[string]bool, error) {
	h, err := registeredHost(root)
	if err != nil || h == nil {
		return map[string]bool{}, err
	}
	images := map[string]bool{}
	err = h.locked(ctx, func(r *hostRegistry) error {
		for _, a := range r.Agents {
			if a.Run != nil {
				for _, c := range a.Corpora {
					images[c.Digest] = true
				}
			}
		}
		return nil
	})
	return images, err
}
