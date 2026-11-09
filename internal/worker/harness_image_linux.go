//go:build linux

package worker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnesspkg"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/runtime"
)

// EnableRegistry lets this host boot agents pinned to imported releases from
// the importer's cache.
// It also lets the importer evict cached packages, keeping those the host
// still records for an agent.
func (w *Placements) EnableRegistry(h *HarnessImporter) error {
	if h == nil || !w.registry.CompareAndSwap(nil, h) {
		return controlplane.ErrConflict
	}
	inUse := w.host.HarnessImagesInUse
	h.host = w.hostID
	h.inUse.Store(&inUse)
	return nil
}

// resolveHarness returns the image an agent's release boots from: nil for the
// platform image's built-in harness, which must be this host's guest image, or
// the verified cached image of an imported release.
func (w *Placements) resolveHarness(ctx context.Context, e controlplane.Enrollment) (*runtime.HarnessImage, error) {
	if e.HarnessSource == "oci" {
		return w.harnessImage(ctx, e)
	}
	if p := w.provisioning; p == nil || e.HarnessDigest != p.digest {
		return nil, controlplane.ErrRelease
	}
	return nil, nil
}

// syncHarness applies a release change before a boot: when the agent's
// release no longer matches the image recorded on this host, the new image is
// verified and recorded. A running VM keeps its harness until it stops; a
// release this host cannot verify fails the boot, so the agent stays stopped
// until its release is changed back or the package is imported here.
func (w *Placements) syncHarness(ctx context.Context, id string) error {
	if w.provisioning == nil {
		return nil
	}
	e, err := w.store.VolumeEnrollment(ctx, id, w.hostID)
	if err != nil {
		return err
	}
	current, err := w.host.HarnessOf(ctx, id)
	if err != nil {
		return err
	}
	if e.HarnessSource == "oci" && current != nil && current.Digest == e.RootfsDigest {
		if h := w.registry.Load(); h != nil && current.Path == filepath.Join(h.PackageDir(e.HarnessDigest), harnesspkg.RootfsFile) {
			return nil
		}
	}
	if e.HarnessSource != "oci" && current == nil && w.provisioning.digest == e.HarnessDigest {
		return nil
	}
	img, err := w.resolveHarness(ctx, e)
	if err != nil {
		return err
	}
	if err = w.host.ReplaceHarness(ctx, id, img); errors.Is(err, runtime.ErrHarnessInUse) {
		return nil
	}
	return err
}

// harnessImage resolves an imported release to its cached harness.ext4. The
// file is hashed again here, once per agent, so a cache altered since import
// is refused rather than booted.
func (w *Placements) harnessImage(ctx context.Context, e controlplane.Enrollment) (*runtime.HarnessImage, error) {
	h := w.registry.Load()
	if h == nil || !harnesspkg.ValidDigest(e.HarnessDigest) || !harnesspkg.ValidDigest(e.RootfsDigest) {
		return nil, controlplane.ErrRelease
	}
	dir := h.PackageDir(e.HarnessDigest)
	raw, err := os.ReadFile(filepath.Join(dir, harnesspkg.ManifestFile))
	if err != nil {
		return nil, controlplane.ErrRelease
	}
	m, err := harnesspkg.ParseManifest(raw)
	if err != nil {
		return nil, controlplane.ErrRelease
	}
	path := filepath.Join(dir, harnesspkg.RootfsFile)
	f, err := os.Open(path)
	if err != nil {
		return nil, controlplane.ErrRelease
	}
	defer f.Close()
	sum := sha256.New()
	if _, err = io.Copy(sum, readerWithContext{ctx, f}); err != nil {
		return nil, err
	}
	if "sha256:"+hex.EncodeToString(sum.Sum(nil)) != e.RootfsDigest {
		return nil, controlplane.ErrRelease
	}
	return &runtime.HarnessImage{Path: path, Digest: e.RootfsDigest, Entrypoint: m.Entrypoint}, nil
}

type readerWithContext struct {
	ctx context.Context
	r   io.Reader
}

func (r readerWithContext) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.r.Read(p)
}
