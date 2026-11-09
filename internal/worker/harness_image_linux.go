//go:build linux

package worker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnesspkg"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/runtime"
)

// EnableRegistry lets this host boot agents pinned to imported releases from
// the importer's cache.
func (w *Placements) EnableRegistry(h *HarnessImporter) error {
	if h == nil || !w.registry.CompareAndSwap(nil, h) {
		return controlplane.ErrConflict
	}
	return nil
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
