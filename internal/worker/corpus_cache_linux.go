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
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/corpuspkg"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/ociregistry/reference"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/runtime"
)

type corpusStamp struct {
	Device, Inode uint64
	Bytes, Mtime  int64
}
type corpusImageCache struct {
	root     string
	mu       sync.Mutex
	verified map[string]corpusStamp
}

func newCorpusCache(root string) *corpusImageCache {
	return &corpusImageCache{root: root, verified: map[string]corpusStamp{}}
}

func (c *corpusImageCache) withLock(ctx context.Context, fn func() error) error {
	if err := os.MkdirAll(c.root, 0700); err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Join(c.root, ".lock"), os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	for {
		err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return fn()
		}
		if !errors.Is(err, syscall.EAGAIN) && !errors.Is(err, syscall.EINTR) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(25 * time.Millisecond):
		}
	}
}
func (c *corpusImageCache) dir(digest string) string {
	return filepath.Join(c.root, "sha256", strings.TrimPrefix(digest, "sha256:"))
}
func (c *corpusImageCache) image(ctx context.Context, d controlplane.BootCorpus) (runtime.CorpusImage, error) {
	if !reference.ValidDigest(d.Digest) {
		return runtime.CorpusImage{}, controlplane.ErrCorpusUnavailable
	}
	img := runtime.CorpusImage{Digest: d.Digest, UUID: d.UUID, Mount: d.Mount, Path: filepath.Join(c.dir(d.Digest), corpuspkg.ImageFile)}
	f, err := os.OpenFile(img.Path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return img, controlplane.ErrCorpusUnavailable
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0222 != 0 {
		return img, controlplane.ErrCorpusUnavailable
	}
	stat := st.Sys().(*syscall.Stat_t)
	stamp := corpusStamp{uint64(stat.Dev), stat.Ino, st.Size(), st.ModTime().UnixNano()}
	c.mu.Lock()
	defer c.mu.Unlock()
	if prev, ok := c.verified[d.Digest]; ok && prev == stamp {
		return img, nil
	}
	h := sha256.New()
	if _, err = io.Copy(h, readerWithContext{ctx, f}); err != nil {
		return img, err
	}
	if "sha256:"+hex.EncodeToString(h.Sum(nil)) != d.Digest {
		delete(c.verified, d.Digest)
		if err = removeTree(c.dir(d.Digest)); err != nil {
			return img, err
		}
		return img, controlplane.ErrCorpusUnavailable
	}
	c.verified[d.Digest] = stamp
	return img, nil
}
func (w *Placements) syncCorpora(ctx context.Context, id string) error {
	if w.corpusCache == nil {
		discs, err := w.store.BootCorpora(ctx, id, w.hostID)
		if err != nil {
			return err
		}
		if len(discs) > 0 {
			return controlplane.ErrCorpusUnavailable
		}
		return w.host.ReplaceCorpora(ctx, id, nil)
	}
	return w.corpusCache.withLock(ctx, func() error {
		discs, err := w.store.BootCorpora(ctx, id, w.hostID)
		if err != nil {
			return err
		}
		images := make([]runtime.CorpusImage, 0, len(discs))
		for _, d := range discs {
			img, err := w.corpusCache.image(ctx, d)
			if err != nil {
				return err
			}
			images = append(images, img)
		}
		err = w.host.ReplaceCorpora(ctx, id, images)
		if errors.Is(err, runtime.ErrDrivesInUse) {
			return nil
		}
		return err
	})
}
func (w *Placements) EnableCorpusCache(root string) error {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || w.corpusCache != nil {
		return controlplane.ErrInput
	}
	w.corpusCache = newCorpusCache(root)
	return nil
}

// collect snapshots the database pins and running VM mounts while holding
// the same filesystem lock that protects publication and boot.
func (c *corpusImageCache) collect(ctx context.Context, s *controlplane.Store, host, root string, dry bool) (ImageGarbage, error) {
	g := ImageGarbage{Unused: []string{}}
	if _, err := os.Stat(c.root); errors.Is(err, os.ErrNotExist) {
		return g, nil
	} else if err != nil {
		return g, err
	}
	err := c.withLock(ctx, func() error {
		entries, err := os.ReadDir(filepath.Join(c.root, "sha256"))
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		pins, err := runtime.CorpusImagesInUseAt(ctx, root)
		if err != nil {
			return err
		}
		durable, err := s.CorpusImagesInUse(ctx, host)
		if err != nil {
			return err
		}
		for _, id := range durable {
			pins[id] = true
		}
		for _, entry := range entries {
			digest := "sha256:" + entry.Name()
			if !entry.IsDir() || !reference.ValidDigest(digest) || pins[digest] {
				continue
			}
			dir := c.dir(digest)
			size, _, err := treeUsage(dir)
			if err != nil {
				return err
			}
			if !dry {
				trash, err := os.MkdirTemp(c.root, ".remove-")
				if err != nil {
					return err
				}
				if err = os.Chmod(dir, 0755); err == nil {
					err = os.Rename(dir, filepath.Join(trash, entry.Name()))
				}
				if err != nil {
					os.Remove(trash)
					return err
				}
				if err = removeTree(trash); err != nil {
					return err
				}
			}
			g.Unused = append(g.Unused, digest)
			g.Bytes += size
		}
		leftovers, err := os.ReadDir(c.root)
		if err != nil {
			return err
		}
		for _, e := range leftovers {
			if !e.IsDir() || !strings.HasPrefix(e.Name(), ".remove-") {
				continue
			}
			dir := filepath.Join(c.root, e.Name())
			size, _, err := treeUsage(dir)
			if err != nil {
				return err
			}
			if !dry {
				if err = removeTree(dir); err != nil {
					return err
				}
			}
			g.Bytes += size
			g.Leftovers++
		}
		return nil
	})
	return g, err
}
