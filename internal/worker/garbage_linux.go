//go:build linux

package worker

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/corpusmeta"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/runtime"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/volumearchive"
)

// GarbageCollection runs, on demand, the cleanup that the maintenance worker
// does on its own (OPR-5): on its host, the archives past retention (the Keep
// newest of each agent stay; the worker applies it after each capture), the
// archives of deleted agents (hourly, ADR 018), the cached harness packages no
// agent of the host can boot (hourly), and what interrupted captures,
// removals and downloads left. It runs beside the maintenance worker: each
// removal is one that the worker may also make, and repeating one is
// harmless; a leftover is removed only once untouched for an hour, so a
// capture or a download in progress is left alone.
type GarbageCollection struct {
	CorpusCache, CorpusStaging, RuntimeRoot string
	Store                                   *controlplane.Store
	HostID                                  string
	// Archives is the host's archive root, nil without the archives
	// section; Keep, its retention per agent.
	Archives *volumearchive.Store
	Keep     int
	// ImageCache is the registry's cache, empty without the registry
	// section. InUse lists the images this host's agents may boot from.
	ImageCache string
	InUse      func(context.Context) (map[string]bool, error)
	// LogsRoot is the runtime root whose VMM logs of runs that are gone go
	// (S-20); empty for none.
	LogsRoot string
}

// ArchiveGarbage is what a collection removed from the archive root, or
// would remove in a dry run.
type ArchiveGarbage struct {
	// Retention are the archives beyond the Keep newest of their agent.
	Retention []string `json:"retention"`
	// Deleted are the archives of deleted agents: their key is destroyed.
	Deleted   []string `json:"deleted_agents"`
	Leftovers int      `json:"leftovers"`
	Bytes     int64    `json:"bytes"`
}

// GarbageReport is a collection's outcome: nil parts are not configured.
type GarbageReport struct {
	Corpora  *ImageGarbage   `json:"corpora,omitempty"`
	Archives *ArchiveGarbage `json:"archives,omitempty"`
	Images   *ImageGarbage   `json:"images,omitempty"`
	// VMMLogs counts the logs of VM runs that are gone.
	VMMLogs int `json:"vmm_logs,omitempty"`
}

// Found reports whether the collection removed, or would remove, anything.
func (r GarbageReport) Found() bool {
	a, i := r.Archives, r.Images
	return r.Corpora != nil && (len(r.Corpora.Unused) > 0 || r.Corpora.Leftovers > 0) || a != nil && (len(a.Retention) > 0 || len(a.Deleted) > 0 || a.Leftovers > 0) ||
		i != nil && (len(i.Unused) > 0 || i.Leftovers > 0) || r.VMMLogs > 0
}

// leftoverAge is how long a leftover stays untouched before a collection
// removes it: no capture or download of a running worker idles that long
// (a download times out after 30 minutes).
const leftoverAge = time.Hour

// Run collects; a dry run reports what it would remove and changes nothing.
// What it removed before an error is in the report.
func (g GarbageCollection) Run(ctx context.Context, dryRun bool) (GarbageReport, error) {
	var r GarbageReport
	if g.Store == nil || g.HostID == "" || g.Archives != nil && (g.Keep < 1 || g.Keep > 365) || g.ImageCache != "" && g.InUse == nil {
		return r, controlplane.ErrInput
	}
	if g.Archives != nil {
		r.Archives = &ArchiveGarbage{Retention: []string{}, Deleted: []string{}}
		if err := g.collectArchives(ctx, r.Archives, dryRun); err != nil {
			return r, err
		}
	}
	if g.ImageCache != "" {
		images := &HarnessImporter{store: g.Store, cache: g.ImageCache}
		collected, err := images.collect(ctx, g.HostID, g.InUse, leftoverAge, dryRun)
		r.Images = &collected
		if err != nil {
			return r, err
		}
	}
	if g.CorpusCache != "" {
		v, err := newCorpusCache(g.CorpusCache).collect(ctx, g.Store, g.HostID, g.RuntimeRoot, dryRun)
		r.Corpora = &v
		if err != nil {
			return r, err
		}
		if err = g.cleanCorpusStaging(ctx, dryRun, &v); err != nil {
			return r, err
		}
	}
	if g.LogsRoot != "" {
		n, err := runtime.CollectStaleLogsAt(ctx, g.LogsRoot, dryRun)
		r.VMMLogs = n
		if err != nil {
			return r, err
		}
	}
	return r, nil
}

func (g GarbageCollection) collectArchives(ctx context.Context, a *ArchiveGarbage, dryRun bool) error {
	leftovers, err := g.Archives.Leftovers(leftoverAge)
	if err != nil {
		return err
	}
	for _, name := range leftovers {
		size, err := g.Archives.LeftoverSize(name)
		if err != nil {
			return err
		}
		a.Leftovers++
		a.Bytes += size
	}
	if !dryRun {
		if err = g.Archives.Sweep(leftoverAge); err != nil {
			return err
		}
	}
	// The deleted agents' first: their records then say removed, and
	// retention does not count them twice.
	deleted, size, err := purgeDeletedArchives(ctx, g.Store, g.HostID, g.Archives, dryRun)
	a.Deleted, a.Bytes = deleted, a.Bytes+size
	if err != nil {
		return err
	}
	expired, err := g.Store.ExpiredHostVolumeArchives(ctx, g.HostID, g.Keep)
	if err != nil {
		return err
	}
	for _, id := range expired {
		if slices.Contains(deleted, id) {
			continue
		}
		size, err := g.Archives.Size(id)
		if err != nil {
			return err
		}
		if !dryRun {
			if err = g.Archives.Remove(id); err != nil {
				return err
			}
			if err = g.Store.RemovedVolumeArchive(ctx, id); err != nil {
				return err
			}
		}
		a.Retention = append(a.Retention, id)
		a.Bytes += size
	}
	return nil
}

// GarbageCollection is the collection of this configuration's host, on its
// archive root and image cache. A root that does not exist holds nothing to
// collect, and is not created.
func (c ServiceConfig) GarbageCollection(s *controlplane.Store) (GarbageCollection, error) {
	g := GarbageCollection{Store: s, HostID: c.HostID, LogsRoot: c.Root}
	a, err := c.archives()
	if err != nil {
		return g, err
	}
	if a != nil {
		if _, err = os.Stat(c.Archives.Root); err == nil {
			if g.Archives, err = volumearchive.New(c.Archives.Root); err != nil {
				return g, err
			}
			g.Keep = a.Keep
		} else if !errors.Is(err, os.ErrNotExist) {
			return g, err
		}
	}
	if c.Corpus != nil {
		cs, err := c.corpusSources()
		if err != nil {
			return g, err
		}
		g.CorpusCache, g.CorpusStaging, g.RuntimeRoot = cs.Cache, cs.Staging, c.Root
	}
	if c.Registry != nil {
		g.ImageCache = c.Registry.Cache
		if g.ImageCache == "" {
			g.ImageCache = filepath.Join(c.Root, "releases")
		}
		if !filepath.IsAbs(g.ImageCache) {
			return g, controlplane.ErrInput
		}
		root := c.Root
		g.InUse = func(ctx context.Context) (map[string]bool, error) { return runtime.HarnessImagesInUseAt(ctx, root) }
	}
	return g, nil
}

func (g GarbageCollection) cleanCorpusStaging(ctx context.Context, dry bool, out *ImageGarbage) error {
	entries, err := os.ReadDir(g.CorpusStaging)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, e := range entries {
		if !e.IsDir() || !buildID.MatchString(e.Name()) && !corpusmeta.ValidID("cex", e.Name()) {
			continue
		}
		done, err := g.Store.CorpusStagingFinished(ctx, g.HostID, e.Name())
		if err != nil {
			return err
		}
		if !done {
			continue
		}
		dir := filepath.Join(g.CorpusStaging, e.Name())
		bytes, _, err := treeUsage(dir)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		if !dry {
			if err = removeTree(dir); err != nil {
				return err
			}
		}
		out.Leftovers++
		out.Bytes += bytes
	}
	return nil
}
