package worker

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnesspkg"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/ociregistry"
)

// ServiceRegistry enables harness imports on this host.
type ServiceRegistry struct {
	// Cache is an absolute directory for verified packages; default <root>/releases.
	Cache string `json:"cache,omitempty"`
	// MaxHarnessMiB bounds one harness.ext4 (default 1024).
	MaxHarnessMiB int            `json:"max_harness_mib,omitempty"`
	Rules         []RegistryRule `json:"rules"`
	// RequireSignatures is strict mode: every rule must list publisher keys,
	// so no unsigned package can be imported.
	RequireSignatures bool `json:"require_signatures,omitempty"`
}

// RegistryRule is one approved registry. CredentialsFile, for a private
// registry, names a private file (see readRegistryCredentials) read once at
// startup; the configuration itself never holds the secret.
type RegistryRule struct {
	ociregistry.Rule
	CredentialsFile string `json:"credentials_file,omitempty"`
	// PublisherKeys are absolute paths to PEM public keys (cosign.pub). When
	// set, every package from this rule must be signed by one of them.
	PublisherKeys []string `json:"publisher_keys,omitempty"`
}

// HarnessImporter downloads requested packages, verifies them and publishes
// them as releases. It runs beside maintenance so a large download never
// delays deliveries or VM lifecycle work.
type HarnessImporter struct {
	store   *controlplane.Store
	fetcher *ociregistry.Fetcher
	cache   string
	worker  string
	// Lease and Timeout bound one attempt; Lease must exceed Timeout.
	Lease, Timeout time.Duration
	// EvictEvery spaces cache evictions in Run (default one hour).
	EvictEvery time.Duration
	// inUse lists the image paths this host's agents may boot from. Without
	// it (no runtime attached) nothing is ever evicted.
	inUse atomic.Pointer[func(context.Context) (map[string]bool, error)]
	host  string
}

// OpenRegistry returns nil when the host does not import harnesses.
func (c ServiceConfig) OpenRegistry(s *controlplane.Store, workerID string) (*HarnessImporter, error) {
	if c.Registry == nil {
		return nil, nil
	}
	cache := c.Registry.Cache
	if cache == "" {
		cache = filepath.Join(c.Root, "releases")
	}
	maxMiB := c.Registry.MaxHarnessMiB
	if maxMiB == 0 {
		maxMiB = 1024
	}
	if !filepath.IsAbs(cache) || maxMiB < 1 || maxMiB > 64<<10 {
		return nil, errors.New("invalid registry configuration")
	}
	policy := ociregistry.Policy{RequireSignatures: c.Registry.RequireSignatures}
	for _, r := range c.Registry.Rules {
		rule := r.Rule
		if r.CredentialsFile != "" {
			user, password, err := readRegistryCredentials(r.CredentialsFile)
			if err != nil {
				return nil, err
			}
			rule.Username, rule.Password = user, password
		}
		if len(r.PublisherKeys) > 16 {
			return nil, errors.New("too many publisher keys")
		}
		for _, path := range r.PublisherKeys {
			key, err := readPublisherKey(path)
			if err != nil {
				return nil, err
			}
			rule.Keys = append(rule.Keys, key)
		}
		policy.Rules = append(policy.Rules, rule)
	}
	f, err := ociregistry.NewFetcher(policy, int64(maxMiB)<<20)
	if err != nil {
		return nil, err
	}
	return NewHarnessImporter(s, f, cache, workerID)
}

func NewHarnessImporter(s *controlplane.Store, f *ociregistry.Fetcher, cache, workerID string) (*HarnessImporter, error) {
	if s == nil || f == nil || !filepath.IsAbs(cache) || workerID == "" {
		return nil, controlplane.ErrInput
	}
	for _, d := range []string{cache, filepath.Join(cache, "sha256"), filepath.Join(cache, ".staging")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return nil, err
		}
	}
	return &HarnessImporter{store: s, fetcher: f, cache: cache, worker: workerID, Lease: 35 * time.Minute, Timeout: 30 * time.Minute,
		EvictEvery: time.Hour}, nil
}

// PackageDir is where a verified package of this digest lives.
func (h *HarnessImporter) PackageDir(digest string) string {
	return filepath.Join(h.cache, "sha256", strings.TrimPrefix(digest, "sha256:"))
}

// Run imports until ctx ends, polling when there is nothing to do. When idle,
// it evicts unused packages at most every EvictEvery. Imports and evictions run
// in this one loop, so an eviction never races with a download on this host.
func (h *HarnessImporter) Run(ctx context.Context, poll time.Duration, report func(error)) error {
	var lastEviction time.Time
	for {
		worked, err := h.ImportOne(ctx)
		if report != nil && err != nil {
			report(err)
		}
		if worked && err == nil {
			continue
		}
		if !worked && time.Since(lastEviction) >= h.EvictEvery {
			lastEviction = time.Now()
			if _, err = h.Evict(ctx); report != nil && err != nil {
				report(err)
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(poll):
		}
	}
}

// ImportOne processes one due import, if any.
func (h *HarnessImporter) ImportOne(ctx context.Context) (bool, error) {
	job, err := h.store.ClaimHarnessImport(ctx, h.worker, h.Lease)
	if errors.Is(err, controlplane.ErrNoWork) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	pkg, err := h.fetch(ctx, job)
	if err != nil {
		code, transient := classifyImport(err)
		_, ferr := h.store.FailHarnessImport(ctx, job, code, transient, backoff(job.Attempt))
		return true, ferr
	}
	_, err = h.store.CompleteHarnessImport(ctx, job, controlplane.ImportedRelease{Name: pkg.Manifest.Name, Version: pkg.Manifest.Version,
		RootfsDigest: pkg.RootfsDigest, RootfsBytes: pkg.RootfsSize, Signer: pkg.Signer})
	return true, err
}

// fetch downloads into a private staging directory, then moves the verified
// package into the content-addressed cache. A package already cached under its
// digest was verified before and is kept.
func (h *HarnessImporter) fetch(ctx context.Context, job controlplane.ImportJob) (ociregistry.Package, error) {
	ref, err := ociregistry.ParseReference(job.Reference)
	if err != nil {
		return ociregistry.Package{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, h.Timeout)
	defer cancel()
	staging, err := os.MkdirTemp(filepath.Join(h.cache, ".staging"), job.ID+"-")
	if err != nil {
		return ociregistry.Package{}, err
	}
	defer os.RemoveAll(staging)
	pkg, err := h.fetcher.Fetch(ctx, ref, staging)
	if err != nil {
		return ociregistry.Package{}, err
	}
	final := h.PackageDir(ref.Digest)
	if _, err = os.Stat(final); errors.Is(err, os.ErrNotExist) {
		// Move first (moving a directory needs write access to it), then seal.
		if err = os.Rename(staging, final); err == nil {
			err = os.Chmod(final, 0o555)
		}
	}
	if err != nil {
		return ociregistry.Package{}, err
	}
	pkg.Dir = final
	return pkg, nil
}

// Evict removes cached packages that no agent of this host can boot any more
// and leftovers of interrupted downloads. It keeps every package the control
// plane retains for this host (approved releases, releases pinned by its
// agents, imports in progress) and every image the host still records for an
// agent. It must not run concurrently with ImportOne; Run serializes them.
// VMs already running keep their own hard link to the image.
func (h *HarnessImporter) Evict(ctx context.Context) ([]string, error) {
	inUse := h.inUse.Load()
	if inUse == nil || h.host == "" {
		return nil, nil
	}
	keep, err := h.store.RetainedHarnessDigests(ctx, h.host)
	if err != nil {
		return nil, err
	}
	booting, err := (*inUse)(ctx)
	if err != nil {
		return nil, err
	}
	staging := filepath.Join(h.cache, ".staging")
	leftovers, err := os.ReadDir(staging)
	if err != nil {
		return nil, err
	}
	for _, e := range leftovers {
		if err = removeTree(filepath.Join(staging, e.Name())); err != nil {
			return nil, err
		}
	}
	entries, err := os.ReadDir(filepath.Join(h.cache, "sha256"))
	if err != nil {
		return nil, err
	}
	var evicted []string
	for _, e := range entries {
		digest := "sha256:" + e.Name()
		dir := h.PackageDir(digest)
		if !harnesspkg.ValidDigest(digest) || keep[digest] || booting[filepath.Join(dir, harnesspkg.RootfsFile)] {
			continue
		}
		// Leave the content-addressed path atomically, then delete.
		doomed, err := os.MkdirTemp(staging, "evict-")
		if err != nil {
			return evicted, err
		}
		// Moving a directory to another parent needs write access to it.
		if err = os.Chmod(dir, 0o755); err == nil {
			err = os.Rename(dir, filepath.Join(doomed, "pkg"))
		}
		if err != nil {
			return evicted, errors.Join(err, os.Remove(doomed))
		}
		if err = removeTree(doomed); err != nil {
			return evicted, err
		}
		evicted = append(evicted, digest)
	}
	return evicted, nil
}

// removeTree deletes a directory whose subdirectories were sealed read-only.
func removeTree(root string) error {
	_ = filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err == nil && d.IsDir() {
			_ = os.Chmod(p, 0o700)
		}
		return nil
	})
	return os.RemoveAll(root)
}

func classifyImport(err error) (string, bool) {
	switch {
	case errors.Is(err, ociregistry.ErrPolicy):
		return "policy", false
	case errors.Is(err, ociregistry.ErrNotFound):
		return "not_found", false
	case errors.Is(err, ociregistry.ErrDenied):
		return "access_denied", false
	case errors.Is(err, ociregistry.ErrSignature):
		return "signature", false
	case errors.Is(err, ociregistry.ErrIntegrity), errors.Is(err, harnesspkg.ErrInvalid):
		return "integrity", false
	default:
		return "unavailable", true
	}
}

func backoff(attempt int) time.Duration {
	d := 30 * time.Second << max(0, min(attempt-1, 6))
	return min(d, 30*time.Minute)
}
