package worker

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
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
}

// RegistryRule is one approved registry. CredentialsFile, for a private
// registry, names a private file (see readRegistryCredentials) read once at
// startup; the configuration itself never holds the secret.
type RegistryRule struct {
	ociregistry.Rule
	CredentialsFile string `json:"credentials_file,omitempty"`
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
	var policy ociregistry.Policy
	for _, r := range c.Registry.Rules {
		rule := r.Rule
		if r.CredentialsFile != "" {
			user, password, err := readRegistryCredentials(r.CredentialsFile)
			if err != nil {
				return nil, err
			}
			rule.Username, rule.Password = user, password
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
	return &HarnessImporter{store: s, fetcher: f, cache: cache, worker: workerID, Lease: 35 * time.Minute, Timeout: 30 * time.Minute}, nil
}

// PackageDir is where a verified package of this digest lives.
func (h *HarnessImporter) PackageDir(digest string) string {
	return filepath.Join(h.cache, "sha256", strings.TrimPrefix(digest, "sha256:"))
}

// Run imports until ctx ends, polling when there is nothing to do.
func (h *HarnessImporter) Run(ctx context.Context, poll time.Duration, report func(error)) error {
	for {
		worked, err := h.ImportOne(ctx)
		if report != nil && err != nil {
			report(err)
		}
		if worked && err == nil {
			continue
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
		RootfsDigest: pkg.RootfsDigest, RootfsBytes: pkg.RootfsSize})
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

func classifyImport(err error) (string, bool) {
	switch {
	case errors.Is(err, ociregistry.ErrPolicy):
		return "policy", false
	case errors.Is(err, ociregistry.ErrNotFound):
		return "not_found", false
	case errors.Is(err, ociregistry.ErrDenied):
		return "access_denied", false
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
