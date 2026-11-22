package worker

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnesspkg"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/ociregistry"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/sandbox"
)

// ServiceRegistry enables harness imports on this host.
type ServiceRegistry struct {
	// Cache is an absolute directory for verified packages; default <root>/releases.
	Cache string `json:"cache,omitempty"`
	// MaxHarnessMiB bounds one harness.ext4 (default 1024).
	MaxHarnessMiB int            `json:"max_harness_mib,omitempty"`
	Rules         []RegistryRule `json:"rules"`
	// RequireSignatures is strict mode: every rule must list publisher keys,
	// so no unsigned package can be imported, and none may say
	// allow_unsigned. In production, without it, a rule must list publisher
	// keys or say "allow_unsigned": true (L-16).
	RequireSignatures bool `json:"require_signatures,omitempty"`
	// InspectionUID is the UID, and the GID of the same number, that debugfs
	// runs as when it inspects a downloaded image (package sandbox):
	// reserved for this use, owning no file, outside the provisioning range,
	// no account's or group's, not 65535 and below 2^31-1. Required when the
	// worker runs as root; a worker that is not root inspects as its own
	// account, in a user namespace, and ignores it.
	InspectionUID uint32 `json:"inspection_uid,omitempty"`
}

var (
	// ErrInspectionUID: a worker run as root needs registry.inspection_uid,
	// not root's, an agent's, the SLIM bridge's, nor any account's or
	// group's.
	ErrInspectionUID = errors.New("registry.inspection_uid must be a UID reserved for image inspection: " +
		"not 0 or 65535, below 2147483647, outside the provisioning range, not the SLIM bridge's, no account's or group's")
	// ErrInspection: debugfs cannot run confined on this host.
	ErrInspection = errors.New("image inspection cannot run confined on this host")
)

// Inspection returns the sandbox of this host's inspections (inspection):
// the restore test's key check runs there too (RestoreTest.Sandbox).
func (c ServiceConfig) Inspection() (sandbox.Options, error) {
	return c.inspection(sandbox.AsRoot())
}

// inspection returns the sandbox of image inspections: as root, the
// configured inspection UID and GID, checked against the values setresuid
// may take as "unchanged" (sandbox.Reservable), the agents' range, the SLIM
// bridge's user, and the host's accounts and groups: the program must own
// nothing and belong to no group (6 is disk on Debian, with /dev/sd*). A
// worker with a helper (ADR 024) delegates each run to it, which runs it as
// that UID, checked the same way.
func (c ServiceConfig) inspection(asRoot bool) (sandbox.Options, error) {
	if !asRoot && c.Helper == nil {
		return sandbox.Options{}, nil
	}
	if c.Registry == nil {
		return sandbox.Options{}, ErrInspectionUID
	}
	uid := c.Registry.InspectionUID
	p, slim := c.Provisioning, c.SLIM
	switch id := strconv.FormatUint(uint64(uid), 10); {
	case !sandbox.Reservable(uid):
		return sandbox.Options{}, fmt.Errorf("%w: %d", ErrInspectionUID, uid)
	case p != nil && uid >= p.FirstUID && uid <= p.LastUID:
		return sandbox.Options{}, fmt.Errorf("%w: %d is in the provisioning range", ErrInspectionUID, uid)
	case slim != nil && int64(slim.BridgeUID) == int64(uid):
		return sandbox.Options{}, fmt.Errorf("%w: %d is the SLIM bridge's", ErrInspectionUID, uid)
	default:
		var account user.UnknownUserIdError
		var group user.UnknownGroupIdError
		if u, err := user.LookupId(id); err == nil {
			return sandbox.Options{}, fmt.Errorf("%w: %d is the account %s's", ErrInspectionUID, uid, u.Username)
		} else if !errors.As(err, &account) {
			return sandbox.Options{}, fmt.Errorf("look up UID %d: %w", uid, err)
		}
		if g, err := user.LookupGroupId(id); err == nil {
			return sandbox.Options{}, fmt.Errorf("%w: %d is the group %s's", ErrInspectionUID, uid, g.Name)
		} else if !errors.As(err, &group) {
			return sandbox.Options{}, fmt.Errorf("look up GID %d: %w", uid, err)
		}
	}
	if c.Helper != nil {
		return sandbox.Options{Delegate: c.HelperClient()}, nil
	}
	return sandbox.Options{UID: uid, GID: uid}, nil
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
	// RefillEvery spaces the refills of missing pinned packages in Run
	// (default one minute).
	RefillEvery time.Duration
	// Pressure, when set, refuses an import while the cache's file system is
	// past the storage pressure threshold (OPS-03): the import is tried
	// again later, and rejected as storage_pressure after its last attempt.
	Pressure func(dir string) error
	// inUse lists the image paths this host's agents may boot from. Without
	// it (no runtime attached) nothing is ever evicted.
	inUse atomic.Pointer[func(context.Context) (map[string]bool, error)]
	host  string
}

// UnsignedRegistryRules returns the hosts of the registry rules that trust
// no publisher key, through which unsigned packages are imported: in
// production, only rules that say allow_unsigned (OpenRegistry refuses the
// others). The worker logs their number at start (registry_unsigned_rules).
func (c ServiceConfig) UnsignedRegistryRules() []string {
	if c.Registry == nil {
		return nil
	}
	var hosts []string
	for _, r := range c.Registry.Rules {
		if len(r.PublisherKeys) == 0 {
			hosts = append(hosts, r.Host)
		}
	}
	return hosts
}

// OpenRegistry returns nil when the host does not import harnesses. In
// production, a rule must trust publisher keys or say allow_unsigned
// (ociregistry.ErrUnsigned otherwise, L-16).
func (c ServiceConfig) OpenRegistry(s *controlplane.Store, workerID string, production bool) (*HarnessImporter, error) {
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
	policy := ociregistry.Policy{RequireSignatures: c.Registry.RequireSignatures, SignaturesByDefault: production}
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
	if f.Sandbox, err = c.inspection(sandbox.AsRoot()); err != nil {
		return nil, err
	}
	// Before any download: debugfs runs confined here, or no import does.
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err = harnesspkg.CheckInspection(ctx, f.Sandbox); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInspection, err)
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
		EvictEvery: time.Hour, RefillEvery: time.Minute}, nil
}

// PackageDir is where a verified package of this digest lives.
func (h *HarnessImporter) PackageDir(digest string) string {
	return filepath.Join(h.cache, "sha256", strings.TrimPrefix(digest, "sha256:"))
}

// Run imports until ctx ends, polling when there is nothing to do. When idle,
// it fetches again the pinned packages the cache lacks at most every
// RefillEvery, and evicts unused packages at most every EvictEvery. Imports,
// refills and evictions run in this one loop, so an eviction never races with
// a download on this host.
func (h *HarnessImporter) Run(ctx context.Context, poll time.Duration, report func(error)) error {
	var lastEviction, lastRefill time.Time
	for {
		worked, err := h.ImportOne(ctx)
		if report != nil && err != nil {
			report(err)
		}
		if worked && err == nil {
			continue
		}
		if !worked && time.Since(lastRefill) >= h.RefillEvery {
			lastRefill = time.Now()
			if _, err = h.Refill(ctx); report != nil && err != nil {
				report(err)
			}
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
	pkg, err := h.fetch(ctx, job, nil)
	if err != nil {
		code, transient := classifyImport(err)
		_, ferr := h.store.FailHarnessImport(ctx, job, code, transient, backoff(job.Attempt))
		return true, ferr
	}
	_, err = h.store.CompleteHarnessImport(ctx, job, controlplane.ImportedRelease{Name: pkg.Manifest.Name, Version: pkg.Manifest.Version,
		RootfsDigest: pkg.RootfsDigest, RootfsBytes: pkg.RootfsSize, Signer: pkg.Signer, Capabilities: pkg.Manifest.Capabilities, Base: pkg.Manifest.Base})
	return true, err
}

// Refill fetches again each package that an agent of this host pins and that
// the cache lacks, by the reference and digest its release recorded at import
// (OPR-10): a host rebuilt from its backups has its releases in PostgreSQL,
// not its cache. Each package is verified as at its import, under the same
// registry policy, and must hold the release's root file system. It returns
// the digests fetched; a package it cannot fetch leaves its agents unable to
// boot, as before. It must not run concurrently with ImportOne or Evict; Run
// serializes them.
func (h *HarnessImporter) Refill(ctx context.Context) ([]string, error) {
	if h.host == "" {
		return nil, nil
	}
	pinned, err := h.store.PinnedHarnessReleases(ctx, h.host)
	if err != nil {
		return nil, err
	}
	var refilled []string
	var failures error
	for _, r := range pinned {
		dir := h.PackageDir(r.Digest)
		_, err := os.Stat(filepath.Join(dir, harnesspkg.ManifestFile))
		if err == nil {
			continue
		}
		if errors.Is(err, os.ErrNotExist) {
			// Not a package: whatever holds its name goes first.
			err = removeTree(dir)
		}
		if err == nil {
			_, err = h.fetch(ctx, controlplane.ImportJob{ID: "refill", Reference: r.Reference}, func(pkg ociregistry.Package) error {
				if pkg.RootfsDigest != r.RootfsDigest {
					return fmt.Errorf("%w: the package does not hold the release's root file system", ociregistry.ErrIntegrity)
				}
				return nil
			})
		}
		if err != nil {
			failures = errors.Join(failures, fmt.Errorf("refill %s:%s: %w", r.Name, r.Version, err))
			continue
		}
		refilled = append(refilled, r.Digest)
	}
	return refilled, failures
}

// fetch downloads into a private staging directory, then moves the verified
// package into the content-addressed cache; accept, when given, may refuse it
// first. A package already cached under its digest was verified before and is
// kept.
func (h *HarnessImporter) fetch(ctx context.Context, job controlplane.ImportJob, accept func(ociregistry.Package) error) (ociregistry.Package, error) {
	ref, err := ociregistry.ParseReference(job.Reference)
	if err != nil {
		return ociregistry.Package{}, err
	}
	if h.Pressure != nil {
		if err = h.Pressure(h.cache); err != nil {
			return ociregistry.Package{}, err
		}
	}
	ctx, cancel := context.WithTimeout(ctx, h.Timeout)
	defer cancel()
	staging, err := os.MkdirTemp(filepath.Join(h.cache, ".staging"), job.ID+"-")
	if err != nil {
		return ociregistry.Package{}, err
	}
	defer removeTree(staging)
	pkg, err := h.fetcher.Fetch(ctx, ref, staging)
	if err == nil && accept != nil {
		err = accept(pkg)
	}
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
	g, err := h.collect(ctx, h.host, *inUse, 0, false)
	return g.Unused, err
}

// ImageGarbage is what a collection of the image cache removed, or would
// remove in a dry run: the packages no agent of the host can boot, by
// digest, the leftovers of interrupted downloads, and their bytes.
type ImageGarbage struct {
	Unused    []string `json:"unused"`
	Leftovers int      `json:"leftovers"`
	Bytes     int64    `json:"bytes"`
}

// collect is Evict for host. With staleAfter, it removes only the download
// leftovers untouched for that long: a collection that runs beside the
// worker's own imports (GarbageCollection) leaves a download in progress
// alone. It lists the cache before it reads what to keep: a package that an
// import moves into the cache meanwhile belongs to an import that is
// IMPORTING by then, or READY, and is kept. A dry run removes nothing.
func (h *HarnessImporter) collect(ctx context.Context, host string, inUse func(context.Context) (map[string]bool, error), staleAfter time.Duration, dryRun bool) (ImageGarbage, error) {
	g := ImageGarbage{Unused: []string{}}
	staging := filepath.Join(h.cache, ".staging")
	leftovers, err := os.ReadDir(staging)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return g, err
	}
	for _, e := range leftovers {
		path := filepath.Join(staging, e.Name())
		size, latest, err := treeUsage(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return g, err
		}
		if staleAfter > 0 && time.Since(latest) < staleAfter {
			continue
		}
		g.Leftovers++
		g.Bytes += size
		if !dryRun {
			if err = removeTree(path); err != nil {
				return g, err
			}
		}
	}
	entries, err := os.ReadDir(filepath.Join(h.cache, "sha256"))
	if errors.Is(err, os.ErrNotExist) {
		return g, nil
	}
	if err != nil {
		return g, err
	}
	keep, err := h.store.RetainedHarnessDigests(ctx, host)
	if err != nil {
		return g, err
	}
	booting, err := inUse(ctx)
	if err != nil {
		return g, err
	}
	for _, e := range entries {
		digest := "sha256:" + e.Name()
		dir := h.PackageDir(digest)
		if !harnesspkg.ValidDigest(digest) || keep[digest] || booting[filepath.Join(dir, harnesspkg.RootfsFile)] {
			continue
		}
		size, _, err := treeUsage(dir)
		if errors.Is(err, os.ErrNotExist) {
			continue // evicted meanwhile, by the worker or another collection
		}
		if err != nil {
			return g, err
		}
		if dryRun {
			g.Unused, g.Bytes = append(g.Unused, digest), g.Bytes+size
			continue
		}
		// Leave the content-addressed path atomically, then delete.
		doomed, err := os.MkdirTemp(staging, "evict-")
		if err != nil {
			return g, err
		}
		// Moving a directory to another parent needs write access to it.
		if err = os.Chmod(dir, 0o755); err == nil {
			err = os.Rename(dir, filepath.Join(doomed, "pkg"))
		}
		if errors.Is(err, os.ErrNotExist) {
			if err = os.Remove(doomed); err != nil {
				return g, err
			}
			continue
		}
		if err != nil {
			return g, errors.Join(err, os.Remove(doomed))
		}
		if err = removeTree(doomed); err != nil {
			return g, err
		}
		g.Unused, g.Bytes = append(g.Unused, digest), g.Bytes+size
	}
	return g, nil
}

// treeUsage is the bytes of the regular files under path and the latest
// modification of path or of anything under it. It follows no link.
func treeUsage(path string) (int64, time.Time, error) {
	var size int64
	var latest time.Time
	err := filepath.WalkDir(path, func(_ string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if info.ModTime().After(latest) {
			latest = info.ModTime()
		}
		if info.Mode().IsRegular() {
			size += info.Size()
		}
		return nil
	})
	return size, latest, err
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
	case errors.Is(err, controlplane.ErrStoragePressure):
		return "storage_pressure", true
	default:
		return "unavailable", true
	}
}

func backoff(attempt int) time.Duration {
	d := 30 * time.Second << max(0, min(attempt-1, 6))
	return min(d, 30*time.Minute)
}
