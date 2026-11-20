package worker

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/corpussource"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/telemetry"
)

// The two fetch phases of a corpus build (ADR 023 §4).
const (
	// CorpusFetchSource is FETCHING: the ref resolved to a commit, then the
	// commit's archive downloaded to <staging>/<build>/source.bin.
	CorpusFetchSource = "source"
	// CorpusFetchLFS is FETCHING_LFS: the LFS objects the builder's scan
	// listed, downloaded to <staging>/<build>/lfs.bin.
	CorpusFetchLFS = "lfs"
	// MaxCorpusFetchAttempts is how many times a fetch phase is tried
	// before its build fails, as for a harness import.
	MaxCorpusFetchAttempts = 5
	// CorpusSourceFile is the archive's drive in a build's staging
	// directory; corpussource.LFSFile is the LFS drive's.
	CorpusSourceFile = "source.bin"
)

// CorpusFetchJob is one leased fetch phase of a build: what the builds'
// store gives the fetcher, and takes back when it completes or fails.
type CorpusFetchJob struct {
	BuildID, TenantID string
	// Phase is CorpusFetchSource or CorpusFetchLFS.
	Phase string
	// Attempt counts this phase's attempts, from 1.
	Attempt int
	// Token is the lease's, which every write of the store checks.
	Token  string
	Source corpussource.Source
	// CredentialID is the corpus's source credential, empty for a public
	// repository.
	CredentialID string
	// Ref is the requested ref; Commit is set once resolved, or from the
	// request: the phase then skips the resolution.
	Ref, Commit string
	// Pointers are the LFS phase's objects, from the builder's scan.
	Pointers []corpussource.Pointer
}

// CorpusFetchStore is what the fetcher needs of the builds' table. Its
// PostgreSQL implementation keeps each write under the job's lease.
type CorpusFetchStore interface {
	// ClaimCorpusFetch leases one due fetch phase, if any:
	// controlplane.ErrNoWork otherwise. A QUEUED build of an organization
	// that has no build from FETCHING to PACKAGING turns FETCHING; a
	// FETCHING or FETCHING_LFS build whose next attempt is due and whose
	// lease is free is claimed again. Attempt counts the phase's claims.
	ClaimCorpusFetch(ctx context.Context, worker string, lease time.Duration) (CorpusFetchJob, error)
	// PinCorpusCommit records the commit the ref named; the build is pinned
	// to it, so a retry does not resolve the ref again.
	PinCorpusCommit(ctx context.Context, job CorpusFetchJob, commit string) error
	// CompleteCorpusSource records the archive's exact size and sha256;
	// the build turns SCANNING.
	CompleteCorpusSource(ctx context.Context, job CorpusFetchJob, archive corpussource.Archive) error
	// CompleteCorpusLFS records the LFS drive; the build turns CONVERTING.
	CompleteCorpusLFS(ctx context.Context, job CorpusFetchJob, drive corpussource.LFSDrive) error
	// FailCorpusFetch ends the attempt. Final, the build turns FAILED with
	// code; otherwise its lease is freed and it is due again after
	// retryAfter.
	FailCorpusFetch(ctx context.Context, job CorpusFetchJob, code string, final bool, retryAfter time.Duration) error
}

// SourceCredentials opens an organization's source credential:
// controlplane.Accounts.OpenSourceCredential.
type SourceCredentials interface {
	OpenSourceCredential(ctx context.Context, tenantID, id string) (controlplane.SourceSecret, error)
}

// CorpusFetcher downloads the sources of corpus builds: it resolves the
// ref, downloads the archive and the LFS objects, and hands them to the
// builder as opaque bytes. It runs beside maintenance, as the harness
// importer does, so that a large download never delays deliveries. It
// starts no program and reads no byte of what it downloads (REG-007,
// RUN-010).
type CorpusFetcher struct {
	store       CorpusFetchStore
	sources     *corpussource.Fetcher
	credentials SourceCredentials
	staging     string
	worker      string
	// Lease and Timeout bound one attempt; Lease must exceed Timeout.
	Lease, Timeout time.Duration
	// Pressure, when set, refuses a fetch while the staging directory's
	// file system is past the storage pressure threshold (OPS-03), before
	// the attempt and before each LFS batch: the phase is tried again
	// later, and fails storage_pressure after its last attempt.
	Pressure func(dir string) error
	// Telemetry, when set, counts the bytes fetched and times the phases.
	Telemetry *CorpusTelemetry
}

// NewCorpusFetcher returns a fetcher for the store, the sources and the
// credentials, staging under staging, an absolute directory.
func NewCorpusFetcher(store CorpusFetchStore, sources *corpussource.Fetcher, credentials SourceCredentials, staging, workerID string) (*CorpusFetcher, error) {
	if store == nil || sources == nil || credentials == nil || !filepath.IsAbs(staging) || workerID == "" {
		return nil, controlplane.ErrInput
	}
	if err := os.MkdirAll(staging, 0o700); err != nil {
		return nil, err
	}
	return &CorpusFetcher{store: store, sources: sources, credentials: credentials, staging: staging, worker: workerID,
		Lease: 125 * time.Minute, Timeout: 2 * time.Hour}, nil
}

// Run fetches until ctx ends, polling when there is nothing to do.
func (f *CorpusFetcher) Run(ctx context.Context, poll time.Duration, report func(error)) error {
	for {
		worked, err := f.FetchOne(ctx)
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

var buildID = regexp.MustCompile(`^cbd_[0-9a-f]{32}$`)

// StagingDir is a build's staging directory.
func (f *CorpusFetcher) StagingDir(build string) string { return filepath.Join(f.staging, build) }

// FetchOne runs one due fetch phase, if any. A refusal fails the build; an
// outage leaves it to a later attempt, until the last.
func (f *CorpusFetcher) FetchOne(ctx context.Context) (bool, error) {
	job, err := f.store.ClaimCorpusFetch(ctx, f.worker, f.Lease)
	if errors.Is(err, controlplane.ErrNoWork) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	start := time.Now()
	err = f.fetch(ctx, job)
	if err == nil {
		f.Telemetry.phase(job.Phase, start)
		return true, nil
	}
	if errors.Is(err, controlplane.ErrLeaseLost) {
		return true, err
	}
	code, transient := classifyCorpusFetch(err)
	final := !transient || job.Attempt >= MaxCorpusFetchAttempts
	if ferr := f.store.FailCorpusFetch(ctx, job, code, final, backoff(job.Attempt)); ferr != nil {
		return true, ferr
	}
	if final && buildID.MatchString(job.BuildID) {
		// A failed build keeps nothing: its staging goes now.
		return true, removeTree(f.StagingDir(job.BuildID))
	}
	return true, nil
}

func (f *CorpusFetcher) fetch(ctx context.Context, job CorpusFetchJob) error {
	if !buildID.MatchString(job.BuildID) || (job.Phase != CorpusFetchSource && job.Phase != CorpusFetchLFS) {
		return fmt.Errorf("%w: a fetch job the fetcher does not know", corpussource.ErrPolicy)
	}
	if f.Pressure != nil {
		if err := f.Pressure(f.staging); err != nil {
			return err
		}
	}
	ctx, cancel := context.WithTimeout(ctx, f.Timeout)
	defer cancel()
	dir := f.StagingDir(job.BuildID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	token, err := f.token(ctx, job)
	if err != nil {
		return err
	}
	if job.Phase == CorpusFetchLFS {
		options := corpussource.LFSOptions{Fetched: func(n int64) { f.Telemetry.fetched("lfs", n) }}
		if f.Pressure != nil {
			options.BeforeBatch = func() error { return f.Pressure(f.staging) }
		}
		drive, err := f.sources.LFS(ctx, job.Source, token, job.Pointers, dir, options)
		if err != nil {
			return err
		}
		return f.store.CompleteCorpusLFS(ctx, job, drive)
	}
	commit := job.Commit
	if commit == "" {
		if commit, err = f.sources.Resolve(ctx, job.Source, job.Ref, token); err != nil {
			return err
		}
		if err = f.store.PinCorpusCommit(ctx, job, commit); err != nil {
			return err
		}
	}
	archive, err := f.sources.Archive(ctx, job.Source, commit, token, filepath.Join(dir, CorpusSourceFile))
	if err != nil {
		return err
	}
	f.Telemetry.fetched("archive", archive.Bytes)
	return f.store.CompleteCorpusSource(ctx, job, archive)
}

// token opens the build's credential, if any. It must be of the source's
// kind and host, and a rule of this worker must name that host: a
// credential is never sent anywhere else.
func (f *CorpusFetcher) token(ctx context.Context, job CorpusFetchJob) (corpussource.Token, error) {
	if job.CredentialID == "" {
		return "", nil
	}
	secret, err := f.credentials.OpenSourceCredential(ctx, job.TenantID, job.CredentialID)
	switch {
	case errors.Is(err, controlplane.ErrSourceCredentialDisabled), errors.Is(err, controlplane.ErrNotFound):
		return "", fmt.Errorf("%w: the source credential is disabled or gone", corpussource.ErrDenied)
	case err != nil:
		return "", err
	case secret.Kind != job.Source.Kind || secret.Host != job.Source.Host || !f.sources.Policy().AllowsHost(secret.Kind, secret.Host):
		return "", fmt.Errorf("%w: the source credential's host matches no source rule", corpussource.ErrPolicy)
	}
	return corpussource.Token(secret.Secret), nil
}

// classifyCorpusFetch maps a failure to the build's error code (ADR 023
// §7.1), and says whether a later attempt may succeed.
func classifyCorpusFetch(err error) (string, bool) {
	switch {
	case errors.Is(err, corpussource.ErrPolicy):
		return "policy", false
	case errors.Is(err, corpussource.ErrNotFound):
		return "not_found", false
	case errors.Is(err, corpussource.ErrDenied):
		return "access_denied", false
	case errors.Is(err, corpussource.ErrIntegrity):
		return "integrity", false
	case errors.Is(err, corpussource.ErrTooLarge):
		return "too_large", false
	case errors.Is(err, controlplane.ErrStoragePressure):
		return "storage_pressure", true
	default:
		return "unavailable", true
	}
}

// CorpusTelemetry counts what the corpus fetcher downloads and times its
// phases, with closed labels only (ADR 023 §16): never an organization, a
// corpus, a forge or a path. The builder times its own phases with it.
type CorpusTelemetry struct {
	bytes  *telemetry.Counter
	phases *telemetry.Histogram
}

var corpusPhases = []string{"fetching", "scanning", "fetching_lfs", "converting", "packaging"}

// NewCorpusTelemetry registers agentcapsule_worker_corpus_fetched_bytes_total
// and agentcapsule_worker_corpus_phase_seconds.
func NewCorpusTelemetry(registry *telemetry.Registry) *CorpusTelemetry {
	m := &CorpusTelemetry{
		bytes: registry.Counter("agentcapsule_worker_corpus_fetched_bytes_total", "Bytes of corpus sources fetched, by kind (archive, lfs).",
			telemetry.Label{Name: "kind", Values: []string{"archive", "lfs"}}),
		phases: registry.Histogram("agentcapsule_worker_corpus_phase_seconds", "Time of the corpus build phases that succeeded, by phase.",
			[]float64{1, 5, 15, 60, 300, 900, 1800, 3600, 7200, 14400}, telemetry.Label{Name: "phase", Values: corpusPhases}),
	}
	for _, kind := range []string{"archive", "lfs"} {
		m.bytes.Add(0, kind)
	}
	return m
}

// Phase records a successful phase that started at start.
func (m *CorpusTelemetry) Phase(phase string, start time.Time) {
	if m != nil {
		m.phases.Since(start, phase)
	}
}

func (m *CorpusTelemetry) phase(fetchPhase string, start time.Time) {
	if fetchPhase == CorpusFetchLFS {
		m.Phase("fetching_lfs", start)
	} else {
		m.Phase("fetching", start)
	}
}

func (m *CorpusTelemetry) fetched(kind string, n int64) {
	if m != nil {
		m.bytes.Add(float64(n), kind)
	}
}
