//go:build linux

package worker

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/corpussource"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/corpussource/forgetest"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/telemetry"
)

const (
	corpusCommit = "3333333333333333333333333333333333333333"
	forgeToken   = "glpat-worker-forge-token-0123456789" // gitleaks:allow test fixture, not a credential
)

// fakeBuild is a build as the builds' store keeps it, for the fetch phases.
type fakeBuild struct {
	job                 CorpusFetchJob
	state, code, leased string
	attempts            int
	due                 bool
	archive             *corpussource.Archive
	drive               *corpussource.LFSDrive
	retries             []time.Duration
}

// fakeBuildStore plays the builds' table: it hands out due phases in
// order, checks the lease on every write, and records what the fetcher
// reports.
type fakeBuildStore struct {
	mu     sync.Mutex
	builds []*fakeBuild
	// loseLease makes every write after the claim fail as a lost lease.
	loseLease bool
}

func (s *fakeBuildStore) add(job CorpusFetchJob) *fakeBuild {
	s.mu.Lock()
	defer s.mu.Unlock()
	b := &fakeBuild{job: job, state: "QUEUED"}
	s.builds = append(s.builds, b)
	return b
}

func (s *fakeBuildStore) find(job CorpusFetchJob) (*fakeBuild, error) {
	for _, b := range s.builds {
		if b.job.BuildID == job.BuildID {
			if s.loseLease || b.leased != job.Token {
				return nil, controlplane.ErrLeaseLost
			}
			return b, nil
		}
	}
	return nil, controlplane.ErrNotFound
}

func (s *fakeBuildStore) ClaimCorpusFetch(_ context.Context, worker string, lease time.Duration) (CorpusFetchJob, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if worker == "" || lease <= 0 {
		return CorpusFetchJob{}, controlplane.ErrInput
	}
	for _, b := range s.builds {
		switch {
		case b.state == "QUEUED":
			b.state, b.attempts, b.job.Phase = "FETCHING", 0, CorpusFetchSource
		case (b.state == "FETCHING" || b.state == "FETCHING_LFS") && b.due:
		default:
			continue
		}
		b.attempts++
		b.due = false
		b.leased = testID("lease")
		job := b.job
		job.Attempt, job.Token = b.attempts, b.leased
		return job, nil
	}
	return CorpusFetchJob{}, controlplane.ErrNoWork
}

func (s *fakeBuildStore) PinCorpusCommit(_ context.Context, job CorpusFetchJob, commit string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, err := s.find(job)
	if err == nil {
		b.job.Commit = commit
	}
	return err
}

func (s *fakeBuildStore) CompleteCorpusSource(_ context.Context, job CorpusFetchJob, a corpussource.Archive) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, err := s.find(job)
	if err == nil {
		b.state, b.archive, b.leased = "SCANNING", &a, ""
	}
	return err
}

func (s *fakeBuildStore) CompleteCorpusLFS(_ context.Context, job CorpusFetchJob, d corpussource.LFSDrive) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, err := s.find(job)
	if err == nil {
		b.state, b.drive, b.leased = "CONVERTING", &d, ""
	}
	return err
}

func (s *fakeBuildStore) FailCorpusFetch(_ context.Context, job CorpusFetchJob, code string, final bool, retryAfter time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, err := s.find(job)
	if err != nil {
		return err
	}
	b.leased, b.code = "", code
	if final {
		b.state = "FAILED"
	} else {
		b.due, b.retries = true, append(b.retries, retryAfter)
	}
	return nil
}

// scanned plays the builder's scan: the build turns FETCHING_LFS with its
// pointers, its phase's attempts counted again from zero.
func (s *fakeBuildStore) scanned(b *fakeBuild, pointers []corpussource.Pointer) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b.state, b.due, b.attempts = "FETCHING_LFS", true, 0
	b.job.Phase, b.job.Pointers = CorpusFetchLFS, pointers
}

// fakeCredentials holds the organizations' source credentials.
type fakeCredentials struct {
	secrets  map[string]controlplane.SourceSecret
	disabled map[string]bool
	opened   int
}

func (c *fakeCredentials) OpenSourceCredential(_ context.Context, tenant, id string) (controlplane.SourceSecret, error) {
	c.opened++
	if c.disabled[id] {
		return controlplane.SourceSecret{}, controlplane.ErrSourceCredentialDisabled
	}
	s, ok := c.secrets[tenant+"/"+id]
	if !ok {
		return controlplane.SourceSecret{}, controlplane.ErrNotFound
	}
	return s, nil
}

type corpusLab struct {
	forge       *forgetest.Forge
	store       *fakeBuildStore
	credentials *fakeCredentials
	fetcher     *CorpusFetcher
	registry    *telemetry.Registry
}

func newCorpusLab(t *testing.T, limits corpussource.Limits) *corpusLab {
	t.Helper()
	forge := forgetest.New(t)
	sources, err := corpussource.NewForTests(corpussource.Policy{Rules: forgetest.Rules()}, limits, forge.Network())
	if err != nil {
		t.Fatal(err)
	}
	l := &corpusLab{forge: forge, store: &fakeBuildStore{}, registry: telemetry.NewRegistry(),
		credentials: &fakeCredentials{secrets: map[string]controlplane.SourceSecret{
			"org_a/scr_github": {Kind: corpussource.GitHub, Host: forgetest.GitHubHost, Secret: forgeToken},
			"org_a/scr_gitlab": {Kind: corpussource.GitLab, Host: forgetest.GitLabHost, Secret: forgeToken},
			"org_a/scr_other":  {Kind: corpussource.GitLab, Host: "gitlab.elsewhere.test", Secret: forgeToken},
		}, disabled: map[string]bool{}}}
	if l.fetcher, err = NewCorpusFetcher(l.store, sources, l.credentials, filepath.Join(t.TempDir(), "staging"), "worker-1"); err != nil {
		t.Fatal(err)
	}
	l.fetcher.Telemetry = NewCorpusTelemetry(l.registry)
	return l
}

var corpusLimits = corpussource.Limits{ArchiveBytes: 1 << 20, LFSBytes: 1 << 20, LFSObjects: 100}

// testID is an identifier as the control plane makes them.
func testID(kind string) string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return kind + "_" + hex.EncodeToString(b)
}

func randomCorpusBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

func (l *corpusLab) fetchOne(t *testing.T) error {
	t.Helper()
	worked, err := l.fetcher.FetchOne(t.Context())
	if !worked {
		t.Fatal("no fetch phase was due")
	}
	return err
}

func corpusJob(kind, repo, credential string) CorpusFetchJob {
	host := forgetest.GitHubHost
	if kind == corpussource.GitLab {
		host = forgetest.GitLabHost
	}
	return CorpusFetchJob{BuildID: testID("cbd"), TenantID: "org_a", Source: corpussource.Source{Kind: kind, Host: host, Repository: repo},
		CredentialID: credential, Ref: "main"}
}

// Lot 3's exit criterion, through the fetcher: a private GitHub and a
// public GitLab repository, each pinned on the commit its ref names, its
// archive in source.bin as the forge sent it; then the LFS objects the scan
// listed, in lfs.bin. A fetcher with nothing due does nothing.
func TestCorpusFetcherFetchesSourcesPinnedOnTheirCommit(t *testing.T) {
	l := newCorpusLab(t, corpusLimits)
	if worked, err := l.fetcher.FetchOne(t.Context()); worked || err != nil {
		t.Fatal("a fetcher with nothing due", worked, err)
	}
	for _, c := range []struct{ kind, repo, credential string }{
		{corpussource.GitHub, "acme/handbook", "scr_github"},
		{corpussource.GitLab, "school/finance/l3", ""},
	} {
		archive := randomCorpusBytes(t, 50_000)
		object := randomCorpusBytes(t, 7000)
		l.forge.Add(&forgetest.Repo{Kind: c.kind, Path: c.repo, Private: c.credential != "", Token: forgeToken,
			Refs: map[string]string{"main": corpusCommit}, Archives: map[string][]byte{corpusCommit: archive},
			Objects: map[string][]byte{forgetest.OID(object): object}})
		b := l.store.add(corpusJob(c.kind, c.repo, c.credential))
		if err := l.fetchOne(t); err != nil {
			t.Fatal(c.kind, err)
		}
		if b.state != "SCANNING" || b.job.Commit != corpusCommit || b.archive == nil || b.archive.Bytes != int64(len(archive)) {
			t.Fatal(c.kind, "after FETCHING:", b.state, b.job.Commit, b.archive)
		}
		raw, err := os.ReadFile(filepath.Join(l.fetcher.StagingDir(b.job.BuildID), CorpusSourceFile))
		if err != nil || !bytes.Equal(raw[:len(archive)], archive) || len(raw)%corpussource.Block != 0 {
			t.Fatal(c.kind, "source.bin is not the forge's archive", err)
		}
		if st, err := os.Stat(l.fetcher.StagingDir(b.job.BuildID)); err != nil || st.Mode().Perm() != 0o700 {
			t.Fatal("the staging directory is not private", err)
		}
		l.store.scanned(b, []corpussource.Pointer{{OID: forgetest.OID(object), Size: int64(len(object))}})
		if err = l.fetchOne(t); err != nil {
			t.Fatal(c.kind, "LFS:", err)
		}
		if b.state != "CONVERTING" || b.drive == nil || b.drive.Objects != 1 || b.drive.ObjectBytes != int64(len(object)) {
			t.Fatal(c.kind, "after FETCHING_LFS:", b.state, b.drive)
		}
	}
	// A build requested with a commit skips the resolution.
	l.forge.Reset()
	job := corpusJob(corpussource.GitLab, "school/finance/l3", "")
	job.Commit = corpusCommit
	b := l.store.add(job)
	if err := l.fetchOne(t); err != nil || b.state != "SCANNING" {
		t.Fatal("a build pinned at its request:", b.state, err)
	}
	for _, r := range l.forge.Requests() {
		if strings.Contains(r.Path, "/commits/") {
			t.Fatal("a build requested with a commit resolved a ref")
		}
	}
	var metrics bytes.Buffer
	if _, err := l.registry.WriteTo(&metrics); err != nil {
		t.Fatal(err)
	}
	for _, line := range []string{`agentcapsule_worker_corpus_fetched_bytes_total{kind="archive"} 150000`, `agentcapsule_worker_corpus_fetched_bytes_total{kind="lfs"} 14000`,
		`agentcapsule_worker_corpus_phase_seconds_count{phase="fetching"} 3`, `agentcapsule_worker_corpus_phase_seconds_count{phase="fetching_lfs"} 2`} {
		if !strings.Contains(metrics.String(), line) {
			t.Fatal("metrics lack", line, "\n", metrics.String())
		}
	}
	if strings.Contains(metrics.String(), "acme") || strings.Contains(metrics.String(), forgetest.GitHubHost) {
		t.Fatal("a metric names a repository or a forge")
	}
}

// A refusal fails the build at once, with its code, and removes its
// staging; nothing is retried.
func TestCorpusFetchRefusalsFailTheBuild(t *testing.T) {
	l := newCorpusLab(t, corpussource.Limits{ArchiveBytes: 1000, LFSBytes: 1 << 20, LFSObjects: 100})
	object := randomCorpusBytes(t, 5000)
	l.forge.Add(&forgetest.Repo{Kind: corpussource.GitHub, Path: "acme/handbook", Refs: map[string]string{"main": corpusCommit},
		Archives: map[string][]byte{corpusCommit: randomCorpusBytes(t, 500)}, Objects: map[string][]byte{forgetest.OID(object): object}})
	l.forge.Add(&forgetest.Repo{Kind: corpussource.GitLab, Path: "school/big", Refs: map[string]string{"main": corpusCommit},
		Archives: map[string][]byte{corpusCommit: randomCorpusBytes(t, 1001)}})
	l.forge.Add(&forgetest.Repo{Kind: corpussource.GitLab, Path: "school/private", Private: true, Token: forgeToken, Refs: map[string]string{"main": corpusCommit},
		Archives: map[string][]byte{corpusCommit: randomCorpusBytes(t, 100)}})
	l.credentials.disabled["scr_gone"] = true
	cases := []struct {
		name, code string
		job        CorpusFetchJob
		setup      func()
	}{
		{"a redirect to an undeclared host", "policy", corpusJob(corpussource.GitHub, "acme/handbook", ""), func() { l.forge.ArchiveRedirect = forgetest.Elsewhere }},
		{"an unapproved repository", "policy", corpusJob(corpussource.GitHub, "other/handbook", ""), nil},
		{"a credential of another host", "policy", corpusJob(corpussource.GitLab, "school/private", "scr_other"), nil},
		{"a credential of another kind", "policy", corpusJob(corpussource.GitLab, "school/private", "scr_github"), nil},
		{"a disabled credential", "access_denied", corpusJob(corpussource.GitLab, "school/private", "scr_gone"), nil},
		{"a credential that does not exist", "access_denied", corpusJob(corpussource.GitLab, "school/private", "scr_none"), nil},
		{"a private repository without a credential", "not_found", corpusJob(corpussource.GitLab, "school/private", ""), nil},
		{"an archive past the limit", "too_large", corpusJob(corpussource.GitLab, "school/big", ""), nil},
		{"an unknown ref", "not_found", func() CorpusFetchJob {
			j := corpusJob(corpussource.GitLab, "school/big", "")
			j.Ref = "missing"
			return j
		}(), nil},
	}
	for _, c := range cases {
		l.forge.ArchiveRedirect = ""
		if c.setup != nil {
			c.setup()
		}
		b := l.store.add(c.job)
		if err := l.fetchOne(t); err != nil {
			t.Fatal(c.name, err)
		}
		if b.state != "FAILED" || b.code != c.code || b.attempts != 1 {
			t.Error(c.name, ": state", b.state, "code", b.code, "attempts", b.attempts)
		}
		if _, err := os.Stat(l.fetcher.StagingDir(b.job.BuildID)); !os.IsNotExist(err) {
			t.Error(c.name, ": the failed build's staging is still there")
		}
	}
	for _, r := range l.forge.Requests() {
		if r.Host == forgetest.Elsewhere {
			t.Fatal("an undeclared host was reached")
		}
	}

	// An altered LFS object fails the build as integrity.
	l.forge.ArchiveRedirect = ""
	l.forge.Tampered[forgetest.OID(object)] = true
	b := l.store.add(corpusJob(corpussource.GitHub, "acme/handbook", ""))
	if err := l.fetchOne(t); err != nil || b.state != "SCANNING" {
		t.Fatal(b.state, err)
	}
	l.store.scanned(b, []corpussource.Pointer{{OID: forgetest.OID(object), Size: int64(len(object))}})
	if err := l.fetchOne(t); err != nil || b.state != "FAILED" || b.code != "integrity" {
		t.Fatal("an altered LFS object:", b.state, b.code, err)
	}
}

// An outage is tried again with the importer's backoff, up to the fifth
// attempt; storage pressure too; and a retry of the LFS phase downloads only
// what is missing.
func TestCorpusFetchRetriesOutagesThenFails(t *testing.T) {
	l := newCorpusLab(t, corpusLimits)
	var objects []corpussource.Pointer
	content := map[string][]byte{}
	for i := 0; i < 3; i++ {
		o := randomCorpusBytes(t, 3000+i)
		content[forgetest.OID(o)] = o
		objects = append(objects, corpussource.Pointer{OID: forgetest.OID(o), Size: int64(len(o))})
	}
	l.forge.Add(&forgetest.Repo{Kind: corpussource.GitLab, Path: "school/media", Refs: map[string]string{"main": corpusCommit},
		Archives: map[string][]byte{corpusCommit: randomCorpusBytes(t, 100)}, Objects: content})
	// Every connection fails: the forge is down.
	l.forge.Resolve(forgetest.GitLabHost)
	b := l.store.add(corpusJob(corpussource.GitLab, "school/media", ""))
	for i := 1; i <= MaxCorpusFetchAttempts; i++ {
		if err := l.fetchOne(t); err != nil {
			t.Fatal(err)
		}
		want := "FETCHING"
		if i == MaxCorpusFetchAttempts {
			want = "FAILED"
		}
		if b.state != want || b.code != "unavailable" {
			t.Fatal("attempt", i, b.state, b.code)
		}
	}
	if len(b.retries) != 4 || b.retries[0] != 30*time.Second || b.retries[3] != 240*time.Second {
		t.Fatal("the retries' backoff", b.retries)
	}

	// Storage pressure stops a fetch before it starts, until the last
	// attempt.
	l.forge.Resolve(forgetest.GitLabHost, "8.8.8.8")
	full := 0
	l.fetcher.Pressure = func(string) error { full++; return controlplane.ErrStoragePressure }
	b = l.store.add(corpusJob(corpussource.GitLab, "school/media", ""))
	for i := 1; i <= MaxCorpusFetchAttempts; i++ {
		if err := l.fetchOne(t); err != nil {
			t.Fatal(err)
		}
	}
	if b.state != "FAILED" || b.code != "storage_pressure" || full != MaxCorpusFetchAttempts {
		t.Fatal("storage pressure", b.state, b.code, full)
	}
	for _, r := range l.forge.Requests() {
		if strings.Contains(r.Path, "school%2Fmedia") && b.job.Commit != "" {
			t.Fatal("a fetch under storage pressure reached the forge")
		}
	}

	// A cut in the LFS phase is retried; the retry fetches only the
	// objects not yet verified.
	l.fetcher.Pressure = nil
	b = l.store.add(corpusJob(corpussource.GitLab, "school/media", ""))
	if err := l.fetchOne(t); err != nil || b.state != "SCANNING" {
		t.Fatal(b.state, err)
	}
	l.store.scanned(b, objects)
	head, idx, err := corpussource.LFSLayout(objects, corpusLimits)
	if err != nil || len(head) == 0 {
		t.Fatal(err)
	}
	l.forge.Cut[idx.Objects[2].OID] = 1
	if err = l.fetchOne(t); err != nil || b.state != "FETCHING_LFS" || b.code != "unavailable" {
		t.Fatal("a cut LFS download:", b.state, b.code, err)
	}
	l.forge.Reset()
	if err = l.fetchOne(t); err != nil || b.state != "CONVERTING" {
		t.Fatal("the retry:", b.state, b.code, err)
	}
	var again []string
	for _, r := range l.forge.Requests() {
		if _, oid, ok := strings.Cut(r.Path, "/gitlab-lfs/objects/"); ok {
			again = append(again, oid)
		}
	}
	if len(again) != 1 || again[0] != idx.Objects[2].OID {
		t.Fatal("the retry fetched", again, "not only the object that was cut")
	}
	// Once complete, the phase has nothing left: a lost lease after it is
	// the store's problem, not a refetch.
	l.forge.Reset()
	l.store.loseLease = true
	l.store.scanned(b, objects)
	if err = l.fetchOne(t); !errors.Is(err, controlplane.ErrLeaseLost) {
		t.Fatal("a lost lease:", err)
	}
	for _, r := range l.forge.Requests() {
		if strings.Contains(r.Path, "/gitlab-lfs/objects/") {
			t.Fatal("verified objects were downloaded again")
		}
	}
}

// The corpus section decodes as ADR 023 §3.2 writes it, refuses an unknown
// key, takes its defaults, and needs the llm section.
func TestCorpusSectionOfTheWorkerConfiguration(t *testing.T) {
	root := t.TempDir()
	raw := `{"version":1,"host_id":"h","root":"` + root + `","llm":{"receipt_key":"/etc/agentcapsule/receipt.key"},
"corpus": {
  "cache": "` + root + `/corpora",
  "staging": "` + root + `/corpus-staging",
  "max_archive_mib": 2048, "max_lfs_mib": 20480, "max_lfs_objects": 10000, "max_image_mib": 16384,
  "builder": {"harness": {"name": "agentcapsule-corpus-builder", "version": "1.0.0"}, "vcpus": 2, "memory_mib": 4096, "volume_mib": 2048},
  "sources": {
    "rules": [
      {"host": "github.com", "kind": "github", "api_host": "api.github.com", "repositories": ["acme/"],
       "archive_hosts": ["codeload.github.com"], "lfs_hosts": ["github-cloud.githubusercontent.com"]},
      {"host": "gitlab.example.org", "kind": "gitlab", "repositories": ["school/"]}
    ],
    "allowed_internal_hosts": ["gitlab.example.org:443"]
  }
}}`
	c, err := decodeServiceConfig(strings.NewReader(raw))
	if err != nil {
		t.Fatal("the ADR's corpus section:", err)
	}
	s, err := c.OpenCorpusSources()
	if err != nil || s.Limits != (corpussource.Limits{ArchiveBytes: 2048 << 20, LFSBytes: 20480 << 20, LFSObjects: 10000}) || s.MaxImageMiB != 16384 {
		t.Fatal("open", err, s)
	}
	if st, err := os.Stat(s.Staging); err != nil || st.Mode().Perm() != 0o700 {
		t.Fatal("the staging directory", err)
	}
	if _, err = decodeServiceConfig(strings.NewReader(strings.Replace(raw, `"max_image_mib"`, `"max_images_mib"`, 1))); err == nil {
		t.Fatal("an unknown corpus key was accepted")
	}
	if _, err = decodeServiceConfig(strings.NewReader(strings.Replace(raw, `"kind": "gitlab",`, `"kind": "gitlab", "token": "x",`, 1))); err == nil {
		t.Fatal("an unknown rule key was accepted")
	}
	// Defaults.
	minimal := ServiceConfig{Root: root, LLM: &ServiceLLM{}, Corpus: &ServiceCorpus{Sources: ServiceCorpusSources{Rules: forgetest.Rules()}}}
	if s, err = minimal.corpusSources(); err != nil || s.Staging != filepath.Join(root, "corpus-staging") || s.Cache != filepath.Join(root, "corpora") || s.Limits.LFSObjects != 10000 {
		t.Fatal("defaults", err, s)
	}
	for name, mutate := range map[string]func(*ServiceConfig){
		"no llm section":           func(c *ServiceConfig) { c.LLM = nil },
		"a relative staging":       func(c *ServiceConfig) { c.Corpus.Staging = "staging" },
		"a negative limit":         func(c *ServiceConfig) { c.Corpus.MaxArchiveMiB = -1 },
		"an invalid rule":          func(c *ServiceConfig) { c.Corpus.Sources.Rules[0].Kind = "svn" },
		"a metadata address":       func(c *ServiceConfig) { c.Corpus.Sources.AllowedInternalHosts = []string{"169.254.169.254:80"} },
		"an internal public range": func(c *ServiceConfig) { c.Corpus.Sources.AllowedInternalHosts = []string{"8.8.8.0/24"} },
	} {
		bad := ServiceConfig{Root: root, LLM: &ServiceLLM{}, Corpus: &ServiceCorpus{Sources: ServiceCorpusSources{Rules: forgetest.Rules()}}}
		mutate(&bad)
		if _, err = bad.OpenCorpusSources(); err == nil {
			t.Error(name, "was accepted")
		}
	}
	if (ServiceConfig{}).CheckProductionTransport() != nil {
		t.Fatal("no corpus section refused")
	}
	local := ServiceConfig{Corpus: &ServiceCorpus{Sources: ServiceCorpusSources{Rules: []corpussource.Rule{{Host: "127.0.0.1:3000", Kind: "gitlab", Repositories: []string{"dev/"}, Local: true}}}}}
	if !errors.Is(local.CheckProductionTransport(), ErrClearTextCorpusSource) {
		t.Fatal("a local corpus rule was accepted for production")
	}
}
