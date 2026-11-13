//go:build linux && cgo

package worker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/keyauthority"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/restoreauthority"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/runtime"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/telemetry"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/volumearchive"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// archiveLab has real PostgreSQL, a real archive root and a real restore
// authority, and LIVE agents on host "local" whose volumes are recorded as
// provisioned and initialized. No VM runs: the worker has no host, so a
// capture it attempts fails at once (controlplane.ErrInput), which is enough
// to observe selection, bounds and retries. Captures are KVM tests.
type archiveLab struct {
	w         *Placements
	store     *controlplane.Store
	db        *pgxpool.Pool
	archives  *volumearchive.Store
	authority *restoreauthority.Catalog
	agents    []controlplane.Enrollment
	reports   []ArchiveReport
	registry  *telemetry.Registry
}

func newArchiveLab(t *testing.T, states ...string) *archiveLab {
	t.Helper()
	dsn := os.Getenv("AGENTCAPSULE_TEST_POSTGRES")
	if dsn == "" {
		if os.Getenv("AGENTCAPSULE_REQUIRE_POSTGRES") == "1" {
			t.Fatal("PostgreSQL required")
		}
		t.Skip("run scripts/verify-postgres.py")
	}
	admin, err := pgxpool.New(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	schema := fmt.Sprintf("worker_archives_%d", time.Now().UnixNano())
	if _, err = admin.Exec(t.Context(), "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	scoped := cfg.ConnString() + " search_path=" + schema + ",pg_catalog"
	s, err := controlplane.Open(t.Context(), scoped)
	if err != nil {
		t.Fatal(err)
	}
	db, err := pgxpool.New(t.Context(), scoped)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		s.Close()
		db.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, err := admin.Exec(ctx, "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE"); err != nil {
			t.Error(err)
		}
		admin.Close()
	})
	if err = s.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	accounts, err := controlplane.NewAccounts(s, bytes.Repeat([]byte{0x3a}, 32))
	if err != nil {
		t.Fatal(err)
	}
	secret, err := s.BootstrapService(t.Context(), "archive-admin", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	p, err := s.Authenticate(t.Context(), secret)
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := controlplane.NewAgentCatalog(accounts, "local")
	if err != nil {
		t.Fatal(err)
	}
	ref := controlplane.HarnessReference{Name: "reference", Version: "1.0.0"}
	if _, err = s.RegisterLocalRelease(t.Context(), ref, "sha256:"+strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
	if err = s.ConfigureHostStorage(t.Context(), "local", 4096); err != nil {
		t.Fatal(err)
	}
	l := &archiveLab{w: &Placements{store: s, hostID: "local", workerID: "archive-test", lease: time.Minute}, store: s, db: db}
	for i, state := range states {
		r, err := accounts.CreateUser(t.Context(), p, fmt.Sprintf("owner-%d", i), controlplane.CreateUserInput{DisplayName: "Owner"})
		if err != nil {
			t.Fatal(err)
		}
		var owner controlplane.User
		if err = json.Unmarshal(r.Body, &owner); err != nil {
			t.Fatal(err)
		}
		if _, err = catalog.Reserve(t.Context(), p, fmt.Sprintf("agent-%d", i), controlplane.CreateAgentInput{OwnerUserID: owner.ID, Name: "Companion", Harness: ref,
			Resources: controlplane.AgentResources{VCPUs: 1, MemoryMiB: 256, DataVolumeMiB: 128}}); err != nil {
			t.Fatal(err)
		}
		jobs, err := s.PendingProvisioning(t.Context(), "local", 10)
		if err != nil || len(jobs) != 1 {
			t.Fatal(jobs, err)
		}
		e := jobs[0]
		if err = s.RecordProvisionedVolume(t.Context(), controlplane.ProvisionedVolume{AgentID: e.AgentID, HostID: e.HostID, VolumeID: e.VolumeID, OperationID: e.OperationID, Device: 1, Inode: uint64(100 + i)}); err != nil {
			t.Fatal(err)
		}
		// Recorded observations of a restricted boot that initialized the
		// volume, then of ordinary boots: no VM runs in this test.
		fence, err := s.ClaimFencePlacement(t.Context(), e.AgentID, e.HostID, "installer", time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		vm := fmt.Sprintf("%016x", fence.Generation)
		if err = s.ConfirmFencePlacement(t.Context(), e.AgentID, e.HostID, "installer", fence.Generation, vm); err != nil {
			t.Fatal(err)
		}
		if err = s.RecordEnrollmentInitialized(t.Context(), controlplane.EnrollmentBoot{Incarnation: 1, AgentID: e.AgentID, VolumeID: e.VolumeID, HostID: e.HostID, Generation: fence.Generation, VMID: vm}); err != nil {
			t.Fatal(err)
		}
		l.stop(t, e, fence.Generation, false)
		if err = s.ActivateProvisionedAgent(t.Context(), e); err != nil {
			t.Fatal(err)
		}
		if state == "running" || state == "asleep" {
			run, err := s.ClaimPlacement(t.Context(), e.AgentID, e.HostID, "archive-test", time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			if err = s.ConfirmPlacement(t.Context(), e.AgentID, e.HostID, "archive-test", run.Generation, fmt.Sprintf("vm-%d", run.Generation)); err != nil {
				t.Fatal(err)
			}
			if state == "asleep" {
				l.stop(t, e, run.Generation, false)
			}
		}
		l.agents = append(l.agents, e)
	}
	parent := t.TempDir()
	keys, err := keyauthority.Initialize(t.Context(), filepath.Join(parent, "keys"))
	if err != nil {
		t.Fatal(err)
	}
	if l.authority, err = restoreauthority.Initialize(t.Context(), filepath.Join(parent, "authority"), keys.Identity()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.authority.Close() })
	if l.archives, err = volumearchive.New(filepath.Join(parent, "archives")); err != nil {
		t.Fatal(err)
	}
	return l
}

func (l *archiveLab) stop(t *testing.T, e controlplane.Enrollment, generation uint64, unclean bool) {
	t.Helper()
	if err := l.store.BeginPlacementStop(t.Context(), e.AgentID, e.HostID, generation); err != nil {
		t.Fatal(err)
	}
	if err := l.store.ObservePlacementStopped(t.Context(), e.AgentID, e.HostID, generation, unclean); err != nil {
		t.Fatal(err)
	}
}

func (l *archiveLab) options(t *testing.T) *Archives {
	t.Helper()
	a := &Archives{Store: l.archives, Every: 24 * time.Hour, SleepWindow: 2 * time.Hour, Keep: 2, PerPass: 1, Timeout: time.Minute,
		Report: func(r ArchiveReport) { l.reports = append(l.reports, r) }}
	l.registry = telemetry.NewRegistry()
	if err := l.w.EnableArchiveTelemetry(l.registry, a); err != nil {
		t.Fatal(err)
	}
	return a
}

// publish writes a real archive of the agent under id, as a capture would.
func (l *archiveLab) publish(t *testing.T, e controlplane.Enrollment, id string) {
	t.Helper()
	binding, err := l.authority.Lookup(t.Context(), e.AgentID)
	if errors.Is(err, restoreauthority.ErrStale) {
		binding, err = l.authority.Register(t.Context(), e.AgentID, e.VolumeID)
	}
	if err != nil {
		t.Fatal(err)
	}
	ciphertext := bytes.Repeat([]byte{0x5a}, 4096)
	if _, err = l.archives.Capture(t.Context(), volumearchive.Spec{ID: id, Binding: binding, HarnessDigest: "sha256:" + strings.Repeat("a", 64), Size: int64(len(ciphertext))},
		bytes.NewReader(ciphertext), l.authority); err != nil {
		t.Fatal(err)
	}
}

func (l *archiveLab) metrics(t *testing.T) string {
	t.Helper()
	var b strings.Builder
	if _, err := l.registry.WriteTo(&b); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

// A pass selects only due agents, captures at most PerPass of them, and puts
// an agent whose capture failed aside for a growing delay: another due agent
// is then captured instead, and a failing one is not retried at each pass.
func TestArchivePassBoundsAndDelaysRetries(t *testing.T) {
	l := newArchiveLab(t, "running", "asleep", "asleep")
	running, first, second := l.agents[0].AgentID, l.agents[1].AgentID, l.agents[2].AgentID
	a := l.options(t)
	if err := l.w.ArchivePass(t.Context(), &Archives{}); err == nil {
		t.Fatal("invalid options accepted")
	}
	for pass := range 2 {
		if err := l.w.ArchivePass(t.Context(), a); err != nil {
			t.Fatal(err)
		}
		if len(l.reports) != pass+1 {
			t.Fatal("a pass did not attempt exactly one capture", len(l.reports))
		}
	}
	if len(a.retries) != 2 || a.retries[running].failures != 0 || a.retries[first].failures != 1 || a.retries[second].failures != 1 {
		t.Fatal("the two sleeping agents were each tried once; the running one is not due", a.retries)
	}
	for _, r := range l.reports {
		if r.Running || !errors.Is(r.Err, controlplane.ErrInput) || ArchiveRetryReason(r.Err) != "error" {
			t.Fatal("unexpected report", r)
		}
	}
	if until := time.Until(a.retries[first].until); until < 29*time.Minute || until > 31*time.Minute {
		t.Fatal("first retry delay is Every/48", until)
	}
	if err := l.w.ArchivePass(t.Context(), a); err != nil || len(l.reports) != 2 {
		t.Fatal("an agent waiting for its retry was tried again", len(l.reports), err)
	}
	if !strings.Contains(l.metrics(t), `agentcapsule_worker_volume_archives_total{vm="asleep",outcome="retried"} 2`) {
		t.Fatal("captures not counted", l.metrics(t))
	}
	// Seen 25 hours later, the running agent is due too, after the sleeping
	// ones: with these still waiting, it is the one tried.
	later := time.Now().Add(25 * time.Hour)
	a.now = func() time.Time { return later }
	if err := l.w.ArchivePass(t.Context(), a); err != nil || len(l.reports) != 3 || !l.reports[2].Running {
		t.Fatal("an overdue running agent was not tried", len(l.reports), err)
	}
	r := a.retries[first]
	r.until = time.Now().Add(-time.Second)
	a.retries[first] = r
	if err := l.w.ArchivePass(t.Context(), a); err != nil || len(l.reports) != 4 || a.retries[first].failures != 2 {
		t.Fatal("an agent was not tried again once its delay passed", len(l.reports), err)
	}
	if until := time.Until(a.retries[first].until); until < 59*time.Minute || until > 61*time.Minute {
		t.Fatal("the retry delay doubles", until)
	}
	if d := a.retryDelay(10); d != 6*time.Hour {
		t.Fatal("the retry delay is bounded by Every/4", d)
	}
	a.record(first, nil, time.Now())
	if _, held := a.retries[first]; held {
		t.Fatal("a success did not clear the delay")
	}
	a.hold(first, time.Now())
	if r := a.retries[first]; r.failures != 0 || time.Until(r.until) < 29*time.Minute {
		t.Fatal("an agent found not due is held without a failure", r)
	}
	delete(a.retries, first)
	a.retries[second] = archiveRetry{until: time.Now().Add(-25 * time.Hour), failures: 1}
	if held := a.waiting(time.Now()); held[second] || len(a.retries) != 1 {
		t.Fatal("a long-expired delay was kept", a.retries)
	}
	// Freshness, read at scrape time: never-archived agents count from their
	// initialization, a few seconds ago.
	scrape := httptest.NewRecorder()
	l.registry.Handler(5*time.Second).ServeHTTP(scrape, httptest.NewRequest("GET", "/metrics", nil))
	if out := scrape.Body.String(); !strings.Contains(out, "agentcapsule_worker_volume_archive_agents 3\n") ||
		!strings.Contains(out, "agentcapsule_worker_volume_archive_oldest_seconds ") || strings.Contains(out, "agentcapsule_worker_volume_archive_oldest_seconds 0\n") {
		t.Fatal("freshness gauges", out)
	}
}

// Under the barrier, before a new capture, captures interrupted by a crash
// are settled: a published archive is recorded as of the start of its
// capture, a capture that published nothing is forgotten, and an archive
// that does not belong to the agent is left pending. Retention then keeps the
// Keep newest archives, on disk and in the records, and finishes a removal
// that a crash interrupted.
func TestArchiveSettleAndRetention(t *testing.T) {
	l := newArchiveLab(t, "asleep", "asleep")
	e, other := l.agents[0], l.agents[1]
	a := l.options(t)
	policy := a.policy()
	id := func(n int) string { return fmt.Sprintf("arc_%032x", n) }
	for n := 1; n <= 3; n++ {
		if err := l.store.BeginVolumeArchive(t.Context(), "local", e.AgentID, id(n), false, nil, policy); err != nil {
			t.Fatal(err)
		}
	}
	l.publish(t, e, id(1))
	l.publish(t, other, id(3))
	if err := l.w.settleArchives(t.Context(), e.AgentID, l.archives); err != nil {
		t.Fatal(err)
	}
	records, err := l.store.VolumeArchives(t.Context(), e.AgentID)
	if err != nil || len(records) != 2 {
		t.Fatal("the unpublished capture was not forgotten", records, err)
	}
	byID := map[string]controlplane.VolumeArchive{}
	for _, r := range records {
		byID[r.ID] = r
	}
	if r := byID[id(1)]; r.CapturedAt == nil || !r.CapturedAt.Equal(r.StartedAt) || r.Size != 4096 {
		t.Fatal("the published archive was not adopted", r)
	}
	if r := byID[id(3)]; r.CapturedAt != nil {
		t.Fatal("another agent's archive was recorded for this one", r)
	}
	// Two more captures, then retention keeps the two newest.
	for n, at := range map[int]time.Duration{4: 23 * time.Hour, 5: 46 * time.Hour} {
		now := time.Now().Add(at)
		if err = l.store.BeginVolumeArchive(t.Context(), "local", e.AgentID, id(n), false, &now, policy); err != nil {
			t.Fatal(err)
		}
	}
	for _, n := range []int{4, 5} {
		l.publish(t, e, id(n))
		if err = l.store.CompleteVolumeArchive(t.Context(), id(n), 4096, false); err != nil {
			t.Fatal(err)
		}
	}
	removed, err := l.w.pruneArchives(t.Context(), a, e.AgentID)
	if err != nil || removed != 1 {
		t.Fatal("retention", removed, err)
	}
	if _, err = l.archives.Manifest(id(1)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the oldest archive is still on disk", err)
	}
	for _, n := range []int{4, 5} {
		if _, err = l.archives.Manifest(id(n)); err != nil {
			t.Fatal("a kept archive was removed", n, err)
		}
	}
	// A crash after the removal on disk, before its record: the next
	// retention finishes it.
	a.Keep = 1
	if err = l.archives.Remove(id(4)); err != nil {
		t.Fatal(err)
	}
	if removed, err = l.w.pruneArchives(t.Context(), a, e.AgentID); err != nil || removed != 1 {
		t.Fatal("interrupted removal not finished", removed, err)
	}
	records, err = l.store.VolumeArchives(t.Context(), e.AgentID)
	if err != nil {
		t.Fatal(err)
	}
	kept := 0
	for _, r := range records {
		if r.CapturedAt != nil && r.RemovedAt == nil {
			kept++
			if r.ID != id(5) {
				t.Fatal("retention kept an older archive", r.ID)
			}
		}
	}
	if kept != 1 {
		t.Fatal("retention deleted the only archive", kept)
	}
	if removed, err = l.w.pruneArchives(t.Context(), a, e.AgentID); err != nil || removed != 0 {
		t.Fatal("retention removed the newest archive", removed, err)
	}
}

func TestArchiveRetryReasons(t *testing.T) {
	for err, want := range map[error]string{
		controlplane.ErrPlacement:                           "placement",
		errors.Join(errors.New("x"), runtime.ErrVolumeBusy): "busy",
		&os.PathError{Op: "write", Err: syscall.ENOSPC}:     "disk_full",
		restoreauthority.ErrStale:                           "authority",
		context.DeadlineExceeded:                            "timeout",
		errors.New("other"):                                 "error",
	} {
		if got := ArchiveRetryReason(err); got != want {
			t.Fatal(err, got, want)
		}
	}
	for _, r := range append(ArchiveRetryReasons(), ArchiveVMs()...) {
		if r == "" || strings.ContainsAny(r, "\"\n\\") {
			t.Fatal("invalid vocabulary", r)
		}
	}
}

// The archives section is validated at load, without touching its root.
func TestServiceArchivesConfiguration(t *testing.T) {
	parent := t.TempDir()
	base := ServiceConfig{Version: 1, HostID: "local", Root: filepath.Join(parent, "runtime"),
		KeyAuthority:     &ServiceKeyAuthority{Root: filepath.Join(parent, "keys")},
		RestoreAuthority: &ServiceKeyAuthority{Root: filepath.Join(parent, "authority")},
		Provisioning:     &ProvisioningConfig{FirstUID: 62000, LastUID: 62009}}
	root := filepath.Join(parent, "archives")
	c := base
	c.Archives = &ServiceArchives{Root: root}
	a, err := c.archives()
	if err != nil || a.Every != 24*time.Hour || a.SleepWindow != 2*time.Hour || a.Keep != 7 || a.PerPass != 1 || a.Timeout != 30*time.Minute || a.Store != nil {
		t.Fatal("defaults", a, err)
	}
	if _, err = os.Stat(root); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("validation created the root", err)
	}
	c.Archives = &ServiceArchives{Root: root, Every: "12h", SleepWindow: "0s", Keep: 1, PerPass: 8, Timeout: "1h"}
	if a, err = c.archives(); err != nil || a.Every != 12*time.Hour || a.SleepWindow != 0 || a.Keep != 1 || a.PerPass != 8 || a.Timeout != time.Hour {
		t.Fatal("explicit values", a, err)
	}
	if a, err = (ServiceConfig{}).archives(); a != nil || err != nil {
		t.Fatal("no section", a, err)
	}
	invalid := map[string]func(*ServiceConfig){
		"relative root":           func(c *ServiceConfig) { c.Archives.Root = "archives" },
		"unclean root":            func(c *ServiceConfig) { c.Archives.Root = root + "/../archives" },
		"inside runtime":          func(c *ServiceConfig) { c.Archives.Root = filepath.Join(c.Root, "archives") },
		"contains runtime":        func(c *ServiceConfig) { c.Archives.Root = parent },
		"inside key authority":    func(c *ServiceConfig) { c.Archives.Root = filepath.Join(c.KeyAuthority.Root, "a") },
		"inside restore":          func(c *ServiceConfig) { c.Archives.Root = filepath.Join(c.RestoreAuthority.Root, "a") },
		"without provisioning":    func(c *ServiceConfig) { c.Provisioning = nil },
		"without authorities":     func(c *ServiceConfig) { c.KeyAuthority, c.RestoreAuthority = nil, nil },
		"every too short":         func(c *ServiceConfig) { c.Archives.Every = "59m" },
		"every too long":          func(c *ServiceConfig) { c.Archives.Every = "169h" },
		"every unparsable":        func(c *ServiceConfig) { c.Archives.Every = "daily" },
		"window above half":       func(c *ServiceConfig) { c.Archives.SleepWindow = "13h" },
		"negative window":         func(c *ServiceConfig) { c.Archives.SleepWindow = "-1h" },
		"keep negative":           func(c *ServiceConfig) { c.Archives.Keep = -1 },
		"keep too many":           func(c *ServiceConfig) { c.Archives.Keep = 366 },
		"per pass too many":       func(c *ServiceConfig) { c.Archives.PerPass = 9 },
		"timeout too short":       func(c *ServiceConfig) { c.Archives.Timeout = "30s" },
		"timeout not below every": func(c *ServiceConfig) { c.Archives.Every, c.Archives.Timeout = "1h", "1h" },
	}
	for name, change := range invalid {
		c := base
		c.Archives = &ServiceArchives{Root: root}
		change(&c)
		if a, err := c.archives(); err == nil || a != nil {
			t.Fatal("accepted", name)
		}
	}
	// Settings refuses the whole configuration.
	c = base
	c.Archives = &ServiceArchives{Root: filepath.Join(base.Root, "archives")}
	c.BootTimeout, c.BootLease, c.PollInterval, c.AttemptTimeout = "10s", "1m", "1s", "20s"
	if _, _, _, err = c.Settings(); err == nil {
		t.Fatal("Settings accepted archives inside the runtime")
	}
	c.Archives.Root = root
	if _, _, _, err = c.Settings(); err != nil {
		t.Fatal(err)
	}
	c.Archives.Every = "30m"
	if _, _, _, err = c.Settings(); err == nil {
		t.Fatal("Settings accepted an invalid archive period")
	}
}
