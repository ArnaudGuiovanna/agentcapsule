//go:build linux && cgo

package worker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnessstore"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/keyauthority"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/restoreauthority"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/runtime"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/volumearchive"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// restoreLab runs the restore coordinator against real PostgreSQL, a real
// key authority, restore authority and archive root, and a real capsule
// protocol guest whose harness database stands for the volume. Only the host
// is a fake: the volume is a 64 MiB file holding the harness database, so
// that an archive and an install carry the agent's actual outcomes. No VM
// runs and no LUKS container is opened; the KVM product test covers those.
type restoreLab struct {
	t         *testing.T
	w         *Placements
	store     *controlplane.Store
	db        *pgxpool.Pool
	authority *restoreauthority.Catalog
	archives  *volumearchive.Store
	opts      runtime.FirecrackerOptions
	e         controlplane.Enrollment
	// volume is the agent's volume; state is where the agent's harness
	// database lives while it runs.
	volume, state string
	guest         *restoreGuest
	installs      int
	// partialInstall makes the next install stop half way, like a crash.
	partialInstall bool
	// withoutOutcomes makes the guest's harness offer no outcome inspection;
	// probeWithoutOutcomes, the harness checked before the agent stops.
	withoutOutcomes, probeWithoutOutcomes bool
	steps                                 []string
}

type restoreGuest struct {
	cancel context.CancelFunc
	done   chan error
	store  *harnessstore.Store
	path   string
}

const restoreVolumeSize = 64 << 20

func newRestoreLab(t *testing.T) *restoreLab {
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
	schema := fmt.Sprintf("worker_restore_%d", time.Now().UnixNano())
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
	accounts, err := controlplane.NewAccounts(s, bytes.Repeat([]byte{0x3b}, 32))
	if err != nil {
		t.Fatal(err)
	}
	secret, err := s.BootstrapService(t.Context(), "restore-admin", time.Hour)
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
	r, err := accounts.CreateUser(t.Context(), p, "owner", controlplane.CreateUserInput{DisplayName: "Owner"})
	if err != nil {
		t.Fatal(err)
	}
	var owner controlplane.User
	if err = json.Unmarshal(r.Body, &owner); err != nil {
		t.Fatal(err)
	}
	if _, err = catalog.Reserve(t.Context(), p, "agent", controlplane.CreateAgentInput{OwnerUserID: owner.ID, Name: "Companion", Harness: ref,
		Resources: controlplane.AgentResources{VCPUs: 1, MemoryMiB: 256, DataVolumeMiB: restoreVolumeSize >> 20}}); err != nil {
		t.Fatal(err)
	}
	jobs, err := s.PendingProvisioning(t.Context(), "local", 10)
	if err != nil || len(jobs) != 1 {
		t.Fatal(jobs, err)
	}
	e := jobs[0]
	if err = s.RecordProvisionedVolume(t.Context(), controlplane.ProvisionedVolume{AgentID: e.AgentID, HostID: e.HostID, VolumeID: e.VolumeID, OperationID: e.OperationID, Device: 1, Inode: 100}); err != nil {
		t.Fatal(err)
	}
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
	if err = s.BeginPlacementStop(t.Context(), e.AgentID, e.HostID, fence.Generation); err != nil {
		t.Fatal(err)
	}
	if err = s.ObservePlacementStopped(t.Context(), e.AgentID, e.HostID, fence.Generation, false); err != nil {
		t.Fatal(err)
	}
	if err = s.ActivateProvisionedAgent(t.Context(), e); err != nil {
		t.Fatal(err)
	}
	if e, err = s.VolumeEnrollment(t.Context(), e.AgentID, e.HostID); err != nil {
		t.Fatal(err)
	}
	parent := t.TempDir()
	keys, err := keyauthority.Initialize(t.Context(), filepath.Join(parent, "keys"))
	if err != nil {
		t.Fatal(err)
	}
	if err = keys.Ensure(t.Context(), e.AgentID, e.VolumeID); err != nil {
		t.Fatal(err)
	}
	authority, err := restoreauthority.Initialize(t.Context(), filepath.Join(parent, "authority"), keys.Identity())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { authority.Close() })
	if _, err = authority.Register(t.Context(), e.AgentID, e.VolumeID); err != nil {
		t.Fatal(err)
	}
	archives, err := volumearchive.New(filepath.Join(parent, "archives"))
	if err != nil {
		t.Fatal(err)
	}
	w := &Placements{store: s, hostID: "local", workerID: "restorer", lease: time.Minute, authority: authority}
	opts, err := w.runtimeOptions(runtime.FirecrackerOptions{AuthenticatedControl: true}, keys)
	if err != nil {
		t.Fatal(err)
	}
	l := &restoreLab{t: t, w: w, store: s, db: db, authority: authority, archives: archives, opts: opts, e: e,
		volume: filepath.Join(parent, "volume"), state: filepath.Join(t.TempDir(), "harness.db")}
	t.Cleanup(l.stopGuest)
	// The agent's first boot: an empty harness database.
	store, err := harnessstore.Open(t.Context(), l.state)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
	l.pack(l.state)
	return l
}

// pack writes a closed harness database into the volume, length first.
func (l *restoreLab) pack(path string) {
	l.t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		l.t.Fatal(err)
	}
	image := make([]byte, restoreVolumeSize)
	binary.BigEndian.PutUint64(image, uint64(len(data)))
	copy(image[8:], data)
	if err = os.WriteFile(l.volume, image, 0600); err != nil {
		l.t.Fatal(err)
	}
}

// unpack writes the volume's harness database at path.
func (l *restoreLab) unpack(path string) {
	l.t.Helper()
	image, err := os.ReadFile(l.volume)
	if err != nil || len(image) != restoreVolumeSize {
		l.t.Fatal("volume", err)
	}
	n := binary.BigEndian.Uint64(image)
	if n == 0 || n > restoreVolumeSize-8 {
		l.t.Fatal("the volume holds no harness database")
	}
	for _, suffix := range []string{"", "-wal", "-shm"} {
		_ = os.Remove(path + suffix)
	}
	if err = os.WriteFile(path, image[8:8+n], 0600); err != nil {
		l.t.Fatal(err)
	}
}

func (l *restoreLab) binding() restoreauthority.Binding {
	l.t.Helper()
	e, err := l.store.VolumeEnrollment(l.t.Context(), l.e.AgentID, "local")
	if err != nil {
		l.t.Fatal(err)
	}
	return enrollmentBinding(e)
}

// deliver applies events to the running agent and records their outcomes in
// the restore authority, as the worker does on every delivery.
func (l *restoreLab) deliver(names ...string) []string {
	l.t.Helper()
	store, err := harnessstore.Open(l.t.Context(), l.state)
	if err != nil {
		l.t.Fatal(err)
	}
	var ids []string
	for _, name := range names {
		event := harnessstore.Event{ID: name, Subjects: []string{"agent/" + l.e.AgentID, "event/" + name}, Body: []byte(name)}
		r, err := store.Apply(l.t.Context(), event, func(context.Context, harnessstore.SQL) ([]byte, error) { return []byte("done " + name), nil })
		if err != nil {
			l.t.Fatal(err)
		}
		var outcome restoreauthority.Outcome
		if outcome.ID, outcome.Digest, err = harnessstore.OutcomeFingerprint(l.e.AgentID, event, r.Result); err != nil {
			l.t.Fatal(err)
		}
		if err = l.authority.RecordOutcome(l.t.Context(), l.binding(), outcome); err != nil {
			l.t.Fatal(err)
		}
		ids = append(ids, outcome.ID)
	}
	if err = store.Close(); err != nil {
		l.t.Fatal(err)
	}
	l.pack(l.state)
	return ids
}

// capture archives the agent's volume, as the nightly archive does.
func (l *restoreLab) capture(id string) restoreauthority.Archive {
	l.t.Helper()
	f, err := os.Open(l.volume)
	if err != nil {
		l.t.Fatal(err)
	}
	defer f.Close()
	a, err := l.archives.Capture(l.t.Context(), volumearchive.Spec{ID: id, Binding: l.binding(), HarnessDigest: "sha256:" + strings.Repeat("a", 64), Size: restoreVolumeSize}, f, l.authority)
	if err != nil {
		l.t.Fatal(err)
	}
	return a
}

func (l *restoreLab) stopGuest() {
	if g := l.guest; g != nil {
		l.guest = nil
		g.cancel()
		<-g.done
		if err := g.store.Close(); err != nil {
			l.t.Error(err)
		}
		// What the restricted boot wrote stays in the volume.
		l.pack(g.path)
	}
}

func (l *restoreLab) host() restoreHost {
	return restoreHost{
		barrier: func(ctx context.Context, _ string, fn func(context.Context) error) error { return fn(ctx) },
		retire: func(ctx context.Context, id string) error {
			l.stopGuest()
			p, err := l.w.placement(ctx, id)
			if err != nil || p.State == "STOPPED" {
				return err
			}
			if err = l.store.BeginPlacementStop(ctx, id, "local", p.Generation); err != nil {
				return err
			}
			return l.store.ObservePlacementStopped(ctx, id, "local", p.Generation, true)
		},
		install: func(_ context.Context, plan controlplane.VolumeRestorePlan, image io.Reader, a restoreauthority.Archive) error {
			if l.guest != nil || plan.Placement.State != "STOPPED" {
				return runtime.ErrVolumeBusy
			}
			data, err := io.ReadAll(image)
			if err != nil {
				return err
			}
			if l.partialInstall {
				l.partialInstall = false
				if err = os.WriteFile(l.volume, data[:len(data)/2], 0600); err != nil {
					return err
				}
				return errors.New("crash during the copy")
			}
			if int64(len(data)) != a.Size || sha256.Sum256(data) != a.Digest {
				return runtime.ErrVolumeImage
			}
			l.installs++
			return os.WriteFile(l.volume, data, 0600)
		},
		probe: func(context.Context, string) error {
			if l.probeWithoutOutcomes {
				return capsuleprotocol.ErrUnsupportedProtocol
			}
			return nil
		},
		boot: l.boot,
		after: func(step string) error {
			l.steps = append(l.steps, step)
			return nil
		},
	}
}

// boot is the restricted boot: a fence-only claim, then the worker's own
// volume preparation and confirmation, against a real guest server whose
// harness database comes from the volume.
func (l *restoreLab) boot(ctx context.Context, id string) (runtime.VMRun, *capsuleprotocol.Client, error) {
	p, err := l.store.ClaimFencePlacement(ctx, id, "local", l.w.workerID, l.w.lease)
	if err != nil {
		return runtime.VMRun{}, nil, err
	}
	e, err := l.store.VolumeEnrollment(ctx, id, "local")
	if err != nil {
		return runtime.VMRun{}, nil, err
	}
	run := runtime.VMRun{Incarnation: e.Incarnation, ID: fmt.Sprintf("%016x", p.Generation), Generation: p.Generation, FenceOnly: true, Phase: "STARTING"}
	h, g, err := capsuleprotocol.NewCredentials(capsuleprotocol.Identity{Incarnation: run.Incarnation, AgentID: id, Generation: run.Generation, VMID: run.ID, FenceOnly: true}, time.Hour)
	if err != nil {
		return run, nil, err
	}
	path := filepath.Join(l.t.TempDir(), "harness.db")
	l.unpack(path)
	guest := &restoreGuest{done: make(chan error, 1), path: path}
	volume, err := capsuleprotocol.NewVolumeServer(g, func(_ context.Context, v capsuleprotocol.VolumeBoot, _ []byte) (http.Handler, error) {
		if !v.Restore || v.Initialize || v.Incarnation != run.Incarnation || v.VolumeID != e.VolumeID {
			return nil, errors.New("not the restricted boot of a restored image")
		}
		store, err := harnessstore.Open(context.Background(), path)
		if err != nil {
			return nil, err
		}
		guest.store = store
		return capsuleprotocol.NewServer(g, v.PreviousShutdown, store, func(context.Context, harnessstore.Event, harnessstore.SQL) ([]byte, error) {
			return nil, errors.New("a restricted boot ran an event")
		})
	})
	if err != nil {
		return run, nil, err
	}
	handler := http.Handler(volume)
	if l.withoutOutcomes {
		handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/v1/capabilities" {
				volume.ServeHTTP(w, r)
				return
			}
			// A harness built before outcome inspection: the required features only.
			w.Header().Set("X-Capsule-Protocol", capsuleprotocol.Version)
			_ = json.NewEncoder(w).Encode(map[string]any{"protocol": capsuleprotocol.Version, "identity": g.Identity,
				"features": []capsuleprotocol.ControlFeature{capsuleprotocol.ControlHealth, capsuleprotocol.ControlFences},
				"limits":   capsuleprotocol.ControlLimits{MessageBytes: capsuleprotocol.MaxMessageBytes, ContentBytes: capsuleprotocol.MaxContentBytes}})
		})
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return run, nil, err
	}
	serve, cancel := context.WithCancel(context.Background())
	guest.cancel = cancel
	go func() { guest.done <- capsuleprotocol.ServeAuthenticated(serve, listener, g, handler) }()
	client, err := capsuleprotocol.NewClient(h, func(ctx context.Context) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", listener.Addr().String())
	})
	if err == nil {
		err = l.opts.PrepareGuest(ctx, id, run, client)
	}
	if guest.store == nil {
		cancel()
		<-guest.done
		return run, nil, errors.Join(err, errors.New("the guest did not open its volume"))
	}
	l.guest = guest
	if err == nil {
		err = l.opts.Confirm(ctx, id, run)
	}
	return run, client, err
}

func (l *restoreLab) restore(id, archive string) (VolumeRestoreResult, error) {
	return l.w.restore(l.t.Context(), l.host(), id, l.e.AgentID, archive, l.archives)
}

// heldOutcomes reads the volume's harness database: the outcomes it holds.
func (l *restoreLab) heldOutcomes(ids []string) map[string][32]byte {
	l.t.Helper()
	path := filepath.Join(l.t.TempDir(), "harness.db")
	l.unpack(path)
	store, err := harnessstore.Open(l.t.Context(), path)
	if err != nil {
		l.t.Fatal(err)
	}
	defer store.Close()
	held, err := store.Outcomes(l.t.Context(), l.e.AgentID, ids)
	if err != nil {
		l.t.Fatal(err)
	}
	return held
}

func (l *restoreLab) enrollment() controlplane.Enrollment {
	l.t.Helper()
	e, err := l.store.VolumeEnrollment(l.t.Context(), l.e.AgentID, "local")
	if err != nil {
		l.t.Fatal(err)
	}
	return e
}

func restoreIDFor(n int) string { return fmt.Sprintf("rst_%032x", n) }

// A restore from an archive declares lost exactly the outcomes acknowledged
// after the archive, and keeps the ones before. It survives a stop after each
// durable step, a copy cut half way and a failure after the declaration:
// each attempt resumes, nothing is declared twice, and the volume never
// serves before the end. The new incarnation is held in both stores, and the
// old one's receipts, fences and outcomes are refused.
func TestRestoreDeclaresOnlyTheLossesAfterTheArchiveAndResumes(t *testing.T) {
	l := newRestoreLab(t)
	kept := l.deliver("before-archive")
	archive := l.capture("arc_" + strings.Repeat("1", 32))
	lost := l.deliver("after-archive-1", "after-archive-2")
	oldBinding := l.binding()
	oldReceipt, err := l.authority.Scan(t.Context(), oldBinding)
	if err != nil {
		t.Fatal(err)
	}
	id := restoreIDFor(1)
	// Stop the restore after each durable step, like a crash.
	crashes := map[string]bool{controlplane.RestoreInstalling: true, controlplane.RestoreReconciling: true, controlplane.RestoreActivated: true}
	l.partialInstall = true
	if _, err = l.db.Exec(t.Context(), `CREATE FUNCTION fail_activation() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN RAISE EXCEPTION 'injected publication failure'; END $$;
        CREATE TRIGGER fail_activation BEFORE UPDATE ON volume_restores FOR EACH ROW
        WHEN (NEW.step='ACTIVATED') EXECUTE FUNCTION fail_activation()`); err != nil {
		t.Fatal(err)
	}
	var result VolumeRestoreResult
	attempt := 0
	for ; ; attempt++ {
		if attempt > 10 {
			t.Fatal("the restore does not converge", l.steps)
		}
		h := l.host()
		h.after = func(step string) error {
			l.steps = append(l.steps, step)
			if crashes[step] {
				delete(crashes, step)
				return errors.New("stopped after " + step)
			}
			return nil
		}
		result, err = l.w.restore(t.Context(), h, id, l.e.AgentID, archive.ID, l.archives)
		if err == nil {
			break
		}
		e := l.enrollment()
		if e.Stage != "RESTORING" || e.Incarnation != 2 {
			t.Fatal("a stopped restore left the volume in service", e.Stage, e.Incarnation, err)
		}
		if _, err := l.store.ClaimPlacement(t.Context(), l.e.AgentID, "local", "worker", time.Minute); !errors.Is(err, controlplane.ErrStoreEnrollment) {
			t.Fatal("an ordinary boot of a restoring volume", err)
		}
		if strings.Contains(err.Error(), "injected publication failure") {
			// Activation declared before it published: the losses survive.
			losses, err := l.authority.Losses(t.Context(), l.e.AgentID)
			if err != nil || len(losses) != 2 {
				t.Fatal("losses declared before the failed publication", losses, err)
			}
			if _, err = l.db.Exec(t.Context(), "DROP TRIGGER fail_activation ON volume_restores"); err != nil {
				t.Fatal(err)
			}
		}
	}
	// Stopped after three steps, in the copy and at the publication.
	if attempt != 5 || !slices.Equal(l.steps, []string{controlplane.RestoreInstalling, controlplane.RestoreReconciling, controlplane.RestoreActivated, controlplane.RestoreSucceeded}) {
		t.Fatal("attempts and steps", attempt, l.steps)
	}
	if l.installs != 1 {
		t.Fatal("the image was not installed once in full", l.installs)
	}
	got := make([]string, len(result.Losses))
	for i, loss := range result.Losses {
		got[i] = loss.OutcomeID
		if loss.MailboxID != "" || loss.Incarnation != 2 {
			t.Fatal("these events have no mailbox: unmatched losses expected", loss)
		}
	}
	slices.Sort(lost)
	if result.Incarnation != 2 || result.RestoreID != id || !slices.Equal(got, lost) {
		t.Fatal("declared losses", result, lost)
	}
	statuses := map[string]restoreauthority.Status{kept[0]: restoreauthority.StatusConfirmed, lost[0]: restoreauthority.StatusLost, lost[1]: restoreauthority.StatusLost}
	for outcome, want := range statuses {
		if status, _, err := l.authority.OutcomeStatus(t.Context(), outcome); err != nil || status != want {
			t.Fatal("outcome status", outcome, status, err)
		}
	}
	held := l.heldOutcomes(append(slices.Clone(kept), lost...))
	if _, ok := held[kept[0]]; !ok || len(held) != 1 {
		t.Fatal("the volume does not hold the archive's outcomes", held)
	}
	e := l.enrollment()
	if e.Stage != "READY" || e.Incarnation != 2 || !e.Initialized {
		t.Fatal("volume after the restore", e)
	}
	if b, err := l.authority.Lookup(t.Context(), l.e.AgentID); err != nil || b.Incarnation != 2 {
		t.Fatal("authority incarnation", b, err)
	}
	// The old incarnation: its fences, its identity and its outcomes.
	if err = l.authority.RecordVerifiedFence(t.Context(), oldReceipt); !errors.Is(err, restoreauthority.ErrStale) {
		t.Fatal("a fence of the old incarnation was recorded", err)
	}
	if err = l.authority.WithBinding(t.Context(), oldBinding, func() error { return nil }); !errors.Is(err, restoreauthority.ErrStale) {
		t.Fatal("the old incarnation is still admitted", err)
	}
	if err = l.authority.RecordOutcome(t.Context(), oldBinding, restoreauthority.Outcome{ID: lost[0]}); !errors.Is(err, restoreauthority.ErrStale) {
		t.Fatal("an outcome of the old incarnation was recorded", err)
	}
	// A repeated call returns the finished restore.
	again, err := l.restore(id, archive.ID)
	if err != nil || again.Incarnation != 2 || len(again.Losses) != 2 {
		t.Fatal("replay", again, err)
	}
	if _, err = l.restore(id, "arc_"+strings.Repeat("2", 32)); !errors.Is(err, controlplane.ErrConflict) {
		t.Fatal("the restore ID reused for another archive", err)
	}
	// The agent serves again: an ordinary boot plan at the new incarnation.
	run, err := l.store.ClaimPlacement(t.Context(), l.e.AgentID, "local", "worker", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := l.store.PrepareVolumeBoot(t.Context(), controlplane.VMCaller{AgentID: l.e.AgentID, HostID: "local", Generation: run.Generation, VMID: "x"}, "worker")
	if err != nil || plan.Restore || plan.Enrollment.Incarnation != 2 {
		t.Fatal("ordinary boot after the restore", plan, err)
	}
}

// Before the agent stops, a restore refuses an archive that is missing, of
// another volume, or older than another archive of the agent on this host:
// nothing changes.
func TestRestoreRefusesAnArchiveBeforeStopping(t *testing.T) {
	l := newRestoreLab(t)
	l.deliver("first")
	older := l.capture("arc_" + strings.Repeat("1", 32))
	l.deliver("second")
	newer := l.capture("arc_" + strings.Repeat("2", 32))
	untouched := func(name string, err, want error) {
		t.Helper()
		if !errors.Is(err, want) {
			t.Fatal(name, err)
		}
		if e := l.enrollment(); e.Stage != "READY" || e.Incarnation != 1 {
			t.Fatal("a refused restore changed the volume", name, e)
		}
		if open, err := l.store.OpenVolumeRestore(t.Context(), l.e.AgentID); err != nil || open != nil {
			t.Fatal("a refused restore was recorded", name, open, err)
		}
	}
	_, err := l.restore(restoreIDFor(1), "arc_"+strings.Repeat("3", 32))
	untouched("missing archive", err, os.ErrNotExist)
	// The nightly records say which archive is newer.
	for i, a := range []restoreauthority.Archive{older, newer} {
		if _, err = l.db.Exec(t.Context(), `INSERT INTO volume_archives(archive_id,agent_id,host_id,volume_id,incarnation,started_at,captured_at,size)
            VALUES($1,$2,'local',$3,1,now()-interval '3 days',now()-$4*interval '1 day',$5)`, a.ID, l.e.AgentID, l.e.VolumeID, 2-i, restoreVolumeSize); err != nil {
			t.Fatal(err)
		}
	}
	_, err = l.restore(restoreIDFor(1), older.ID)
	untouched("newer archive", err, ErrNewerArchive)
	if RestoreFailure(err) != "newer_archive" {
		t.Fatal("failure reason", RestoreFailure(err))
	}
	if _, err = l.db.Exec(t.Context(), "UPDATE agent_specs SET volume_mib=128 WHERE agent_id=$1", l.e.AgentID); err != nil {
		t.Fatal(err)
	}
	_, err = l.restore(restoreIDFor(1), newer.ID)
	untouched("archive of another size", err, ErrRestoreArchive)
	if RestoreFailure(err) != "archive" {
		t.Fatal("failure reason", RestoreFailure(err))
	}
}

// A harness that cannot report its outcomes is refused before the agent
// stops. If the restored boot still cannot report them, it is never
// activated: the restore stops before any declaration and the volume stays
// out of service until a resumed restore can inspect it.
func TestRestoreFailsClosedWhenTheImageCannotBeInspected(t *testing.T) {
	l := newRestoreLab(t)
	l.deliver("first")
	archive := l.capture("arc_" + strings.Repeat("1", 32))
	l.deliver("second")
	l.probeWithoutOutcomes = true
	_, err := l.restore(restoreIDFor(1), archive.ID)
	if !errors.Is(err, capsuleprotocol.ErrUnsupportedProtocol) {
		t.Fatal("a harness without inspection was not refused first", err)
	}
	if e := l.enrollment(); e.Stage != "READY" || e.Incarnation != 1 {
		t.Fatal("the refused restore stopped the agent", e)
	}
	l.probeWithoutOutcomes, l.withoutOutcomes = false, true
	_, err = l.restore(restoreIDFor(1), archive.ID)
	if !errors.Is(err, capsuleprotocol.ErrUnsupportedProtocol) || RestoreFailure(err) != "unsupported_harness" {
		t.Fatal("restored without inspection", err)
	}
	if losses, lerr := l.authority.Losses(t.Context(), l.e.AgentID); lerr != nil || len(losses) != 0 {
		t.Fatal("a loss declared without inspection", losses, lerr)
	}
	plan, perr := l.store.VolumeRestoreTarget(t.Context(), restoreIDFor(1), "local")
	if perr != nil || plan.Restore.Step != controlplane.RestoreReconciling || plan.Enrollment.Stage != "RESTORING" || plan.Placement.State != "STOPPED" {
		t.Fatal("a failed activation left the agent half restored", plan, perr)
	}
	// With an inspecting guest, the same restore resumes and ends.
	l.withoutOutcomes = false
	result, err := l.restore(restoreIDFor(1), archive.ID)
	if err != nil || len(result.Losses) != 1 {
		t.Fatal("resumed restore", result, err)
	}
}

// A new restore replaces an unfinished one, even one stopped between its
// SQL record and its reservation in the restore authority: both stores then
// move one incarnation at a time, to the same one.
func TestRestoreSupersedesAnUnfinishedRestore(t *testing.T) {
	l := newRestoreLab(t)
	l.deliver("first")
	archive := l.capture("arc_" + strings.Repeat("1", 32))
	lost := l.deliver("second")
	// A restore stopped right after its SQL record: no reservation yet.
	if _, err := l.store.BeginVolumeRestore(t.Context(), restoreIDFor(1), l.e.AgentID, "local", archive.ID); err != nil {
		t.Fatal(err)
	}
	if b, err := l.authority.Lookup(t.Context(), l.e.AgentID); err != nil || b.Incarnation != 1 {
		t.Fatal("authority before the reservation", b, err)
	}
	result, err := l.restore(restoreIDFor(2), archive.ID)
	if err != nil || result.Incarnation != 3 || len(result.Losses) != 1 || result.Losses[0].OutcomeID != lost[0] {
		t.Fatal("superseding restore", result, err)
	}
	if b, err := l.authority.Lookup(t.Context(), l.e.AgentID); err != nil || b.Incarnation != 3 {
		t.Fatal("authority incarnation", b, err)
	}
	if e := l.enrollment(); e.Stage != "READY" || e.Incarnation != 3 {
		t.Fatal("volume", e)
	}
	if _, err = l.restore(restoreIDFor(1), archive.ID); !errors.Is(err, controlplane.ErrRestore) {
		t.Fatal("a superseded restore resumed", err)
	}
	// The loss declared for incarnation 3 does not name incarnation 2.
	losses, err := l.authority.Losses(t.Context(), l.e.AgentID)
	if err != nil || len(losses) != 1 || losses[0].Incarnation != 3 {
		t.Fatal("authority losses", losses, err)
	}
}

func TestRestoreFailureVocabulary(t *testing.T) {
	for err, want := range map[error]string{
		volumearchive.ErrArchive:                              "archive",
		errors.Join(errors.New("wrapped"), ErrRestoreArchive): "archive",
		ErrNewerArchive:                                       "newer_archive",
		runtime.ErrVolumeBusy:                                 "busy",
		restoreauthority.ErrHistory:                           "authority",
		capsuleprotocol.ErrUnsupportedProtocol:                "unsupported_harness",
		controlplane.ErrRestore:                               "state",
		errors.New("other"):                                   "error",
	} {
		if got := RestoreFailure(err); got != want {
			t.Fatal(err, got, want)
		}
		if !slices.Contains(RestoreFailures(), want) {
			t.Fatal("reason outside the vocabulary", want)
		}
	}
}
