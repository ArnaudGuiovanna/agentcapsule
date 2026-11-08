//go:build linux

package worker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnessstore"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/keyauthority"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/runtime"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type observedKeys struct {
	keyauthority.Provider
	uses      int
	beforeUse func()
	borrowed  []byte
}

func (k *observedKeys) WithKey(ctx context.Context, agent, volume string, use func([]byte) error) error {
	k.uses++
	return k.Provider.WithKey(ctx, agent, volume, func(key []byte) error {
		k.borrowed = key
		if k.beforeUse != nil {
			k.beforeUse()
		}
		return use(key)
	})
}

// This fixture exercises real SQL authority, the file key provider, mTLS and
// SQLite. Physical exclusion, LUKS and VM retirement are covered by KVM tests;
// the explicit RecordProvisionedVolume/ObservePlacementStopped calls below
// stand for those observations and do not claim a physical boot here.
type bootLab struct {
	w        *Placements
	e        controlplane.Enrollment
	db       *pgxpool.Pool
	keys     *observedKeys
	opts     runtime.FirecrackerOptions
	accounts *controlplane.Accounts
	admin    controlplane.Principal
	owner    controlplane.User
}

func newBootLab(t *testing.T) *bootLab {
	return newBootReservation(t, true, "sha256:"+strings.Repeat("a", 64))
}

func newBootReservation(t *testing.T, observed bool, artifact string) *bootLab {
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
	schema := fmt.Sprintf("worker_boot_%d", time.Now().UnixNano())
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
	accounts, err := controlplane.NewAccounts(s, bytes.Repeat([]byte{0x39}, 32))
	if err != nil {
		t.Fatal(err)
	}
	secret, err := s.BootstrapService(t.Context(), "boot-admin", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	p, err := s.Authenticate(t.Context(), secret)
	if err != nil {
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
	catalog, err := controlplane.NewAgentCatalog(accounts, "local")
	if err != nil {
		t.Fatal(err)
	}
	ref := controlplane.HarnessReference{Name: "reference", Version: "1.0.0"}
	if _, err = s.RegisterLocalRelease(t.Context(), ref, artifact); err != nil {
		t.Fatal(err)
	}
	if err = s.ConfigureHostStorage(t.Context(), "local", 256); err != nil {
		t.Fatal(err)
	}
	if _, err = catalog.Reserve(t.Context(), p, "agent", controlplane.CreateAgentInput{OwnerUserID: owner.ID, Name: "Companion", Harness: ref, Resources: controlplane.AgentResources{VCPUs: 1, MemoryMiB: 256, DataVolumeMiB: 128}}); err != nil {
		t.Fatal(err)
	}
	jobs, err := s.PendingProvisioning(t.Context(), "local", 10)
	if err != nil || len(jobs) != 1 {
		t.Fatal(jobs, err)
	}
	e := jobs[0]
	if observed {
		if err = s.RecordProvisionedVolume(t.Context(), controlplane.ProvisionedVolume{AgentID: e.AgentID, HostID: e.HostID, VolumeID: e.VolumeID, OperationID: e.OperationID, Device: 1, Inode: 100}); err != nil {
			t.Fatal(err)
		}
	}
	provider, err := keyauthority.Initialize(t.Context(), filepath.Join(t.TempDir(), "keys"))
	if err != nil {
		t.Fatal(err)
	}
	if observed {
		if err = provider.Ensure(t.Context(), e.AgentID, e.VolumeID); err != nil {
			t.Fatal(err)
		}
	}
	keys := &observedKeys{Provider: provider}
	w := &Placements{store: s, hostID: e.HostID, workerID: "installer", lease: time.Minute}
	opts, err := w.runtimeOptions(runtime.FirecrackerOptions{AuthenticatedControl: true}, keys)
	if err != nil {
		t.Fatal(err)
	}
	return &bootLab{w: w, e: e, db: db, keys: keys, opts: opts, accounts: accounts, admin: p, owner: owner}
}

func (b *bootLab) claim(t *testing.T) runtime.VMRun {
	t.Helper()
	p, err := b.w.store.ClaimFencePlacement(t.Context(), b.e.AgentID, b.e.HostID, b.w.workerID, b.w.lease)
	if err != nil {
		t.Fatal(err)
	}
	return runtime.VMRun{Incarnation: 1, ID: fmt.Sprintf("%016x", p.Generation), Generation: p.Generation, FenceOnly: true, Phase: "STARTING"}
}
func (b *bootLab) initialized(t *testing.T) bool {
	t.Helper()
	jobs, err := b.w.store.PendingProvisioning(t.Context(), b.e.HostID, 10)
	if err != nil || len(jobs) != 1 {
		t.Fatal(jobs, err)
	}
	return jobs[0].Initialized
}
func (b *bootLab) expire(t *testing.T) {
	t.Helper()
	if _, err := b.db.Exec(t.Context(), "UPDATE agent_placements SET lease_until=clock_timestamp()-interval '1 second' WHERE agent_id=$1", b.e.AgentID); err != nil {
		t.Fatal(err)
	}
}

type lostBootACK struct{ http.ResponseWriter }

func (w lostBootACK) WriteHeader(int) {
	c, _, err := w.ResponseWriter.(http.Hijacker).Hijack()
	if err == nil {
		_ = c.Close()
	}
}
func (w lostBootACK) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func bootClient(t *testing.T, id string, run runtime.VMRun, prepare func(capsuleprotocol.VolumeBoot, []byte) error, drop bool) *capsuleprotocol.Client {
	t.Helper()
	return bootClientHealth(t, id, run, prepare, drop, nil)
}

func bootClientHealth(t *testing.T, id string, run runtime.VMRun, prepare func(capsuleprotocol.VolumeBoot, []byte) error, drop bool, override *capsuleprotocol.ShutdownState) *capsuleprotocol.Client {
	t.Helper()
	client, _ := bootClientHarness(t, id, run, prepare, drop, override, nil)
	return client
}

func bootClientHarness(t *testing.T, id string, run runtime.VMRun, prepare func(capsuleprotocol.VolumeBoot, []byte) error, drop bool, override *capsuleprotocol.ShutdownState, dropFence *atomic.Bool) (*capsuleprotocol.Client, *harnessstore.Store) {
	return bootClientHarnessContract(t, id, run, prepare, drop, override, dropFence, nil)
}

func bootClientHarnessContract(t *testing.T, id string, run runtime.VMRun, prepare func(capsuleprotocol.VolumeBoot, []byte) error, drop bool, override *capsuleprotocol.ShutdownState, dropFence *atomic.Bool, contract http.Handler) (*capsuleprotocol.Client, *harnessstore.Store) {
	t.Helper()
	h, g, err := capsuleprotocol.NewCredentials(capsuleprotocol.Identity{Incarnation: run.Incarnation, AgentID: id, Generation: run.Generation, VMID: run.ID, FenceOnly: run.FenceOnly}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	local, err := harnessstore.Open(t.Context(), filepath.Join(t.TempDir(), "harness.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { local.Close() })
	volume, err := capsuleprotocol.NewVolumeServer(g, func(_ context.Context, v capsuleprotocol.VolumeBoot, key []byte) (http.Handler, error) {
		if err := prepare(v, key); err != nil {
			return nil, err
		}
		previous := v.PreviousShutdown
		if override != nil {
			previous = *override
		}
		return capsuleprotocol.NewServer(g, previous, local, func(context.Context, harnessstore.Event, harnessstore.SQL) ([]byte, error) { return []byte("ok"), nil })
	})
	if err != nil {
		t.Fatal(err)
	}
	var pending atomic.Bool
	pending.Store(drop)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if contract != nil && r.URL.Path == "/v1/capabilities" {
			contract.ServeHTTP(w, r)
			return
		}
		if (r.URL.Path == "/v1/volume" && pending.Swap(false)) || (r.URL.Path == "/v1/fences" && dropFence != nil && dropFence.Swap(false)) {
			volume.ServeHTTP(lostBootACK{w}, r)
		} else {
			volume.ServeHTTP(w, r)
		}
	})
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- capsuleprotocol.ServeAuthenticated(ctx, l, g, handler) }()
	t.Cleanup(func() { cancel(); <-done })
	client, err := capsuleprotocol.NewClient(h, func(ctx context.Context) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", l.Addr().String())
	})
	if err != nil {
		t.Fatal(err)
	}
	return client, local
}

func TestWorkerVolumeBootstrapAuthorityAndLostACK(t *testing.T) {
	b := newBootLab(t)
	run := b.claim(t)
	var calls atomic.Int32
	client := bootClient(t, b.e.AgentID, run, func(v capsuleprotocol.VolumeBoot, key []byte) error {
		calls.Add(1)
		if !v.Initialize || v.VolumeID != b.e.VolumeID || len(key) != 32 || v.PreviousShutdown != capsuleprotocol.ShutdownClean {
			return errors.New("wrong volume binding")
		}
		return nil
	}, true)
	if err := b.opts.Confirm(t.Context(), b.e.AgentID, run); !errors.Is(err, capsuleprotocol.ErrVolumeBoot) {
		t.Fatal("confirmed without volume ACK", err)
	}
	stale := run
	stale.Generation++
	if err := b.opts.PrepareGuest(t.Context(), b.e.AgentID, stale, client); !errors.Is(err, controlplane.ErrPlacement) || b.keys.uses != 0 {
		t.Fatal("stale boot received key", err)
	}
	if err := b.opts.PrepareGuest(t.Context(), b.e.AgentID, run, client); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 || !bytes.Equal(b.keys.borrowed, make([]byte, 32)) || b.initialized(t) {
		t.Fatal("reopened volume, retained key or acknowledged before confirmation")
	}
	if err := b.opts.Confirm(t.Context(), b.e.AgentID, run); err != nil {
		t.Fatal(err)
	}
	if !b.initialized(t) {
		t.Fatal("missing initialization receipt")
	}
	if err := b.w.store.BeginPlacementStop(t.Context(), b.e.AgentID, b.e.HostID, run.Generation); err != nil {
		t.Fatal(err)
	}
	if err := b.w.store.ObservePlacementStopped(t.Context(), b.e.AgentID, b.e.HostID, run.Generation, true); err != nil {
		t.Fatal(err)
	}
	next := b.claim(t)
	client = bootClient(t, b.e.AgentID, next, func(v capsuleprotocol.VolumeBoot, _ []byte) error {
		if v.Initialize || v.PreviousShutdown != capsuleprotocol.ShutdownUnclean {
			return errors.New("reformat authorized or unclean shutdown forgotten")
		}
		return nil
	}, false)
	if err := b.opts.PrepareGuest(t.Context(), b.e.AgentID, next, client); err != nil {
		t.Fatal(err)
	}
	if err := b.opts.Confirm(t.Context(), b.e.AgentID, run); !errors.Is(err, capsuleprotocol.ErrVolumeBoot) {
		t.Fatal("ACK used for different generation", err)
	}
	if err := b.opts.PrepareGuest(t.Context(), b.e.AgentID, next, client); err != nil {
		t.Fatal(err)
	}
	if err := b.opts.Confirm(t.Context(), b.e.AgentID, next); err != nil {
		t.Fatal(err)
	}
	// SQL retirement is a host-observation fixture, not a physical VM proof.
	if err := b.w.store.ObservePlacementStopped(t.Context(), b.e.AgentID, b.e.HostID, next.Generation, false); err != nil {
		t.Fatal(err)
	}
	clean := b.claim(t)
	client = bootClient(t, b.e.AgentID, clean, func(v capsuleprotocol.VolumeBoot, _ []byte) error {
		if v.Initialize || v.PreviousShutdown != capsuleprotocol.ShutdownClean {
			return errors.New("clean shutdown observation lost")
		}
		return nil
	}, false)
	if err := b.opts.PrepareGuest(t.Context(), b.e.AgentID, clean, client); err != nil {
		t.Fatal(err)
	}
	if err := b.opts.Confirm(t.Context(), b.e.AgentID, clean); err != nil {
		t.Fatal(err)
	}
}

func TestWorkerRefusesContradictoryShutdownHealth(t *testing.T) {
	b := newBootLab(t)
	run := b.claim(t)
	wrong := capsuleprotocol.ShutdownUnclean // the fresh SQL plan says clean
	client := bootClientHealth(t, b.e.AgentID, run, func(capsuleprotocol.VolumeBoot, []byte) error { return nil }, false, &wrong)
	if err := b.opts.PrepareGuest(t.Context(), b.e.AgentID, run, client); !errors.Is(err, capsuleprotocol.ErrVolumeBoot) {
		t.Fatal("contradictory guest health admitted", err)
	}
	if b.initialized(t) {
		t.Fatal("contradictory guest initialized")
	}
	if err := b.opts.Confirm(t.Context(), b.e.AgentID, run); !errors.Is(err, capsuleprotocol.ErrVolumeBoot) {
		t.Fatal("contradictory guest confirmed", err)
	}
}

func TestWorkerVolumeBootstrapRechecksAuthorityAfterKeyWait(t *testing.T) {
	b := newBootLab(t)
	run := b.claim(t)
	var calls atomic.Int32
	client := bootClient(t, b.e.AgentID, run, func(capsuleprotocol.VolumeBoot, []byte) error { calls.Add(1); return nil }, false)
	b.keys.beforeUse = func() { b.expire(t) }
	if err := b.opts.PrepareGuest(t.Context(), b.e.AgentID, run, client); !errors.Is(err, controlplane.ErrPlacement) {
		t.Fatal(err)
	}
	if calls.Load() != 0 || b.initialized(t) || !bytes.Equal(b.keys.borrowed, make([]byte, 32)) {
		t.Fatal("expired boot received authority or retained key")
	}
	if err := b.opts.Confirm(t.Context(), b.e.AgentID, run); !errors.Is(err, capsuleprotocol.ErrVolumeBoot) {
		t.Fatal("failed opening confirmed", err)
	}
}

func TestWorkerVolumeBootstrapLateACKCannotConfirmExpiredBoot(t *testing.T) {
	b := newBootLab(t)
	run := b.claim(t)
	client := bootClient(t, b.e.AgentID, run, func(capsuleprotocol.VolumeBoot, []byte) error { b.expire(t); return nil }, false)
	if err := b.opts.PrepareGuest(t.Context(), b.e.AgentID, run, client); err != nil {
		t.Fatal(err)
	}
	if err := b.opts.Confirm(t.Context(), b.e.AgentID, run); !errors.Is(err, controlplane.ErrPlacement) {
		t.Fatal("expired confirmation", err)
	}
	if b.initialized(t) {
		t.Fatal("late ACK initialized expired boot")
	}
}

func TestWorkerVolumeBootstrapFailureCannotInitialize(t *testing.T) {
	b := newBootLab(t)
	run := b.claim(t)
	var calls atomic.Int32
	client := bootClient(t, b.e.AgentID, run, func(capsuleprotocol.VolumeBoot, []byte) error {
		calls.Add(1)
		return errors.New("physical opening failed")
	}, false)
	if err := b.opts.PrepareGuest(t.Context(), b.e.AgentID, run, client); !errors.Is(err, capsuleprotocol.ErrVolumeBoot) {
		t.Fatal(err)
	}
	if calls.Load() != 1 || b.initialized(t) {
		t.Fatal("definitive failure retried or initialized")
	}
	if err := b.opts.Confirm(t.Context(), b.e.AgentID, run); !errors.Is(err, capsuleprotocol.ErrVolumeBoot) {
		t.Fatal("failed opening confirmed", err)
	}
}

func TestWorkerKeyAuthorityConfigurationIsPinnedAndSeparate(t *testing.T) {
	root := t.TempDir()
	authority := filepath.Join(root, "keys")
	keys, err := keyauthority.Initialize(t.Context(), authority)
	if err != nil {
		t.Fatal(err)
	}
	c := ServiceConfig{Root: filepath.Join(root, "runtime"), KeyAuthority: &ServiceKeyAuthority{Root: authority, Identity: keys.Identity()}}
	if _, err = c.OpenVolumeKeys(); err != nil {
		t.Fatal(err)
	}
	c.Root = authority
	if _, err = c.OpenVolumeKeys(); err == nil {
		t.Fatal("nested authority accepted")
	}
	c.Root = filepath.Join(root, "runtime")
	c.KeyAuthority.Identity = "keyauth_" + strings.Repeat("a", 32)
	if _, err = c.OpenVolumeKeys(); err == nil {
		t.Fatal("foreign authority accepted")
	}
	c.KeyAuthority.Root = filepath.Join(root, "missing")
	if _, err = c.OpenVolumeKeys(); err == nil {
		t.Fatal("missing authority created")
	}
	if _, err = os.Stat(c.KeyAuthority.Root); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("opening created state", err)
	}
}
