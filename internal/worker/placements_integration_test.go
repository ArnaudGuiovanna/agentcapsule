//go:build linux && kvm_integration

package worker

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/runtime"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type labConfig struct{ Firecracker, Jailer, Kernel, Initrd, ControlInitrd, RootParent, Output, WorkerExecutable string }

func config(t *testing.T) labConfig {
	t.Helper()
	var c labConfig
	b, err := os.ReadFile(os.Getenv("AGENTCAPSULE_KVM_CONFIG"))
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(b, &c); err != nil {
		t.Fatal(err)
	}
	return c
}

func digest(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func probe(ctx context.Context, socket string) error {
	for {
		err := func() error {
			conn, err := (&net.Dialer{}).DialContext(ctx, "unix", socket)
			if err != nil {
				return err
			}
			defer conn.Close()
			deadline := time.Now().Add(time.Second)
			if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
				deadline = dl
			}
			conn.SetDeadline(deadline)
			if _, err = fmt.Fprintln(conn, "CONNECT 5000"); err != nil {
				return err
			}
			r := bufio.NewReader(conn)
			line, err := r.ReadString('\n')
			if err != nil {
				return err
			}
			if !strings.HasPrefix(line, "OK ") {
				return fmt.Errorf("vsock handshake: %q", line)
			}
			if _, err = fmt.Fprintln(conn, `{"op":"info"}`); err != nil {
				return err
			}
			var reply struct {
				OK bool `json:"ok"`
			}
			if err = json.NewDecoder(r).Decode(&reply); err != nil {
				return err
			}
			if !reply.OK {
				return errors.New("guest not ready")
			}
			return nil
		}()
		if err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return errors.Join(ctx.Err(), err)
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func opts(t *testing.T, root string) runtime.FirecrackerOptions {
	c := config(t)
	return runtime.FirecrackerOptions{Root: root, Firecracker: c.Firecracker, Jailer: c.Jailer, Kernel: c.Kernel, Initrd: c.Initrd,
		FirecrackerSHA256: digest(t, c.Firecracker), JailerSHA256: digest(t, c.Jailer), KernelSHA256: digest(t, c.Kernel), InitrdSHA256: digest(t, c.Initrd),
		MaxActive: 2, BootTimeout: 12 * time.Second, Ready: probe}
}

func database(t *testing.T, schema string, create bool) (*controlplane.Store, *pgxpool.Pool) {
	t.Helper()
	dsn := os.Getenv("AGENTCAPSULE_TEST_POSTGRES")
	if dsn == "" {
		t.Fatal("real PostgreSQL is required")
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema + ",pg_catalog"
	scoped := cfg.ConnString() + " search_path=" + schema + ",pg_catalog"
	admin, err := pgxpool.New(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	if create {
		if _, err = admin.Exec(t.Context(), "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize()); err != nil {
			t.Fatal(err)
		}
	}
	s, err := controlplane.Open(t.Context(), scoped)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	if create {
		for _, id := range []string{"a", "b", "c"} {
			if _, err = admin.Exec(t.Context(), "INSERT INTO "+pgx.Identifier{schema, "agents"}.Sanitize()+"(id,owner_user_id) VALUES ($1,$2)", id, "user-"+id); err != nil {
				t.Fatal(err)
			}
		}
	}
	t.Cleanup(func() { s.Close(); admin.Close() })
	return s, admin
}

func lab(t *testing.T, authenticated ...bool) (*Placements, *pgxpool.Pool, string, runtime.FirecrackerOptions) {
	return labWithCapacity(t, 0, authenticated...)
}

func labWithCapacity(t *testing.T, capacity int, authenticated ...bool) (*Placements, *pgxpool.Pool, string, runtime.FirecrackerOptions) {
	t.Helper()
	root, err := os.MkdirTemp(config(t).RootParent, "instance-")
	if err != nil {
		t.Fatal(err)
	}
	schema := fmt.Sprintf("placement_%d", time.Now().UnixNano())
	s, admin := database(t, schema, true)
	options := opts(t, root)
	if len(authenticated) > 0 && authenticated[0] {
		options.AuthenticatedControl = true
		options.Initrd = config(t).ControlInitrd
		options.InitrdSHA256 = digest(t, options.Initrd)
		options.MaxActive = 3
	}
	if capacity > 0 {
		options.MaxActive = capacity
	}
	w, err := NewPlacements(s, "host", "worker-a", time.Minute, options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		// Only the test's registered agent; the runner also scopes emergency cleanup
		// to this private root/cgroup. No global process or volume operations.
		if err := w.host.Retire(ctx, "a", 1000); err != nil {
			t.Error(err)
		}
		if _, err := admin.Exec(ctx, "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE"); err != nil {
			t.Error(err)
		}
	})
	provision(t, w, root)
	return w, admin, schema, options
}

func provision(t *testing.T, w *Placements, root string) {
	provisionAgent(t, w, root, "a", 61201)
}

func provisionAgent(t *testing.T, w *Placements, root, id string, uid uint32) {
	t.Helper()
	path := filepath.Join(root, "volumes", id+".ext4")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.Truncate(128 << 20); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if b, err := exec.Command("/usr/sbin/mkfs.ext4", "-F", "-b", "4096", path).CombinedOutput(); err != nil {
		t.Fatalf("mkfs: %s %v", b, err)
	}
	if err = w.Register(t.Context(), id, path, uid); err != nil {
		t.Fatal(err)
	}
}

func lockedVolume(t *testing.T, root string, busy bool) {
	t.Helper()
	f, err := os.OpenFile(filepath.Join(root, "volumes", "a.ext4"), os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if busy && err != syscall.EWOULDBLOCK || !busy && err != nil {
		t.Fatalf("busy=%v flock=%v", busy, err)
	}
}

func expire(t *testing.T, db *pgxpool.Pool, schema string) {
	t.Helper()
	if _, err := db.Exec(t.Context(), "UPDATE "+pgx.Identifier{schema, "agent_placements"}.Sanitize()+" SET lease_until=clock_timestamp()-interval '1 second' WHERE agent_id='a'"); err != nil {
		t.Fatal(err)
	}
}

func TestPostgresKVMConcurrentStartAdoptionAndFencedStop(t *testing.T) {
	w, _, _, options := lab(t)
	start := make(chan struct{})
	type result struct {
		run runtime.VMRun
		err error
	}
	results := make(chan result, 8)
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() { defer wg.Done(); <-start; r, e := w.Start(t.Context(), "a"); results <- result{r, e} }()
	}
	close(start)
	wg.Wait()
	close(results)
	var first runtime.VMRun
	for r := range results {
		if r.err != nil {
			t.Fatal(r.err)
		}
		if first.ID == "" {
			first = r.run
		}
		if r.run != first {
			t.Fatalf("multiple VMMs: %+v %+v", first, r.run)
		}
	}
	lockedVolume(t, options.Root, true)
	w2, err := NewPlacements(w.store, "host", "worker-b", time.Minute, options)
	if err != nil {
		t.Fatal(err)
	}
	runs, err := w2.Reconcile(t.Context())
	if err != nil || runs["a"] != first {
		t.Fatalf("adoption: %+v %v", runs, err)
	}
	// A stale host snapshot must not kill the VM that appeared before DB read.
	retired, err := w2.host.RetireMissing(t.Context(), "a", first.Generation, first.ID)
	if err != nil || retired {
		t.Fatalf("snapshot race retired live placement: %v %v", retired, err)
	}
	if err = w2.Stop(t.Context(), "a", first.Generation); err != nil {
		t.Fatal(err)
	}
	second, err := w2.Start(t.Context(), "a")
	if err != nil || second.Generation != first.Generation+1 || second.ID == first.ID {
		t.Fatalf("replacement: %+v %v", second, err)
	}
	if err = w.Stop(t.Context(), "a", first.Generation); !errors.Is(err, controlplane.ErrPlacement) {
		t.Fatal(err)
	}
	if err = w.host.Retire(t.Context(), "a", first.Generation); !errors.Is(err, runtime.ErrGeneration) {
		t.Fatal(err)
	}
	if err = w.store.ObservePlacementStopped(t.Context(), "a", "host", first.Generation, true); !errors.Is(err, controlplane.ErrPlacement) {
		t.Fatal(err)
	}
	if err = probe(t.Context(), second.Socket); err != nil {
		t.Fatal(err)
	}
	lockedVolume(t, options.Root, true)
}

func TestPostgresKVMExpiredBootAndDelayedWorker(t *testing.T) {
	w, db, schema, options := lab(t)
	// Expire and replace the lease after guest readiness but before Confirm.
	options.Ready = func(ctx context.Context, path string) error {
		if err := probe(ctx, path); err != nil {
			return err
		}
		expire(t, db, schema)
		_, err := w.store.ClaimPlacement(ctx, "a", "host", "replacement", time.Minute)
		return err
	}
	old, err := NewPlacements(w.store, "host", "old-worker", time.Minute, options)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = old.Start(t.Context(), "a"); !errors.Is(err, controlplane.ErrPlacement) {
		t.Fatalf("stale boot confirmed: %v", err)
	}
	lockedVolume(t, options.Root, false)
	options.Ready = probe
	replacement, err := NewPlacements(w.store, "host", "replacement", time.Minute, options)
	if err != nil {
		t.Fatal(err)
	}
	run, err := replacement.Start(t.Context(), "a")
	if err != nil || run.Generation != 2 {
		t.Fatalf("replacement: %+v %v", run, err)
	}
	if err = replacement.Stop(t.Context(), "a", 2); err != nil {
		t.Fatal(err)
	}
	p, err := w.store.ClaimPlacement(t.Context(), "a", "host", "delayed", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	expire(t, db, schema)
	if _, err = replacement.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err = old.host.Start(t.Context(), "a", p.Generation); !errors.Is(err, runtime.ErrGeneration) {
		t.Fatalf("retired delayed launch accepted: %v", err)
	}
	lockedVolume(t, options.Root, false)
	newRun, err := replacement.Start(t.Context(), "a")
	if err != nil || newRun.Generation != p.Generation+1 {
		t.Fatalf("after retirement: %+v %v", newRun, err)
	}
}

func TestPostgresKVMQuiesceAndDatabaseTimeout(t *testing.T) {
	w, db, schema, options := lab(t)
	run, err := w.Start(t.Context(), "a")
	if err != nil {
		t.Fatal(err)
	}
	// An actual SQL row-lock timeout must retain the VM; it is not ErrPlacement.
	tx, err := db.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	if _, err = tx.Exec(t.Context(), "SELECT id FROM "+pgx.Identifier{schema, "agents"}.Sanitize()+" WHERE id='a' FOR NO KEY UPDATE"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	_, err = w.Reconcile(ctx)
	cancel()
	if err == nil || errors.Is(err, runtime.ErrGeneration) {
		t.Fatalf("SQL outage classified as obsolete: %v", err)
	}
	lockedVolume(t, options.Root, true)
	if err = tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	runs, err := w.Reconcile(t.Context())
	if err != nil || runs["a"] != run {
		t.Fatalf("lost survivor: %+v %v", runs, err)
	}
	// Cancellation after reading a RUNNING placement must not retire it through
	// the failed-new-boot cleanup path. The SQL callback sees the canceled context.
	reuse, cancelReuse := context.WithCancel(t.Context())
	w.afterClaim = cancelReuse
	_, err = w.Start(reuse, "a")
	w.afterClaim = nil
	cancelReuse()
	if err == nil {
		t.Fatal("canceled adoption unexpectedly succeeded")
	}
	lockedVolume(t, options.Root, true)
	if err = w.store.ValidatePlacement(t.Context(), "a", "host", run.Generation, run.ID); err != nil {
		t.Fatal(err)
	}
	if err = w.store.RequestDeletion(t.Context(), "user-a", "a"); err != nil {
		t.Fatal(err)
	}
	runs, err = w.Reconcile(t.Context())
	if err != nil || runs["a"] != run {
		t.Fatalf("quiesce lost fence guest: %+v %v", runs, err)
	}
	if _, err = w.Start(t.Context(), "a"); !errors.Is(err, controlplane.ErrUnavailable) {
		t.Fatal(err)
	}
	// Isolate the placement check. This SQL transition is not evidence for the
	// distributed application fence, whose real vsock transport is still pending.
	if _, err = db.Exec(t.Context(), "UPDATE "+pgx.Identifier{schema, "agents"}.Sanitize()+" SET phase='DELETING' WHERE id='a'"); err != nil {
		t.Fatal(err)
	}
	runs, err = w.Reconcile(t.Context())
	if err != nil || len(runs) != 0 {
		t.Fatalf("deleted VM adopted: %+v %v", runs, err)
	}
	lockedVolume(t, options.Root, false)
}

func TestPostgresKVMWorkerCrashAfterDatabaseConfirmation(t *testing.T) {
	w, _, schema, options := lab(t)
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestPostgresKVMWorkerChild$", "-test.v")
	cmd.Env = append(os.Environ(), "AC_PLACEMENT_CHILD_SCHEMA="+schema, "AC_PLACEMENT_CHILD_ROOT="+options.Root)
	log, err := os.Create(filepath.Join(options.Root, "logs", "worker-child.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	cmd.Stdout = log
	cmd.Stderr = log
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Process.Kill()
	var confirmed runtime.VMRun
	for {
		b, err := os.ReadFile(filepath.Join(options.Root, "logs", "confirmed.json"))
		if err == nil && json.Unmarshal(b, &confirmed) == nil && confirmed.PID > 0 {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(10 * time.Millisecond):
		}
	}
	if err = cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	err = cmd.Wait()
	var exited *exec.ExitError
	if !errors.As(err, &exited) || exited.Sys().(syscall.WaitStatus).Signal() != syscall.SIGKILL {
		t.Fatalf("worker was not SIGKILLed: %v", err)
	}
	if err = syscall.Kill(confirmed.PID, 0); err != nil {
		t.Fatal("VMM did not survive worker:", err)
	}
	lockedVolume(t, options.Root, true)
	if err = w.store.ValidatePlacement(t.Context(), "a", "host", confirmed.Generation, confirmed.ID); err != nil {
		t.Fatal(err)
	}
	// The durable host record is still STARTING; do not infer that it has finished
	// confirming locally just because the database commit survived.
	runs, err := w.Reconcile(t.Context())
	if err != nil || len(runs) != 0 {
		t.Fatalf("uncertain attempt adopted: %+v %v", runs, err)
	}
	lockedVolume(t, options.Root, false)
	placements, err := w.store.Placements(t.Context(), "host")
	if err != nil || len(placements) != 1 || placements[0].State != "STOPPED" || !placements[0].UncleanStop {
		t.Fatalf("missing unclean stop: %+v %v", placements, err)
	}
	replacement, err := w.Start(t.Context(), "a")
	if err != nil || replacement.Generation != confirmed.Generation+1 || replacement.ID == confirmed.ID {
		t.Fatalf("replacement: %+v %v", replacement, err)
	}
}

func TestPostgresKVMWorkerChild(t *testing.T) {
	schema := os.Getenv("AC_PLACEMENT_CHILD_SCHEMA")
	if schema == "" {
		return
	}
	root := os.Getenv("AC_PLACEMENT_CHILD_ROOT")
	s, _ := database(t, schema, false)
	w, err := NewPlacements(s, "host", "child-worker", time.Minute, opts(t, root))
	if err != nil {
		t.Fatal(err)
	}
	w.afterConfirm = func(run runtime.VMRun) {
		b, err := json.Marshal(run)
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(filepath.Join(root, "logs", "confirmed.json"), b, 0600); err != nil {
			t.Fatal(err)
		}
		select {} // The parent kills this actual worker after the SQL commit.
	}
	if _, err = w.Start(t.Context(), "a"); err != nil {
		t.Fatal(err)
	}
	t.Fatal("confirmation crash barrier not reached")
}

// The runner executes prepare, SIGQUITs only its PGDATA, restarts PostgreSQL and
// invokes verify in a new process. The VMM must survive both worker exits and the
// database crash, then be adopted by exact generation/VM ID/PID/start ticks.
func TestPostgresKVMDatabaseRecovery(t *testing.T) {
	phase := os.Getenv("AGENTCAPSULE_VM_PG_RECOVERY")
	if phase == "" {
		return
	}
	c := config(t)
	schema := "placement_vm_restart"
	root := filepath.Join(c.RootParent, "restart")
	s, db := database(t, schema, phase == "prepare")
	w, err := NewPlacements(s, "host", "recovery-"+phase, time.Minute, opts(t, root))
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(c.Output, "vm-restart.json")
	if phase == "prepare" {
		provision(t, w, root)
		run, err := w.Start(t.Context(), "a")
		if err != nil {
			t.Fatal(err)
		}
		if err = os.MkdirAll(c.Output, 0700); err != nil {
			t.Fatal(err)
		}
		b, err := json.MarshalIndent(run, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(file, b, 0600); err != nil {
			t.Fatal(err)
		}
		return
	}
	if phase != "verify" {
		t.Fatal("invalid recovery phase")
	}
	var expected runtime.VMRun
	b, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(b, &expected); err != nil {
		t.Fatal(err)
	}
	runs, err := w.Reconcile(t.Context())
	if err != nil || runs["a"] != expected {
		t.Fatalf("WAL recovery lost VMM identity: %+v want %+v err %v", runs, expected, err)
	}
	lockedVolume(t, root, true)
	if err = probe(t.Context(), expected.Socket); err != nil {
		t.Fatal(err)
	}
	if err = w.Stop(t.Context(), "a", expected.Generation); err != nil {
		t.Fatal(err)
	}
	lockedVolume(t, root, false)
	if _, err = db.Exec(t.Context(), "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE"); err != nil {
		t.Fatal(err)
	}
}
