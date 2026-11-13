//go:build linux && kvm_integration && kvm_control_integration

package worker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnessstore"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/runtime"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestMaintenanceLoopDiscoversExpiryOnLaterPoll(t *testing.T) {
	w, db, schema, options := labWithCapacity(t, 1, true)
	t.Cleanup(w.Close)
	old, err := w.Start(t.Context(), "a")
	if err != nil {
		t.Fatal(err)
	}
	deadline := renewalClock(t, hostCredentials(t, options.Root, old), "margin")
	var due atomic.Bool
	w.credentialNow = func() time.Time {
		if due.Load() {
			return deadline
		}
		return time.Now()
	}
	w.afterCredentialStop = func() { due.Store(false) }
	var completed atomic.Int32
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- w.RunMaintenance(ctx, MaintenanceOptions{Interval: 30 * time.Millisecond, AttemptTimeout: 20 * time.Second, Report: func(err error) {
			if err == nil {
				completed.Add(1)
			}
		}})
	}()
	t.Cleanup(func() {
		cancel()
		if err := <-done; !errors.Is(err, context.Canceled) {
			t.Error(err)
		}
	})
	waitMaintenance(t, func() bool { return completed.Load() > 0 })
	if registryRun(t, options.Root, "a").ID != old.ID {
		t.Fatal("fresh boot rotated")
	}
	due.Store(true)
	// No Start/Send is invoked after the clock change. The next periodic poll
	// must discover the expiry, persist its intent, replace and acknowledge it.
	waitMaintenance(t, func() bool {
		return !due.Load() && renewalCount(t, db, schema) == 0 && registryRun(t, options.Root, "a").Generation == old.Generation+1
	})
}

func waitMaintenance(t *testing.T, check func() bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 25*time.Second)
	defer cancel()
	for !check() {
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(20 * time.Millisecond):
		}
	}
}

func serviceProcess(t *testing.T, options runtime.FirecrackerOptions, schema string) (string, func()) {
	t.Helper()
	c := ServiceConfig{Version: 1, HostID: "host", Root: options.Root,
		Firecracker: ServiceImage{options.Firecracker, options.FirecrackerSHA256}, Jailer: ServiceImage{options.Jailer, options.JailerSHA256},
		Kernel: ServiceImage{options.Kernel, options.KernelSHA256}, Initrd: ServiceImage{options.Initrd, options.InitrdSHA256},
		MaxActive: options.MaxActive, BootTimeout: "12s", BootLease: "1m", PollInterval: "100ms", AttemptTimeout: "20s"}
	free, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	c.MetricsListen = free.Addr().String()
	free.Close()
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(options.Root, "service.json")
	if err = os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(options.Root, "logs", "maintenance-service.log")
	log, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(config(t).WorkerExecutable, "-config", path)
	cmd.Env = append(os.Environ(), "AGENTCAPSULE_DATABASE_URL="+os.Getenv("AGENTCAPSULE_TEST_POSTGRES")+" search_path="+schema+",pg_catalog")
	cmd.Stdout, cmd.Stderr = log, log
	if err = cmd.Start(); err != nil {
		log.Close()
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	// The service's metrics (OPS-02), on its loopback listener.
	waitMaintenance(t, func() bool {
		r, err := http.Get("http://" + c.MetricsListen + "/metrics")
		if err != nil {
			return false
		}
		body, _ := io.ReadAll(r.Body)
		r.Body.Close()
		return r.StatusCode == 200 && strings.Contains(string(body), "agentcapsule_worker_vm_capacity "+strconv.Itoa(options.MaxActive)+"\n") &&
			strings.Contains(string(body), "# TYPE agentcapsule_worker_jobs_total counter")
	})
	var once sync.Once
	stop := func() {
		once.Do(func() {
			_ = cmd.Process.Signal(syscall.SIGTERM)
			select {
			case err := <-done:
				if err != nil {
					t.Error("maintenance process failed:", err)
				}
			case <-time.After(10 * time.Second):
				_ = cmd.Process.Kill()
				<-done
				t.Error("maintenance did not stop promptly")
			}
			log.Close()
		})
	}
	t.Cleanup(stop)
	return logPath, stop
}

func serviceEvents(t *testing.T, path, word string) int {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Count(string(b), word)
}

func renewalCount(t *testing.T, db *pgxpool.Pool, schema string) int {
	t.Helper()
	var n int
	if err := db.QueryRow(t.Context(), "SELECT count(*) FROM "+pgx.Identifier{schema, "placement_renewals"}.Sanitize()).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func killRenewalWorker(t *testing.T, options runtime.FirecrackerOptions, schema, stage string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCredentialRotationChild$", "-test.v")
	cmd.Env = append(os.Environ(), "AC_CREDENTIAL_CHILD_SCHEMA="+schema, "AC_CREDENTIAL_CHILD_ROOT="+options.Root, "AC_CREDENTIAL_CHILD_STAGE="+stage)
	log, err := os.Create(filepath.Join(options.Root, "logs", "renewal-crash.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	cmd.Stdout, cmd.Stderr = log, log
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Process.Kill()
	for {
		if _, err = os.Stat(filepath.Join(options.Root, "logs", "rotation-boundary")); err == nil {
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
		t.Fatal(err)
	}
}

func registryRun(t *testing.T, root, id string) runtime.VMRun {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, "registry.json"))
	if err != nil {
		t.Fatal(err)
	}
	var r struct {
		Agents map[string]struct {
			Run *runtime.VMRun `json:"run"`
		} `json:"agents"`
	}
	if err = json.Unmarshal(b, &r); err != nil {
		t.Fatal(err)
	}
	if r.Agents[id].Run == nil {
		return runtime.VMRun{}
	}
	return *r.Agents[id].Run
}

func TestMaintenanceServiceRecoversRenewalCrashesWithoutIncomingWork(t *testing.T) {
	for _, stage := range []string{"intent", "retired", "confirmed", "running"} {
		t.Run(stage, func(t *testing.T) {
			w, db, schema, options := labWithCapacity(t, 1, true)
			t.Cleanup(w.Close)
			e := harnessstore.Event{ID: "before-maintenance", Subjects: []string{"agent/a", "event/before-maintenance"}, Body: []byte("local")}
			original, err := w.Send(t.Context(), "a", e)
			if err != nil {
				t.Fatal(err)
			}
			old, err := w.Start(t.Context(), "a")
			if err != nil {
				t.Fatal(err)
			}
			w.Close()
			killRenewalWorker(t, options, schema, stage)
			if renewalCount(t, db, schema) != 1 {
				t.Fatal("restart intent lost before durable completion")
			}
			before := registryRun(t, options.Root, "a")
			log, stop := serviceProcess(t, options, schema)
			// Only the standalone service may make progress; the test observes SQL
			// and files, sending no control or application request until completion.
			waitMaintenance(t, func() bool {
				return renewalCount(t, db, schema) == 0 && serviceEvents(t, log, "maintenance_complete") > 0
			})
			after := registryRun(t, options.Root, "a")
			want := old.Generation + 1
			if stage == "confirmed" {
				want++
			}
			if after.Phase != "RUNNING" || after.Generation != want {
				t.Fatal("wrong recovery generation:", after, want)
			}
			if stage == "running" && (after.ID != before.ID || after.PID != before.PID) {
				t.Fatal("confirmed VMM needlessly restarted")
			}
			stop()
			next, err := NewPlacements(w.store, "host", "check-service", time.Minute, options)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(next.Close)
			r, err := next.Send(t.Context(), "a", e)
			if err != nil || !r.Replayed || !bytes.Equal(r.Result, original.Result) {
				t.Fatal("autonomous recovery duplicated effect:", r, err)
			}
			if got := registryRun(t, options.Root, "a"); got.ID != after.ID {
				t.Fatal("service exit stopped adoptable VM")
			}
		})
	}
}

func TestMaintenanceDefersAtCapacityAndResumesWithoutDemand(t *testing.T) {
	w, db, schema, options := labWithCapacity(t, 1, true)
	t.Cleanup(w.Close)
	provisionAgent(t, w, options.Root, "b", 61212)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := w.host.Retire(ctx, "b", 1000); err != nil {
			t.Error(err)
		}
	})
	a, err := w.Start(t.Context(), "a")
	if err != nil {
		t.Fatal(err)
	}
	if err = w.store.BeginCredentialRenewal(t.Context(), "a", "host", a.Generation, a.ID); err != nil {
		t.Fatal(err)
	}
	if err = w.stopAfterIntent(t.Context(), "a", a.Generation, true); err != nil {
		t.Fatal(err)
	}
	b, err := w.Start(t.Context(), "b")
	if err != nil {
		t.Fatal(err)
	}
	log, stop := serviceProcess(t, options, schema)
	waitMaintenance(t, func() bool { return serviceEvents(t, log, "maintenance_retry") >= 2 })
	if renewalCount(t, db, schema) != 1 || registryRun(t, options.Root, "b").ID != b.ID || registryRun(t, options.Root, "a").ID != "" {
		t.Fatal("capacity limit ignored or pending wake lost")
	}
	if err = w.Stop(t.Context(), "b", b.Generation); err != nil {
		t.Fatal(err)
	}
	waitMaintenance(t, func() bool {
		return renewalCount(t, db, schema) == 0 && registryRun(t, options.Root, "a").Phase == "RUNNING"
	})
	stop()
}

func TestMaintenanceDoesNotReviveCanceledOrDeletedAgent(t *testing.T) {
	for _, reason := range []string{"stop", "delete"} {
		t.Run(reason, func(t *testing.T) {
			w, db, schema, options := labWithCapacity(t, 1, true)
			t.Cleanup(w.Close)
			if reason == "delete" {
				provisionDispatchPeers(t, w, options.Root)
			}
			a, err := w.Start(t.Context(), "a")
			if err != nil {
				t.Fatal(err)
			}
			if err = w.store.BeginCredentialRenewal(t.Context(), "a", "host", a.Generation, a.ID); err != nil {
				t.Fatal(err)
			}
			if reason == "stop" {
				err = w.Stop(t.Context(), "a", a.Generation)
			} else {
				err = w.store.RequestDeletion(t.Context(), "user-a", "a")
			}
			if err != nil {
				t.Fatal(err)
			}
			log, stop := serviceProcess(t, options, schema)
			waitMaintenance(t, func() bool { return serviceEvents(t, log, "maintenance_complete") >= 3 })
			if renewalCount(t, db, schema) != 0 || registryRun(t, options.Root, "a").ID != "" {
				t.Fatal("canceled wake revived agent")
			}
			stop()
		})
	}
}
