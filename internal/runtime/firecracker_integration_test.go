//go:build linux && kvm_integration

package runtime

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
)

type kvmConfig struct{ Firecracker, Jailer, Kernel, Initrd, UpstreamFirecracker, Output, RootParent string }

func kvmSettings(t *testing.T) kvmConfig {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Fatal("KVM integration requires root orchestration")
	}
	b, e := os.ReadFile(os.Getenv("AGENTCAPSULE_KVM_CONFIG"))
	if e != nil {
		t.Fatal(e)
	}
	var c kvmConfig
	if e = json.Unmarshal(b, &c); e != nil {
		t.Fatal(e)
	}
	return c
}
func hashFile(t *testing.T, path string) string {
	t.Helper()
	b, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func guestCall(ctx context.Context, path string, command map[string]any) (map[string]any, error) {
	d := net.Dialer{}
	conn, e := d.DialContext(ctx, "unix", path)
	if e != nil {
		return nil, e
	}
	defer conn.Close()
	deadline := time.Now().Add(3 * time.Second)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	conn.SetDeadline(deadline)
	if _, e = fmt.Fprintln(conn, "CONNECT 5000"); e != nil {
		return nil, e
	}
	r := bufio.NewReader(conn)
	line, e := r.ReadString('\n')
	if e != nil {
		return nil, e
	}
	if !strings.HasPrefix(line, "OK ") {
		return nil, fmt.Errorf("vsock handshake: %q", line)
	}
	if e = json.NewEncoder(conn).Encode(command); e != nil {
		return nil, e
	}
	var result map[string]any
	e = json.NewDecoder(r).Decode(&result)
	return result, e
}

func readyGuest(ctx context.Context, path string) error {
	for {
		r, e := guestCall(ctx, path, map[string]any{"op": "info"})
		if e == nil && r["ok"] == true {
			return nil
		}
		select {
		case <-ctx.Done():
			return errors.Join(ctx.Err(), e)
		case <-time.After(20 * time.Millisecond):
		}
	}
}

func options(t *testing.T, root string) FirecrackerOptions {
	c := kvmSettings(t)
	return FirecrackerOptions{Root: root, Firecracker: c.Firecracker, Jailer: c.Jailer, Kernel: c.Kernel, Initrd: c.Initrd, FirecrackerSHA256: hashFile(t, c.Firecracker), JailerSHA256: hashFile(t, c.Jailer), KernelSHA256: hashFile(t, c.Kernel), InitrdSHA256: hashFile(t, c.Initrd), MaxActive: 2, BootTimeout: 12 * time.Second, Ready: readyGuest, Confirm: func(context.Context, string, VMRun) error { return nil }, Adopt: func(context.Context, string, VMRun) error { return nil }}
}

func newHost(t *testing.T) (*FirecrackerHost, string) {
	t.Helper()
	return newHostWithOptions(t, nil)
}

func newHostWithOptions(t *testing.T, change func(*FirecrackerOptions)) (*FirecrackerHost, string) {
	t.Helper()
	root, e := os.MkdirTemp(kvmSettings(t).RootParent, "instance-")
	if e != nil {
		t.Fatal(e)
	}
	opts := options(t, root)
	if change != nil {
		change(&opts)
	}
	h, e := NewFirecrackerHost(opts)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		// Persist diagnostics before cleanup; retain no guest disk in the evidence.
		c := kvmSettings(t)
		dest := filepath.Join(c.Output, strings.ReplaceAll(t.Name(), "/", "-"), filepath.Base(root))
		os.MkdirAll(dest, 0700)
		for _, name := range []string{"registry.json"} {
			if b, e := os.ReadFile(filepath.Join(root, name)); e == nil {
				os.WriteFile(filepath.Join(dest, name), b, 0600)
			}
		}
		entries, _ := os.ReadDir(filepath.Join(root, "logs"))
		for _, f := range entries {
			b, _ := os.ReadFile(filepath.Join(root, "logs", f.Name()))
			os.WriteFile(filepath.Join(dest, f.Name()), b, 0600)
		}
		if e := h.locked(context.Background(), func(r *hostRegistry) error {
			for _, a := range r.Agents {
				if a.Run != nil {
					if e := h.cleanup(a.Run); e != nil {
						return e
					}
					a.Run = nil
				}
			}
			return h.save(r)
		}); e != nil {
			t.Error(e)
			return
		}
		if e := os.Remove(h.cgroup); e != nil {
			t.Error(e)
		}
		if e := os.RemoveAll(root); e != nil {
			t.Error(e)
		}
	})
	return h, root
}

func enroll(t *testing.T, h *FirecrackerHost, id string, uid uint32) string {
	t.Helper()
	path := filepath.Join(h.root, "volumes", id+".ext4")
	f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if e != nil {
		t.Fatal(e)
	}
	if e = f.Truncate(128 << 20); e != nil {
		t.Fatal(e)
	}
	f.Close()
	if b, e := exec.Command("/usr/sbin/mkfs.ext4", "-F", "-b", "4096", path).CombinedOutput(); e != nil {
		t.Fatalf("mkfs: %s: %v", b, e)
	}
	if e = h.Register(context.Background(), id, path, uid); e != nil {
		t.Fatal(e)
	}
	return path
}

func requireLock(t *testing.T, path string, busy bool) {
	t.Helper()
	f, e := os.OpenFile(path, os.O_RDWR, 0)
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	e = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if busy && e != syscall.EWOULDBLOCK {
		t.Fatalf("expected occupied volume, got %v", e)
	}
	if !busy && e != nil {
		t.Fatalf("expected free volume, got %v", e)
	}
}

func TestFirecrackerConcurrentStartAndGenerations(t *testing.T) {
	h, _ := newHost(t)
	volume := enroll(t, h, "a", 61101)
	ctx := context.Background()
	var wg sync.WaitGroup
	results := make(chan VMRun, 8)
	errs := make(chan error, 8)
	for range 8 {
		wg.Add(1)
		go func() { defer wg.Done(); r, e := h.Start(ctx, "a", 1); results <- r; errs <- e }()
	}
	wg.Wait()
	close(results)
	close(errs)
	for e := range errs {
		if e != nil {
			t.Fatal(e)
		}
	}
	var run VMRun
	for r := range results {
		if run.ID != "" && run != r {
			t.Fatal("concurrent start created different VMMs")
		}
		run = r
	}
	if e := ownedVolumeLock(run.PID, volume); e != nil {
		t.Fatal(e)
	}
	requireLock(t, volume, true)
	if _, e := h.Start(ctx, "a", 2); !errors.Is(e, ErrVolumeBusy) {
		t.Fatalf("new generation overlapped old: %v", e)
	}
	if e := h.Stop(ctx, "a", 2); !errors.Is(e, ErrGeneration) {
		t.Fatalf("stale stop accepted: %v", e)
	}
	if e := h.Stop(ctx, "a", 1); e != nil {
		t.Fatal(e)
	}
	requireLock(t, volume, false)
	if _, e := h.Start(ctx, "a", 1); !errors.Is(e, ErrGeneration) {
		t.Fatalf("generation reused: %v", e)
	}
	next, e := h.Start(ctx, "a", 2)
	if e != nil {
		t.Fatal(e)
	}
	if next.ID == run.ID || next.PID == run.PID {
		t.Fatal("new generation reused process identity")
	}
	t.Logf("8 concurrent callers -> one VMM %d; lock survives until exit; generation 2 -> %d", run.PID, next.PID)
}

func TestFirecrackerCrossRegistryVolumeAlias(t *testing.T) {
	a, _ := newHost(t)
	volume := enroll(t, a, "a", 61102)
	b, _ := newHost(t)
	alias := filepath.Join(b.root, "volumes", "alias.ext4")
	if e := os.Link(volume, alias); e != nil {
		t.Fatal(e)
	}
	if e := b.Register(context.Background(), "alias", alias, 61102); e != nil {
		t.Fatal(e)
	}
	// Both workers pass their preliminary lock check before either VMM starts.
	// Their registries/worker locks are independent: the VMM lock must arbitrate.
	barrier := make(chan struct{})
	arrived := make(chan struct{}, 2)
	for _, h := range []*FirecrackerHost{a, b} {
		h.hook = func(stage string, _ VMRun) {
			if stage == "intent" {
				arrived <- struct{}{}
				<-barrier
			}
		}
	}
	type outcome struct {
		run VMRun
		err error
	}
	done := make(chan outcome, 2)
	var release sync.Once
	defer release.Do(func() { close(barrier) })
	waitIntent := func() {
		select {
		case <-arrived:
		case early := <-done:
			t.Fatalf("worker exited before the shared launch barrier: %v", early.err)
		case <-time.After(15 * time.Second):
			t.Fatal("worker never reached its durable intent")
		}
	}
	go func() { r, e := a.Start(context.Background(), "a", 1); done <- outcome{r, e} }()
	waitIntent()
	go func() { r, e := b.Start(context.Background(), "alias", 1); done <- outcome{r, e} }()
	waitIntent()
	release.Do(func() { close(barrier) })
	x, y := <-done, <-done
	if (x.err == nil) == (y.err == nil) {
		t.Fatalf("expected exactly one lock winner, got %v / %v", x.err, y.err)
	}
	winner := x
	if winner.err != nil {
		winner = y
	}
	if e := ownedVolumeLock(winner.run.PID, volume); e != nil {
		t.Fatal(e)
	}
	// A setup failure is not a valid negative: the losing VMM must have reached
	// the backing file and received EWOULDBLOCK from the kernel lock attempt.
	loser := a
	if strings.HasPrefix(winner.run.Socket, a.root+"/") {
		loser = b
	}
	logs, _ := filepath.Glob(filepath.Join(loser.root, "logs", "*.log"))
	found := false
	for _, p := range logs {
		data, _ := os.ReadFile(p)
		found = found || strings.Contains(string(data), "Resource temporarily unavailable")
	}
	if !found {
		t.Fatal("loser did not report the expected kernel lock conflict")
	}
	t.Logf("two independent workers, same inode through a hard link: exactly one live writer, PID %d", winner.run.PID)
}

func TestFirecrackerWorkerCrash(t *testing.T) {
	for _, stage := range []string{"intent", "spawned", "confirmed"} {
		t.Run(stage, func(t *testing.T) {
			h, root := newHost(t)
			volume := enroll(t, h, "a", 61103)
			mark := filepath.Join(root, "child-stage")
			c := exec.Command(os.Args[0], "-test.run=^TestFirecrackerWorkerChild$", "-test.v")
			c.Env = append(os.Environ(), "AC_RUNTIME_CHILD_ROOT="+root, "AC_RUNTIME_CHILD_STAGE="+stage, "AC_RUNTIME_CHILD_MARK="+mark)
			log, e := os.Create(filepath.Join(root, "logs", "worker.log"))
			if e != nil {
				t.Fatal(e)
			}
			defer log.Close()
			c.Stdout = log
			c.Stderr = log
			if e = c.Start(); e != nil {
				t.Fatal(e)
			}
			defer c.Process.Kill()
			deadline := time.Now().Add(25 * time.Second)
			for {
				if _, e = os.Stat(mark); e == nil {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("child never reached crash point")
				}
				time.Sleep(10 * time.Millisecond)
			}
			if e = c.Process.Kill(); e != nil {
				t.Fatal(e)
			}
			if e = c.Wait(); e == nil {
				t.Fatal("worker did not crash")
			}
			reopened, e := NewFirecrackerHost(options(t, root))
			if e != nil {
				t.Fatal(e)
			}
			runs, e := reopened.Reconcile(context.Background())
			if e != nil {
				t.Fatal(e)
			}
			if stage == "confirmed" {
				r, ok := runs["a"]
				if !ok {
					t.Fatal("orphan VMM was lost")
				}
				requireLock(t, volume, true)
				if _, e = reopened.Start(context.Background(), "a", 2); !errors.Is(e, ErrVolumeBusy) {
					t.Fatalf("orphan volume reused: %v", e)
				}
				t.Logf("worker SIGKILL preserved VMM %d and its kernel lock; new worker adopted it", r.PID)
			} else {
				if len(runs) != 0 {
					t.Fatal("unconfirmed attempt was adopted")
				}
				requireLock(t, volume, false)
				if _, e = reopened.Start(context.Background(), "a", 2); e != nil {
					t.Fatal(e)
				}
				t.Log("interrupted attempt neutralized; next generation starts")
			}
		})
	}
}

func TestFirecrackerWorkerChild(t *testing.T) {
	root := os.Getenv("AC_RUNTIME_CHILD_ROOT")
	if root == "" {
		return
	}
	h, e := NewFirecrackerHost(options(t, root))
	if e != nil {
		t.Fatal(e)
	}
	h.hook = func(stage string, run VMRun) {
		if stage == os.Getenv("AC_RUNTIME_CHILD_STAGE") {
			b, _ := json.Marshal(run)
			if e := os.WriteFile(os.Getenv("AC_RUNTIME_CHILD_MARK"), b, 0600); e != nil {
				panic(e)
			}
			for {
				time.Sleep(time.Hour)
			}
		}
	}
	if _, e = h.Start(context.Background(), "a", 1); e != nil {
		t.Fatal(e)
	}
	t.Fatal("crash point not reached")
}

func TestFirecrackerPlacementAndHostFence(t *testing.T) {
	h, root := newHost(t)
	volume := enroll(t, h, "a", 61104)
	ctx := context.Background()
	h.opts.Confirm = func(context.Context, string, VMRun) error { return ErrGeneration }
	if _, e := h.Start(ctx, "a", 1); !errors.Is(e, ErrGeneration) {
		t.Fatalf("obsolete lease accepted: %v", e)
	}
	requireLock(t, volume, false)
	h.opts.Confirm = func(context.Context, string, VMRun) error { return nil }
	run, e := h.Start(ctx, "a", 2)
	if e != nil {
		t.Fatal(e)
	}
	dbDown := errors.New("placement database unavailable")
	h.opts.Adopt = func(context.Context, string, VMRun) error { return dbDown }
	if _, e = h.Reconcile(ctx); !errors.Is(e, dbDown) {
		t.Fatalf("database outage ignored: %v", e)
	}
	requireLock(t, volume, true)
	h.opts.Adopt = func(context.Context, string, VMRun) error { return ErrGeneration }
	if r, e := h.Reconcile(ctx); e != nil || len(r) != 0 {
		t.Fatalf("obsolete placement retained: %v %v", r, e)
	}
	requireLock(t, volume, false)
	h.opts.Adopt = func(context.Context, string, VMRun) error { return nil }
	if _, e = h.Start(ctx, "a", 3); e != nil {
		t.Fatal(e)
	}
	if e = h.FenceAgent(ctx, "a"); e != nil {
		t.Fatal(e)
	}
	requireLock(t, volume, false)
	next, e := NewFirecrackerHost(options(t, root))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = next.Start(ctx, "a", 4); !errors.Is(e, ErrHostFenced) {
		t.Fatalf("fenced agent restarted: %v", e)
	}
	t.Logf("obsolete confirmation killed its own attempt; outage preserved PID %d; stale placement and durable fence prevented unsafe starts", run.PID)
}

func TestFirecrackerRejectsUnpatchedVMM(t *testing.T) {
	c := kvmSettings(t)
	if c.UpstreamFirecracker == "" {
		t.Fatal("upstream negative control is required")
	}
	h, _ := newHost(t)
	volume := enroll(t, h, "a", 61105)
	// This isolated test intentionally replaces the trusted binary before any VM
	// has started. The readiness gate must detect absence of the lifetime flock.
	b, e := os.ReadFile(c.UpstreamFirecracker)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(h.root, "bin", "firecracker"), b, 0500); e != nil {
		t.Fatal(e)
	}
	_, e = h.Start(context.Background(), "a", 1)
	if e == nil || !strings.Contains(e.Error(), "does not own") {
		t.Fatalf("unpatched VMM not rejected for missing lock: %v", e)
	}
	requireLock(t, volume, false)
	t.Log("unmodified upstream VMM booted but was rejected before placement confirmation")
}

func TestFirecrackerCapacityAfterControllerRestart(t *testing.T) {
	h, root := newHost(t)
	for i, id := range []string{"a", "b", "c"} {
		enroll(t, h, id, uint32(61106+i))
	}
	ctx := context.Background()
	a, err := h.Start(ctx, "a", 1)
	if err != nil {
		t.Fatal(err)
	}
	b, err := h.Start(ctx, "b", 1)
	if err != nil {
		t.Fatal(err)
	}
	if a.PID == b.PID {
		t.Fatal("two agents share a VMM")
	}
	restarted, err := NewFirecrackerHost(options(t, root))
	if err != nil {
		t.Fatal(err)
	}
	runs, err := restarted.Reconcile(ctx)
	if err != nil || len(runs) != 2 {
		t.Fatalf("lost live placements: %v %v", runs, err)
	}
	if _, err = restarted.Start(ctx, "c", 1); !errors.Is(err, ErrCapacity) {
		t.Fatalf("capacity bypass after restart: %v", err)
	}
	if err = restarted.Stop(ctx, "a", 1); err != nil {
		t.Fatal(err)
	}
	c, err := restarted.Start(ctx, "c", 1)
	if err != nil {
		t.Fatal(err)
	}
	runs, err = restarted.Reconcile(ctx)
	if err != nil || len(runs) != 2 || runs["b"].PID != b.PID || runs["c"].PID != c.PID {
		t.Fatalf("incorrect admission set: %v %v", runs, err)
	}
	t.Logf("three agents, capacity two: restarted worker retained PIDs %d/%d and admitted %d only after stopping the first", a.PID, b.PID, c.PID)
}
