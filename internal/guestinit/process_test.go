//go:build linux

package guestinit

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnessstore"
)

func TestRealHarnessProcessPersistenceAndFences(t *testing.T) {
	// Direct /tmp parent is traversable when a root test drops to UID 1000.
	root, err := os.MkdirTemp("", "acp-harness-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(root) })
	if err = os.Chmod(root, 0755); err != nil {
		t.Fatal(err)
	}
	data := filepath.Join(root, "data")
	if err = os.Mkdir(data, 0700); err != nil {
		t.Fatal(err)
	}
	uid, gid := uint32(os.Geteuid()), uint32(os.Getegid())
	if uid == 0 {
		uid, gid = 1000, 1000
	}
	if err = os.Chown(data, int(uid), int(gid)); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(root, "capsule-echo")
	buildCtx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	build := exec.CommandContext(buildCtx, "go", "build", "-race", "-o", binary, "./cmd/capsule-echo")
	build.Dir = filepath.Join("..", "..")
	output, err := build.CombinedOutput()
	cancel()
	if err != nil {
		t.Fatalf("reference harness build: %v %s", err, output)
	}
	opts := ProcessOptions{Boot: HarnessBoot{Protocol: capsuleprotocol.Version, PreviousShutdown: capsuleprotocol.ShutdownClean, Identity: capsuleprotocol.Identity{Incarnation: 1, AgentID: "a", Generation: 1, VMID: "0123456789abcdef"}, DataDirectory: data, SupervisorUID: uint32(os.Geteuid())}, Entrypoint: []string{binary}, SocketPath: filepath.Join(root, "control.sock"), UID: uid, GID: gid}
	lifetime, stopLifetime := context.WithCancel(t.Context())
	defer stopLifetime()
	var active *Process
	t.Cleanup(func() {
		if active != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = active.Stop(ctx)
		}
	})
	start := func() (*Process, *capsuleprotocol.Client) {
		t.Helper()
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer cancel()
		p, err := StartHarness(lifetime, ctx, opts)
		if err != nil {
			t.Fatal(err)
		}
		active = p
		c, err := capsuleprotocol.NewLocalClient(opts.Boot.Identity, opts.SocketPath)
		if err != nil {
			t.Fatal(err)
		}
		health, err := c.HealthStatus(t.Context())
		if err != nil || health.PreviousShutdown != opts.Boot.PreviousShutdown || health.Identity != opts.Boot.Identity {
			t.Fatal("real harness lost boot shutdown observation", health, err)
		}
		return p, c
	}
	p, c := start()
	status, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", p.cmd.Process.Pid))
	if err != nil || !strings.Contains(string(status), fmt.Sprintf("Uid:\t%d\t%d\t%d\t%d", uid, uid, uid, uid)) {
		t.Fatal("harness privilege drop", err)
	}
	e := harnessstore.Event{ID: "same-event", Subjects: []string{"agent/a", "request/r"}, Body: []byte("owner instruction")}
	receipt, err := c.Send(t.Context(), e)
	if err != nil || receipt.Replayed {
		t.Fatal("first durable effect", err)
	}
	var response struct {
		Echo []byte `json:"echo"`
	}
	if err = json.Unmarshal(receipt.Result, &response); err != nil || string(response.Echo) != string(e.Body) {
		t.Fatal("reference echo response mismatch", err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	err = p.Stop(ctx)
	cancel()
	if err != nil {
		t.Fatal("graceful harness stop", err)
	}
	opts.Boot.Identity.Generation++
	opts.Boot.Identity.VMID = "0123456789abcdee"
	p, c = start()
	receipt, err = c.Send(t.Context(), e)
	if err != nil || !receipt.Replayed {
		t.Fatal("process restart repeated effect", err)
	}
	if err = c.Fence(t.Context(), "request/r"); err != nil {
		t.Fatal(err)
	}
	if err = p.cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-p.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("killed harness not observed")
	}
	opts.Boot.Identity.Generation++
	opts.Boot.Identity.VMID = "0123456789abcded"
	opts.Boot.PreviousShutdown = capsuleprotocol.ShutdownUnclean
	p, c = start()
	if _, err = c.Send(t.Context(), e); !errors.Is(err, harnessstore.ErrFenced) {
		t.Fatal("durable fence lost after process kill", err)
	}
	ctx, cancel = context.WithTimeout(t.Context(), 5*time.Second)
	err = p.Stop(ctx)
	cancel()
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite3", "file:"+filepath.Join(data, "harness.db")+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var count int
	if err = db.QueryRow("SELECT count(*) FROM echo_events").Scan(&count); err != nil || count != 1 {
		t.Fatal("durable effect count", count, err)
	}
	// A frozen real harness cannot handle SIGTERM. The supervisor must kill it
	// after the deadline and retain the non-clean result on repeated Stop calls.
	opts.Boot.PreviousShutdown = capsuleprotocol.ShutdownClean
	p, _ = start()
	if err = p.cmd.Process.Signal(syscall.SIGSTOP); err != nil {
		t.Fatal(err)
	}
	ctx, cancel = context.WithTimeout(t.Context(), 50*time.Millisecond)
	err = p.Stop(ctx)
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) || p.Err() == nil {
		t.Fatal("forced termination reported clean", err)
	}
	if err = p.Stop(t.Context()); err == nil {
		t.Fatal("forced termination forgotten on retry")
	}
}

func TestGuestVolumeCannotBeMountedByHostProcess(t *testing.T) {
	if os.Getpid() == 1 {
		t.Fatal("unit tests must not run as PID 1")
	}
	v := capsuleprotocol.VolumeBoot{Incarnation: 1, VolumeID: "vol_" + strings.Repeat("b", 32), UUID: "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", Initialize: true, PreviousShutdown: capsuleprotocol.ShutdownClean}
	if _, err := OpenVolume(t.Context(), v, make([]byte, 32)); !errors.Is(err, ErrGuest) {
		t.Fatal("host process admitted to guest mount path", err)
	}
}
