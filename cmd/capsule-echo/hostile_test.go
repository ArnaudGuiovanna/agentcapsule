//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnessstore"
)

// Every hostile behaviour parses to itself, and each of its acts ends with
// its context: a harness stopped by its supervisor stops pushing.
func TestHostileActsStopWithTheirContext(t *testing.T) {
	if len(hostile) != 3 {
		t.Fatal("hostile behaviours", len(hostile))
	}
	for name, act := range hostile {
		if got, err := parseBehaviour([]string{name}); err != nil || got != (behaviour{hostile: name}) {
			t.Error(name, got, err)
		}
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		done := make(chan struct{})
		go func() { act(ctx); close(done) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal(name, "did not stop with its context")
		}
	}
	if children := childProcesses(t); len(children) != 0 {
		t.Fatal("a stopped fork bomb forked", children)
	}
}

// A hostile behaviour starts once, after the harness's first answer and its
// delay: the answer reaches the platform before the harness turns. Answers
// pass through unchanged, and a failed one does not count.
func TestHostileBehavioursStartAfterTheFirstAnswer(t *testing.T) {
	var started atomic.Int32
	turned := make(chan time.Time, 4)
	fail := true
	handle := afterFirstAnswer(func(context.Context, harnessstore.Event, harnessstore.SQL) ([]byte, error) {
		if fail {
			return nil, errors.New("refused")
		}
		return []byte(`{"echo":"x"}`), nil
	}, 200*time.Millisecond, func() { started.Add(1); turned <- time.Now() })
	if _, err := handle(t.Context(), harnessstore.Event{}, nil); err == nil {
		t.Fatal("the error did not pass through")
	}
	time.Sleep(300 * time.Millisecond)
	if started.Load() != 0 {
		t.Fatal("a failed answer turned the harness")
	}
	fail = false
	answered := time.Now()
	for range 3 {
		if result, err := handle(t.Context(), harnessstore.Event{}, nil); err != nil || string(result) != `{"echo":"x"}` {
			t.Fatal("answer", string(result), err)
		}
	}
	select {
	case at := <-turned:
		if at.Sub(answered) < 200*time.Millisecond {
			t.Fatal("turned before its delay", at.Sub(answered))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("never turned")
	}
	time.Sleep(400 * time.Millisecond)
	if n := started.Load(); n != 1 {
		t.Fatal("turned", n, "times")
	}
}

// burn keeps its goroutines running until its context ends: two of them for
// 300 ms use far more than 150 ms of CPU.
func TestBurnKeepsItsGoroutinesBusy(t *testing.T) {
	before := cpuTime(t)
	ctx, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
	defer cancel()
	done := make(chan struct{})
	go func() { burn(ctx, 2); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("burn did not stop with its context")
	}
	if used := cpuTime(t) - before; used < 150*time.Millisecond {
		t.Fatal("two burning goroutines used", used, "of CPU in 300 ms")
	}
}

// eatMemory maps its memory a chunk at a time and writes every page of it, so
// that each page is really the process's; it keeps every chunk.
func TestEatMemoryWritesEveryPage(t *testing.T) {
	held, err := eatMemory(t.Context(), 16<<20)
	defer func() {
		for _, b := range held {
			_ = syscall.Munmap(b)
		}
	}()
	if err != nil || len(held) != 16 {
		t.Fatal("chunks held", len(held), err)
	}
	page := os.Getpagesize()
	for _, b := range held {
		if len(b) != eatChunk {
			t.Fatal("chunk of", len(b))
		}
		for i := 0; i < len(b); i += page {
			if b[i] == 0 {
				t.Fatal("a page was not written", i)
			}
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if more, err := eatMemory(ctx, 0); len(more) != 0 || err != nil {
		t.Fatal("ate after its context ended", len(more), err)
	}
}

// forkHolder forks a process that waits, doing nothing, until it is killed:
// a child of this process, asleep.
func TestForkHolderWaitsUntilKilled(t *testing.T) {
	pid, errno := forkHolder()
	if errno != 0 || pid <= 0 {
		t.Fatal("fork", pid, errno)
	}
	reaped := false
	t.Cleanup(func() {
		if !reaped {
			_ = syscall.Kill(pid, syscall.SIGKILL)
			var ws syscall.WaitStatus
			_, _ = syscall.Wait4(pid, &ws, 0, nil)
		}
	})
	state, ppid := "", 0
	for deadline := time.Now().Add(5 * time.Second); state != "S"; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the holder never waits", state)
		}
		state, ppid = procState(t, pid)
	}
	if ppid != os.Getpid() {
		t.Fatal("the holder is not this process's child", ppid)
	}
	time.Sleep(100 * time.Millisecond)
	if state, _ = procState(t, pid); state != "S" {
		t.Fatal("the holder woke", state)
	}
	if err := syscall.Kill(pid, syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	var ws syscall.WaitStatus
	if got, err := syscall.Wait4(pid, &ws, 0, nil); err != nil || got != pid || !ws.Signaled() || ws.Signal() != syscall.SIGKILL {
		t.Fatal("holder end", got, ws, err)
	}
	reaped = true
}

// forkBomb forks as fast as it can until refused, then keeps trying every
// retry, until its context ends; an error other than a refusal stops it.
func TestForkBombKeepsTryingWhenRefused(t *testing.T) {
	var calls atomic.Int32
	fork := func() (int, syscall.Errno) {
		switch n := calls.Add(1); {
		case n <= 5:
			return 1000 + int(n), 0
		case n%2 == 0:
			return 0, syscall.EAGAIN
		default:
			return 0, syscall.ENOMEM
		}
	}
	ctx, cancel := context.WithTimeout(t.Context(), 500*time.Millisecond)
	defer cancel()
	if err := forkBomb(ctx, fork, 50*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	// 5 forks, then one refusal every 50 ms or so: about 10 in 500 ms.
	if n := calls.Load(); n < 8 || n > 20 {
		t.Fatal("fork calls", n)
	}
	calls.Store(0)
	refused := func() (int, syscall.Errno) { calls.Add(1); return 0, syscall.EPERM }
	if err := forkBomb(t.Context(), refused, time.Millisecond); !errors.Is(err, syscall.EPERM) || calls.Load() != 1 {
		t.Fatal("an unexpected error", err, calls.Load())
	}
}

// never-files answers every invocation "working" and loops on it, without
// handling it; any other event is handled as usual.
func TestNeverFilesAnswersWorkingAndLoops(t *testing.T) {
	const agent = "agt_hostile"
	body, err := json.Marshal(capsuleprotocol.Invocation{Kind: "message.user", OperationID: "op_one",
		Mandate: capsuleprotocol.InstructionMandate{ID: "mdt_one", MaxAgentRequests: 1, ExpiresAt: time.Now().Add(time.Hour)},
		Content: []capsuleprotocol.TextContent{{Type: "text", Text: "work forever"}}})
	if err != nil {
		t.Fatal(err)
	}
	invocation := harnessstore.Event{ID: "evt_one", Subjects: []string{"agent/" + agent, "event/evt_one"}, Body: body}
	message := harnessstore.Event{ID: "evt_two", Subjects: []string{"agent/" + agent}, Body: []byte("a message")}
	var handled []string
	looping := make(chan struct{}, 4)
	handle := neverFiles(agent, func(_ context.Context, e harnessstore.Event, _ harnessstore.SQL) ([]byte, error) {
		handled = append(handled, e.ID)
		return []byte(`{"echo":"x"}`), nil
	}, func() { looping <- struct{}{} })
	result, err := handle(t.Context(), invocation, nil)
	if err != nil || !capsuleprotocol.IsWorkingResult(result) {
		t.Fatal("the invocation's answer", string(result), err)
	}
	select {
	case <-looping:
	case <-time.After(5 * time.Second):
		t.Fatal("no loop on the invocation")
	}
	if result, err = handle(t.Context(), message, nil); err != nil || !bytes.Equal(result, []byte(`{"echo":"x"}`)) {
		t.Fatal("the message's answer", string(result), err)
	}
	if len(handled) != 1 || handled[0] != "evt_two" {
		t.Fatal("handled", handled)
	}
	select {
	case <-looping:
		t.Fatal("a loop for a message")
	case <-time.After(100 * time.Millisecond):
	}
}

// cpuTime is the CPU this process used, user and system.
func cpuTime(t *testing.T) time.Duration {
	t.Helper()
	var u syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &u); err != nil {
		t.Fatal(err)
	}
	return time.Duration(u.Utime.Nano() + u.Stime.Nano())
}

// procState reads a process's state letter and parent from /proc/<pid>/stat.
func procState(t *testing.T, pid int) (string, int) {
	t.Helper()
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		t.Fatal(err)
	}
	i := strings.LastIndex(string(raw), ")")
	f := strings.Fields(string(raw[i+1:]))
	if i < 0 || len(f) < 2 {
		t.Fatal("stat", string(raw))
	}
	var ppid int
	if _, err = fmt.Sscan(f[1], &ppid); err != nil {
		t.Fatal(err)
	}
	return f[0], ppid
}

// childProcesses lists the children of every thread of this process.
func childProcesses(t *testing.T) []string {
	t.Helper()
	tasks, err := os.ReadDir("/proc/self/task")
	if err != nil {
		t.Fatal(err)
	}
	var children []string
	for _, task := range tasks {
		raw, err := os.ReadFile("/proc/self/task/" + task.Name() + "/children")
		if err != nil {
			continue // the thread ended meanwhile
		}
		children = append(children, strings.Fields(string(raw))...)
	}
	return children
}
