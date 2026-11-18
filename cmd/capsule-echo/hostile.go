//go:build linux

package main

import (
	"context"
	"os"
	"runtime"
	"sync"
	"syscall"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnessstore"
)

// The hostile test behaviours push a guest against its VM's ceilings (RUN-007,
// ADR 012). Each is the harness's own act, inside its guest; the KVM tests
// of internal/worker check what the host sees.

// mutation is what the harness does with each event it is delivered, inside
// its store's transaction (referenceharness.Engine.Handle).
type mutation = func(context.Context, harnessstore.Event, harnessstore.SQL) ([]byte, error)

// hostileDelay is how long after its first answer a hostile harness turns:
// long enough for that answer to reach the platform, so that a test knows
// the agent answered before it turned.
const hostileDelay = 2 * time.Second

// forkRetry is how often a refused fork bomb tries again.
const forkRetry = 100 * time.Millisecond

// hostile maps each behaviour that turns after the first answer to what it
// then does, without end, until its context ends.
var hostile = map[string]func(context.Context){
	// Every vCPU of the guest runs flat out.
	"burn-cpu": func(ctx context.Context) { burn(ctx, runtime.NumCPU()) },
	// Memory is taken until the guest's kernel stops the harness.
	"eat-memory": func(ctx context.Context) { _, _ = eatMemory(ctx, 0) },
	// Processes are forked until the guest refuses, and again and again.
	"fork-bomb": func(ctx context.Context) { _ = forkBomb(ctx, forkHolder, forkRetry) },
}

// afterFirstAnswer runs start once, delay after handle first answers without
// error. Answers pass through unchanged.
func afterFirstAnswer(handle mutation, delay time.Duration, start func()) mutation {
	var once sync.Once
	return func(ctx context.Context, e harnessstore.Event, tx harnessstore.SQL) ([]byte, error) {
		result, err := handle(ctx, e, tx)
		if err == nil {
			once.Do(func() { time.AfterFunc(delay, start) })
		}
		return result, err
	}
}

// burn keeps n goroutines busy until ctx ends.
func burn(ctx context.Context, n int) {
	var wg sync.WaitGroup
	for range n {
		wg.Go(func() {
			for i := uint64(1); ; i++ {
				if i%(1<<16) == 0 && ctx.Err() != nil {
					return
				}
			}
		})
	}
	wg.Wait()
}

// eatChunk is how much memory eatMemory maps at a time.
const eatChunk = 1 << 20

// eatMemory maps anonymous memory a chunk at a time, writes every page of it
// so that the kernel must back it, and never gives it back. A refused mapping
// is tried again. With a positive limit (tests), it stops there and returns
// what it holds; otherwise it stops only with ctx, or when the kernel kills
// the process.
func eatMemory(ctx context.Context, limit int64) ([][]byte, error) {
	var held [][]byte
	page := os.Getpagesize()
	for ctx.Err() == nil && (limit <= 0 || int64(len(held))*eatChunk < limit) {
		b, err := syscall.Mmap(-1, 0, eatChunk, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_ANON|syscall.MAP_PRIVATE)
		if err != nil {
			select {
			case <-ctx.Done():
			case <-time.After(10 * time.Millisecond):
			}
			continue
		}
		for i := 0; i < len(b); i += page {
			b[i] = 1
		}
		held = append(held, b)
	}
	return held, nil
}

// forkHolder forks a process that only waits, until it is killed: one more
// task in the harness's cgroup. The child is a copy of this thread alone, so
// it runs no Go code: like the syscall package's own fork, it makes raw
// system calls only, and waits in ppoll(2) without descriptors or timeout.
//
//go:noinline
//go:nosplit
//go:norace
func forkHolder() (int, syscall.Errno) {
	pid, _, errno := syscall.RawSyscall(syscall.SYS_CLONE, uintptr(syscall.SIGCHLD), 0, 0)
	if errno != 0 || pid != 0 {
		return int(pid), errno
	}
	for {
		syscall.RawSyscall6(syscall.SYS_PPOLL, 0, 0, 0, 0, 0, 0)
	}
}

// forkBomb forks as fast as it can until it is refused (EAGAIN or ENOMEM:
// the guest's ceiling), then tries again every retry, until ctx ends. Any
// other error stops it.
func forkBomb(ctx context.Context, fork func() (int, syscall.Errno), retry time.Duration) error {
	for ctx.Err() == nil {
		switch _, errno := fork(); errno {
		case 0:
		case syscall.EAGAIN, syscall.ENOMEM:
			select {
			case <-ctx.Done():
			case <-time.After(retry):
			}
		default:
			return errno
		}
	}
	return nil
}

// neverFiles answers every invocation "working", as a harness that answers
// later, then loops on it and never files its outcome. Other events are
// handled as usual.
func neverFiles(agent string, handle mutation, loop func()) mutation {
	return func(ctx context.Context, e harnessstore.Event, tx harnessstore.SQL) ([]byte, error) {
		if _, err := capsuleprotocol.DecodeInvocation(e, agent); err != nil {
			return handle(ctx, e, tx)
		}
		go loop()
		return capsuleprotocol.WorkingResult(), nil
	}
}
