//go:build linux

// capsule-echo is the manually packaged reference harness. It owns its SQLite
// effects and deduplication; capsule-init only supervises and relays requests.
package main

import (
	"context"
	"errors"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/guestinit"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnessstore"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/referenceharness"
)

func run() (result error) {
	mode, err := parseBehaviour(os.Args[1:])
	if err != nil {
		return err
	}
	if mode.crashAtBoot {
		return errCrashAtBoot
	}
	config := os.NewFile(3, "harness-configuration")
	if config == nil {
		return guestinit.ErrGuest
	}
	b, err := guestinit.ReadHarnessBoot(config)
	config.Close()
	if err != nil {
		return err
	}
	if mode.fillTmp != 0 && !b.Identity.FenceOnly {
		if err = fillTmp("/tmp", mode.fillTmp); err != nil {
			return err
		}
	}
	f := os.NewFile(4, "harness-control")
	if f == nil {
		return guestinit.ErrGuest
	}
	l, err := net.FileListener(f)
	f.Close()
	if err != nil {
		return err
	}
	defer l.Close()
	unix, ok := l.(*net.UnixListener)
	if !ok {
		return guestinit.ErrGuest
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	store, err := harnessstore.Open(ctx, filepath.Join(b.DataDirectory, "harness.db"))
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, store.Close()) }()
	var platform referenceharness.Platform
	if b.PlatformSocket != "" {
		platform, err = capsuleprotocol.NewLocalPlatformClient(b.Identity, b.PlatformSocket)
		if err != nil {
			return err
		}
	}
	h, err := referenceharness.New(b.Identity.AgentID, store, platform)
	if err != nil {
		return err
	}
	handle := h.Handle
	if mode.neverFiles {
		handle = neverFiles(b.Identity.AgentID, handle, func() { burn(ctx, 1) })
	} else if mode.neverReturns {
		handle = neverReturns(b.Identity.AgentID, handle, ctx)
	} else if act := hostile[mode.hostile]; act != nil {
		handle = afterFirstAnswer(handle, hostileDelay, func() { act(ctx) })
	}
	s, err := capsuleprotocol.NewLocalServer(b.Identity, b.PreviousShutdown, store, handle)
	if err != nil {
		return err
	}
	// The echo keeps JSON parts as they came (ADR 016); text-only plays a
	// harness built before JSON content.
	if !mode.textOnly {
		s.AcceptJSONContent()
	}
	background := make(chan error, 1)
	go func() {
		background <- h.Run(ctx)
		cancel()
	}()
	if mode.floodChunk != 0 && !b.Identity.FenceOnly {
		go func() { _ = flood(ctx, filepath.Join(b.DataDirectory, "flood"), mode.floodChunk) }()
	}
	err = s.ServeLocal(ctx, unix, b.SupervisorUID)
	cancel()
	workerErr := <-background // no SQLite close while an outgoing call is active
	if errors.Is(err, context.Canceled) {
		err = nil
	}
	if errors.Is(workerErr, context.Canceled) {
		workerErr = nil
	}
	return errors.Join(err, workerErr)
}

func main() {
	if run() != nil {
		os.Exit(1)
	}
}
