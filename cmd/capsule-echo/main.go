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
	config := os.NewFile(3, "harness-configuration")
	if config == nil {
		return guestinit.ErrGuest
	}
	b, err := guestinit.ReadHarnessBoot(config)
	config.Close()
	if err != nil {
		return err
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
	s, err := capsuleprotocol.NewLocalServer(b.Identity, b.PreviousShutdown, store, h.Handle)
	if err != nil {
		return err
	}
	background := make(chan error, 1)
	go func() {
		background <- h.Run(ctx)
		cancel()
	}()
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
