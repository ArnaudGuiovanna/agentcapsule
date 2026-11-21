//go:build linux

package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/agentadapter"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/guestinit"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnessstore"
)

func run() error {
	config := os.NewFile(3, "harness-configuration")
	boot, err := guestinit.ReadHarnessBoot(config)
	config.Close()
	if err != nil {
		return err
	}
	fd := os.NewFile(4, "harness-control")
	listener, err := net.FileListener(fd)
	fd.Close()
	if err != nil {
		return err
	}
	defer listener.Close()
	unix, ok := listener.(*net.UnixListener)
	if !ok {
		return guestinit.ErrGuest
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	store, err := harnessstore.Open(ctx, filepath.Join(boot.DataDirectory, "course-enricher.db"))
	if err != nil {
		return err
	}
	defer store.Close()
	var platform agentadapter.Platform
	if boot.PlatformSocket != "" {
		p, err := capsuleprotocol.NewLocalPlatformClient(boot.Identity, boot.PlatformSocket)
		if err != nil {
			return err
		}
		platform = p
	}
	engine, err := agentadapter.New(boot.Identity.AgentID, boot.DataDirectory, store, platform, func(ctx context.Context, j agentadapter.Job) agentadapter.Output {
		if len(j.Content) != 1 || j.Content[0].Type != "json" {
			return agentadapter.Output{}
		}
		reply, err := enrich(ctx, []byte(j.Content[0].JSON), "/corpus/base", "/dev/corpus/output", boot.DataDirectory)
		if err != nil {
			return agentadapter.Output{}
		}
		data, err := json.Marshal(reply)
		if err != nil {
			return agentadapter.Output{}
		}
		return agentadapter.Output{Completed: true, Content: []capsuleprotocol.ContentPart{{Type: "json", JSON: capsuleprotocol.JSONValue(data)}}}
	})
	if err != nil {
		return err
	}
	srv, err := capsuleprotocol.NewLocalServer(boot.Identity, boot.PreviousShutdown, store, engine.Handle)
	if err != nil {
		return err
	}
	srv.AcceptJSONContent()
	done := make(chan error, 1)
	go func() { done <- engine.Run(ctx); cancel() }()
	err = srv.ServeLocal(ctx, unix, boot.SupervisorUID)
	cancel()
	background := <-done
	if errors.Is(err, context.Canceled) {
		err = nil
	}
	if errors.Is(background, context.Canceled) {
		background = nil
	}
	return errors.Join(err, background)
}
func main() {
	if run() != nil {
		os.Exit(1)
	}
}
