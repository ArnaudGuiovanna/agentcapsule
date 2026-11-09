//go:build linux

// capsule-adapter runs an unmodified agent program as a capsule.v1 harness: it
// answers each invocation by running the agent's command, and serves the
// agent's OpenAI or Anthropic SDK on the VM's loopback through the platform.
// Its only argument is the configuration file (default /agentcapsule/adapter.json).
package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/agentadapter"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/guestinit"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnessstore"
)

func run() (result error) {
	path := agentadapter.ConfigPath
	switch len(os.Args) {
	case 1:
	case 2:
		path = os.Args[1]
	default:
		return agentadapter.ErrConfig
	}
	cfg, err := agentadapter.LoadConfig(path)
	if err != nil {
		return err
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
	state := filepath.Join(b.DataDirectory, ".agentcapsule")
	if err = os.MkdirAll(state, 0o700); err != nil {
		return err
	}
	store, err := harnessstore.Open(ctx, filepath.Join(state, "adapter.db"))
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, store.Close()) }()
	var platform *capsuleprotocol.PlatformClient
	var engPlatform agentadapter.Platform
	if b.PlatformSocket != "" {
		if platform, err = capsuleprotocol.NewLocalPlatformClient(b.Identity, b.PlatformSocket); err != nil {
			return err
		}
		engPlatform = platform
	}
	engine, err := agentadapter.New(b.Identity.AgentID, b.DataDirectory, store, engPlatform, agentadapter.CommandRunner(cfg, b.DataDirectory))
	if err != nil {
		return err
	}
	s, err := capsuleprotocol.NewLocalServer(b.Identity, b.PreviousShutdown, store, engine.Handle)
	if err != nil {
		return err
	}
	endpoint := &agentadapter.ModelEndpoint{Config: cfg}
	if platform != nil {
		endpoint.Platform = platform
	}
	models, err := net.Listen("tcp", cfg.ModelAddress)
	if err != nil {
		return err
	}
	server := &http.Server{Handler: endpoint, ReadHeaderTimeout: 10 * time.Second}
	served := make(chan error, 1)
	go func() { served <- server.Serve(models) }()
	background := make(chan error, 1)
	go func() {
		background <- engine.Run(ctx)
		cancel()
	}()
	err = s.ServeLocal(ctx, unix, b.SupervisorUID)
	cancel()
	workerErr := <-background // no SQLite close while a job or an answer is active
	shutdown, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	_ = server.Shutdown(shutdown)
	if serveErr := <-served; !errors.Is(serveErr, http.ErrServerClosed) {
		err = errors.Join(err, serveErr)
	}
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
