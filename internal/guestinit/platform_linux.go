//go:build linux

package guestinit

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"syscall"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
)

type platformBridge struct {
	cancel context.CancelFunc
	done   chan struct{}
	err    error // published by closing done
}

func startPlatformBridge(ctx context.Context, opts ProcessOptions) (*platformBridge, error) {
	if opts.Platform == nil && opts.Boot.PlatformSocket == "" {
		return nil, nil
	}
	if opts.Platform == nil || opts.Boot.PlatformSocket == "" || opts.Platform.Identity() != opts.Boot.Identity || opts.Boot.PlatformSocket == opts.SocketPath {
		return nil, ErrGuest
	}
	// The harness may connect, but cannot replace/unlink the listening socket.
	// The parent directory is created by capsule-init, never by untrusted input.
	parent, err := os.Lstat(filepath.Dir(opts.Boot.PlatformSocket))
	if err != nil {
		return nil, err
	}
	if !parent.IsDir() || parent.Mode().Perm()&0022 != 0 || parent.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) {
		return nil, ErrGuest
	}
	s, err := capsuleprotocol.NewLocalPlatformServer(opts.Platform)
	if err != nil {
		return nil, err
	}
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: opts.Boot.PlatformSocket, Net: "unix"})
	if err != nil {
		return nil, err
	}
	// net.ListenUnix removes only this listener's path on Close. Never unlink an
	// existing path to make startup succeed: it may belong to a live supervisor.
	if err = os.Chown(opts.Boot.PlatformSocket, int(opts.UID), int(opts.GID)); err == nil {
		err = os.Chmod(opts.Boot.PlatformSocket, 0600)
	}
	if err != nil {
		l.Close()
		return nil, err
	}
	lifetime, cancel := context.WithCancel(ctx)
	b := &platformBridge{cancel: cancel, done: make(chan struct{})}
	go func() { defer close(b.done); defer l.Close(); b.err = s.Serve(lifetime, l, opts.UID) }()
	return b, nil
}

func (b *platformBridge) close() error {
	if b == nil {
		return nil
	}
	b.cancel()
	<-b.done
	if errors.Is(b.err, context.Canceled) {
		return nil
	}
	return b.err
}
