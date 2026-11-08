//go:build linux

package capsuleprotocol

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"path/filepath"
	"syscall"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnessstore"
)

type localPeerKey struct{}

// NewLocalServer is the harness side of the private capsule-init Unix bridge.
// It accepts requests only through ServeLocal, which derives the peer's UID from
// the kernel. HTTP headers and fake TLS metadata cannot authorize local calls.
func NewLocalServer(id Identity, previous ShutdownState, store *harnessstore.Store, mutate func(context.Context, harnessstore.Event, harnessstore.SQL) ([]byte, error)) (*Server, error) {
	if err := id.Validate(); err != nil {
		return nil, err
	}
	if !previous.Valid() || store == nil || mutate == nil {
		return nil, ErrProtocol
	}
	return &Server{credentials: Credentials{Identity: id}, previousShutdown: previous, store: store, mutate: mutate, slots: make(chan struct{}, 16), localAuth: func(r *http.Request) bool {
		ok, _ := r.Context().Value(localPeerKey{}).(bool)
		return ok
	}}, nil
}

func unixPeer(conn net.Conn, uid uint32) bool {
	c, ok := conn.(*net.UnixConn)
	if !ok {
		return false
	}
	raw, err := c.SyscallConn()
	if err != nil {
		return false
	}
	var credentials *syscall.Ucred
	var readErr error
	if err = raw.Control(func(fd uintptr) {
		credentials, readErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		return false
	}
	return readErr == nil && credentials != nil && credentials.Uid == uid
}

// ServeLocal takes a prebound Unix listener inherited from capsule-init. The
// production supervisor has UID 0, distinct from the unprivileged harness. A
// bounded graceful shutdown drains accepted handlers before the caller closes
// its SQLite store. Cancellation can still abort an uncommitted transaction.
func (s *Server) ServeLocal(ctx context.Context, l *net.UnixListener, supervisorUID uint32) error {
	if s.localAuth == nil || l == nil {
		return ErrProtocol
	}
	return serveLocal(ctx, l, supervisorUID, s)
}

func serveLocal(ctx context.Context, l *net.UnixListener, uid uint32, handler http.Handler) error {
	h := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 20 * time.Second, WriteTimeout: 20 * time.Second,
		IdleTimeout: 5 * time.Second, MaxHeaderBytes: 4096, ErrorLog: log.New(io.Discard, "", 0),
		BaseContext: func(net.Listener) context.Context { return ctx },
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			return context.WithValue(ctx, localPeerKey{}, unixPeer(c, uid))
		},
	}
	drained := make(chan struct{})
	var shutdownErr error // published by closing drained
	stop := context.AfterFunc(ctx, func() {
		defer close(drained)
		deadline, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		shutdownErr = h.Shutdown(deadline)
		if shutdownErr != nil {
			_ = h.Close()
		}
	})
	err := h.Serve(l)
	if !stop() {
		<-drained
	}
	if shutdownErr != nil {
		return errors.Join(ErrQuiesce, shutdownErr)
	}
	if errors.Is(err, http.ErrServerClosed) && ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

// NewLocalClient is only for capsule-init's fixed private Unix destination.
// Authentication is performed by the kernel peer check on the harness side.
func NewLocalClient(id Identity, path string) (*Client, error) {
	if err := id.Validate(); err != nil {
		return nil, err
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, ErrProtocol
	}
	transport := &http.Transport{DisableKeepAlives: true, MaxResponseHeaderBytes: 4096,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", path)
		},
	}
	return &Client{identity: id, serverName: "harness.local", scheme: "http", http: &http.Client{Transport: transport, Timeout: 20 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}, nil
}
