//go:build linux

package capsuleprotocol

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnessstore"
)

func TestLocalHarnessAuthenticatesKernelPeerAndKeepsFences(t *testing.T) {
	_, g := credentialPair(t, "a", "0123456789abcdef")
	for _, allowed := range []bool{true, false} {
		name := "allowed"
		if !allowed {
			name = "wrong_uid"
		}
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, "control.sock")
			store, err := harnessstore.Open(t.Context(), filepath.Join(root, "state.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			s, err := NewLocalServer(g.Identity, ShutdownClean, store, func(context.Context, harnessstore.Event, harnessstore.SQL) ([]byte, error) {
				return []byte("durable"), nil
			})
			if err != nil {
				t.Fatal(err)
			}
			l, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
			if err != nil {
				t.Fatal(err)
			}
			uid := uint32(os.Geteuid())
			if !allowed {
				uid++
			}
			ctx, cancel := context.WithCancel(t.Context())
			done := make(chan error, 1)
			go func() { done <- s.ServeLocal(ctx, l, uid) }()
			defer func() { cancel(); <-done }()
			c, err := NewLocalClient(g.Identity, path)
			if err != nil {
				t.Fatal(err)
			}
			err = c.Health(t.Context())
			capabilities, negotiationErr := c.Negotiate(t.Context(), []string{Version})
			if !allowed {
				if !errors.Is(err, ErrTransport) || !errors.Is(negotiationErr, ErrTransport) {
					t.Fatal("foreign local UID admitted", err, negotiationErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if negotiationErr != nil || capabilities.Identity != g.Identity || !capabilities.Supports(ControlEvents) {
				t.Fatal("Unix bridge did not negotiate current control contract", capabilities, negotiationErr)
			}
			r, err := c.Send(t.Context(), event("local"))
			if err != nil || r.Replayed || string(r.Result) != "durable" {
				t.Fatal("local effect", err)
			}
			r, err = c.Send(t.Context(), event("local"))
			if err != nil || !r.Replayed {
				t.Fatal("local deduplication", err)
			}
			if err = c.Fence(t.Context(), "request/r"); err != nil {
				t.Fatal(err)
			}
			if _, err = c.Send(t.Context(), event("local")); !errors.Is(err, harnessstore.ErrFenced) {
				t.Fatal("local fenced replay", err)
			}
			// Calling the handler directly cannot synthesize kernel provenance.
			w := httptest.NewRecorder()
			rHTTP := httptest.NewRequest(http.MethodGet, "http://local/v1/health", nil)
			rHTTP.Header.Set("X-UID", "0")
			s.ServeHTTP(w, rHTTP)
			if w.Code != http.StatusUnauthorized {
				t.Fatal("HTTP header supplied local authority")
			}
		})
	}
}

func TestLocalShutdownTimeoutCannotReportCleanExit(t *testing.T) {
	_, g := credentialPair(t, "a", "0123456789abcdef")
	root := t.TempDir()
	store, err := harnessstore.Open(t.Context(), filepath.Join(root, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	entered, release := make(chan struct{}), make(chan struct{})
	s, err := NewLocalServer(g.Identity, ShutdownClean, store, func(context.Context, harnessstore.Event, harnessstore.SQL) ([]byte, error) {
		close(entered)
		<-release
		return []byte("late"), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "control.sock")
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.ServeLocal(ctx, l, uint32(os.Geteuid())) }()
	c, err := NewLocalClient(g.Identity, path)
	if err != nil {
		t.Fatal(err)
	}
	requestDone := make(chan error, 1)
	go func() { _, err := c.Send(t.Context(), event("blocked")); requestDone <- err }()
	<-entered
	cancel()
	select {
	case err = <-done:
	case <-time.After(8 * time.Second):
		t.Fatal("local shutdown exceeded its bound")
	}
	close(release)
	<-requestDone
	if !errors.Is(err, ErrQuiesce) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("timed-out shutdown concealed as cancellation", err)
	}
}
