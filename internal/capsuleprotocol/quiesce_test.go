package capsuleprotocol

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// These tests use real per-boot mTLS and interrupted connections. The shutdown
// callback is controlled, not a claim about real mounts or VMM retirement.
func TestQuiesceDrainsAdmissionBeforePhysicalCallbackAndACK(t *testing.T) {
	h, g := volumeCredentials(t, false)
	entered, release := make(chan struct{}), make(chan struct{})
	closing, closed := make(chan struct{}), make(chan struct{})
	var first atomic.Bool
	first.Store(true)
	next := volumeHarness(t, g)
	s, err := NewQuiescingVolumeServer(g, func(context.Context, VolumeBoot, []byte) (http.Handler, error) {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if first.Swap(false) {
				close(entered)
				<-release
			}
			next.ServeHTTP(w, r)
		}), nil
	}, func(context.Context) error { close(closing); <-closed; return nil })
	if err != nil {
		t.Fatal(err)
	}
	c, _ := volumeFixture(t, h, g, s)
	if err = c.OpenVolume(t.Context(), volumeCommand(false), bytes.Repeat([]byte{3}, 32)); err != nil {
		t.Fatal(err)
	}
	old := make(chan error, 1)
	go func() { old <- c.Health(t.Context()) }()
	<-entered
	done := make(chan error, 1)
	go func() { done <- c.Quiesce(t.Context()) }()
	deadline := time.After(5 * time.Second)
	for {
		s.mu.Lock()
		stopping := s.stopping
		s.mu.Unlock()
		if stopping {
			break
		}
		select {
		case <-deadline:
			t.Fatal("quiesce did not close admission")
		case <-time.After(time.Millisecond):
		}
	}
	if err = c.Health(t.Context()); err == nil {
		t.Fatal("new control request admitted during quiesce")
	}
	if err = c.OpenVolume(t.Context(), volumeCommand(false), bytes.Repeat([]byte{3}, 32)); err == nil {
		t.Fatal("volume reopened while stopping")
	}
	select {
	case <-closing:
		t.Fatal("shutdown began before admitted work drained")
	default:
	}
	select {
	case <-done:
		t.Fatal("ACK preceded physical completion")
	default:
	}
	close(release)
	if err = <-old; err != nil {
		t.Fatal("already admitted request lost", err)
	}
	<-closing
	select {
	case <-done:
		t.Fatal("ACK preceded volume close")
	default:
	}
	close(closed)
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	if err = c.Health(t.Context()); err == nil {
		t.Fatal("successful quiesce reopened admission")
	}
}

func TestQuiesceLostACKConcurrentReplayAndStickyFailure(t *testing.T) {
	for _, fail := range []bool{false, true} {
		name := "clean"
		if fail {
			name = "failed_close"
		}
		t.Run(name, func(t *testing.T) {
			h, g := volumeCredentials(t, true)
			next := volumeHarness(t, g)
			var calls atomic.Int32
			s, err := NewQuiescingVolumeServer(g, func(context.Context, VolumeBoot, []byte) (http.Handler, error) { return next, nil },
				func(context.Context) error {
					calls.Add(1)
					if fail {
						return errors.New("private unmount failure")
					}
					return nil
				})
			if err != nil {
				t.Fatal(err)
			}
			var drop atomic.Bool
			drop.Store(true)
			c, dial := volumeFixture(t, h, g, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/v1/lifecycle/quiesce" && drop.Swap(false) {
					s.ServeHTTP(lostVolumeACK{w}, r)
				} else {
					s.ServeHTTP(w, r)
				}
			}))
			foreign, _ := credentialPair(t, "foreign", "fedcba9876543210")
			bad, err := NewClient(foreign, dial)
			if err != nil {
				t.Fatal(err)
			}
			if err = bad.Quiesce(t.Context()); !errors.Is(err, ErrTransport) {
				t.Fatal("foreign boot stopped guest", err)
			}
			if calls.Load() != 0 {
				t.Fatal("foreign boot reached shutdown")
			}
			if err = c.OpenVolume(t.Context(), volumeCommand(true), bytes.Repeat([]byte{4}, 32)); err != nil {
				t.Fatal(err)
			}
			if err = c.Quiesce(t.Context()); !errors.Is(err, ErrTransport) {
				t.Fatal("lost ACK returned certainty", err)
			}
			results := make(chan error, 8)
			var wg sync.WaitGroup
			for range 8 {
				wg.Add(1)
				go func() { defer wg.Done(); results <- c.Quiesce(t.Context()) }()
			}
			wg.Wait()
			close(results)
			for err := range results {
				if fail && !errors.Is(err, ErrQuiesce) || !fail && err != nil {
					t.Fatal("incorrect shutdown replay", err)
				}
			}
			if calls.Load() != 1 {
				t.Fatal("shutdown repeated", calls.Load())
			}
			c.identity.Generation++
			if err = c.Quiesce(t.Context()); !errors.Is(err, ErrIdentity) {
				t.Fatal("wrong-generation ACK accepted", err)
			}
		})
	}
}

func TestQuiesceWaitsForOpeningAndSurvivesClientCancellation(t *testing.T) {
	h, g := volumeCredentials(t, true)
	next := volumeHarness(t, g)
	opening, opened := make(chan struct{}), make(chan struct{})
	closing, closed := make(chan struct{}), make(chan struct{})
	s, err := NewQuiescingVolumeServer(g, func(context.Context, VolumeBoot, []byte) (http.Handler, error) {
		close(opening)
		<-opened
		return next, nil
	}, func(context.Context) error { close(closing); <-closed; return nil })
	if err != nil {
		t.Fatal(err)
	}
	c, _ := volumeFixture(t, h, g, s)
	boot := make(chan error, 1)
	go func() { boot <- c.OpenVolume(t.Context(), volumeCommand(true), bytes.Repeat([]byte{5}, 32)) }()
	<-opening
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	err = c.Quiesce(ctx)
	cancel()
	if !errors.Is(err, ErrTransport) {
		t.Fatal("uncompleted shutdown reported clean", err)
	}
	select {
	case <-closing:
		t.Fatal("unmount raced preparation")
	default:
	}
	close(opened)
	if err = <-boot; !errors.Is(err, ErrVolumeBoot) {
		t.Fatal("stopping bootstrap advertised readiness", err)
	}
	<-closing
	close(closed)
	if err = c.Quiesce(t.Context()); err != nil {
		t.Fatal("lost caller canceled durable shutdown", err)
	}
}

func TestQuiesceRejectsUnauthenticatedMalformedAndUnopenedBoots(t *testing.T) {
	h, g := volumeCredentials(t, false)
	var calls atomic.Int32
	s, err := NewQuiescingVolumeServer(g, func(context.Context, VolumeBoot, []byte) (http.Handler, error) { return volumeHarness(t, g), nil },
		func(context.Context) error { calls.Add(1); return nil })
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/v1/lifecycle/quiesce", nil))
	if w.Code != http.StatusUnauthorized {
		t.Fatal("missing authentication accepted")
	}
	c, _ := volumeFixture(t, h, g, s)
	r, err := http.NewRequestWithContext(t.Context(), http.MethodPost, c.endpoint("/v1/lifecycle/quiesce?force=true"), nil)
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("X-Capsule-Protocol", Version)
	resp, err := c.http.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatal("malformed lifecycle command accepted")
	}
	if err = c.Quiesce(t.Context()); !errors.Is(err, ErrQuiesce) {
		t.Fatal("unopened boot claimed clean close", err)
	}
	if calls.Load() != 0 {
		t.Fatal("unopened guest reached shutdown callback")
	}
}
