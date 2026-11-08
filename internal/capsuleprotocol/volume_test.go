package capsuleprotocol

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnessstore"
)

func volumeCommand(initial bool) VolumeBoot {
	return VolumeBoot{Incarnation: 1, VolumeID: "vol_" + strings.Repeat("b", 32), UUID: "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", Initialize: initial, PreviousShutdown: ShutdownClean}
}

func volumeCredentials(t *testing.T, restricted bool) (Credentials, Credentials) {
	t.Helper()
	h, g, err := NewCredentials(Identity{Incarnation: 1, AgentID: "agt_" + strings.Repeat("a", 32), VMID: "0123456789abcdef", Generation: 1, FenceOnly: restricted}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return h, g
}

func volumeHarness(t *testing.T, g Credentials) http.Handler {
	t.Helper()
	store, err := harnessstore.Open(t.Context(), filepath.Join(t.TempDir(), "harness.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	h, err := NewServer(g, ShutdownClean, store, func(context.Context, harnessstore.Event, harnessstore.SQL) ([]byte, error) { return []byte("ok"), nil })
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func volumeFixture(t *testing.T, h, g Credentials, handler http.Handler) (*Client, func(context.Context) (net.Conn, error)) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- ServeAuthenticated(ctx, l, g, handler) }()
	t.Cleanup(func() { cancel(); <-done })
	dial := func(ctx context.Context) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", l.Addr().String())
	}
	c, err := NewClient(h, dial)
	if err != nil {
		t.Fatal(err)
	}
	return c, dial
}

// Interrupt the authenticated response after prepare succeeded, before the
// client can observe its ACK. No real volume mount is claimed by these tests.
type lostVolumeACK struct{ http.ResponseWriter }

func (w lostVolumeACK) WriteHeader(int) {
	conn, _, err := w.ResponseWriter.(http.Hijacker).Hijack()
	if err == nil {
		_ = conn.Close()
	}
}
func (w lostVolumeACK) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestVolumeBootstrapLostACKAndImmutableReplay(t *testing.T) {
	h, g := volumeCredentials(t, true)
	next := volumeHarness(t, g)
	key := bytes.Repeat([]byte{0x83}, 32)
	want := sha256.Sum256(key)
	var calls atomic.Int32
	var borrowed []byte
	s, err := NewVolumeServer(g, func(_ context.Context, v VolumeBoot, k []byte) (http.Handler, error) {
		calls.Add(1)
		if v != volumeCommand(true) || sha256.Sum256(k) != want {
			return nil, errors.New("wrong opening binding")
		}
		borrowed = k
		return next, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	var drop atomic.Bool
	drop.Store(true)
	c, _ := volumeFixture(t, h, g, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/volume" && drop.Swap(false) {
			s.ServeHTTP(lostVolumeACK{w}, r)
		} else {
			s.ServeHTTP(w, r)
		}
	}))
	if err = c.Health(t.Context()); !errors.Is(err, ErrTransport) {
		t.Fatal("unopened volume advertised readiness", err)
	}
	if err = c.Fence(t.Context(), "agent/old"); !errors.Is(err, ErrTransport) {
		t.Fatal("barrier accepted before volume readiness", err)
	}
	if err = c.OpenVolume(t.Context(), volumeCommand(true), key); !errors.Is(err, ErrTransport) {
		t.Fatal("lost ACK returned success", err)
	}
	if err = c.OpenVolume(t.Context(), volumeCommand(true), key); err != nil {
		t.Fatal("identical retry cannot recover ACK", err)
	}
	if calls.Load() != 1 {
		t.Fatal("ACK retry opened volume again")
	}
	if !bytes.Equal(borrowed, make([]byte, 32)) {
		t.Fatal("guest retained borrowed secret")
	}
	if sha256.Sum256(key) != want {
		t.Fatal("client changed caller's secret buffer")
	}
	if err = c.Health(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err = c.Fence(t.Context(), "agent/old"); err != nil {
		t.Fatal(err)
	}
	wrong := append([]byte(nil), key...)
	wrong[0] ^= 1
	if err = c.OpenVolume(t.Context(), volumeCommand(true), wrong); !errors.Is(err, ErrVolumeBoot) {
		t.Fatal("changed key accepted on initialized boot", err)
	}
	other := VolumeBoot{Incarnation: 1, VolumeID: "vol_" + strings.Repeat("c", 32), UUID: "cccccccc-cccc-cccc-cccc-cccccccccccc", Initialize: true, PreviousShutdown: ShutdownClean}
	if err = c.OpenVolume(t.Context(), other, key); !errors.Is(err, ErrVolumeBoot) {
		t.Fatal("boot rebound to another volume", err)
	}
	if calls.Load() != 1 {
		t.Fatal("changed retry reached physical opener")
	}
	contradictory := volumeCommand(true)
	contradictory.PreviousShutdown = ShutdownUnclean
	if err = c.OpenVolume(t.Context(), contradictory, key); !errors.Is(err, ErrVolumeBoot) {
		t.Fatal("same boot changed previous shutdown on replay", err)
	}
	if calls.Load() != 1 {
		t.Fatal("contradictory replay prepared the volume twice")
	}
}

func TestVolumeBootstrapConcurrentCallsAndFailure(t *testing.T) {
	for _, fail := range []bool{false, true} {
		name := "success"
		if fail {
			name = "failure"
		}
		t.Run(name, func(t *testing.T) {
			h, g := volumeCredentials(t, true)
			next := volumeHarness(t, g)
			entered, release := make(chan struct{}), make(chan struct{})
			var calls atomic.Int32
			s, err := NewVolumeServer(g, func(ctx context.Context, _ VolumeBoot, _ []byte) (http.Handler, error) {
				calls.Add(1)
				close(entered)
				select {
				case <-release:
				case <-ctx.Done():
					return nil, ctx.Err()
				}
				if fail {
					return nil, errors.New("private mount diagnostic with sensitive data")
				}
				return next, nil
			})
			if err != nil {
				t.Fatal(err)
			}
			c, _ := volumeFixture(t, h, g, s)
			key := bytes.Repeat([]byte{0x42}, 32)
			done := make(chan error, 1)
			go func() { done <- c.OpenVolume(t.Context(), volumeCommand(true), key) }()
			<-entered
			busy := c.OpenVolume(t.Context(), volumeCommand(true), key)
			health := c.Health(t.Context())
			close(release)
			opened := <-done
			if !errors.Is(busy, ErrVolumeBoot) || !errors.Is(health, ErrTransport) {
				t.Fatal("concurrent boot exposed partial readiness", busy, health)
			}
			if fail {
				if !errors.Is(opened, ErrVolumeBoot) {
					t.Fatal("failed opener returned success", opened)
				}
				if err = c.OpenVolume(t.Context(), volumeCommand(true), key); !errors.Is(err, ErrVolumeBoot) {
					t.Fatal("failed partial boot retried physical opening", err)
				}
				if err = c.Health(t.Context()); !errors.Is(err, ErrTransport) {
					t.Fatal("failed volume ready", err)
				}
			} else if opened != nil {
				t.Fatal(opened)
			}
			if calls.Load() != 1 {
				t.Fatal("concurrent or failed requests repeated physical preparation")
			}
		})
	}
}

func TestVolumeBootstrapRefusesForeignBootAndOrdinaryFormat(t *testing.T) {
	h, g := volumeCredentials(t, false)
	next := volumeHarness(t, g)
	var calls atomic.Int32
	s, err := NewVolumeServer(g, func(context.Context, VolumeBoot, []byte) (http.Handler, error) { calls.Add(1); return next, nil })
	if err != nil {
		t.Fatal(err)
	}
	c, dial := volumeFixture(t, h, g, s)
	key := bytes.Repeat([]byte{0x42}, 32)
	foreign, _ := credentialPair(t, "other-agent", "fedcba9876543210")
	bad, err := NewClient(foreign, dial)
	if err != nil {
		t.Fatal(err)
	}
	if err = bad.OpenVolume(t.Context(), volumeCommand(false), key); !errors.Is(err, ErrTransport) {
		t.Fatal("foreign boot authenticated", err)
	}
	if err = c.OpenVolume(t.Context(), volumeCommand(true), key); !errors.Is(err, ErrFenceOnly) {
		t.Fatal("ordinary client requested format", err)
	}
	// Bypass the client's convenience check: the guest must enforce its own
	// certificate-bound boot purpose independently of request headers.
	c.identity.FenceOnly = true
	if err = c.OpenVolume(t.Context(), volumeCommand(true), key); err == nil {
		t.Fatal("server accepted ordinary format")
	}
	c.identity.FenceOnly = false
	if calls.Load() != 0 {
		t.Fatal("unauthorized command reached physical opener")
	}
	if err = c.OpenVolume(t.Context(), volumeCommand(false), key); err != nil {
		t.Fatal("ordinary boot cannot open existing volume", err)
	}
	if calls.Load() != 1 {
		t.Fatal("ordinary opening missing")
	}
}

func TestVolumeMalformedIncarnationOnWire(t *testing.T) {
	for _, header := range []string{"", "0", "not-an-integer", "9223372036854775808"} {
		t.Run(header, func(t *testing.T) {
			// At the largest valid incarnation, an overflowing wire integer must
			// not be silently clamped into an otherwise matching identity.
			id := Identity{Incarnation: 1<<63 - 1, AgentID: "a", Generation: 1, VMID: "0123456789abcdef", FenceOnly: true}
			h, g, err := NewCredentials(id, time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			var calls atomic.Int32
			s, err := NewVolumeServer(g, func(context.Context, VolumeBoot, []byte) (http.Handler, error) {
				calls.Add(1)
				return volumeHarness(t, g), nil
			})
			if err != nil {
				t.Fatal(err)
			}
			c, _ := volumeFixture(t, h, g, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				r.Header.Set("X-Capsule-Incarnation", header)
				s.ServeHTTP(w, r)
			}))
			v := volumeCommand(true)
			v.Incarnation = id.Incarnation
			if err = c.OpenVolume(t.Context(), v, make([]byte, 32)); !errors.Is(err, ErrVolumeBoot) {
				t.Fatal("malformed incarnation accepted", err)
			}
			if calls.Load() != 0 {
				t.Fatal("malformed header reached volume opener")
			}
			header = "9223372036854775807"
			if err = c.OpenVolume(t.Context(), v, make([]byte, 32)); err != nil {
				t.Fatal("largest valid incarnation refused", err)
			}
		})
	}
}

func TestVolumeIncarnationIsEnforcedByGuest(t *testing.T) {
	h, g := volumeCredentials(t, true)
	var calls atomic.Int32
	s, err := NewVolumeServer(g, func(context.Context, VolumeBoot, []byte) (http.Handler, error) {
		calls.Add(1)
		return volumeHarness(t, g), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	c, _ := volumeFixture(t, h, g, s)
	v := volumeCommand(true)
	v.Incarnation++
	if err = c.OpenVolume(t.Context(), v, bytes.Repeat([]byte{0x42}, 32)); !errors.Is(err, ErrProtocol) {
		t.Fatal("client allowed wrong incarnation", err)
	}
	// Bypass convenience validation while retaining the original TLS identity.
	c.identity.Incarnation = v.Incarnation
	if err = c.OpenVolume(t.Context(), v, bytes.Repeat([]byte{0x42}, 32)); err == nil {
		t.Fatal("guest accepted foreign incarnation")
	}
	if calls.Load() != 0 {
		t.Fatal("wrong incarnation reached physical opener")
	}
	c.identity = h.Identity
	if err = c.OpenVolume(t.Context(), volumeCommand(true), bytes.Repeat([]byte{0x42}, 32)); err != nil {
		t.Fatal("current incarnation refused", err)
	}
}

func TestVolumeShutdownWaitsForPreparationAndClosesAdmission(t *testing.T) {
	h, g := volumeCredentials(t, true)
	next := volumeHarness(t, g)
	entered, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	s, err := NewVolumeServer(g, func(context.Context, VolumeBoot, []byte) (http.Handler, error) {
		calls.Add(1)
		close(entered)
		<-release
		return next, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	c, _ := volumeFixture(t, h, g, s)
	key := bytes.Repeat([]byte{0x42}, 32)
	done := make(chan error, 1)
	go func() { done <- c.OpenVolume(t.Context(), volumeCommand(true), key) }()
	<-entered
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
	err = s.StopPreparation(ctx)
	cancel()
	close(release)
	opened := <-done
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("shutdown did not wait for physical preparation", err)
	}
	if !errors.Is(opened, ErrVolumeBoot) {
		t.Fatal("stopping boot advertised readiness", opened)
	}
	if err = s.StopPreparation(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err = c.Health(t.Context()); !errors.Is(err, ErrTransport) {
		t.Fatal("stopped preparation has ordinary health", err)
	}
	if err = c.OpenVolume(t.Context(), volumeCommand(true), key); !errors.Is(err, ErrVolumeBoot) {
		t.Fatal("shutdown admitted another opening", err)
	}
	if calls.Load() != 1 {
		t.Fatal("preparation repeated during shutdown")
	}
}
