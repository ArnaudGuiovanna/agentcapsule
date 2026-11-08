package capsuleprotocol

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnessstore"
)

func TestHealthRequiresExplicitShutdownObservation(t *testing.T) {
	for _, previous := range []ShutdownState{ShutdownClean, ShutdownUnclean, "", "unknown"} {
		name := string(previous)
		if name == "" {
			name = "missing"
		}
		t.Run(name, func(t *testing.T) {
			h, g := volumeCredentials(t, false)
			c, _ := volumeFixture(t, h, g, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_ = json.NewEncoder(w).Encode(response{Protocol: Version, Identity: g.Identity, PreviousShutdown: previous})
			}))
			health, err := c.HealthStatus(t.Context())
			if previous.Valid() {
				if err != nil || health.PreviousShutdown != previous || health.Identity != h.Identity || health.Protocol != Version {
					t.Fatal(health, err)
				}
			} else if !errors.Is(err, ErrProtocol) {
				t.Fatal("invalid shutdown observation accepted as healthy", health, err)
			}
			if err := c.Health(t.Context()); (err == nil) != previous.Valid() {
				t.Fatal("readiness bypassed shutdown observation validation", err)
			}
		})
	}
}

func TestControlServerRejectsMissingShutdownObservation(t *testing.T) {
	_, g := volumeCredentials(t, false)
	store, err := harnessstore.Open(t.Context(), filepath.Join(t.TempDir(), "harness.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	handler := func(context.Context, harnessstore.Event, harnessstore.SQL) ([]byte, error) { return nil, nil }
	if _, err := NewServer(g, "", store, handler); !errors.Is(err, ErrProtocol) {
		t.Fatal("server silently invented clean shutdown", err)
	}
}

func TestVolumeBootstrapRejectsMissingShutdownOnWire(t *testing.T) {
	for _, header := range []string{"", "unknown"} {
		name := header
		if name == "" {
			name = "missing"
		}
		t.Run(name, func(t *testing.T) {
			h, g := volumeCredentials(t, true)
			s, err := NewVolumeServer(g, func(context.Context, VolumeBoot, []byte) (http.Handler, error) {
				t.Error("invalid shutdown observation reached physical preparation")
				return nil, ErrVolumeBoot
			})
			if err != nil {
				t.Fatal(err)
			}
			c, _ := volumeFixture(t, h, g, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				r.Header.Set("X-Capsule-Previous-Shutdown", header)
				s.ServeHTTP(w, r)
			}))
			if err := c.OpenVolume(t.Context(), volumeCommand(true), make([]byte, 32)); !errors.Is(err, ErrVolumeBoot) {
				t.Fatal("malformed metadata accepted by guest", err)
			}
			if err := c.Health(t.Context()); !errors.Is(err, ErrTransport) {
				t.Fatal("unprepared guest reported ready", err)
			}
		})
	}
}
