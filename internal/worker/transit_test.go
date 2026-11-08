//go:build linux

package worker

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/operatorconfig"
)

func TestWorkerTransitRequiresExplicitActivationAndOneStoreBinding(t *testing.T) {
	b := newBootLab(t)
	key := filepath.Join(t.TempDir(), "transit.key")
	if err := os.WriteFile(key, bytes.Repeat([]byte{0x43}, 32), 0600); err != nil {
		t.Fatal(err)
	}
	c := ServiceConfig{Transit: &ServiceTransit{ActiveKey: "v1", Keys: operatorconfig.KeyFiles{"v1": key}}}
	tr, err := c.OpenTransit(b.w.store)
	if err != nil {
		t.Fatal(err)
	}
	if err = b.w.EnableTransit(t.Context(), tr); !errors.Is(err, controlplane.ErrTransitKey) {
		t.Fatal("worker implicitly activated keys", err)
	}
	if err = tr.ActivateKeys(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err = b.w.EnableTransit(t.Context(), tr); err != nil {
		t.Fatal(err)
	}
	if err = b.w.EnableTransit(t.Context(), tr); !errors.Is(err, controlplane.ErrConflict) {
		t.Fatal("worker transit replaced", err)
	}
	foreign := &Placements{}
	if err = foreign.EnableTransit(t.Context(), tr); !errors.Is(err, controlplane.ErrInput) {
		t.Fatal("foreign store attachment", err)
	}
	if err = os.WriteFile(key, bytes.Repeat([]byte{0x44}, 32), 0600); err != nil {
		t.Fatal(err)
	}
	wrong, err := c.OpenTransit(b.w.store)
	if err != nil {
		t.Fatal(err)
	}
	if err = wrong.CheckKeys(t.Context()); !errors.Is(err, controlplane.ErrTransitKey) {
		t.Fatal("replacement key accepted", err)
	}
	c.Transit.Keys["v1"] = "relative.key"
	if _, err = c.OpenTransit(b.w.store); !errors.Is(err, operatorconfig.ErrPrivateFile) {
		t.Fatal("relative key path", err)
	}
}
