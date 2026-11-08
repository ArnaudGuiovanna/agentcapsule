//go:build linux

package worker

import (
	"context"
	"path/filepath"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/operatorconfig"
)

type ServiceTransit struct {
	ActiveKey string                  `json:"active_key"`
	Keys      operatorconfig.KeyFiles `json:"keys"`
}

// EnableTransit validates existing operator-managed keys, never creates or
// activates them. One immutable attachment avoids races with dispatch passes.
func (w *Placements) EnableTransit(ctx context.Context, t *controlplane.Transit) error {
	if !t.BoundTo(w.store) {
		return controlplane.ErrInput
	}
	if err := t.CheckKeys(ctx); err != nil {
		return err
	}
	if !w.transit.CompareAndSwap(nil, t) {
		return controlplane.ErrConflict
	}
	return nil
}

func (c ServiceConfig) OpenTransit(s *controlplane.Store) (*controlplane.Transit, error) {
	if c.Transit == nil {
		return nil, nil
	}
	for _, path := range c.Transit.Keys {
		if !filepath.IsAbs(path) {
			return nil, operatorconfig.ErrPrivateFile
		}
	}
	keys, err := c.Transit.Keys.Read()
	if err != nil {
		return nil, err
	}
	defer operatorconfig.ClearKeys(keys)
	return controlplane.NewTransit(s, c.Transit.ActiveKey, keys, 7*24*time.Hour)
}
