package controlplane

import (
	"context"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane/diagnostics"
)

type Diagnostics = diagnostics.Snapshot
type AppliedMigration = diagnostics.AppliedMigration
type HostDiagnostics = diagnostics.HostDiagnostics
type HostStatistics = diagnostics.HostStatistics
type QueueByKind = diagnostics.QueueByKind
type CountBy = diagnostics.CountBy

// Diagnostics reads the database's state for an operator's diagnostic export.
func (s *Store) Diagnostics(ctx context.Context) (Diagnostics, error) {
	return s.diagnostics(ctx, nil)
}

func (s *Store) PlatformDiagnostics(ctx context.Context, p Principal) (Diagnostics, error) {
	return s.diagnostics(ctx, &p)
}

func (s *Store) diagnostics(ctx context.Context, p *Principal) (Diagnostics, error) {
	d := diagnostics.NewSnapshot(len(controlPlaneMigrations))
	tx, err := s.begin(ctx)
	if err != nil {
		return d, err
	}
	defer rollback(tx)
	if p != nil {
		if err = authorizePlatform(ctx, tx, *p); err != nil {
			return d, err
		}
	}
	if err = d.Read(ctx, tx); err != nil {
		return d, err
	}
	return d, commit(ctx, tx)
}
