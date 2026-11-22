package controlplane

import (
	"context"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane/diagnostics"
	"github.com/jackc/pgx/v5"
)

type WALArchiving = diagnostics.WALArchiving

type rowQuerier interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

// WALArchiving reads the state of PostgreSQL's WAL archiving.
func (s *Store) WALArchiving(ctx context.Context) (WALArchiving, error) {
	return diagnostics.ReadWALArchiving(ctx, s.pool)
}
