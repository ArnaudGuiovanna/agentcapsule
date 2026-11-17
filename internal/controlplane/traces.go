package controlplane

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
)

// TraceKey returns the installation's pseudonym key for traces (OPR-3,
// migration 0046): the API and the worker read the same one, so an
// identifier has the same pseudonym in every process's spans.
func (s *Store) TraceKey(ctx context.Context) ([]byte, error) {
	var key []byte
	err := s.pool.QueryRow(ctx, "SELECT key FROM trace_pseudonym_key WHERE singleton").Scan(&key)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return key, err
}

// TraceOrigin returns the X-Request-ID of the API request whose trace a
// guest's platform call joins (OPR-3), or "" when none: the request that
// created an invocation (kind "invocation"), or the invocation whose mandate
// a request between agents (kind "request") or a mandate (kind "mandate")
// came from. One indexed read.
func (s *Store) TraceOrigin(ctx context.Context, kind, id string) (string, error) {
	var query string
	switch kind {
	case "invocation":
		query = "SELECT request_id FROM platform_operations WHERE id=$1"
	case "request":
		query = originOfRequest
	case "mandate":
		query = `SELECT o.request_id FROM owner_instructions i JOIN platform_operations o ON o.id=i.operation_id WHERE i.mandate_id=$1`
	default:
		return "", ErrInput
	}
	var origin *string
	err := s.pool.QueryRow(ctx, query, id).Scan(&origin)
	if errors.Is(err, pgx.ErrNoRows) || origin == nil {
		return "", nil
	}
	return *origin, err
}
