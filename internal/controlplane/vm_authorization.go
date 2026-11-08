package controlplane

import (
	"context"

	"github.com/jackc/pgx/v5"
)

// VMCaller is supplied by the trusted, authenticated per-boot listener. It must
// NEVER be decoded from an HTTP body/header. Transport authentication binds the
// peer; these checks keep that binding current through the business SQL commit.
type VMCaller struct {
	AgentID, HostID, VMID string
	Generation            uint64
}

// The caller's agent row is already locked in the global sorted agent order.
// Every placement mutation also locks that row. Holding the placement row until
// commit serializes admission with stop/replacement, including idempotent replay.
func authorizeVM(ctx context.Context, tx pgx.Tx, caller *VMCaller, agents map[string]agent) error {
	if caller == nil {
		return nil
	} // trusted non-VM/owner path, not the public VM adapter
	a, ok := agents[caller.AgentID]
	if !ok || a.Phase != "LIVE" || caller.HostID == "" || caller.VMID == "" || caller.Generation == 0 {
		return ErrPlacement
	}
	p, err := scanPlacement(tx.QueryRow(ctx, `SELECT `+placementColumns+` FROM agent_placements WHERE agent_id=$1 FOR SHARE`, caller.AgentID))
	if err != nil {
		return err
	}
	if p.HostID != caller.HostID || p.Generation != caller.Generation || p.VMID != caller.VMID || p.State != "RUNNING" || p.FenceOnly {
		return ErrPlacement
	}
	return ordinaryStoreReady(ctx, tx, caller.AgentID)
}

func (s *Store) SubmitFromVM(ctx context.Context, caller VMCaller, key string, input Submission) (Receipt, error) {
	return s.submit(ctx, caller.AgentID, key, input, &caller)
}

func (s *Store) ReplyFromVM(ctx context.Context, caller VMCaller, requestID, key string, input Reply) (Receipt, error) {
	return s.replyToRequest(ctx, caller.AgentID, requestID, key, input, &caller)
}

func (s *Store) ValidateVMCaller(ctx context.Context, caller VMCaller) error {
	tx, err := s.begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(tx)
	agents, err := lockAgents(ctx, tx, caller.AgentID)
	if err != nil {
		return err
	}
	return authorizeVM(ctx, tx, &caller, agents)
}

// SearchDirectoryFromVM postchecks bounded candidate IDs against PostgreSQL.
// An actual full-text ADS client is a separate adapter. No caller identity or
// ownership information is taken from the candidate list.
func (s *Store) SearchDirectoryFromVM(ctx context.Context, caller VMCaller, candidates []string) ([]string, error) {
	if len(candidates) > 100 {
		return nil, ErrNotFound
	}
	tx, err := s.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer rollback(tx)
	agents, err := lockAgents(ctx, tx, caller.AgentID)
	if err != nil {
		return nil, err
	}
	if err = authorizeVM(ctx, tx, &caller, agents); err != nil {
		return nil, err
	}
	rows, err := tx.Query(ctx, `SELECT id FROM agents WHERE id=ANY($1) AND id<>$2
        AND discoverable AND phase='LIVE' ORDER BY id`, candidates, caller.AgentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		result = append(result, id)
	}
	return result, rows.Err()
}

// vmTenant returns the organization of a running tenant agent after the same
// placement check every VM call passes. An agent of the historical owner domain
// has no organization and therefore no model gateway.
func (s *Store) vmTenant(ctx context.Context, caller VMCaller) (string, error) {
	tx, err := s.begin(ctx)
	if err != nil {
		return "", err
	}
	defer rollback(tx)
	agents, err := lockAgents(ctx, tx, caller.AgentID)
	if err != nil {
		return "", err
	}
	if err = authorizeVM(ctx, tx, &caller, agents); err != nil {
		return "", err
	}
	if agents[caller.AgentID].Tenant == "" {
		return "", ErrForbidden
	}
	return agents[caller.AgentID].Tenant, commit(ctx, tx)
}
