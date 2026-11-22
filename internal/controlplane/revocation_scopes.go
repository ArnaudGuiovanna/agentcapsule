package controlplane

import (
	"context"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane/reconciliation"
)

type RevocationScope = reconciliation.RevocationScope
type ScopedImporter = reconciliation.ScopedImporter

const agentScope = reconciliation.AgentScope

func (s *Store) RevocationScopes(ctx context.Context, subjects []string) ([]RevocationScope, error) {
	return reconciliation.Scopes(ctx, s.pool, subjects)
}

func (s *Store) RevocationSubjects(ctx context.Context) ([]string, error) {
	return reconciliation.Subjects(ctx, s.pool)
}

// scopedSubjects is the part of revocation_catalogue in store's scope, with
// $1 the store: what a new store must fence before it becomes LIVE. Its cost
// follows the store's own requests and closing mailboxes, not the platform's
// revocations.
const scopedSubjects = `SELECT c.subject FROM revocation_catalogue c JOIN (
        SELECT 'agent/'||$1::text AS subject
        UNION SELECT 'agent/'||recipient_agent_id FROM agent_requests WHERE sender_agent_id=$1
        UNION SELECT 'agent/'||sender_agent_id FROM agent_requests WHERE recipient_agent_id=$1
        UNION SELECT 'request/'||id FROM agent_requests WHERE sender_agent_id=$1
        UNION SELECT 'request/'||id FROM agent_requests WHERE recipient_agent_id=$1
        UNION SELECT 'event/'||id FROM agent_mailboxes WHERE dest_agent_id=$1 AND closing) scope ON scope.subject=c.subject`
