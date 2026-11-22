package controlplane

import (
	"context"
	"slices"
	"strings"
)

// The scope of a revocation subject (docs/adr/006-authority-service.md,
// "Changes after the v0.1.0 audit"): the stores that can act on it. A store
// acts only on the events PostgreSQL addresses to it, and each event names
// its subjects (peer_payloads.go, delivery.go, instruction_delivery.go):
//
//   - agent/<id>: the agent's own store, and the store of every agent that
//     shares a request with it, as sender or recipient. A request joins only
//     two LIVE agents of one organization (submitPayload), so once the
//     deletion's subject is committed no store joins this scope;
//   - request/<id>: the request's sender and recipient, which never change;
//   - event/<id>: the mailbox's destination, which never changes.
//
// The worker names this scope when it begins the subject in the authority.
// Another organization's store is never in it: its guests no longer receive
// this organization's subject IDs. A subject of another form, or whose row
// PostgreSQL lacks, gets no store: the authority then puts it in every
// store's scope, as before.

// RevocationScope is a revocation subject and the stores that can act on
// it; no store means every store.
type RevocationScope struct {
	Subject string
	Stores  []string
}

// ScopedImporter is a reconciliation authority that takes each imported
// subject's scope. The reconciliation uses it when the authority offers it.
type ScopedImporter interface {
	ImportScopes(ctx context.Context, scopes []RevocationScope) error
}

// RevocationScopes returns the scope of each subject, in its order.
func (s *Store) RevocationScopes(ctx context.Context, subjects []string) ([]RevocationScope, error) {
	out := make([]RevocationScope, 0, len(subjects))
	for _, subject := range subjects {
		scope := RevocationScope{Subject: subject}
		kind, id, _ := strings.Cut(subject, "/")
		var query string
		switch kind {
		case "agent":
			query = `SELECT $1::text UNION SELECT recipient_agent_id FROM agent_requests WHERE sender_agent_id=$1
                UNION SELECT sender_agent_id FROM agent_requests WHERE recipient_agent_id=$1`
		case "request":
			query = `SELECT sender_agent_id FROM agent_requests WHERE id=$1 UNION SELECT recipient_agent_id FROM agent_requests WHERE id=$1`
		case "event":
			query = `SELECT dest_agent_id FROM agent_mailboxes WHERE id=$1`
		}
		if query != "" && id != "" {
			rows, err := s.pool.Query(ctx, query, id)
			if err != nil {
				return nil, err
			}
			for rows.Next() {
				var store string
				if err = rows.Scan(&store); err != nil {
					rows.Close()
					return nil, err
				}
				scope.Stores = append(scope.Stores, store)
			}
			rows.Close()
			if err = rows.Err(); err != nil {
				return nil, err
			}
			slices.Sort(scope.Stores)
		}
		out = append(out, scope)
	}
	return out, nil
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
