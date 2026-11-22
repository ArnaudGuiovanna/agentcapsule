package reconciliation

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
//     shares a kept request with it, as sender or recipient. A request joins
//     only two LIVE agents of one organization (submitPayload), so once the
//     deletion's subject is committed no store joins this scope. The
//     retention of finished records (finished_retention.go) deletes a request
//     only once no store can act on its events any more: each was delivered
//     and answered, or died, or the request's closure fenced request/<id> in
//     both parties, and no archive a restore can start from predates it. A
//     party it joined to the agent alone then leaves the scope, safely;
//   - request/<id>: the request's sender and recipient, which never change;
//   - event/<id>: the mailbox's destination, which never changes.
//
// The stores of a request/ or event/ subject are recorded with the subject
// in revocation_catalogue.stores (publishRevocation): they outlive the
// request and the mailbox entry, which the retention deletes, so a subject
// the authority begins later (a reconciliation after a failover) keeps its
// scope. The worker names this scope when it begins the subject in the
// authority. Another organization's store is never in it: its guests no
// longer receive this organization's subject IDs. A subject of another form,
// or of which PostgreSQL holds neither its stores nor its row, gets no store:
// the authority then puts it in every store's scope, as before.

// AgentScope is the scope of agent/$1: the agent's own store and the store
// of every agent that shares a request with it. A deletion's census is this
// scope (requestDeletion).
const AgentScope = `SELECT $1::text UNION SELECT recipient_agent_id FROM agent_requests WHERE sender_agent_id=$1
                UNION SELECT sender_agent_id FROM agent_requests WHERE recipient_agent_id=$1`

// Scopes returns the scope of each subject, in its order.
func Scopes(ctx context.Context, db database, subjects []string) ([]RevocationScope, error) {
	out := make([]RevocationScope, 0, len(subjects))
	for _, subject := range subjects {
		scope := RevocationScope{Subject: subject}
		kind, id, _ := strings.Cut(subject, "/")
		var query string
		switch kind {
		case "agent":
			query = AgentScope
		case "request":
			query = recordedStores + ` UNION SELECT sender_agent_id FROM agent_requests WHERE id=$1
                UNION SELECT recipient_agent_id FROM agent_requests WHERE id=$1`
		case "event":
			query = recordedStores + ` UNION SELECT dest_agent_id FROM agent_mailboxes WHERE id=$1`
		}
		if query != "" && id != "" {
			args := []any{id}
			if kind != "agent" {
				args = append(args, subject)
			}
			rows, err := db.Query(ctx, query, args...)
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

// recordedStores are the stores recorded with subject $2, if any.
const recordedStores = `SELECT unnest(stores) FROM revocation_catalogue WHERE subject=$2`

// Subjects returns durable, already-authorized intents. No SQL lock
// crosses the worker's subsequent independent-authority or guest RPC operation.
// It reads the platform's whole history: the reconciliation uses it; a boot
// no longer does (RevocationScopes).
func Subjects(ctx context.Context, db database) ([]string, error) {
	rows, err := db.Query(ctx, "SELECT subject FROM revocation_catalogue ORDER BY subject")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var subjects []string
	for rows.Next() {
		var subject string
		if err = rows.Scan(&subject); err != nil {
			return nil, err
		}
		subjects = append(subjects, subject)
	}
	return subjects, rows.Err()
}
