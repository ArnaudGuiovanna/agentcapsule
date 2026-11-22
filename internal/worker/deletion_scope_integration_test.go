//go:build linux && kvm_integration && kvm_control_integration

package worker

import (
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// shareRequests records an ended request between each pair of agents. A
// deletion's census is its agent's scope, the stores that share a request
// with it (controlplane, requestDeletion): with these, it is every one of
// these agents' stores, as the tests that fence every store need.
func shareRequests(t *testing.T, db *pgxpool.Pool, schema string, agents ...string) {
	t.Helper()
	mandates, requests := pgx.Identifier{schema, "mandates"}.Sanitize(), pgx.Identifier{schema, "agent_requests"}.Sanitize()
	for i, sender := range agents {
		for _, recipient := range agents[i+1:] {
			mandate, request := "mnd-share-"+sender+"-"+recipient, "arq-share-"+sender+"-"+recipient
			if _, err := db.Exec(t.Context(), `INSERT INTO `+mandates+`(id,agent_id,origin_event_id,max_requests,remaining,expires_at)
                VALUES($1,$2,'evt-share',1,1,clock_timestamp()+interval '1 hour')`, mandate, sender); err != nil {
				t.Fatal(err)
			}
			if _, err := db.Exec(t.Context(), `INSERT INTO `+requests+`(id,sender_agent_id,recipient_agent_id,mandate_id,state,via_auto,payload_ref,expires_at,decided_at)
                VALUES($1,$2,$3,$4,'CANCELED',true,'opaque',clock_timestamp()+interval '1 hour',clock_timestamp())`, request, sender, recipient, mandate); err != nil {
				t.Fatal(err)
			}
		}
	}
}
