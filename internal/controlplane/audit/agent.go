package audit

import (
	"context"
	"strings"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane/internal/persistence"
	"github.com/jackc/pgx/v5"
)

// RecordAgent records a tenant event and updates the policy version when permissions change.
func RecordAgent(ctx context.Context, tx pgx.Tx, tenant, actor, agent string, assignment *string, action string) error {
	// A file upload or deletion changes no authorization policy. Bumping the
	// version would also take the organization row exclusively after the agent
	// lock, against concurrent uploads that read it shared before (deadlock).
	if action != "agent.created" && !strings.HasPrefix(action, "attachment.") {
		if _, err := tx.Exec(ctx, `UPDATE organizations SET policy_version=policy_version+1 WHERE id=$1`, tenant); err != nil {
			return err
		}
	}
	_, err := tx.Exec(ctx, `INSERT INTO tenant_agent_audit(id,tenant_id,actor_principal_id,agent_id,assignment_id,action) VALUES($1,$2,$3,$4,$5,$6)`,
		persistence.ID("audit"), tenant, actor, agent, assignment, action)
	return err
}
