-- Lifecycle commands on tenant agents are audited like assignments (CAP-02):
-- who asked to wake, sleep or delete which agent, atomically with the command.
-- Agent-level actions carry no assignment; assignment actions always do.
ALTER TABLE tenant_agent_audit DROP CONSTRAINT tenant_agent_audit_action_check;
ALTER TABLE tenant_agent_audit DROP CONSTRAINT tenant_agent_audit_check;
ALTER TABLE tenant_agent_audit ADD CONSTRAINT tenant_agent_audit_action_check CHECK (action IN (
  'agent.created','agent.wake_requested','agent.sleep_requested','agent.delete_requested',
  'assignment.created','assignment.revoked'));
ALTER TABLE tenant_agent_audit ADD CONSTRAINT tenant_agent_audit_check
  CHECK ((action LIKE 'agent.%') = (assignment_id IS NULL));
