-- An organization decides how requests from its other agents reach one of its
-- agents (PUT /v1/agents/{id}/inbound): accepted by policy or held for
-- approval. agents.inbound_mode already holds it; the change is audited.
ALTER TABLE tenant_agent_audit DROP CONSTRAINT tenant_agent_audit_action_check;
ALTER TABLE tenant_agent_audit ADD CONSTRAINT tenant_agent_audit_action_check CHECK (action IN (
  'agent.created','agent.wake_requested','agent.sleep_requested','agent.delete_requested',
  'agent.idle_policy_set','agent.idle_sleep_requested','agent.release_changed','agent.directory_changed',
  'agent.inbound_changed',
  'attachment.uploaded','attachment.deleted','assignment.created','assignment.revoked'));
