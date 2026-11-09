-- Harness upgrades and rollbacks (REG-03): an organization may pin a live agent
-- to another approved release. The change is audited with the new release; the
-- previous one is the release of the agent's preceding change or creation.
ALTER TABLE tenant_agent_audit
  ADD COLUMN release_id text REFERENCES harness_releases(id),
  ADD CONSTRAINT tenant_agent_audit_release CHECK ((action = 'agent.release_changed') = (release_id IS NOT NULL));
ALTER TABLE tenant_agent_audit DROP CONSTRAINT tenant_agent_audit_action_check;
ALTER TABLE tenant_agent_audit ADD CONSTRAINT tenant_agent_audit_action_check CHECK (action IN (
  'agent.created','agent.wake_requested','agent.sleep_requested','agent.delete_requested',
  'agent.idle_policy_set','agent.idle_sleep_requested','agent.release_changed',
  'attachment.uploaded','attachment.deleted','assignment.created','assignment.revoked'));
