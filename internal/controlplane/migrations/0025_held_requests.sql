-- A person of an organization accepts or declines a request one of its agents
-- holds for approval (manual inbound policy): whoever may configure the
-- recipient, or whoever is assigned to it with invoke. Each decision is
-- audited with the request it decided; held requests are listed per recipient.
ALTER TABLE tenant_agent_audit
  ADD COLUMN request_id text REFERENCES agent_requests(id),
  ADD CONSTRAINT tenant_agent_audit_request
    CHECK ((action IN ('agent.request_accepted','agent.request_declined')) = (request_id IS NOT NULL));
ALTER TABLE tenant_agent_audit DROP CONSTRAINT tenant_agent_audit_action_check;
ALTER TABLE tenant_agent_audit ADD CONSTRAINT tenant_agent_audit_action_check CHECK (action IN (
  'agent.created','agent.wake_requested','agent.sleep_requested','agent.delete_requested',
  'agent.idle_policy_set','agent.idle_sleep_requested','agent.release_changed','agent.directory_changed',
  'agent.inbound_changed','agent.request_accepted','agent.request_declined',
  'attachment.uploaded','attachment.deleted','assignment.created','assignment.revoked'));
CREATE INDEX agent_requests_held ON agent_requests(recipient_agent_id, expires_at, id)
  WHERE state = 'PENDING_APPROVAL';
