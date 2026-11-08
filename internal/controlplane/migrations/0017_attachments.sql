-- Attachments (EVT-04). A file is uploaded for one agent by a principal who may
-- invoke it, stored as independently authenticated encrypted segments, bound to
-- one invocation, and readable only by that agent while that invocation runs.
-- The platform stores and moves bytes; it never interprets them.
CREATE TABLE attachments (
  id text PRIMARY KEY CHECK (id <> ''),
  tenant_id text NOT NULL REFERENCES organizations(id),
  agent_id text NOT NULL,
  uploader_principal_id text NOT NULL,
  name text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
  media_type text NOT NULL CHECK (length(media_type) BETWEEN 3 AND 100),
  size_bytes bigint NOT NULL CHECK (size_bytes BETWEEN 1 AND 67108864),
  sha256 bytea NOT NULL CHECK (octet_length(sha256)=32),
  key_id text NOT NULL REFERENCES transit_keys(id),
  segments integer NOT NULL CHECK (segments BETWEEN 1 AND 256),
  status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','attached','purged')),
  operation_id text REFERENCES platform_operations(id),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  expires_at timestamptz NOT NULL,
  attached_at timestamptz,
  position integer CHECK (position BETWEEN 0 AND 7),
  purged_at timestamptz,
  CHECK (status = 'purged' OR ((status = 'attached') = (operation_id IS NOT NULL))),
  CHECK ((status = 'purged') = (purged_at IS NOT NULL)),
  FOREIGN KEY (tenant_id,agent_id) REFERENCES agents(tenant_id,id),
  FOREIGN KEY (tenant_id,uploader_principal_id) REFERENCES principals(tenant_id,id)
);
CREATE INDEX attachments_tenant_live ON attachments(tenant_id) WHERE status <> 'purged';
CREATE INDEX attachments_operation ON attachments(operation_id) WHERE operation_id IS NOT NULL;
CREATE INDEX attachments_pending_expiry ON attachments(expires_at) WHERE status = 'pending';
CREATE INDEX attachments_agent_live ON attachments(agent_id) WHERE status <> 'purged';

CREATE TABLE attachment_segments (
  attachment_id text NOT NULL REFERENCES attachments(id),
  idx integer NOT NULL CHECK (idx >= 0),
  ciphertext bytea NOT NULL,
  PRIMARY KEY (attachment_id, idx)
);

-- Storage the organization may hold at once (default 512 MiB).
ALTER TABLE queue_limits
  ADD COLUMN max_attachment_bytes bigint NOT NULL DEFAULT 536870912 CHECK (max_attachment_bytes BETWEEN 1048576 AND 68719476736);

ALTER TABLE tenant_agent_audit DROP CONSTRAINT tenant_agent_audit_action_check;
ALTER TABLE tenant_agent_audit DROP CONSTRAINT tenant_agent_audit_check;
ALTER TABLE tenant_agent_audit ADD CONSTRAINT tenant_agent_audit_action_check CHECK (action IN (
  'agent.created','agent.wake_requested','agent.sleep_requested','agent.delete_requested',
  'agent.idle_policy_set','agent.idle_sleep_requested','attachment.uploaded','attachment.deleted',
  'assignment.created','assignment.revoked'));
ALTER TABLE tenant_agent_audit ADD CONSTRAINT tenant_agent_audit_check
  CHECK ((action LIKE 'assignment.%') = (assignment_id IS NOT NULL));
