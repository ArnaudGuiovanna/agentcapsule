-- Tenant-owned agents and their assignments (TEN-04/TEN-05, decision D-02).
--
-- An agent belongs to exactly one domain: the historical owner domain
-- (owner_user_id, one agent per owner) or a tenant (tenant_id, any number of
-- agents). Historical rows are unchanged and keep their uniqueness.
ALTER TABLE agents ADD COLUMN tenant_id text REFERENCES organizations(id);
ALTER TABLE agents ALTER COLUMN owner_user_id DROP NOT NULL;
ALTER TABLE agents DROP CONSTRAINT agents_owner_user_id_key;
CREATE UNIQUE INDEX agents_legacy_owner ON agents(owner_user_id) WHERE owner_user_id IS NOT NULL;
ALTER TABLE agents ADD CONSTRAINT agents_one_domain CHECK ((tenant_id IS NULL) <> (owner_user_id IS NULL));
ALTER TABLE agents ADD CONSTRAINT agents_tenant_identity UNIQUE (tenant_id, id);
CREATE INDEX agents_tenant ON agents(tenant_id, id) WHERE tenant_id IS NOT NULL;

-- Operations on a tenant agent have no owner user. They record the principal
-- that requested them instead.
ALTER TABLE platform_operations ALTER COLUMN owner_user_id DROP NOT NULL;
ALTER TABLE platform_operations ADD COLUMN requested_by_principal_id text;
ALTER TABLE platform_operations ADD CONSTRAINT platform_operations_requester
  CHECK (owner_user_id IS NOT NULL OR requested_by_principal_id IS NOT NULL);

-- An assignment grants one principal, or every active member of one team,
-- permissions on one agent. Administrative roles never imply content access.
CREATE TABLE agent_assignments (
  id text PRIMARY KEY,
  tenant_id text NOT NULL,
  agent_id text NOT NULL,
  principal_id text,
  team_id text,
  permissions text[] NOT NULL,
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active','revoked')),
  created_by text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  revoked_by text,
  revoked_at timestamptz,
  CHECK ((principal_id IS NULL) <> (team_id IS NULL)),
  CHECK (cardinality(permissions) BETWEEN 1 AND 3 AND permissions <@ ARRAY['read_metadata','invoke','read_content']),
  CHECK ((status = 'active') = (revoked_at IS NULL AND revoked_by IS NULL)),
  FOREIGN KEY (tenant_id,agent_id) REFERENCES agents(tenant_id,id),
  FOREIGN KEY (tenant_id,principal_id) REFERENCES principals(tenant_id,id),
  FOREIGN KEY (tenant_id,team_id) REFERENCES teams(tenant_id,id),
  FOREIGN KEY (tenant_id,created_by) REFERENCES principals(tenant_id,id),
  FOREIGN KEY (tenant_id,revoked_by) REFERENCES principals(tenant_id,id)
);
CREATE UNIQUE INDEX agent_assignments_active_principal ON agent_assignments(tenant_id,agent_id,principal_id) WHERE status='active' AND principal_id IS NOT NULL;
CREATE UNIQUE INDEX agent_assignments_active_team ON agent_assignments(tenant_id,agent_id,team_id) WHERE status='active' AND team_id IS NOT NULL;
CREATE INDEX agent_assignments_principal ON agent_assignments(tenant_id,principal_id) WHERE status='active';
CREATE INDEX agent_assignments_team ON agent_assignments(tenant_id,team_id) WHERE status='active';

CREATE TABLE tenant_agent_audit (
  id text PRIMARY KEY,
  tenant_id text NOT NULL,
  actor_principal_id text NOT NULL,
  agent_id text NOT NULL,
  assignment_id text REFERENCES agent_assignments(id),
  action text NOT NULL CHECK (action IN ('agent.created','assignment.created','assignment.revoked')),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CHECK ((action = 'agent.created') = (assignment_id IS NULL)),
  FOREIGN KEY (tenant_id,actor_principal_id) REFERENCES principals(tenant_id,id),
  FOREIGN KEY (tenant_id,agent_id) REFERENCES agents(tenant_id,id)
);
CREATE INDEX tenant_agent_audit_tenant ON tenant_agent_audit(tenant_id,created_at,id);
