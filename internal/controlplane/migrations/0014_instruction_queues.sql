-- Instruction queues (EVT-02). Depth limits are per organization and enforced at
-- admission, before anything is accepted; a refused request leaves no trace.
-- close_reason records why a queued instruction ended without running, kept
-- apart from platform_operations.error_code so the verified delivery codes
-- (delivery_failed, delivery_outcome_unknown) do not change.
CREATE TABLE queue_limits (
  tenant_id text PRIMARY KEY REFERENCES organizations(id),
  max_pending_per_agent integer NOT NULL CHECK (max_pending_per_agent BETWEEN 1 AND 100000),
  max_pending_tenant integer NOT NULL CHECK (max_pending_tenant BETWEEN 1 AND 1000000),
  updated_by text NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CHECK (max_pending_per_agent <= max_pending_tenant),
  FOREIGN KEY (tenant_id,updated_by) REFERENCES principals(tenant_id,id)
);

CREATE TABLE queue_audit (
  id text PRIMARY KEY CHECK (id <> ''),
  tenant_id text NOT NULL REFERENCES organizations(id),
  actor_principal_id text NOT NULL,
  action text NOT NULL CHECK (action IN ('limits.set')),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  FOREIGN KEY (tenant_id,actor_principal_id) REFERENCES principals(tenant_id,id)
);

ALTER TABLE owner_instructions
  ADD COLUMN close_reason text NOT NULL DEFAULT '' CHECK (close_reason IN ('','expired','attempts_exhausted','closed'));
