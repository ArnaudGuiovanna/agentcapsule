-- Operations (OPS-03, API-02, TEN-06; ADR 014): the storage pressure each
-- worker records for its host, the audit of the operator's destructive
-- commands, and the retention of the audit trail.

-- A worker records whether the file system of its volumes (data) or of its
-- harness images is past its pressure threshold. While one is, the API refuses
-- new agents on that host (their volume) or imports (their image).
ALTER TABLE worker_hosts
  ADD COLUMN data_pressure boolean NOT NULL DEFAULT false,
  ADD COLUMN image_pressure boolean NOT NULL DEFAULT false,
  ADD COLUMN pressure_observed_at timestamptz;

-- An import the worker could not store ends as storage_pressure.
ALTER TABLE harness_imports DROP CONSTRAINT harness_imports_error_code_check,
  ADD CONSTRAINT harness_imports_error_code_check CHECK (error_code IN
    ('','policy','not_found','access_denied','signature','integrity','version_conflict','unavailable','storage_pressure'));

-- The operator's destructive commands (agentcapsule-admin), done or refused,
-- and the purges of the audit trail. The actor is a local user ID
-- (local-uid:<n>) or the worker. No secret, no content.
CREATE TABLE operator_audit (
  id text PRIMARY KEY CHECK (id <> ''),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  actor text NOT NULL CHECK (actor <> '' AND length(actor) <= 100),
  action text NOT NULL CHECK (action IN ('credential.revoked','provisioning.abandoned','audit.retention_set','audit.purged')),
  target text NOT NULL CHECK (length(target) <= 100),
  outcome text NOT NULL CHECK (outcome IN ('done','unchanged','refused')),
  reason text NOT NULL DEFAULT '' CHECK (reason IN ('','invalid_input','not_found','conflict','forbidden')),
  CHECK ((outcome = 'refused') = (reason <> ''))
);
CREATE INDEX operator_audit_created ON operator_audit(created_at,id);

-- How long audit events are kept (product §7: audit follows the legal
-- context). No row, or a NULL retention, keeps every event: the default until
-- the operator sets one. Then the worker deletes older events.
CREATE TABLE audit_retention (
  singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
  retention_days integer CHECK (retention_days IS NULL OR retention_days BETWEEN 30 AND 36500),
  changed_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

-- The purge selects by age alone.
CREATE INDEX organization_audit_created ON organization_audit(created_at);
CREATE INDEX delegation_audit_created ON delegation_audit(created_at);
CREATE INDEX tenant_member_audit_created ON tenant_member_audit(created_at);
CREATE INDEX tenant_team_audit_created ON tenant_team_audit(created_at);
CREATE INDEX tenant_agent_audit_created ON tenant_agent_audit(created_at);
CREATE INDEX tenant_service_audit_created ON tenant_service_audit(created_at);
CREATE INDEX llm_audit_created ON llm_audit(created_at);
CREATE INDEX queue_audit_created ON queue_audit(created_at);
CREATE INDEX harness_audit_created ON harness_audit(created_at);
