-- An organization's refused administrative attempts (TEN-009, ADR 014 §10).
-- A route of an audited action answered a member or a technical account of
-- the organization with an authorization refusal (403, 404) or a validation
-- refusal (400, 409, 413, 415, 422). The refused change rolled back; the
-- refusal is recorded after it, in its own transaction. A row says who, when,
-- the action attempted, the identifiers the request's path named and the
-- refusal's code: never its body, a token or any content.
CREATE TABLE tenant_refusal_audit (
  id text PRIMARY KEY,
  tenant_id text NOT NULL REFERENCES organizations(id),
  actor_principal_id text NOT NULL,
  action text NOT NULL CHECK (action ~ '^[a-z_]+(\.[a-z_]+){1,2}$'),
  target text NOT NULL CHECK (target ~ '^[A-Za-z0-9_.:-]{1,100}$'),
  reference text NOT NULL DEFAULT '' CHECK (reference ~ '^[A-Za-z0-9_.:-]{0,100}$'),
  reason text NOT NULL CHECK (reason ~ '^[a-z_]{1,64}$'),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  FOREIGN KEY (tenant_id,actor_principal_id) REFERENCES principals(tenant_id,id)
);
CREATE INDEX tenant_refusal_audit_feed ON tenant_refusal_audit(tenant_id, created_at, id);
-- The audit retention selects by age alone (0039).
CREATE INDEX tenant_refusal_audit_created ON tenant_refusal_audit(created_at);
-- The replays of dead letters join their organization's trail.
CREATE INDEX instruction_replays_tenant ON instruction_replays(tenant_id, replayed_at) WHERE tenant_id IS NOT NULL;
