-- Capability negotiation (CAP-01, EXT-003, ADR 016). What an agent may ask the
-- platform for over its platform channel is the intersection of what its
-- harness requests, what its organization allows and what the agent allows.
--
-- A release records the capabilities its harness.yaml requests at import.
-- NULL: the manifest predates the field; the release is treated as requesting
-- every capability (a default pending the product owner). An empty array
-- requests none.
ALTER TABLE harness_releases ADD COLUMN capabilities text[]
  CHECK (capabilities IS NULL OR capabilities <@ ARRAY['llm.invoke','agents.delegate','agents.discover']::text[]);

-- No row: the organization, or the agent, allows every capability.
CREATE TABLE organization_capability_policies (
  tenant_id text PRIMARY KEY REFERENCES organizations(id),
  allowed text[] NOT NULL CHECK (allowed <@ ARRAY['llm.invoke','agents.delegate','agents.discover']::text[]),
  updated_by text NOT NULL CHECK (updated_by <> ''),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE agent_capability_policies (
  agent_id text PRIMARY KEY REFERENCES agents(id),
  allowed text[] NOT NULL CHECK (allowed <@ ARRAY['llm.invoke','agents.delegate','agents.discover']::text[]),
  updated_by text NOT NULL CHECK (updated_by <> ''),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

-- Who changed a policy, and when; never which capabilities were used.
CREATE TABLE capability_audit (
  id text PRIMARY KEY,
  tenant_id text NOT NULL REFERENCES organizations(id),
  actor_principal_id text NOT NULL CHECK (actor_principal_id <> ''),
  agent_id text REFERENCES agents(id),
  action text NOT NULL CHECK (action IN ('organization.capabilities_changed','agent.capabilities_changed')),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CHECK ((action = 'agent.capabilities_changed') = (agent_id IS NOT NULL))
);
CREATE INDEX capability_audit_feed ON capability_audit(tenant_id, created_at, id);
