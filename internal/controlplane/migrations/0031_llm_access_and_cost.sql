-- Model access per agent and team, cost budgets and the reconciliation of
-- unknown outcomes (LLM-01, LLM-03, ADR 011).
--
-- An alias's access is 'organization' (every agent of the organization, as
-- before this migration) or 'listed' (only the agents its active grants name,
-- directly or through an active assignment of the agent to an active team).
-- 'priced' says that the organization set the alias's prices, zero included: a
-- hard cost budget refuses a call it cannot price.
ALTER TABLE llm_model_aliases
  ADD COLUMN access text NOT NULL DEFAULT 'organization' CHECK (access IN ('organization','listed')),
  ADD COLUMN priced boolean NOT NULL DEFAULT false;
UPDATE llm_model_aliases SET priced = (input_micro_per_mtok > 0 OR output_micro_per_mtok > 0);

-- A grant names an agent or a team. The agent has no foreign key: abandoning a
-- provisioning deletes the agent row, and a grant must not block it. A grant is
-- created only for an existing agent of the organization, and agent
-- identifiers are never reused.
CREATE TABLE llm_alias_grants (
  id text PRIMARY KEY CHECK (id <> ''),
  tenant_id text NOT NULL,
  alias text NOT NULL,
  agent_id text CHECK (agent_id <> ''),
  team_id text,
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active','revoked')),
  created_by text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  revoked_by text,
  revoked_at timestamptz,
  CHECK ((agent_id IS NULL) <> (team_id IS NULL)),
  CHECK ((status = 'revoked') = (revoked_at IS NOT NULL AND revoked_by IS NOT NULL)),
  FOREIGN KEY (tenant_id,alias) REFERENCES llm_model_aliases(tenant_id,alias),
  FOREIGN KEY (tenant_id,team_id) REFERENCES teams(tenant_id,id),
  FOREIGN KEY (tenant_id,created_by) REFERENCES principals(tenant_id,id),
  FOREIGN KEY (tenant_id,revoked_by) REFERENCES principals(tenant_id,id)
);
CREATE UNIQUE INDEX llm_alias_grants_active_agent ON llm_alias_grants(tenant_id,alias,agent_id) WHERE status='active' AND agent_id IS NOT NULL;
CREATE UNIQUE INDEX llm_alias_grants_active_team ON llm_alias_grants(tenant_id,alias,team_id) WHERE status='active' AND team_id IS NOT NULL;

-- A budget limits tokens or estimated cost, in micro-units of the
-- organization's currency, never both. One active budget per scope, period and
-- unit.
ALTER TABLE llm_budgets
  ALTER COLUMN limit_tokens DROP NOT NULL,
  ADD COLUMN limit_cost_micro bigint CHECK (limit_cost_micro > 0),
  ADD CONSTRAINT llm_budgets_one_limit CHECK ((limit_tokens IS NULL) <> (limit_cost_micro IS NULL));
DROP INDEX llm_budgets_active_scope;
CREATE UNIQUE INDEX llm_budgets_active_scope_unit ON llm_budgets(tenant_id,coalesce(agent_id,''),coalesce(alias,''),period,(limit_cost_micro IS NOT NULL)) WHERE status='active';

-- A call keeps the prices of its reservation: its reserved cost and its
-- settlement use them even if the alias's prices change in between. A call of
-- unknown outcome counts its reserved cost, as it counts its reserved tokens.
-- resolved_by names who settled or released a call of unknown outcome.
ALTER TABLE llm_usage
  ADD COLUMN priced boolean NOT NULL DEFAULT false,
  ADD COLUMN input_micro_per_mtok bigint NOT NULL DEFAULT 0 CHECK (input_micro_per_mtok >= 0),
  ADD COLUMN output_micro_per_mtok bigint NOT NULL DEFAULT 0 CHECK (output_micro_per_mtok >= 0),
  ADD COLUMN reserved_cost_micro bigint NOT NULL DEFAULT 0 CHECK (reserved_cost_micro >= 0),
  ADD COLUMN resolved_by text,
  ADD COLUMN resolved_at timestamptz,
  ADD CONSTRAINT llm_usage_resolution CHECK ((resolved_by IS NULL) = (resolved_at IS NULL));
-- Calls reserved before this migration take their alias's current prices. Their
-- split between input and output is unknown, so the reserved tokens of a call
-- still open are priced at the higher of the two, rounded up.
UPDATE llm_usage u SET priced=m.priced, input_micro_per_mtok=m.input_micro_per_mtok, output_micro_per_mtok=m.output_micro_per_mtok,
  reserved_cost_micro=CASE WHEN u.state IN ('reserved','unknown') AND m.priced
    THEN ceil(u.reserved_tokens::numeric * greatest(m.input_micro_per_mtok,m.output_micro_per_mtok) / 1000000)::bigint ELSE 0 END
  FROM llm_model_aliases m WHERE (m.tenant_id,m.alias)=(u.tenant_id,u.alias);
CREATE INDEX llm_usage_unresolved ON llm_usage(tenant_id,id) WHERE state IN ('reserved','unknown');

ALTER TABLE llm_audit
  ADD COLUMN grant_id text,
  ADD COLUMN usage_id text,
  ADD COLUMN subject_id text,
  DROP CONSTRAINT llm_audit_action_check,
  ADD CONSTRAINT llm_audit_action_check CHECK (action IN ('provider.created','provider.rotated','provider.disabled','alias.created','alias.disabled',
    'budget.created','budget.disabled','alias.access_set','alias.prices_set','alias.grant_created','alias.grant_revoked','usage.settled','usage.released')),
  ADD CONSTRAINT llm_audit_references CHECK ((action LIKE 'alias.grant_%') = (grant_id IS NOT NULL) AND (action LIKE 'usage.%') = (usage_id IS NOT NULL)
    AND (subject_id IS NOT NULL) = (action LIKE 'alias.grant_%' OR action LIKE 'usage.%'));
