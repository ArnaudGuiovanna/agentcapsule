-- LLM budgets and usage (LLM-03). A reservation is written before an upstream
-- call and settled or released afterwards. An outcome that cannot be known (a
-- timeout after the request left) stays 'unknown' and keeps counting its
-- reserved tokens, so uncertainty never reads as zero spend.
ALTER TABLE llm_model_aliases
  ADD COLUMN input_micro_per_mtok bigint NOT NULL DEFAULT 0 CHECK (input_micro_per_mtok >= 0),
  ADD COLUMN output_micro_per_mtok bigint NOT NULL DEFAULT 0 CHECK (output_micro_per_mtok >= 0);

CREATE TABLE llm_budgets (
  id text PRIMARY KEY CHECK (id <> ''),
  tenant_id text NOT NULL REFERENCES organizations(id),
  agent_id text,
  alias text,
  period text NOT NULL CHECK (period IN ('day','month')),
  limit_tokens bigint NOT NULL CHECK (limit_tokens > 0),
  mode text NOT NULL CHECK (mode IN ('hard','soft')),
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active','disabled')),
  created_by text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  disabled_at timestamptz,
  CHECK ((status = 'disabled') = (disabled_at IS NOT NULL)),
  FOREIGN KEY (tenant_id,agent_id) REFERENCES agents(tenant_id,id),
  FOREIGN KEY (tenant_id,created_by) REFERENCES principals(tenant_id,id)
);
CREATE UNIQUE INDEX llm_budgets_active_scope ON llm_budgets(tenant_id,coalesce(agent_id,''),coalesce(alias,''),period) WHERE status='active';

CREATE TABLE llm_usage (
  id text PRIMARY KEY,
  tenant_id text NOT NULL,
  agent_id text NOT NULL,
  alias text NOT NULL,
  request_key text NOT NULL CHECK (length(request_key) BETWEEN 1 AND 200),
  state text NOT NULL DEFAULT 'reserved' CHECK (state IN ('reserved','settled','unknown','released')),
  reserved_tokens bigint NOT NULL CHECK (reserved_tokens > 0),
  input_tokens bigint,
  output_tokens bigint,
  estimated_cost_micro bigint,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  settled_at timestamptz,
  CHECK ((state = 'settled') = (input_tokens IS NOT NULL AND output_tokens IS NOT NULL AND settled_at IS NOT NULL)),
  UNIQUE (tenant_id,agent_id,request_key),
  FOREIGN KEY (tenant_id,agent_id) REFERENCES agents(tenant_id,id)
);
CREATE INDEX llm_usage_window ON llm_usage(tenant_id,created_at);

ALTER TABLE llm_audit
  ALTER COLUMN provider_id DROP NOT NULL,
  ADD COLUMN budget_id text,
  DROP CONSTRAINT llm_audit_action_check,
  ADD CONSTRAINT llm_audit_action_check CHECK (action IN ('provider.created','provider.rotated','provider.disabled','alias.created','alias.disabled','budget.created','budget.disabled')),
  ADD CONSTRAINT llm_audit_target CHECK ((action LIKE 'budget.%') = (budget_id IS NOT NULL) AND (action LIKE 'budget.%') = (provider_id IS NULL));
