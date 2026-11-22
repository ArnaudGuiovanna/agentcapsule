-- The budgets' counters (v0.1.0 audit, P-05; ADR 011, "Changes after the
-- v0.1.0 audit"). A reservation summed its budgets' window over llm_usage
-- under their row locks: its cost grew with the month's calls. A row here
-- holds what one budget's UTC day or month counts, in the budget's unit:
-- tokens, or micro-units of cost. A reservation adds its amounts to it, a
-- settlement or a release the change of its call's amounts
-- (llm_budgets.go). used is what the window's calls of the budget's scope
-- count, as the sum counted them.
CREATE TABLE llm_budget_windows (
  tenant_id text NOT NULL,
  budget_id text NOT NULL REFERENCES llm_budgets(id),
  window_start timestamptz NOT NULL,
  used bigint NOT NULL,
  PRIMARY KEY (budget_id, window_start)
);

-- Each active budget's current window, from the calls already made. The
-- migration runs with the API and the workers stopped (docs/cli-host.md):
-- no call changes meanwhile.
INSERT INTO llm_budget_windows(tenant_id, budget_id, window_start, used)
SELECT b.tenant_id, b.id, w.start, coalesce((
  SELECT sum(CASE WHEN b.limit_cost_micro IS NULL
    THEN CASE u.state WHEN 'settled' THEN u.input_tokens + u.output_tokens WHEN 'released' THEN 0 ELSE u.reserved_tokens END
    ELSE CASE u.state WHEN 'settled' THEN coalesce(u.estimated_cost_micro, 0) WHEN 'released' THEN 0 ELSE u.reserved_cost_micro END END)
    FROM llm_usage u
   WHERE u.tenant_id = b.tenant_id AND u.created_at >= w.start
     AND (b.agent_id IS NULL OR u.agent_id = b.agent_id) AND (b.alias IS NULL OR u.alias = b.alias)), 0)
  FROM llm_budgets b
  CROSS JOIN LATERAL (SELECT date_trunc(b.period, clock_timestamp() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC' AS start) w
 WHERE b.status = 'active';
