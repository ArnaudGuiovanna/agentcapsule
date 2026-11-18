-- Restart budgets (CAP-03, RUN-011, ADR 012). A guest that keeps failing to
-- boot, or keeps crashing, must not be booted again and again. Each failed
-- boot or crash of a live agent's guest is recorded once, keyed by its boot
-- generation. Once an agent has had as many failures as its host's budget
-- allows within the budget's window, it is FAILED: it does not boot until a
-- wake requested for it, or the operator, clears it.
CREATE TABLE guest_failures (
  agent_id text NOT NULL REFERENCES agents(id),
  generation bigint NOT NULL CHECK (generation > 0),
  kind text NOT NULL CHECK (kind IN ('boot','crash')),
  failed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (agent_id, generation)
);
CREATE INDEX guest_failures_window ON guest_failures(agent_id, failed_at);
-- The reason is the kind of the failure that spent the budget.
CREATE TABLE failed_agents (
  agent_id text PRIMARY KEY REFERENCES agents(id),
  reason text NOT NULL CHECK (reason IN ('boot_failed','crashed')),
  failures integer NOT NULL CHECK (failures > 0),
  failed_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
