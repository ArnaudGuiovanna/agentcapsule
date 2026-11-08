-- Scheduled invocations and idle policy (EVT-03).
--
-- A scheduled instruction is created now, with its operation identity and its
-- encrypted content, but has no mailbox entry until its due time: a future item
-- at the head of the per-agent FIFO would block everything behind it. Releasing
-- it creates the mailbox entry exactly once; the operation id never changes, so
-- a scheduler restart cannot lose or duplicate the event.
ALTER TABLE owner_instructions
  ADD COLUMN run_at timestamptz,
  ADD COLUMN released_at timestamptz,
  ADD COLUMN ttl_micros bigint CHECK (ttl_micros IS NULL OR ttl_micros > 0),
  ADD CONSTRAINT owner_instructions_schedule CHECK (
    (run_at IS NULL) = (ttl_micros IS NULL) AND (released_at IS NULL OR run_at IS NOT NULL));
CREATE INDEX owner_instructions_due ON owner_instructions(run_at) WHERE run_at IS NOT NULL AND released_at IS NULL;

-- Idle closure is opt-in per agent. The principal who set the policy answers for
-- the sleeps it causes, which is why platform_operations.cause distinguishes them.
ALTER TABLE agent_specs
  ADD COLUMN idle_timeout_seconds integer CHECK (idle_timeout_seconds BETWEEN 60 AND 604800),
  ADD COLUMN idle_policy_by text,
  ADD CONSTRAINT agent_specs_idle_policy CHECK ((idle_timeout_seconds IS NULL) = (idle_policy_by IS NULL));
ALTER TABLE platform_operations
  ADD COLUMN cause text NOT NULL DEFAULT 'request' CHECK (cause IN ('request','idle_policy'));

-- The idle clock starts when the scheduler first sees a generation running, never
-- earlier: it can delay a stop, but it cannot stop an agent that just woke.
CREATE TABLE agent_idle_watch (
  agent_id text PRIMARY KEY REFERENCES agents(id),
  generation bigint NOT NULL CHECK (generation > 0),
  observed_at timestamptz NOT NULL
);

ALTER TABLE tenant_agent_audit DROP CONSTRAINT tenant_agent_audit_action_check;
ALTER TABLE tenant_agent_audit ADD CONSTRAINT tenant_agent_audit_action_check CHECK (action IN (
  'agent.created','agent.wake_requested','agent.sleep_requested','agent.delete_requested',
  'agent.idle_policy_set','agent.idle_sleep_requested',
  'assignment.created','assignment.revoked'));
