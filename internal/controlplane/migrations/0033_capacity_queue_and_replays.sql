-- Work waiting for VM capacity, and replays of dead letters (EVT-02, EVT-007,
-- RUN-011, ADR 017).
--
-- An agent that needs a VM slot on a full host waits here, in arrival order
-- (ticket). It boots only when no older waiter of its host still needs a slot,
-- so new work never overtakes older work that waits for capacity. A waiter
-- whose work is no longer due (delivered, expired, canceled, its agent FAILED,
-- running or deleted) is removed by the next decision on its host.
CREATE TABLE capacity_waits (
  agent_id text PRIMARY KEY REFERENCES agents(id),
  host_id text NOT NULL REFERENCES worker_hosts(host_id),
  ticket bigint NOT NULL CHECK (ticket > 0),
  since timestamptz NOT NULL DEFAULT clock_timestamp(),
  UNIQUE (host_id, ticket)
);

-- An agent whose VM stopped while it held work in progress (an invocation it
-- acknowledged "working", a request it was processing) is booted again so that
-- its harness resumes that work: the "resume" job.
ALTER TABLE worker_jobs DROP CONSTRAINT worker_jobs_kind_check;
ALTER TABLE worker_jobs ADD CONSTRAINT worker_jobs_kind_check
  CHECK (kind IN ('delivery','closure','deletion','expiration','provision','lifecycle','resume'));

-- Each replay of a dead letter, by the operator or by an administrator of the
-- agent's organization: its audit and its idempotency key. The instruction
-- keeps its identifier and its event ID; previous_reason is how it had died.
CREATE TABLE instruction_replays (
  id text PRIMARY KEY,
  operation_id text NOT NULL REFERENCES platform_operations(id),
  agent_id text NOT NULL REFERENCES agents(id),
  tenant_id text REFERENCES organizations(id),
  actor_kind text NOT NULL CHECK (actor_kind IN ('operator','principal')),
  actor_principal_id text,
  request_key text NOT NULL CHECK (request_key <> '' AND length(request_key) <= 200),
  previous_reason text NOT NULL CHECK (previous_reason IN ('expired','attempts_exhausted','closed')),
  expires_at timestamptz NOT NULL,
  replayed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CHECK ((actor_kind = 'principal') = (actor_principal_id IS NOT NULL))
);
CREATE UNIQUE INDEX instruction_replays_key
  ON instruction_replays(operation_id, actor_kind, coalesce(actor_principal_id, ''), request_key);
CREATE INDEX instruction_replays_operation ON instruction_replays(operation_id, replayed_at);
