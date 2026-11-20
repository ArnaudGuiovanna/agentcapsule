-- The output stream of a working invocation (ADR 022 §5.8). A harness sends
-- deltas and steps over one long platform channel call; the worker coalesces
-- them into chunks, each sealed as a result is and stored here for a short
-- while after the invocation's outcome. Deltas are never an outcome.

-- The invocation's attempt: 1 at its first delivery, plus one at each rerun
-- of a restore (queueRerun) and each replay of a dead letter.
ALTER TABLE owner_instructions ADD COLUMN attempt integer NOT NULL DEFAULT 1 CHECK (attempt >= 1);

-- The output stream of the invocation's current attempt: the last stored seq,
-- the attempt's counters against its limits, and its truncation.
CREATE TABLE invocation_streams (
  operation_id text PRIMARY KEY REFERENCES owner_instructions(operation_id),
  attempt integer NOT NULL CHECK (attempt >= 1),
  last_seq bigint NOT NULL DEFAULT 0 CHECK (last_seq >= 0),
  frames integer NOT NULL DEFAULT 0 CHECK (frames >= 0),
  bytes bigint NOT NULL DEFAULT 0 CHECK (bytes >= 0),
  truncated boolean NOT NULL DEFAULT false,
  first_delta_at timestamptz,
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

-- One sealed chunk of frames. Its payload is a transit payload of kind
-- stream_chunk, whose reference is <operation_id>/<attempt>/<first_seq>.
CREATE TABLE invocation_stream_chunks (
  operation_id text NOT NULL REFERENCES owner_instructions(operation_id),
  attempt integer NOT NULL CHECK (attempt >= 1),
  first_seq bigint NOT NULL CHECK (first_seq >= 1),
  last_seq bigint NOT NULL,
  payload_id text NOT NULL UNIQUE REFERENCES transit_payloads(id),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (operation_id, attempt, first_seq),
  CHECK (last_seq >= first_seq)
);

ALTER TABLE transit_payloads DROP CONSTRAINT transit_payloads_kind_check;
ALTER TABLE transit_payloads ADD CONSTRAINT transit_payloads_kind_check
  CHECK (kind IN ('instruction','instruction_result','request','reply','owner_message','stream_chunk'));

-- The capability to send that stream (ADR 022 §5.9). A policy written before
-- it does not list it: it is not effective there until added.
ALTER TABLE harness_releases DROP CONSTRAINT harness_releases_capabilities_check;
ALTER TABLE harness_releases ADD CONSTRAINT harness_releases_capabilities_check
  CHECK (capabilities IS NULL OR capabilities <@ ARRAY['llm.invoke','agents.delegate','agents.discover','stream.output']::text[]);
ALTER TABLE organization_capability_policies DROP CONSTRAINT organization_capability_policies_allowed_check;
ALTER TABLE organization_capability_policies ADD CONSTRAINT organization_capability_policies_allowed_check
  CHECK (allowed <@ ARRAY['llm.invoke','agents.delegate','agents.discover','stream.output']::text[]);
ALTER TABLE agent_capability_policies DROP CONSTRAINT agent_capability_policies_allowed_check;
ALTER TABLE agent_capability_policies ADD CONSTRAINT agent_capability_policies_allowed_check
  CHECK (allowed <@ ARRAY['llm.invoke','agents.delegate','agents.discover','stream.output']::text[]);

-- Waking the API (ADR 022 §5.10). Every transaction that changes a stream or
-- an outcome notifies at its commit, through these triggers, so none can
-- forget. The payload is an opaque identifier, never content; PostgreSQL folds
-- identical notifications of one transaction.
CREATE FUNCTION invocation_stream_notify_operation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  PERFORM pg_notify('agentcapsule_invocation_stream', NEW.operation_id);
  RETURN NULL;
END $$;
CREATE FUNCTION invocation_stream_notify_status() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  PERFORM pg_notify('agentcapsule_invocation_stream', NEW.id);
  RETURN NULL;
END $$;
CREATE TRIGGER invocation_stream_chunk_added AFTER INSERT ON invocation_stream_chunks
  FOR EACH ROW EXECUTE FUNCTION invocation_stream_notify_operation();
CREATE TRIGGER invocation_stream_status_changed AFTER UPDATE OF status ON platform_operations
  FOR EACH ROW WHEN (NEW.kind = 'instruction' AND NEW.status IS DISTINCT FROM OLD.status)
  EXECUTE FUNCTION invocation_stream_notify_status();
CREATE TRIGGER invocation_stream_attempt_changed AFTER UPDATE OF attempt ON owner_instructions
  FOR EACH ROW WHEN (NEW.attempt IS DISTINCT FROM OLD.attempt)
  EXECUTE FUNCTION invocation_stream_notify_operation();
CREATE TRIGGER invocation_stream_truncated AFTER UPDATE OF truncated ON invocation_streams
  FOR EACH ROW WHEN (NEW.truncated IS DISTINCT FROM OLD.truncated)
  EXECUTE FUNCTION invocation_stream_notify_operation();

-- An organization's authorization rules changed: subscribers recheck their
-- rights at once rather than at their next periodic check.
CREATE FUNCTION organization_policy_notify() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  PERFORM pg_notify('agentcapsule_organization_policy', NEW.id);
  RETURN NULL;
END $$;
CREATE TRIGGER organization_policy_changed AFTER UPDATE OF policy_version ON organizations
  FOR EACH ROW WHEN (NEW.policy_version IS DISTINCT FROM OLD.policy_version)
  EXECUTE FUNCTION organization_policy_notify();
