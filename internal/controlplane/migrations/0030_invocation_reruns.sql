-- Reruns of the invocations that a restore lost (REC-02, ADR 003). The
-- transaction that copies a restore's losses and puts the volume back in
-- service also decides, for each lost invocation, whether it runs again under
-- the same mailbox ID:
--   queued   the mailbox is back in the queue; the rerun is pending until the
--            invocation ends again
--   skipped  it does not run again; skip_reason says why
-- A queued rerun becomes skipped when its requester is revoked before the
-- rerun reaches the agent. Nothing else changes a row, and no row is deleted.
ALTER TABLE volume_restore_losses ADD CONSTRAINT volume_restore_losses_invocation_key
  UNIQUE (restore_id, outcome_id, invocation_id);
CREATE INDEX volume_restore_losses_invocation ON volume_restore_losses(invocation_id) WHERE invocation_id IS NOT NULL;

CREATE TABLE invocation_reruns (
  restore_id text NOT NULL,
  outcome_id text NOT NULL,
  invocation_id text NOT NULL REFERENCES owner_instructions(operation_id),
  state text NOT NULL CHECK (state IN ('queued','skipped')),
  skip_reason text NOT NULL DEFAULT ''
    CHECK (skip_reason IN ('','requester_revoked','agent_unavailable','input_purged','attachments_purged')),
  decided_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (restore_id, outcome_id),
  UNIQUE (restore_id, invocation_id),
  CHECK ((state = 'skipped') = (skip_reason <> '')),
  FOREIGN KEY (restore_id, outcome_id, invocation_id)
    REFERENCES volume_restore_losses(restore_id, outcome_id, invocation_id)
);
CREATE INDEX invocation_reruns_invocation ON invocation_reruns(invocation_id);
CREATE FUNCTION preserve_invocation_rerun() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP='DELETE' OR
     (NEW.restore_id,NEW.outcome_id,NEW.invocation_id) IS DISTINCT FROM (OLD.restore_id,OLD.outcome_id,OLD.invocation_id) OR
     NOT (OLD.state='queued' AND NEW.state='skipped') THEN
    RAISE EXCEPTION 'a rerun only moves from queued to skipped' USING ERRCODE='23514';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER invocation_rerun_guard BEFORE UPDATE OR DELETE ON invocation_reruns
FOR EACH ROW EXECUTE FUNCTION preserve_invocation_rerun();
