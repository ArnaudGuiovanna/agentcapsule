-- Redeliveries of the agent-to-agent events that a restore lost (REC-02,
-- ADR 008). The transaction that copies a restore's losses and puts the
-- volume back in service also decides, for each lost request, reply or
-- status that PostgreSQL recorded as delivered, whether it is delivered again
-- under the same mailbox ID:
--   queued   the mailbox is back in the queue, at its place
--   skipped  it is not delivered again; skip_reason says why
-- A request in a final state never reopens (request_closed). Rows are never
-- changed or deleted.
ALTER TABLE volume_restore_losses ADD CONSTRAINT volume_restore_losses_mailbox_key
  UNIQUE (restore_id, outcome_id, mailbox_id);

CREATE TABLE peer_redeliveries (
  restore_id text NOT NULL,
  outcome_id text NOT NULL,
  mailbox_id text NOT NULL REFERENCES agent_mailboxes(id),
  request_id text NOT NULL REFERENCES agent_requests(id),
  kind text NOT NULL CHECK (kind IN ('request','reply','status')),
  state text NOT NULL CHECK (state IN ('queued','skipped')),
  skip_reason text NOT NULL DEFAULT ''
    CHECK (skip_reason IN ('','request_closed','agent_unavailable','requester_revoked','content_purged')),
  decided_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (restore_id, outcome_id),
  UNIQUE (restore_id, mailbox_id),
  CHECK ((state = 'skipped') = (skip_reason <> '')),
  FOREIGN KEY (restore_id, outcome_id, mailbox_id)
    REFERENCES volume_restore_losses(restore_id, outcome_id, mailbox_id)
);
CREATE INDEX peer_redeliveries_request ON peer_redeliveries(request_id);
CREATE FUNCTION preserve_peer_redelivery() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'a redelivery decision is permanent' USING ERRCODE='23514';
END
$$;
CREATE TRIGGER peer_redelivery_guard BEFORE UPDATE OR DELETE ON peer_redeliveries
FOR EACH ROW EXECUTE FUNCTION preserve_peer_redelivery();
