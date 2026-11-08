-- Asynchronous invocation results (EVT-01/CAP-01 correction).
--
-- An instruction is delivered under an exclusive host admission turn, and the
-- guest's own platform calls (attachments, model, peers) wait behind it. So an
-- agent that needs the platform to do its work cannot answer within the delivery.
-- It may instead acknowledge "working": delivery is then final (FIFO advances),
-- the operation stays RUNNING, and the agent posts the result later, once, over
-- the platform channel, before result_due_at. Delivery semantics are unchanged.
ALTER TABLE owner_instructions
  ADD COLUMN work_timeout_seconds integer NOT NULL DEFAULT 3600 CHECK (work_timeout_seconds BETWEEN 60 AND 86400),
  ADD COLUMN working_since timestamptz,
  ADD COLUMN result_due_at timestamptz,
  ADD COLUMN completion_key text CHECK (completion_key IS NULL OR length(completion_key) BETWEEN 1 AND 256),
  ADD COLUMN completion_hash bytea CHECK (completion_hash IS NULL OR octet_length(completion_hash) = 32),
  ADD CONSTRAINT owner_instructions_working CHECK (
    (working_since IS NULL) = (result_due_at IS NULL) AND (result_due_at IS NULL OR result_due_at > working_since)
    AND (completion_key IS NULL) = (completion_hash IS NULL)
    AND (completion_key IS NULL OR working_since IS NOT NULL));
CREATE INDEX owner_instructions_working_due ON owner_instructions(result_due_at)
  WHERE working_since IS NOT NULL AND completion_key IS NULL;
