-- Access revocations are recorded after their commit (ADR 006, "Changes
-- after the v0.1.0 audit"). The revoking transaction commits its effect and
-- this row, in state recording, without waiting for the authority service
-- under its locks. Once it has committed, the API appends the record with no
-- lock held, then sets the row to pending or confirmed with the epoch and
-- sequence number of the stream's record; a row the API could not record is
-- recorded by its next pass (every 5 seconds) or by the reconciliation. A
-- rolled-back transaction leaves no record in the authority service.
ALTER TABLE access_revocations ALTER COLUMN epoch DROP NOT NULL, ALTER COLUMN seq DROP NOT NULL;
ALTER TABLE access_revocations DROP CONSTRAINT access_revocations_state_check;
ALTER TABLE access_revocations ADD CONSTRAINT access_revocations_state_check CHECK (state IN ('recording','pending','confirmed'));
ALTER TABLE access_revocations ADD CONSTRAINT access_revocations_recorded
  CHECK ((state = 'recording') = (epoch IS NULL) AND (epoch IS NULL) = (seq IS NULL));
CREATE INDEX access_revocations_recording ON access_revocations(recorded_at, id) WHERE state = 'recording';

-- A row only moves forward: recording to pending or confirmed, taking its
-- record's epoch and sequence number, and pending to confirmed. Nothing else
-- in it changes, and it is never deleted.
CREATE OR REPLACE FUNCTION preserve_access_revocation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'UPDATE'
     AND (NEW.id, NEW.tenant_id, NEW.organization_id, NEW.kind, NEW.objects, NEW.recorded_at)
         IS NOT DISTINCT FROM (OLD.id, OLD.tenant_id, OLD.organization_id, OLD.kind, OLD.objects, OLD.recorded_at)
     AND ((OLD.state = 'pending' AND NEW.state = 'confirmed'
           AND (NEW.epoch, NEW.seq) IS NOT DISTINCT FROM (OLD.epoch, OLD.seq))
       OR (OLD.state = 'recording' AND NEW.state IN ('pending', 'confirmed') AND OLD.epoch IS NULL AND NEW.epoch IS NOT NULL)) THEN
    RETURN NEW;
  END IF;
  RAISE EXCEPTION 'an access revocation is permanent; only its recording and its confirmation change it' USING ERRCODE='23514';
END
$$;
