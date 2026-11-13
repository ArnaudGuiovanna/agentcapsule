-- Restores of an agent's volume from one of its archives, on its own host
-- (REC-02, ADR 003). A restore moves the volume to a new incarnation. Its row
-- is written before anything stops, in the transaction that takes the volume
-- out of service, so a crash at any step leaves a restore that the operator
-- resumes with the same restore ID. Steps, in order:
--   DRAINING     the volume is RESTORING at the new incarnation
--   INSTALLING   the agent's VMs are retired; the archive is being written
--   RECONCILING  the archive is installed; its restricted boot is inspected
--   ACTIVATED    the restore authority activated the image: losses declared
--   SUCCEEDED    the losses are copied below; the volume is READY again
--   SUPERSEDED   a later restore of the agent replaced this unfinished one
CREATE TABLE volume_restores (
  restore_id text PRIMARY KEY CHECK (restore_id ~ '^rst_[0-9a-f]{32}$'),
  agent_id text NOT NULL,
  host_id text NOT NULL CHECK (host_id <> ''),
  volume_id text NOT NULL,
  archive_id text NOT NULL CHECK (archive_id ~ '^arc_[0-9a-f]{32}$'),
  from_incarnation bigint NOT NULL CHECK (from_incarnation > 0),
  incarnation bigint NOT NULL CHECK (incarnation = from_incarnation + 1),
  step text NOT NULL DEFAULT 'DRAINING'
    CHECK (step IN ('DRAINING','INSTALLING','RECONCILING','ACTIVATED','SUCCEEDED','SUPERSEDED')),
  started_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  activated_at timestamptz,
  completed_at timestamptz,
  CHECK ((step IN ('ACTIVATED','SUCCEEDED')) = (activated_at IS NOT NULL)),
  CHECK ((step IN ('SUCCEEDED','SUPERSEDED')) = (completed_at IS NOT NULL)),
  UNIQUE (agent_id, incarnation),
  UNIQUE (restore_id, incarnation),
  FOREIGN KEY (agent_id, volume_id) REFERENCES store_enrollments(agent_id, volume_id)
);
-- At most one unfinished restore per agent.
CREATE UNIQUE INDEX volume_restores_open ON volume_restores(agent_id)
  WHERE step NOT IN ('SUCCEEDED','SUPERSEDED');
CREATE FUNCTION preserve_volume_restore() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP='DELETE' OR
     (NEW.restore_id,NEW.agent_id,NEW.host_id,NEW.volume_id,NEW.archive_id,NEW.from_incarnation,NEW.incarnation,NEW.started_at)
       IS DISTINCT FROM
     (OLD.restore_id,OLD.agent_id,OLD.host_id,OLD.volume_id,OLD.archive_id,OLD.from_incarnation,OLD.incarnation,OLD.started_at) OR
     (OLD.step,NEW.step) NOT IN (('DRAINING','INSTALLING'),('INSTALLING','RECONCILING'),('RECONCILING','ACTIVATED'),
       ('ACTIVATED','SUCCEEDED'),('DRAINING','SUPERSEDED'),('INSTALLING','SUPERSEDED'),('RECONCILING','SUPERSEDED')) THEN
    RAISE EXCEPTION 'a volume restore only moves forward' USING ERRCODE='23514';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER volume_restore_guard BEFORE UPDATE OR DELETE ON volume_restores
FOR EACH ROW EXECUTE FUNCTION preserve_volume_restore();

-- The losses that a restore declared in the restore authority, copied once
-- the authority activated the image and before the volume is READY again.
-- Each names the outcome and, when the control plane still knows it, the
-- delivery whose outcome it is: its mailbox, and the invocation for an owner
-- instruction. No mailbox: this database lost that work too, within its own
-- loss window. declared_at is when the control plane recorded the loss. Rows
-- are never changed or deleted.
CREATE TABLE volume_restore_losses (
  restore_id text NOT NULL,
  incarnation bigint NOT NULL,
  outcome_id text NOT NULL CHECK (outcome_id ~ '^outcome-v1/[0-9a-f]{64}$'),
  mailbox_id text REFERENCES agent_mailboxes(id),
  invocation_id text REFERENCES owner_instructions(operation_id),
  declared_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (restore_id, outcome_id),
  CHECK (invocation_id IS NULL OR mailbox_id IS NOT NULL),
  FOREIGN KEY (restore_id, incarnation) REFERENCES volume_restores(restore_id, incarnation)
);
CREATE INDEX volume_restore_losses_mailbox ON volume_restore_losses(mailbox_id) WHERE mailbox_id IS NOT NULL;
CREATE FUNCTION preserve_restore_loss() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'a declared loss is permanent' USING ERRCODE='23514';
END
$$;
CREATE TRIGGER volume_restore_loss_guard BEFORE UPDATE OR DELETE ON volume_restore_losses
FOR EACH ROW EXECUTE FUNCTION preserve_restore_loss();

-- A restoring volume serves nothing: no ordinary boot, no archive.
ALTER TABLE store_enrollments DROP CONSTRAINT store_enrollments_stage_check;
ALTER TABLE store_enrollments ADD CONSTRAINT store_enrollments_stage_check
  CHECK (stage IN ('INSTALLING','FENCING','READY','RESTORING'));

-- Each incarnation records its own initialization: the restricted boot of a
-- restored image records the new one.
ALTER TABLE store_initializations DROP CONSTRAINT store_initializations_pkey,
  ADD PRIMARY KEY (agent_id, incarnation);

-- The enrollment guard of the baseline, plus the restore path. A restore is
-- the only change of incarnation: one step up, to the incarnation that its
-- unfinished row reserved, as the volume becomes RESTORING. A restoring volume
-- becomes READY only once its restore is ACTIVATED. Every other rule stands.
CREATE OR REPLACE FUNCTION preserve_enrollment_identity() RETURNS trigger LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
  IF (NEW.agent_id,NEW.operation_id,NEW.volume_id) IS DISTINCT FROM (OLD.agent_id,OLD.operation_id,OLD.volume_id) OR
     (OLD.stage<>'INSTALLING' AND (NEW.volume_device,NEW.volume_inode) IS DISTINCT FROM
       (OLD.volume_device,OLD.volume_inode)) OR
     (OLD.stage='FENCING' AND NEW.stage='INSTALLING') OR
     (OLD.stage IN ('INSTALLING','FENCING') AND NEW.stage='RESTORING') THEN
    RAISE EXCEPTION 'enrollment identity cannot be replaced or reset' USING ERRCODE='23514';
  END IF;
  IF NEW.incarnation IS DISTINCT FROM OLD.incarnation THEN
    IF NEW.stage<>'RESTORING' OR OLD.stage NOT IN ('READY','RESTORING') OR NEW.incarnation<>OLD.incarnation+1 OR
       NOT EXISTS(SELECT 1 FROM volume_restores r WHERE r.agent_id=NEW.agent_id AND r.volume_id=NEW.volume_id
         AND r.from_incarnation=OLD.incarnation AND r.incarnation=NEW.incarnation AND r.step='DRAINING') THEN
      RAISE EXCEPTION 'only a restore changes the incarnation' USING ERRCODE='23514';
    END IF;
  ELSIF OLD.stage='READY' AND NEW.stage<>'READY' THEN
    RAISE EXCEPTION 'enrollment identity cannot be replaced or reset' USING ERRCODE='23514';
  ELSIF OLD.stage='RESTORING' AND NEW.stage<>'RESTORING' AND NOT (NEW.stage='READY' AND
      EXISTS(SELECT 1 FROM volume_restores r WHERE r.agent_id=NEW.agent_id AND r.incarnation=NEW.incarnation AND r.step='ACTIVATED')) THEN
    RAISE EXCEPTION 'a restoring volume is ready only once its restore is activated' USING ERRCODE='23514';
  END IF;
  RETURN NEW;
END
$$;
