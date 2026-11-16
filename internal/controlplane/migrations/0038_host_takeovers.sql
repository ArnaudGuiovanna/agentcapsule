-- A host lost in a disaster, and the host that takes its agents over
-- (REC-02, REC-03, ADR 020). The operator records it once the lost host is
-- fenced, and it is final: a lost host never serves again. A lost host's
-- worker gets no work, and no agent is reserved on it. Its agents move to the
-- new host one at a time, each in the transaction that begins its restore
-- from an archive (volume_relocations). Rows are never changed or deleted.
CREATE TABLE host_takeovers (
  lost_host_id text PRIMARY KEY REFERENCES worker_hosts(host_id),
  host_id text NOT NULL REFERENCES worker_hosts(host_id),
  taken_over_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CHECK (host_id <> lost_host_id)
);
CREATE FUNCTION preserve_host_takeover() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'a host takeover is permanent' USING ERRCODE='23514';
END
$$;
CREATE TRIGGER host_takeover_guard BEFORE UPDATE OR DELETE ON host_takeovers
FOR EACH ROW EXECUTE FUNCTION preserve_host_takeover();
-- The takeover is an audited operator command (ADR 014), refused for a host
-- that is itself lost.
ALTER TABLE operator_audit DROP CONSTRAINT operator_audit_action_check,
  ADD CONSTRAINT operator_audit_action_check
  CHECK (action IN ('credential.revoked','provisioning.abandoned','audit.retention_set','audit.purged','host.taken_over'));
ALTER TABLE operator_audit DROP CONSTRAINT operator_audit_reason_check,
  ADD CONSTRAINT operator_audit_reason_check
  CHECK (reason IN ('','invalid_input','not_found','conflict','forbidden','host_lost'));

-- The restores that moved an agent off a lost host: the host it was on, and
-- the identity of the volume file it had there. The new host creates a new
-- volume file, of the same volume ID and key, and records its identity, here
-- and in store_enrollments, before it installs the archive there. Until then
-- the relocation is pending. Rows are never deleted; a pending one is
-- completed once, and nothing else changes.
CREATE TABLE volume_relocations (
  restore_id text PRIMARY KEY REFERENCES volume_restores(restore_id),
  agent_id text NOT NULL,
  from_host_id text NOT NULL REFERENCES host_takeovers(lost_host_id),
  host_id text NOT NULL CHECK (host_id <> from_host_id),
  from_volume_device text NOT NULL CHECK (from_volume_device ~ '^[0-9a-f]{16}$'),
  from_volume_inode text NOT NULL CHECK (from_volume_inode ~ '^[0-9a-f]{16}$'),
  relocated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  volume_device text CHECK (volume_device ~ '^[0-9a-f]{16}$'),
  volume_inode text CHECK (volume_inode ~ '^[0-9a-f]{16}$'),
  recorded_at timestamptz,
  CHECK ((volume_device IS NULL) = (volume_inode IS NULL) AND (volume_device IS NULL) = (recorded_at IS NULL))
);
CREATE INDEX volume_relocations_agent ON volume_relocations(agent_id);
CREATE INDEX volume_relocations_from ON volume_relocations(from_host_id);
CREATE FUNCTION preserve_volume_relocation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP='DELETE' OR OLD.recorded_at IS NOT NULL OR
     (NEW.restore_id,NEW.agent_id,NEW.from_host_id,NEW.host_id,NEW.from_volume_device,NEW.from_volume_inode,NEW.relocated_at)
       IS DISTINCT FROM
     (OLD.restore_id,OLD.agent_id,OLD.from_host_id,OLD.host_id,OLD.from_volume_device,OLD.from_volume_inode,OLD.relocated_at) THEN
    RAISE EXCEPTION 'a volume relocation is completed once and never changed' USING ERRCODE='23514';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER volume_relocation_guard BEFORE UPDATE OR DELETE ON volume_relocations
FOR EACH ROW EXECUTE FUNCTION preserve_volume_relocation();

-- The enrollment guard of 0029, plus relocation. The volume file's identity
-- changes from the lost host's to the new host's while a relocation of the
-- agent is pending, the volume RESTORING, before the archive is installed: a
-- restore of the agent at that incarnation is DRAINING or INSTALLING. Every
-- other rule stands.
CREATE OR REPLACE FUNCTION preserve_enrollment_identity() RETURNS trigger LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
  IF (NEW.agent_id,NEW.operation_id,NEW.volume_id) IS DISTINCT FROM (OLD.agent_id,OLD.operation_id,OLD.volume_id) OR
     (OLD.stage<>'INSTALLING' AND (NEW.volume_device,NEW.volume_inode) IS DISTINCT FROM (OLD.volume_device,OLD.volume_inode)
       AND NOT (OLD.stage='RESTORING' AND NEW.stage='RESTORING' AND NEW.incarnation=OLD.incarnation
         AND NEW.volume_device IS NOT NULL AND NEW.volume_inode IS NOT NULL
         AND EXISTS(SELECT 1 FROM volume_relocations l WHERE l.agent_id=NEW.agent_id AND l.recorded_at IS NULL)
         AND EXISTS(SELECT 1 FROM volume_restores r WHERE r.agent_id=NEW.agent_id AND r.volume_id=NEW.volume_id
           AND r.incarnation=NEW.incarnation AND r.step IN ('DRAINING','INSTALLING')))) OR
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
