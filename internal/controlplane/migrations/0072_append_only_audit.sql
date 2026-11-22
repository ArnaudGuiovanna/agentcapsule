-- The audit trail is append-only, and its feed never skips an event that
-- commits late (ADR 014, "Changes after the v0.1.0 audit", finding L-03).
--
-- An event is never changed, and deleted only by the retention purge
-- (PurgeAudit): an event older than the retention the operator set. Until
-- v0.1.0 the roles that write the trail could change or delete any of its
-- rows. preserve_audit_event refuses every other change, and TRUNCATE. Its
-- first argument names the column the retention counts from; the others
-- name columns that may change (none so far): a later migration that lets a
-- column change recreates the table's trigger with it.
CREATE FUNCTION preserve_audit_event() RETURNS trigger LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
DECLARE
  days integer;
BEGIN
  IF TG_OP = 'DELETE' THEN
    SELECT retention_days INTO days FROM audit_retention;
    IF days IS NOT NULL AND (to_jsonb(OLD) ->> TG_ARGV[0])::timestamptz < clock_timestamp() - make_interval(days => days) THEN
      RETURN OLD;
    END IF;
  ELSIF TG_OP = 'UPDATE' THEN
    IF to_jsonb(NEW) - TG_ARGV[1:] = to_jsonb(OLD) - TG_ARGV[1:] THEN
      RETURN NEW;
    END IF;
  END IF;
  RAISE EXCEPTION 'the audit trail is append-only (%, %)', TG_TABLE_NAME, TG_OP USING ERRCODE = '23514';
END
$$;

-- Only the schema's owner, which agentcapsule-admin set-audit-retention runs
-- as, sets the retention: a service role cannot shorten it to purge recent
-- events. The worker reads it under a row lock, which fires no trigger.
CREATE FUNCTION preserve_audit_retention() RETURNS trigger LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
  IF NOT pg_has_role(current_user, (SELECT relowner FROM pg_class WHERE oid = TG_RELID), 'USAGE') THEN
    RAISE EXCEPTION 'only the owner of the schema sets the audit retention' USING ERRCODE = '42501';
  END IF;
  IF TG_OP = 'DELETE' THEN
    RETURN OLD;
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER audit_retention_owner BEFORE INSERT OR UPDATE OR DELETE ON audit_retention
FOR EACH ROW EXECUTE FUNCTION preserve_audit_retention();

-- An organization's feed (GET /v1/audit) pages on (created_at, id). An event
-- was stamped when inserted, not when its transaction committed: a page read
-- while an older transaction was still open moved past its event, which then
-- committed behind the cursor and was never read. Now each event of the
-- feed's tables is stamped once its transaction holds its organization's
-- feed lock, in shared mode, which it keeps until it commits. A page is read
-- up to a horizon taken before the reader looks at that lock's holders, and
-- once those holders have ended (ListAudit): every event stamped before the
-- horizon has then committed or rolled back, and a later one is stamped after
-- it. Writers never wait on each other or on a reader.
CREATE FUNCTION stamp_audit_event() RETURNS trigger LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
  PERFORM pg_advisory_xact_lock_shared(756610047, hashtext(NEW.tenant_id));
  IF TG_ARGV[0] = 'replayed_at' THEN
    NEW.replayed_at := clock_timestamp();
  ELSE
    NEW.created_at := clock_timestamp();
  END IF;
  RETURN NEW;
END
$$;

-- The audit tables (operations.go, auditTables): append-only, and those of
-- the organizations' feed (audit_feed.go, auditUnion) stamped under the lock.
CREATE TRIGGER application_audit_append_only BEFORE UPDATE OR DELETE ON application_audit FOR EACH ROW EXECUTE FUNCTION preserve_audit_event('created_at');
CREATE TRIGGER application_audit_no_truncate BEFORE TRUNCATE ON application_audit FOR EACH STATEMENT EXECUTE FUNCTION preserve_audit_event('created_at');
CREATE TRIGGER application_audit_stamp BEFORE INSERT ON application_audit FOR EACH ROW EXECUTE FUNCTION stamp_audit_event('created_at');
CREATE TRIGGER organization_audit_append_only BEFORE UPDATE OR DELETE ON organization_audit FOR EACH ROW EXECUTE FUNCTION preserve_audit_event('created_at');
CREATE TRIGGER organization_audit_no_truncate BEFORE TRUNCATE ON organization_audit FOR EACH STATEMENT EXECUTE FUNCTION preserve_audit_event('created_at');
CREATE TRIGGER organization_audit_stamp BEFORE INSERT ON organization_audit FOR EACH ROW EXECUTE FUNCTION stamp_audit_event('created_at');
CREATE TRIGGER delegation_audit_append_only BEFORE UPDATE OR DELETE ON delegation_audit FOR EACH ROW EXECUTE FUNCTION preserve_audit_event('created_at');
CREATE TRIGGER delegation_audit_no_truncate BEFORE TRUNCATE ON delegation_audit FOR EACH STATEMENT EXECUTE FUNCTION preserve_audit_event('created_at');
CREATE TRIGGER delegation_audit_stamp BEFORE INSERT ON delegation_audit FOR EACH ROW EXECUTE FUNCTION stamp_audit_event('created_at');
CREATE TRIGGER tenant_member_audit_append_only BEFORE UPDATE OR DELETE ON tenant_member_audit FOR EACH ROW EXECUTE FUNCTION preserve_audit_event('created_at');
CREATE TRIGGER tenant_member_audit_no_truncate BEFORE TRUNCATE ON tenant_member_audit FOR EACH STATEMENT EXECUTE FUNCTION preserve_audit_event('created_at');
CREATE TRIGGER tenant_member_audit_stamp BEFORE INSERT ON tenant_member_audit FOR EACH ROW EXECUTE FUNCTION stamp_audit_event('created_at');
CREATE TRIGGER tenant_team_audit_append_only BEFORE UPDATE OR DELETE ON tenant_team_audit FOR EACH ROW EXECUTE FUNCTION preserve_audit_event('created_at');
CREATE TRIGGER tenant_team_audit_no_truncate BEFORE TRUNCATE ON tenant_team_audit FOR EACH STATEMENT EXECUTE FUNCTION preserve_audit_event('created_at');
CREATE TRIGGER tenant_team_audit_stamp BEFORE INSERT ON tenant_team_audit FOR EACH ROW EXECUTE FUNCTION stamp_audit_event('created_at');
CREATE TRIGGER tenant_agent_audit_append_only BEFORE UPDATE OR DELETE ON tenant_agent_audit FOR EACH ROW EXECUTE FUNCTION preserve_audit_event('created_at');
CREATE TRIGGER tenant_agent_audit_no_truncate BEFORE TRUNCATE ON tenant_agent_audit FOR EACH STATEMENT EXECUTE FUNCTION preserve_audit_event('created_at');
CREATE TRIGGER tenant_agent_audit_stamp BEFORE INSERT ON tenant_agent_audit FOR EACH ROW EXECUTE FUNCTION stamp_audit_event('created_at');
CREATE TRIGGER tenant_service_audit_append_only BEFORE UPDATE OR DELETE ON tenant_service_audit FOR EACH ROW EXECUTE FUNCTION preserve_audit_event('created_at');
CREATE TRIGGER tenant_service_audit_no_truncate BEFORE TRUNCATE ON tenant_service_audit FOR EACH STATEMENT EXECUTE FUNCTION preserve_audit_event('created_at');
CREATE TRIGGER tenant_service_audit_stamp BEFORE INSERT ON tenant_service_audit FOR EACH ROW EXECUTE FUNCTION stamp_audit_event('created_at');
CREATE TRIGGER llm_audit_append_only BEFORE UPDATE OR DELETE ON llm_audit FOR EACH ROW EXECUTE FUNCTION preserve_audit_event('created_at');
CREATE TRIGGER llm_audit_no_truncate BEFORE TRUNCATE ON llm_audit FOR EACH STATEMENT EXECUTE FUNCTION preserve_audit_event('created_at');
CREATE TRIGGER llm_audit_stamp BEFORE INSERT ON llm_audit FOR EACH ROW EXECUTE FUNCTION stamp_audit_event('created_at');
CREATE TRIGGER queue_audit_append_only BEFORE UPDATE OR DELETE ON queue_audit FOR EACH ROW EXECUTE FUNCTION preserve_audit_event('created_at');
CREATE TRIGGER queue_audit_no_truncate BEFORE TRUNCATE ON queue_audit FOR EACH STATEMENT EXECUTE FUNCTION preserve_audit_event('created_at');
CREATE TRIGGER queue_audit_stamp BEFORE INSERT ON queue_audit FOR EACH ROW EXECUTE FUNCTION stamp_audit_event('created_at');
CREATE TRIGGER harness_audit_append_only BEFORE UPDATE OR DELETE ON harness_audit FOR EACH ROW EXECUTE FUNCTION preserve_audit_event('created_at');
CREATE TRIGGER harness_audit_no_truncate BEFORE TRUNCATE ON harness_audit FOR EACH STATEMENT EXECUTE FUNCTION preserve_audit_event('created_at');
CREATE TRIGGER platform_audit_append_only BEFORE UPDATE OR DELETE ON platform_audit FOR EACH ROW EXECUTE FUNCTION preserve_audit_event('created_at');
CREATE TRIGGER platform_audit_no_truncate BEFORE TRUNCATE ON platform_audit FOR EACH STATEMENT EXECUTE FUNCTION preserve_audit_event('created_at');
CREATE TRIGGER operator_audit_append_only BEFORE UPDATE OR DELETE ON operator_audit FOR EACH ROW EXECUTE FUNCTION preserve_audit_event('created_at');
CREATE TRIGGER operator_audit_no_truncate BEFORE TRUNCATE ON operator_audit FOR EACH STATEMENT EXECUTE FUNCTION preserve_audit_event('created_at');
CREATE TRIGGER deployment_audit_append_only BEFORE UPDATE OR DELETE ON deployment_audit FOR EACH ROW EXECUTE FUNCTION preserve_audit_event('created_at');
CREATE TRIGGER deployment_audit_no_truncate BEFORE TRUNCATE ON deployment_audit FOR EACH STATEMENT EXECUTE FUNCTION preserve_audit_event('created_at');
CREATE TRIGGER deployment_audit_stamp BEFORE INSERT ON deployment_audit FOR EACH ROW EXECUTE FUNCTION stamp_audit_event('created_at');
CREATE TRIGGER capability_audit_append_only BEFORE UPDATE OR DELETE ON capability_audit FOR EACH ROW EXECUTE FUNCTION preserve_audit_event('created_at');
CREATE TRIGGER capability_audit_no_truncate BEFORE TRUNCATE ON capability_audit FOR EACH STATEMENT EXECUTE FUNCTION preserve_audit_event('created_at');
CREATE TRIGGER capability_audit_stamp BEFORE INSERT ON capability_audit FOR EACH ROW EXECUTE FUNCTION stamp_audit_event('created_at');
CREATE TRIGGER instruction_replays_append_only BEFORE UPDATE OR DELETE ON instruction_replays FOR EACH ROW EXECUTE FUNCTION preserve_audit_event('replayed_at');
CREATE TRIGGER instruction_replays_no_truncate BEFORE TRUNCATE ON instruction_replays FOR EACH STATEMENT EXECUTE FUNCTION preserve_audit_event('replayed_at');
CREATE TRIGGER instruction_replays_stamp BEFORE INSERT ON instruction_replays FOR EACH ROW EXECUTE FUNCTION stamp_audit_event('replayed_at');
CREATE TRIGGER tenant_refusal_audit_append_only BEFORE UPDATE OR DELETE ON tenant_refusal_audit FOR EACH ROW EXECUTE FUNCTION preserve_audit_event('created_at');
CREATE TRIGGER tenant_refusal_audit_no_truncate BEFORE TRUNCATE ON tenant_refusal_audit FOR EACH STATEMENT EXECUTE FUNCTION preserve_audit_event('created_at');
CREATE TRIGGER tenant_refusal_audit_stamp BEFORE INSERT ON tenant_refusal_audit FOR EACH ROW EXECUTE FUNCTION stamp_audit_event('created_at');
CREATE TRIGGER corpus_audit_append_only BEFORE UPDATE OR DELETE ON corpus_audit FOR EACH ROW EXECUTE FUNCTION preserve_audit_event('created_at');
CREATE TRIGGER corpus_audit_no_truncate BEFORE TRUNCATE ON corpus_audit FOR EACH STATEMENT EXECUTE FUNCTION preserve_audit_event('created_at');
CREATE TRIGGER corpus_audit_stamp BEFORE INSERT ON corpus_audit FOR EACH ROW EXECUTE FUNCTION stamp_audit_event('created_at');
