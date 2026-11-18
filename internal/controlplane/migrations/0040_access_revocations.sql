-- Access revocation records (ADR 006 wave 5; ADR 005, "What the code must
-- do", items 6 and 7). Each transaction that revokes access appends its
-- record to the authority service before it commits here. This row is the
-- API's view of that record: confirmed once the standby's replica holds it
-- (at once without a standby, and at once for a bearer token's in degraded
-- mode), pending until then. tenant_id is the organization whose
-- administrators and auditors read it, NULL for the platform's own
-- revocations; organization_id is the organization whose access it revokes.
-- objects names the revoked objects, as the record does. Rows are never
-- deleted; a pending row only becomes confirmed.
CREATE TABLE access_revocations (
  id text PRIMARY KEY CHECK (id ~ '^arv_[0-9a-f]{32}$'),
  tenant_id text,
  organization_id text,
  kind text NOT NULL CHECK (kind IN ('api_token','service_token','platform_credential','delegated_token',
    'member','principal','organization','team','team_membership','assignment','mandate','delegation_trust','llm_provider')),
  objects jsonb NOT NULL CHECK (jsonb_typeof(objects) = 'array'),
  epoch bigint NOT NULL CHECK (epoch > 0),
  seq bigint NOT NULL CHECK (seq >= 0),
  state text NOT NULL CHECK (state IN ('pending','confirmed')),
  recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  confirmed_at timestamptz,
  CHECK ((state = 'confirmed') = (confirmed_at IS NOT NULL))
);
CREATE INDEX access_revocations_pending ON access_revocations(recorded_at, id) WHERE state = 'pending';
CREATE INDEX access_revocations_tenant ON access_revocations(tenant_id, recorded_at);

CREATE FUNCTION preserve_access_revocation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'UPDATE' AND OLD.state = 'pending' AND NEW.state = 'confirmed'
     AND (NEW.id, NEW.tenant_id, NEW.organization_id, NEW.kind, NEW.objects, NEW.epoch, NEW.seq, NEW.recorded_at)
         IS NOT DISTINCT FROM (OLD.id, OLD.tenant_id, OLD.organization_id, OLD.kind, OLD.objects, OLD.epoch, OLD.seq, OLD.recorded_at) THEN
    RETURN NEW;
  END IF;
  RAISE EXCEPTION 'an access revocation is permanent; only its confirmation changes it' USING ERRCODE='23514';
END
$$;
CREATE TRIGGER access_revocation_guard BEFORE UPDATE OR DELETE ON access_revocations
FOR EACH ROW EXECUTE FUNCTION preserve_access_revocation();
