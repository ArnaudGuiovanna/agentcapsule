-- The authority stream lives outside the restored PostgreSQL domain. On
-- recovery this permanent record also covers an agent whose application,
-- policy or intended principal had yet to exist in the restored database.
ALTER TABLE access_revocations DROP CONSTRAINT access_revocations_kind_check;
ALTER TABLE access_revocations ADD CONSTRAINT access_revocations_kind_check
  CHECK (kind IN ('api_token','service_token','platform_credential','delegated_token','blanket',
    'member','principal','organization','team','team_membership','assignment','mandate','delegation_trust','llm_provider','personal_volume'));
ALTER TABLE access_revocations ADD CONSTRAINT personal_volume_hold_identity
  CHECK (kind <> 'personal_volume' OR
    (organization_id IS NOT NULL AND jsonb_array_length(objects)=1 AND jsonb_typeof(objects->0)='array' AND jsonb_array_length(objects->0)=3));
CREATE INDEX personal_volume_hold_agent ON access_revocations(organization_id, (objects->0->>0)) WHERE kind='personal_volume';
CREATE VIEW personal_volume_holds AS SELECT organization_id AS tenant_id, objects->0->>0 AS agent_id,
  objects->0->>1 AS volume_id, objects->0->>2 AS principal_id FROM access_revocations WHERE kind='personal_volume';
CREATE INDEX application_audit_retention ON application_audit(created_at);
