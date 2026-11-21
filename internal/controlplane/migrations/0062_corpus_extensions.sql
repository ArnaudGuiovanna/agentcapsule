CREATE TABLE corpus_enrichers (
 id text PRIMARY KEY, tenant_id text NOT NULL REFERENCES organizations(id), name text NOT NULL CHECK(name ~ '^[a-z0-9][a-z0-9_-]{0,62}$'),
 release_id text NOT NULL REFERENCES harness_releases(id), authorized_by text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(), UNIQUE(tenant_id,id), UNIQUE(tenant_id,name),
 FOREIGN KEY(tenant_id,authorized_by) REFERENCES principals(tenant_id,id)
);
-- Only remove checks from migration 60 whose definition refers to kind.
DO $$ DECLARE c record;
BEGIN
 FOR c IN SELECT conname FROM pg_constraint WHERE conrelid='agents'::regclass AND contype='c'
  AND (SELECT attnum FROM pg_attribute WHERE attrelid='agents'::regclass AND attname='kind')=ANY(conkey) LOOP
  EXECUTE format('ALTER TABLE agents DROP CONSTRAINT %I',c.conname);
 END LOOP;
END $$;
ALTER TABLE agents ADD COLUMN enricher_id text,
 ADD CHECK(kind IN ('agent','corpus_builder','corpus_enricher')),
 ADD CHECK((kind<>'agent')=(builder_principal IS NOT NULL)),
 ADD CHECK((kind='corpus_enricher')=(enricher_id IS NOT NULL)),
 ADD CHECK(kind='agent' OR (tenant_id IS NOT NULL AND NOT discoverable)),
 ADD FOREIGN KEY(tenant_id,enricher_id) REFERENCES corpus_enrichers(tenant_id,id);
CREATE UNIQUE INDEX corpus_enricher_agent ON agents(tenant_id,enricher_id) WHERE kind='corpus_enricher';
CREATE TABLE corpus_extensions (
 id text PRIMARY KEY CHECK(id ~ '^cex_[0-9a-f]{32}$'), tenant_id text NOT NULL, build_id text NOT NULL, enricher_id text NOT NULL,
 state text NOT NULL DEFAULT 'QUEUED' CHECK(state IN ('QUEUED','RUNNING','READY','FAILED','CANCELED')),
 agent_id text, invocation_id text REFERENCES platform_operations(id), error_code text,
 image_digest text CHECK(image_digest ~ '^sha256:[0-9a-f]{64}$'), image_uuid uuid, image_bytes bigint CHECK(image_bytes>0),
 lease_token text, lease_until timestamptz, next_attempt_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 deadline_at timestamptz NOT NULL DEFAULT clock_timestamp()+interval '24 hours', created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(build_id,enricher_id), UNIQUE(tenant_id,id),
 FOREIGN KEY(tenant_id,build_id) REFERENCES corpus_builds(tenant_id,id),
 FOREIGN KEY(tenant_id,enricher_id) REFERENCES corpus_enrichers(tenant_id,id),
 FOREIGN KEY(tenant_id,agent_id) REFERENCES agents(tenant_id,id),
 CHECK((lease_token IS NULL)=(lease_until IS NULL)), CHECK((state='FAILED')=(error_code IS NOT NULL)),
 CHECK((state='READY')=(image_bytes IS NOT NULL AND image_digest IS NOT NULL AND image_uuid IS NOT NULL))
);
CREATE INDEX corpus_extension_queue ON corpus_extensions(state,next_attempt_at,created_at);
CREATE UNIQUE INDEX one_running_corpus_enricher ON corpus_extensions(enricher_id) WHERE state='RUNNING';
ALTER TABLE corpus_releases ADD COLUMN extensions jsonb NOT NULL DEFAULT '[]' CHECK(jsonb_typeof(extensions)='array');
ALTER TABLE corpus_audit DROP CONSTRAINT corpus_audit_action_check,
 ADD CHECK(action IN ('source_credential.created','source_credential.rotated','source_credential.disabled',
 'corpus.created','corpus_build.requested','corpus_build.canceled','corpus_build.tried','corpus_build.published',
 'corpus_release.deprecated','corpus_enricher.authorized','corpus_extension.requested')),
 ADD COLUMN enricher_id text, ADD COLUMN extension_id text,
 ADD FOREIGN KEY(tenant_id,enricher_id) REFERENCES corpus_enrichers(tenant_id,id),
 ADD FOREIGN KEY(tenant_id,extension_id) REFERENCES corpus_extensions(tenant_id,id);
ALTER TABLE system_images DROP CONSTRAINT system_images_features_check,
 ADD CHECK(features <@ ARRAY['corpus.mount','corpus.extensions']::text[] AND ('corpus.extensions'<>ALL(features) OR 'corpus.mount'=ANY(features)));
