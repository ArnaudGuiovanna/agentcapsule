-- Organization-scoped builds and immutable releases (ADR 023).
CREATE TABLE corpora (
 id text PRIMARY KEY, tenant_id text NOT NULL REFERENCES organizations(id),
 name text NOT NULL CHECK (name ~ '^[a-z0-9][a-z0-9._-]{0,99}$'), title text NOT NULL DEFAULT '',
 source_kind text NOT NULL CHECK (source_kind IN ('github','gitlab')), source_url text NOT NULL,
 source_ref text NOT NULL, source_path text NOT NULL, source_credential_id text,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(tenant_id,id), UNIQUE(tenant_id,name),
 FOREIGN KEY(tenant_id,source_credential_id) REFERENCES source_credentials(tenant_id,id)
);

CREATE TABLE corpus_builds (
 id text PRIMARY KEY CHECK(id ~ '^cbd_[0-9a-f]{32}$'), tenant_id text NOT NULL, corpus_id text NOT NULL,
 state text NOT NULL DEFAULT 'QUEUED' CHECK (state IN ('QUEUED','FETCHING','SCANNING','FETCHING_LFS','CONVERTING','PACKAGING','REVIEW','PUBLISHED','FAILED','CANCELED','EXPIRED')),
 requested_ref text NOT NULL, commit_sha text CHECK(commit_sha ~ '^[0-9a-f]{40}$'), host_id text, builder text,
 source_drive jsonb, lfs_drive jsonb, pointers jsonb NOT NULL DEFAULT '[]', scan_cursor text,
 attempts integer NOT NULL DEFAULT 0, phase_attempts integer NOT NULL DEFAULT 0,
 next_attempt_at timestamptz NOT NULL DEFAULT clock_timestamp(), lease_token text, lease_until timestamptz,
 estimate jsonb, invocation_id text, builder_agent_id text, files jsonb NOT NULL DEFAULT '{}', costs jsonb NOT NULL DEFAULT '{}',
 image_digest text CHECK(image_digest ~ '^sha256:[0-9a-f]{64}$'), image_uuid uuid, image_bytes bigint CHECK(image_bytes>0),
 release_id text, review_truncated boolean NOT NULL DEFAULT false,
 error_code text CHECK(error_code IN ('policy','not_found','access_denied','integrity','too_large','invalid_manifest','builder_failed','invalid_image','timeout','unavailable','storage_pressure','quota_exceeded')),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(), started_at timestamptz,
 deadline_at timestamptz NOT NULL DEFAULT clock_timestamp()+interval '24 hours',
 review_at timestamptz, review_expires_at timestamptz, completed_at timestamptz,
 UNIQUE(tenant_id,id), UNIQUE(tenant_id,corpus_id,id),
 FOREIGN KEY(tenant_id,corpus_id) REFERENCES corpora(tenant_id,id),
 CHECK ((lease_token IS NULL) = (lease_until IS NULL)),
 CHECK ((state='FAILED') = (error_code IS NOT NULL)),
 CHECK ((state='PUBLISHED') = (release_id IS NOT NULL)),
 CHECK (state NOT IN ('REVIEW','PUBLISHED') OR (image_bytes IS NOT NULL AND image_digest IS NOT NULL AND image_uuid IS NOT NULL AND host_id IS NOT NULL AND commit_sha IS NOT NULL))
);
CREATE UNIQUE INDEX corpus_one_running ON corpus_builds(tenant_id) WHERE state IN ('FETCHING','SCANNING','FETCHING_LFS','CONVERTING','PACKAGING');
CREATE INDEX corpus_builds_queue ON corpus_builds(state,next_attempt_at,created_at);
CREATE INDEX corpus_builds_listing ON corpus_builds(tenant_id,created_at DESC,id DESC);
CREATE TABLE corpus_releases (
 id text PRIMARY KEY, tenant_id text NOT NULL, corpus_id text NOT NULL, build_id text NOT NULL,
 version integer NOT NULL CHECK(version>0), digest text NOT NULL CHECK(digest ~ '^sha256:[0-9a-f]{64}$'),
 image_bytes bigint NOT NULL CHECK(image_bytes>0), image_uuid uuid NOT NULL, host_id text NOT NULL,
 commit_sha text NOT NULL CHECK(commit_sha ~ '^[0-9a-f]{40}$'), builder text NOT NULL,
 created_by text NOT NULL, created_at timestamptz NOT NULL DEFAULT clock_timestamp(), deprecated_at timestamptz,
 UNIQUE(corpus_id,version), UNIQUE(tenant_id,id), UNIQUE(tenant_id,corpus_id,id),
 FOREIGN KEY(tenant_id,corpus_id,build_id) REFERENCES corpus_builds(tenant_id,corpus_id,id),
 FOREIGN KEY(tenant_id,created_by) REFERENCES principals(tenant_id,id)
);
ALTER TABLE corpus_builds ADD FOREIGN KEY(tenant_id,corpus_id,release_id) REFERENCES corpus_releases(tenant_id,corpus_id,id);
CREATE FUNCTION protect_corpus_release() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='DELETE' OR (to_jsonb(NEW)-'deprecated_at') IS DISTINCT FROM (to_jsonb(OLD)-'deprecated_at')
    OR (OLD.deprecated_at IS NOT NULL AND NEW.deprecated_at IS DISTINCT FROM OLD.deprecated_at) THEN
   RAISE EXCEPTION 'immutable corpus release' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER corpus_release_immutable BEFORE DELETE OR UPDATE ON corpus_releases FOR EACH ROW EXECUTE FUNCTION protect_corpus_release();
CREATE TABLE agent_corpora (
 tenant_id text NOT NULL, agent_id text NOT NULL, corpus_id text NOT NULL, position integer NOT NULL CHECK(position BETWEEN 0 AND 3),
 mount text NOT NULL CHECK(mount ~ '^[a-z0-9][a-z0-9_-]{0,62}$'), release_id text, build_id text,
 PRIMARY KEY(agent_id,position), UNIQUE(agent_id,mount), UNIQUE(agent_id,corpus_id),
 CHECK(num_nonnulls(release_id,build_id)=1),
 FOREIGN KEY(tenant_id,agent_id) REFERENCES agents(tenant_id,id),
 FOREIGN KEY(tenant_id,corpus_id,release_id) REFERENCES corpus_releases(tenant_id,corpus_id,id),
 FOREIGN KEY(tenant_id,corpus_id,build_id) REFERENCES corpus_builds(tenant_id,corpus_id,id)
);
CREATE TABLE corpus_review_files (
 build_id text NOT NULL REFERENCES corpus_builds(id), path text NOT NULL,
 bytes integer NOT NULL CHECK(bytes BETWEEN 0 AND 1048576), sha256 text NOT NULL CHECK(sha256 ~ '^[0-9a-f]{64}$'),
 key_id text NOT NULL REFERENCES transit_keys(id),
 PRIMARY KEY(build_id,path)
);
CREATE TABLE corpus_review_segments (
 build_id text NOT NULL, path text NOT NULL, idx integer NOT NULL CHECK(idx>=0), ciphertext bytea NOT NULL,
 PRIMARY KEY(build_id,path,idx), FOREIGN KEY(build_id,path) REFERENCES corpus_review_files(build_id,path) ON DELETE CASCADE
);
ALTER TABLE corpus_audit ADD FOREIGN KEY (tenant_id,corpus_id) REFERENCES corpora(tenant_id,id),
 ADD FOREIGN KEY(tenant_id,build_id) REFERENCES corpus_builds(tenant_id,id),
 ADD FOREIGN KEY(tenant_id,release_id) REFERENCES corpus_releases(tenant_id,id),
 ADD FOREIGN KEY(tenant_id,agent_id) REFERENCES agents(tenant_id,id);
ALTER TABLE tenant_agent_audit DROP CONSTRAINT tenant_agent_audit_action_check;
ALTER TABLE tenant_agent_audit ADD CONSTRAINT tenant_agent_audit_action_check CHECK (action IN (
 'agent.created','agent.wake_requested','agent.sleep_requested','agent.delete_requested',
 'agent.idle_policy_set','agent.idle_sleep_requested','agent.release_changed','agent.directory_changed',
 'agent.inbound_changed','agent.request_accepted','agent.request_declined','agent.corpora_changed',
 'attachment.uploaded','attachment.deleted','assignment.created','assignment.revoked'));
ALTER TABLE organization_quotas ADD COLUMN max_corpus_builds integer CHECK(max_corpus_builds>=0),
 ADD COLUMN max_corpus_storage_mib bigint CHECK(max_corpus_storage_mib>=0);
