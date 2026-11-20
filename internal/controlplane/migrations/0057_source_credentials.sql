-- Source credentials (ADR 023 §3.1, corpus lot 3): an organization's
-- read-only forge tokens. The secret is stored only as AES-GCM ciphertext
-- under a key derived from the installation's receipt key, bound to the
-- organization, the credential and its generation. Only the worker opens it,
-- when it fetches a corpus's sources. Disabling erases the ciphertext; a
-- disabled credential never comes back.
CREATE TABLE source_credentials (
  id text PRIMARY KEY CHECK (id ~ '^scr_[0-9a-f]{32}$'),
  tenant_id text NOT NULL REFERENCES organizations(id),
  name text NOT NULL CHECK (name ~ '^[a-z0-9][a-z0-9._-]{0,99}$'),
  kind text NOT NULL CHECK (kind IN ('github','gitlab')),
  host text NOT NULL CHECK (length(host) BETWEEN 1 AND 253),
  generation bigint NOT NULL DEFAULT 1 CHECK (generation > 0),
  sealed bytea,
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active','disabled')),
  created_by text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  rotated_at timestamptz,
  disabled_at timestamptz,
  CHECK ((status = 'disabled') = (disabled_at IS NOT NULL)),
  CHECK ((status = 'active') = (sealed IS NOT NULL)),
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, name),
  FOREIGN KEY (tenant_id,created_by) REFERENCES principals(tenant_id,id)
);

-- The corpus trail (ADR 023 §11). Its actions are the corpus work's whole
-- list, so that the later lots add rows, not actions. An event names
-- identifiers only: never a secret, a path inside a repository or content.
-- corpus_id, build_id, release_id and agent_id get their foreign keys with
-- their tables (lot 6).
CREATE TABLE corpus_audit (
  id text PRIMARY KEY,
  tenant_id text NOT NULL REFERENCES organizations(id),
  actor_principal_id text NOT NULL,
  credential_id text CHECK (credential_id IS NULL OR length(credential_id) BETWEEN 1 AND 200),
  action text NOT NULL CHECK (action IN ('source_credential.created','source_credential.rotated','source_credential.disabled',
    'corpus.created','corpus_build.requested','corpus_build.canceled','corpus_build.tried','corpus_build.published',
    'corpus_release.deprecated')),
  corpus_id text,
  build_id text,
  release_id text,
  source_credential_id text,
  agent_id text,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CHECK (action NOT LIKE 'source_credential.%' OR source_credential_id IS NOT NULL),
  FOREIGN KEY (tenant_id,actor_principal_id) REFERENCES principals(tenant_id,id),
  FOREIGN KEY (tenant_id,source_credential_id) REFERENCES source_credentials(tenant_id,id)
);
CREATE INDEX corpus_audit_feed ON corpus_audit(tenant_id,created_at,id);
-- The audit retention selects by age alone (0039).
CREATE INDEX corpus_audit_created ON corpus_audit(created_at);
