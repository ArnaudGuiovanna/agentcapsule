-- Harness registry (REG): releases imported from OCI registries by digest.
--
-- A release is immutable: name:version maps to one package digest forever.
-- Imports are asynchronous and tracked separately, so a rejected or pending
-- import never occupies a name:version. Deprecation keeps running agents on
-- their pinned release but refuses new agents.
ALTER TABLE harness_releases
  ADD COLUMN reference text CHECK (reference IS NULL OR length(reference) BETWEEN 1 AND 512),
  ADD COLUMN rootfs_digest text CHECK (rootfs_digest IS NULL OR rootfs_digest ~ '^sha256:[0-9a-f]{64}$'),
  ADD COLUMN rootfs_bytes bigint CHECK (rootfs_bytes IS NULL OR rootfs_bytes > 0),
  ADD COLUMN deprecated_at timestamptz;
-- A release disabled before this migration counts as deprecated since its creation.
UPDATE harness_releases SET deprecated_at = created_at WHERE NOT enabled;
ALTER TABLE harness_releases
  ADD CONSTRAINT harness_releases_oci CHECK (
    (source = 'oci') = (reference IS NOT NULL AND rootfs_digest IS NOT NULL AND rootfs_bytes IS NOT NULL)),
  ADD CONSTRAINT harness_releases_deprecation CHECK ((deprecated_at IS NULL) = enabled);
CREATE UNIQUE INDEX harness_releases_package ON harness_releases(artifact_digest) WHERE source = 'oci';

CREATE TABLE harness_imports (
  id text PRIMARY KEY CHECK (id <> ''),
  reference text NOT NULL CHECK (length(reference) BETWEEN 1 AND 512),
  manifest_digest text NOT NULL CHECK (manifest_digest ~ '^sha256:[0-9a-f]{64}$'),
  status text NOT NULL DEFAULT 'IMPORTING' CHECK (status IN ('IMPORTING','READY','REJECTED')),
  error_code text NOT NULL DEFAULT '' CHECK (error_code IN ('','policy','not_found','integrity','version_conflict','unavailable')),
  release_id text REFERENCES harness_releases(id),
  requested_by text NOT NULL CHECK (requested_by <> ''),
  attempts integer NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 100),
  next_attempt_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  lease_owner text,
  lease_token text,
  lease_until timestamptz,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  completed_at timestamptz,
  CHECK ((status = 'READY') = (release_id IS NOT NULL)),
  CHECK ((status = 'REJECTED') = (error_code <> '')),
  CHECK ((status = 'IMPORTING') = (completed_at IS NULL)),
  CHECK ((lease_token IS NULL) = (lease_until IS NULL) AND (lease_token IS NULL) = (lease_owner IS NULL))
);
-- At most one import in flight per package; a finished one may be retried.
CREATE UNIQUE INDEX harness_imports_in_flight ON harness_imports(manifest_digest) WHERE status = 'IMPORTING';
CREATE INDEX harness_imports_due ON harness_imports(next_attempt_at) WHERE status = 'IMPORTING';

CREATE TABLE harness_audit (
  id text PRIMARY KEY,
  actor_account text NOT NULL,
  credential_id text NOT NULL,
  action text NOT NULL CHECK (action IN ('import.requested','release.deprecated')),
  import_id text REFERENCES harness_imports(id),
  release_id text REFERENCES harness_releases(id),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CHECK ((action = 'import.requested') = (import_id IS NOT NULL)),
  CHECK ((action = 'release.deprecated') = (release_id IS NOT NULL))
);
