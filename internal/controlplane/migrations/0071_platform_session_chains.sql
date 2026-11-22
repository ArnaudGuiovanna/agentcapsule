-- A platform session records the credential that issued it (ADR 001,
-- "Changes after the v0.1.0 audit", finding L-01). Until v0.1.0 any
-- platform:admin credential issued another for twelve hours, without
-- limit, and revoking it left the sessions it had issued active. Now a
-- session names its parent, and revoking a credential revokes every session
-- descended from it. A chain of sessions starts when its root, an enrollment
-- proof or a credential of bootstrap-platform, was issued, and no session of
-- it outlives a fixed lifetime from that start. A credential has at most
-- one live child, unless the child replaces it.
--
-- Existing credentials start their own chains, as of their creation. The
-- table is small: the backfill rewrites it under the migration's lock.
ALTER TABLE platform_credentials ADD COLUMN parent_id text REFERENCES platform_credentials(id);
ALTER TABLE platform_credentials ADD COLUMN chain_started_at timestamptz;
UPDATE platform_credentials SET chain_started_at=created_at;
ALTER TABLE platform_credentials ALTER COLUMN chain_started_at SET DEFAULT clock_timestamp(),
  ALTER COLUMN chain_started_at SET NOT NULL;
ALTER TABLE platform_credentials ADD CONSTRAINT platform_credentials_parent CHECK (parent_id IS DISTINCT FROM id);
CREATE INDEX platform_credentials_children ON platform_credentials(parent_id) WHERE parent_id IS NOT NULL;
