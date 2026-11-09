-- Directory publication (INT-02). An organization describes an agent for the
-- private AGNTCY Directory: a description and OASF skill and domain IDs. The
-- row is also the outbox of the publisher: every change of the description, of
-- the agent's discoverability or phase, or of its organization's status bumps
-- revision; the publisher brings the Directory to that revision, then records
-- it. The Directory is an index: search results are always checked again here.
CREATE TABLE agent_directory (
  agent_id text PRIMARY KEY REFERENCES agents(id),
  tenant_id text NOT NULL REFERENCES organizations(id),
  description text NOT NULL CHECK (char_length(description) BETWEEN 1 AND 1000),
  skills integer[] NOT NULL CHECK (cardinality(skills) BETWEEN 1 AND 20 AND array_position(skills, NULL) IS NULL),
  domains integer[] NOT NULL DEFAULT '{}' CHECK (cardinality(domains) <= 20 AND array_position(domains, NULL) IS NULL),
  revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
  -- The Directory reflects published_revision: published_cid is the record
  -- there now (NULL when the agent is not published), retired_cid an older one
  -- still to delete.
  published_revision bigint NOT NULL DEFAULT 0 CHECK (published_revision <= revision),
  published_cid text CHECK (published_cid <> ''),
  retired_cid text CHECK (retired_cid <> ''),
  -- invalid: the schema refused the record of published_revision; error holds
  -- the schema server's message, shown to the organization.
  state text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending','published','unpublished','invalid')),
  error text CHECK (char_length(error) <= 2000),
  attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
  next_attempt_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  lease_until timestamptz,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CHECK ((state = 'invalid') = (error IS NOT NULL))
);
CREATE UNIQUE INDEX agent_directory_cid ON agent_directory(published_cid) WHERE published_cid IS NOT NULL;
CREATE INDEX agent_directory_due ON agent_directory(next_attempt_at)
  WHERE revision > published_revision OR retired_cid IS NOT NULL;

CREATE FUNCTION agent_directory_follow_agent() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.discoverable IS DISTINCT FROM OLD.discoverable OR NEW.phase IS DISTINCT FROM OLD.phase THEN
    UPDATE agent_directory SET revision = revision + 1, state = 'pending', error = NULL,
      next_attempt_at = clock_timestamp(), updated_at = clock_timestamp()
      WHERE agent_id = NEW.id;
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER agent_directory_follow_agent AFTER UPDATE OF discoverable, phase ON agents
  FOR EACH ROW EXECUTE FUNCTION agent_directory_follow_agent();

CREATE FUNCTION agent_directory_follow_organization() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.status IS DISTINCT FROM OLD.status THEN
    UPDATE agent_directory SET revision = revision + 1, state = 'pending', error = NULL,
      next_attempt_at = clock_timestamp(), updated_at = clock_timestamp()
      WHERE tenant_id = NEW.id;
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER agent_directory_follow_organization AFTER UPDATE OF status ON organizations
  FOR EACH ROW EXECUTE FUNCTION agent_directory_follow_organization();

ALTER TABLE tenant_agent_audit DROP CONSTRAINT tenant_agent_audit_action_check;
ALTER TABLE tenant_agent_audit ADD CONSTRAINT tenant_agent_audit_action_check CHECK (action IN (
  'agent.created','agent.wake_requested','agent.sleep_requested','agent.delete_requested',
  'agent.idle_policy_set','agent.idle_sleep_requested','agent.release_changed','agent.directory_changed',
  'attachment.uploaded','attachment.deleted','assignment.created','assignment.revoked'));
