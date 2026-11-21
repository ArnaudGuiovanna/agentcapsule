-- Retain the conversion's identity across PACKAGING and REVIEW so that a
-- reconnect can still follow the file steps stored just before that transition.
ALTER TABLE corpus_builds ADD COLUMN conversion_invocation_id text REFERENCES owner_instructions(operation_id);
CREATE UNIQUE INDEX corpus_conversion_invocation ON corpus_builds(conversion_invocation_id) WHERE conversion_invocation_id IS NOT NULL;

UPDATE corpus_builds SET conversion_invocation_id=invocation_id WHERE state='CONVERTING' AND invocation_id IS NOT NULL;
CREATE FUNCTION corpus_remember_conversion() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.state='CONVERTING' AND NEW.invocation_id IS NOT NULL THEN
    NEW.conversion_invocation_id := NEW.invocation_id;
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER corpus_remember_conversion BEFORE INSERT OR UPDATE OF state,invocation_id ON corpus_builds
  FOR EACH ROW EXECUTE FUNCTION corpus_remember_conversion();

CREATE FUNCTION corpus_notify_build() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  PERFORM pg_notify('agentcapsule_corpus_build',NEW.id);
  RETURN NULL;
END $$;
CREATE TRIGGER corpus_notify_build AFTER UPDATE OF state,invocation_id ON corpus_builds
  FOR EACH ROW WHEN (OLD.state IS DISTINCT FROM NEW.state OR OLD.invocation_id IS DISTINCT FROM NEW.invocation_id) EXECUTE FUNCTION corpus_notify_build();

CREATE FUNCTION corpus_notify_file_progress() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  PERFORM pg_notify('agentcapsule_corpus_build',b.id) FROM corpus_builds b WHERE b.conversion_invocation_id=NEW.operation_id;
  RETURN NULL;
END $$;
CREATE TRIGGER corpus_notify_file_chunk AFTER INSERT ON invocation_stream_chunks FOR EACH ROW EXECUTE FUNCTION corpus_notify_file_progress();
CREATE TRIGGER corpus_notify_file_limit AFTER UPDATE OF truncated ON invocation_streams
  FOR EACH ROW WHEN (OLD.truncated IS DISTINCT FROM NEW.truncated) EXECUTE FUNCTION corpus_notify_file_progress();
CREATE TRIGGER corpus_notify_file_attempt AFTER UPDATE OF attempt ON owner_instructions
  FOR EACH ROW WHEN (OLD.attempt IS DISTINCT FROM NEW.attempt) EXECUTE FUNCTION corpus_notify_file_progress();

-- Upgrade the builder's original, managed policy. An organization's explicit
-- capability policy, including a narrower policy on this agent, still applies.
UPDATE agent_capability_policies p SET allowed=array_append(p.allowed,'stream.output'),updated_at=clock_timestamp()
 FROM agents a WHERE a.id=p.agent_id AND a.kind='corpus_builder' AND p.updated_by=a.builder_principal AND p.allowed=ARRAY['llm.invoke']::text[];
