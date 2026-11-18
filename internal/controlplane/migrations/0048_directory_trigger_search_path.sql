-- The triggers that keep the Directory record in step with its agent and its
-- organization (0023) name agent_directory without a schema. A trigger runs
-- with the search path of the session that changes the row, so a change made
-- from a session whose search path lacks this schema (an operator's psql, an
-- administration pool) failed: relation "agent_directory" does not exist. Pin
-- the search path of this migration, as the other triggers that read another
-- table do (preserve_sealed_agent).
ALTER FUNCTION agent_directory_follow_agent() SET search_path FROM CURRENT;
ALTER FUNCTION agent_directory_follow_organization() SET search_path FROM CURRENT;
