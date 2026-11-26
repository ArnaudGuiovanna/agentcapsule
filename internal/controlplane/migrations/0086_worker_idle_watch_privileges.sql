-- The worker's running-generation UPSERT changes the clock and generation.
-- Its agent_id remains immutable to both service roles.
ALTER FUNCTION agentcapsule_service_privileges() RENAME TO agentcapsule_service_privileges_before_idle_watch;

CREATE FUNCTION agentcapsule_service_privileges() RETURNS TABLE(role text, tbl text, privileges text)
LANGUAGE sql IMMUTABLE SET search_path FROM CURRENT AS $$
    SELECT p.role, p.tbl, CASE
        WHEN p.role = 'agentcapsule_worker' AND p.tbl = 'agent_idle_watch'
            THEN 'INSERT,DELETE,UPDATE (generation, observed_at)'
        ELSE p.privileges
    END
    FROM agentcapsule_service_privileges_before_idle_watch() p
$$;

SELECT agentcapsule_service_grants();
