-- Credential resolution locks the organization row. Both processes read
-- delegated token tombstones, which are append-only, and the worker reads
-- application activations. Only the API changes an activation. Preserve the
-- API's model usage privilege from migration 0082.
CREATE OR REPLACE FUNCTION agentcapsule_service_privileges() RETURNS TABLE(role text, tbl text, privileges text)
LANGUAGE sql IMMUTABLE SET search_path FROM CURRENT AS $$
    SELECT p.role, p.tbl, CASE
        WHEN p.tbl = 'delegation_revocations' THEN 'INSERT'
        WHEN p.role = 'agentcapsule_worker' AND p.tbl = 'app_activations' THEN ''
        WHEN p.role = 'agentcapsule_api' AND p.tbl = 'llm_usage' THEN 'UPDATE'
        ELSE p.privileges
    END
    FROM agentcapsule_service_privileges_before_model_split() p
$$;

SELECT agentcapsule_service_grants();
