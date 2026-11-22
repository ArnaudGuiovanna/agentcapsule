-- Only the worker reserves model calls. The API can reconcile an existing
-- call, which needs UPDATE. Keep the previous policy for every other row.
ALTER FUNCTION agentcapsule_service_privileges() RENAME TO agentcapsule_service_privileges_before_model_split;

CREATE FUNCTION agentcapsule_service_privileges() RETURNS TABLE(role text, tbl text, privileges text)
LANGUAGE sql IMMUTABLE SET search_path FROM CURRENT AS $$
    SELECT p.role, p.tbl, CASE WHEN p.role = 'agentcapsule_api' AND p.tbl = 'llm_usage'
                               THEN 'UPDATE' ELSE p.privileges END
      FROM agentcapsule_service_privileges_before_model_split() p
$$;

SELECT agentcapsule_service_grants();
