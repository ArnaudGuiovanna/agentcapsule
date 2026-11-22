-- The worker checks the VM placement and creates its peer request. The HTTP
-- API reads placements and updates requests when the owner records consent.
-- Preserve every other grant from the policy installed on this schema.
ALTER FUNCTION agentcapsule_service_privileges() RENAME TO agentcapsule_service_privileges_before_api_guest_split;

CREATE FUNCTION agentcapsule_service_privileges() RETURNS TABLE(role text, tbl text, privileges text)
LANGUAGE sql IMMUTABLE SET search_path FROM CURRENT AS $$
    SELECT p.role, p.tbl, CASE
        WHEN p.role = 'agentcapsule_api' AND p.tbl = 'agent_placements' THEN ''
        WHEN p.role = 'agentcapsule_api' AND p.tbl = 'agent_requests' THEN 'UPDATE'
        ELSE p.privileges
    END
    FROM agentcapsule_service_privileges_before_api_guest_split() p
$$;

SELECT agentcapsule_service_grants();
