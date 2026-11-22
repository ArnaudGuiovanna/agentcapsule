-- Service roles (ADR 001, "Changes after the v0.1.0 audit"). The owner of
-- the schema (agentcapsule on a host the installer set up) alone runs the
-- migrations and owns every object. The API connects as agentcapsule_api and
-- the worker as agentcapsule_worker: login roles that own nothing, so that
-- neither can truncate, alter, drop or disable a table or one of its
-- triggers (the permanent guards of revocation_catalogue, store_seals,
-- access_revocations...), nor create an object. Each reads every table and
-- writes only the tables its process writes, with only the privileges it
-- uses (a row lock needs UPDATE): service_roles_analysis_test.go derives
-- that list from the code, and TestServiceRolesHoldWhatTheirProcessWrites
-- checks this database against it. No role gets TRUNCATE, REFERENCES or
-- TRIGGER.
--
-- agentcapsule_service_grants() states the whole policy and applies it
-- again each time it runs: the tables listed below get exactly their row's
-- privileges; a table a later migration creates gets the default privileges
-- (read and write rows), until a migration lists it. A role that does not
-- exist (development, tests) is skipped; agentcapsule-admin migrate runs the
-- function again at its end, so a role created later gets its privileges at
-- the next migrate. Only the owner runs it.
CREATE FUNCTION agentcapsule_service_grants() RETURNS void LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
DECLARE
  s text := current_schema();
  grantee text;
  w record;
BEGIN
  EXECUTE format('REVOKE CREATE ON SCHEMA %I FROM PUBLIC', s);
  FOREACH grantee IN ARRAY ARRAY['agentcapsule_api','agentcapsule_worker'] LOOP
    CONTINUE WHEN NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = grantee);
    EXECUTE format('REVOKE CREATE ON SCHEMA %I FROM %I', s, grantee);
    EXECUTE format('GRANT USAGE ON SCHEMA %I TO %I', s, grantee);
    EXECUTE format('ALTER DEFAULT PRIVILEGES IN SCHEMA %I GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO %I', s, grantee);
    EXECUTE format('ALTER DEFAULT PRIVILEGES IN SCHEMA %I GRANT USAGE ON SEQUENCES TO %I', s, grantee);
    EXECUTE format('REVOKE ALL ON ALL SEQUENCES IN SCHEMA %I FROM %I', s, grantee);
    EXECUTE format('GRANT USAGE ON ALL SEQUENCES IN SCHEMA %I TO %I', s, grantee);
    EXECUTE format('REVOKE ALL ON ALL TABLES IN SCHEMA %I FROM %I', s, grantee);
    EXECUTE format('GRANT SELECT ON ALL TABLES IN SCHEMA %I TO %I', s, grantee);
    -- One statement per set of write privileges, naming its tables.
    FOR w IN
      SELECT x.granted, string_agg(format('%I.%I', s, c.relname), ', ' ORDER BY c.relname) AS tables
        FROM pg_class c
        LEFT JOIN agentcapsule_service_privileges() p ON p.role = grantee AND p.tbl = c.relname
        CROSS JOIN LATERAL (SELECT CASE WHEN p.tbl IS NOT NULL THEN p.privileges
                                        WHEN c.relkind = 'v' THEN '' ELSE 'INSERT,UPDATE,DELETE' END AS granted) x
       WHERE c.relnamespace = s::regnamespace AND c.relkind IN ('r','p','v') AND x.granted <> ''
       GROUP BY x.granted
    LOOP
      EXECUTE format('GRANT %s ON TABLE %s TO %I', w.granted, w.tables, grantee);
    END LOOP;
  END LOOP;
END
$$;

-- What each service role writes, per table: the privileges beyond SELECT.
-- A later migration that changes them replaces this function.
CREATE FUNCTION agentcapsule_service_privileges() RETURNS TABLE(role text, tbl text, privileges text)
LANGUAGE sql IMMUTABLE SET search_path FROM CURRENT AS $$
  SELECT * FROM (VALUES
      ('agentcapsule_api','access_revocations','INSERT,UPDATE'),
      ('agentcapsule_worker','access_revocations','INSERT,UPDATE'),
      ('agentcapsule_api','agent_assignments','INSERT,UPDATE'),
      ('agentcapsule_worker','agent_assignments','INSERT,UPDATE'),
      ('agentcapsule_api','agent_capability_policies','INSERT,UPDATE'),
      ('agentcapsule_worker','agent_capability_policies','INSERT,UPDATE,DELETE'),
      ('agentcapsule_api','agent_corpora','INSERT,UPDATE,DELETE'),
      ('agentcapsule_worker','agent_corpora','INSERT,DELETE'),
      ('agentcapsule_api','agent_deployment_members','INSERT'),
      ('agentcapsule_worker','agent_deployment_members',''),
      ('agentcapsule_api','agent_deployments','INSERT,UPDATE'),
      ('agentcapsule_worker','agent_deployments','UPDATE'),
      ('agentcapsule_api','agent_directory','INSERT,UPDATE'),
      ('agentcapsule_worker','agent_directory','UPDATE'),
      ('agentcapsule_api','agent_idle_watch','DELETE'),
      ('agentcapsule_worker','agent_idle_watch','INSERT,DELETE'),
      ('agentcapsule_api','agent_mailboxes','INSERT,UPDATE'),
      ('agentcapsule_worker','agent_mailboxes','INSERT,UPDATE'),
      ('agentcapsule_api','agent_placements','UPDATE'),
      ('agentcapsule_worker','agent_placements','INSERT,UPDATE'),
      ('agentcapsule_api','agent_pool_inventory',''),
      ('agentcapsule_worker','agent_pool_inventory',''),
      ('agentcapsule_api','agent_pool_members','INSERT'),
      ('agentcapsule_worker','agent_pool_members',''),
      ('agentcapsule_api','agent_pools','INSERT'),
      ('agentcapsule_worker','agent_pools',''),
      ('agentcapsule_api','agent_requests','INSERT,UPDATE'),
      ('agentcapsule_worker','agent_requests','INSERT,UPDATE'),
      ('agentcapsule_api','agent_rollout_steps','INSERT'),
      ('agentcapsule_worker','agent_rollout_steps','UPDATE'),
      ('agentcapsule_api','agent_rollouts','INSERT,UPDATE'),
      ('agentcapsule_worker','agent_rollouts','UPDATE'),
      ('agentcapsule_api','agent_specs','INSERT,UPDATE'),
      ('agentcapsule_worker','agent_specs','INSERT,UPDATE'),
      ('agentcapsule_api','agent_template_revisions','INSERT'),
      ('agentcapsule_worker','agent_template_revisions','UPDATE'),
      ('agentcapsule_api','agent_volume_growth','INSERT,UPDATE'),
      ('agentcapsule_worker','agent_volume_growth','UPDATE'),
      ('agentcapsule_api','agents','INSERT,UPDATE'),
      ('agentcapsule_worker','agents','INSERT,UPDATE'),
      ('agentcapsule_api','api_receipt_key',''),
      ('agentcapsule_worker','api_receipt_key',''),
      ('agentcapsule_api','api_tokens','INSERT,UPDATE'),
      ('agentcapsule_worker','api_tokens','UPDATE'),
      ('agentcapsule_api','app_activations','INSERT,UPDATE'),
      ('agentcapsule_worker','app_activations','UPDATE'),
      ('agentcapsule_api','app_invitations','INSERT,UPDATE'),
      ('agentcapsule_worker','app_invitations',''),
      ('agentcapsule_api','app_personal_reservations','INSERT'),
      ('agentcapsule_worker','app_personal_reservations',''),
      ('agentcapsule_api','app_policies','INSERT,UPDATE'),
      ('agentcapsule_worker','app_policies',''),
      ('agentcapsule_api','application_audit','INSERT'),
      ('agentcapsule_worker','application_audit','DELETE'),
      ('agentcapsule_api','applications','INSERT,UPDATE'),
      ('agentcapsule_worker','applications','UPDATE'),
      ('agentcapsule_api','attachment_segments','INSERT,DELETE'),
      ('agentcapsule_worker','attachment_segments','UPDATE,DELETE'),
      ('agentcapsule_api','attachments','INSERT,UPDATE'),
      ('agentcapsule_worker','attachments','UPDATE'),
      ('agentcapsule_api','audit_retention',''),
      ('agentcapsule_worker','audit_retention','UPDATE'),
      ('agentcapsule_api','authority_reconciliations',''),
      ('agentcapsule_worker','authority_reconciliations','INSERT,UPDATE'),
      ('agentcapsule_api','available_pool_members',''),
      ('agentcapsule_worker','available_pool_members',''),
      ('agentcapsule_api','capability_audit','INSERT'),
      ('agentcapsule_worker','capability_audit','DELETE'),
      ('agentcapsule_api','capacity_waits',''),
      ('agentcapsule_worker','capacity_waits','INSERT,UPDATE,DELETE'),
      ('agentcapsule_api','corpora','INSERT,UPDATE'),
      ('agentcapsule_worker','corpora','UPDATE'),
      ('agentcapsule_api','corpus_audit','INSERT'),
      ('agentcapsule_worker','corpus_audit','DELETE'),
      ('agentcapsule_api','corpus_builds','INSERT,UPDATE'),
      ('agentcapsule_worker','corpus_builds','UPDATE'),
      ('agentcapsule_api','corpus_enrichers','INSERT,UPDATE'),
      ('agentcapsule_worker','corpus_enrichers','UPDATE'),
      ('agentcapsule_api','corpus_extensions','INSERT,UPDATE'),
      ('agentcapsule_worker','corpus_extensions','UPDATE'),
      ('agentcapsule_api','corpus_releases','INSERT,UPDATE'),
      ('agentcapsule_worker','corpus_releases','UPDATE'),
      ('agentcapsule_api','corpus_review_files','UPDATE,DELETE'),
      ('agentcapsule_worker','corpus_review_files','INSERT,DELETE'),
      ('agentcapsule_api','corpus_review_segments','UPDATE'),
      ('agentcapsule_worker','corpus_review_segments','INSERT'),
      ('agentcapsule_api','delegation_admin_receipts',''),
      ('agentcapsule_worker','delegation_admin_receipts',''),
      ('agentcapsule_api','delegation_audit',''),
      ('agentcapsule_worker','delegation_audit','DELETE'),
      ('agentcapsule_api','delegation_issuers','INSERT,UPDATE'),
      ('agentcapsule_worker','delegation_issuers','INSERT,UPDATE'),
      ('agentcapsule_api','delegation_keys','INSERT,UPDATE'),
      ('agentcapsule_worker','delegation_keys','UPDATE'),
      ('agentcapsule_api','delegation_revocations','INSERT,UPDATE'),
      ('agentcapsule_worker','delegation_revocations','INSERT,UPDATE'),
      ('agentcapsule_api','delegation_trusts','INSERT,UPDATE'),
      ('agentcapsule_worker','delegation_trusts','UPDATE'),
      ('agentcapsule_api','deletion_operations','INSERT,UPDATE'),
      ('agentcapsule_worker','deletion_operations','INSERT,UPDATE'),
      ('agentcapsule_api','deletion_targets','INSERT'),
      ('agentcapsule_worker','deletion_targets','INSERT,UPDATE'),
      ('agentcapsule_api','deployment_audit','INSERT'),
      ('agentcapsule_worker','deployment_audit','DELETE'),
      ('agentcapsule_api','deployment_hosts',''),
      ('agentcapsule_worker','deployment_hosts','INSERT,UPDATE'),
      ('agentcapsule_api','failed_agents','DELETE'),
      ('agentcapsule_worker','failed_agents','INSERT'),
      ('agentcapsule_api','guest_failures','DELETE'),
      ('agentcapsule_worker','guest_failures','INSERT,DELETE'),
      ('agentcapsule_api','harness_audit','INSERT'),
      ('agentcapsule_worker','harness_audit','DELETE'),
      ('agentcapsule_api','harness_imports','INSERT'),
      ('agentcapsule_worker','harness_imports','UPDATE'),
      ('agentcapsule_api','harness_releases','UPDATE'),
      ('agentcapsule_worker','harness_releases','INSERT,UPDATE'),
      ('agentcapsule_api','host_system_images','UPDATE'),
      ('agentcapsule_worker','host_system_images','INSERT,UPDATE,DELETE'),
      ('agentcapsule_api','host_takeovers','UPDATE'),
      ('agentcapsule_worker','host_takeovers','UPDATE'),
      ('agentcapsule_api','http_receipts','INSERT,DELETE'),
      ('agentcapsule_worker','http_receipts','INSERT,UPDATE,DELETE'),
      ('agentcapsule_api','idempotency_keys','INSERT'),
      ('agentcapsule_worker','idempotency_keys','INSERT'),
      ('agentcapsule_api','inbox_items','INSERT'),
      ('agentcapsule_worker','inbox_items','INSERT'),
      ('agentcapsule_api','instruction_replays','INSERT'),
      ('agentcapsule_worker','instruction_replays','DELETE'),
      ('agentcapsule_api','invocation_reruns','UPDATE'),
      ('agentcapsule_worker','invocation_reruns','INSERT,UPDATE'),
      ('agentcapsule_api','invocation_stream_chunks','DELETE'),
      ('agentcapsule_worker','invocation_stream_chunks','INSERT,UPDATE,DELETE'),
      ('agentcapsule_api','invocation_streams','UPDATE'),
      ('agentcapsule_worker','invocation_streams','INSERT,UPDATE'),
      ('agentcapsule_api','llm_alias_grants','INSERT,UPDATE'),
      ('agentcapsule_worker','llm_alias_grants','INSERT,UPDATE'),
      ('agentcapsule_api','llm_audit','INSERT'),
      ('agentcapsule_worker','llm_audit','DELETE'),
      ('agentcapsule_api','llm_budgets','INSERT,UPDATE'),
      ('agentcapsule_worker','llm_budgets','UPDATE'),
      ('agentcapsule_api','llm_model_aliases','INSERT,UPDATE'),
      ('agentcapsule_worker','llm_model_aliases','UPDATE'),
      ('agentcapsule_api','llm_providers','INSERT,UPDATE'),
      ('agentcapsule_worker','llm_providers','UPDATE'),
      ('agentcapsule_api','llm_usage','INSERT,UPDATE'),
      ('agentcapsule_worker','llm_usage','INSERT,UPDATE'),
      ('agentcapsule_api','mandates','UPDATE'),
      ('agentcapsule_worker','mandates','INSERT,UPDATE'),
      ('agentcapsule_api','memberships','INSERT,UPDATE'),
      ('agentcapsule_worker','memberships','INSERT,UPDATE'),
      ('agentcapsule_api','operator_audit',''),
      ('agentcapsule_worker','operator_audit','INSERT,DELETE'),
      ('agentcapsule_api','organization_audit','INSERT'),
      ('agentcapsule_worker','organization_audit','DELETE'),
      ('agentcapsule_api','organization_capability_policies','INSERT,UPDATE'),
      ('agentcapsule_worker','organization_capability_policies',''),
      ('agentcapsule_api','organization_quotas','INSERT,UPDATE'),
      ('agentcapsule_worker','organization_quotas',''),
      ('agentcapsule_api','organizations','INSERT,UPDATE'),
      ('agentcapsule_worker','organizations','UPDATE'),
      ('agentcapsule_api','outbox','INSERT,DELETE'),
      ('agentcapsule_worker','outbox','INSERT,UPDATE,DELETE'),
      ('agentcapsule_api','owner_instructions','INSERT,UPDATE'),
      ('agentcapsule_worker','owner_instructions','INSERT,UPDATE'),
      ('agentcapsule_api','owner_messages',''),
      ('agentcapsule_worker','owner_messages','INSERT'),
      ('agentcapsule_api','peer_redeliveries',''),
      ('agentcapsule_worker','peer_redeliveries','INSERT'),
      ('agentcapsule_api','peer_wakes',''),
      ('agentcapsule_worker','peer_wakes','INSERT,DELETE'),
      ('agentcapsule_api','personal_volume_holds',''),
      ('agentcapsule_worker','personal_volume_holds',''),
      ('agentcapsule_api','placement_control_contracts',''),
      ('agentcapsule_worker','placement_control_contracts','INSERT,UPDATE,DELETE'),
      ('agentcapsule_api','placement_renewals','DELETE'),
      ('agentcapsule_worker','placement_renewals','INSERT,UPDATE,DELETE'),
      ('agentcapsule_api','platform_audit','INSERT'),
      ('agentcapsule_worker','platform_audit','DELETE'),
      ('agentcapsule_api','platform_credentials','INSERT,UPDATE'),
      ('agentcapsule_worker','platform_credentials','UPDATE'),
      ('agentcapsule_api','platform_operations','INSERT,UPDATE'),
      ('agentcapsule_worker','platform_operations','INSERT,UPDATE'),
      ('agentcapsule_api','principals','INSERT,UPDATE'),
      ('agentcapsule_worker','principals','INSERT,UPDATE'),
      ('agentcapsule_api','queue_audit','INSERT'),
      ('agentcapsule_worker','queue_audit','DELETE'),
      ('agentcapsule_api','queue_limits','INSERT,UPDATE'),
      ('agentcapsule_worker','queue_limits',''),
      ('agentcapsule_api','request_closure_targets','INSERT'),
      ('agentcapsule_worker','request_closure_targets','INSERT,UPDATE'),
      ('agentcapsule_api','request_closures','INSERT'),
      ('agentcapsule_worker','request_closures','INSERT,UPDATE'),
      ('agentcapsule_api','revocation_catalogue','INSERT'),
      ('agentcapsule_worker','revocation_catalogue','INSERT'),
      ('agentcapsule_api','schema_migrations',''),
      ('agentcapsule_worker','schema_migrations',''),
      ('agentcapsule_api','service_tokens','INSERT,UPDATE'),
      ('agentcapsule_worker','service_tokens','UPDATE'),
      ('agentcapsule_api','source_credentials','INSERT,UPDATE'),
      ('agentcapsule_worker','source_credentials','UPDATE'),
      ('agentcapsule_api','store_enrollment_receipts',''),
      ('agentcapsule_worker','store_enrollment_receipts','INSERT'),
      ('agentcapsule_api','store_enrollments','INSERT'),
      ('agentcapsule_worker','store_enrollments','INSERT,UPDATE'),
      ('agentcapsule_api','store_initializations',''),
      ('agentcapsule_worker','store_initializations','INSERT'),
      ('agentcapsule_api','store_removals',''),
      ('agentcapsule_worker','store_removals','INSERT'),
      ('agentcapsule_api','store_seals',''),
      ('agentcapsule_worker','store_seals','INSERT'),
      ('agentcapsule_api','system_images','INSERT,UPDATE'),
      ('agentcapsule_worker','system_images','UPDATE'),
      ('agentcapsule_api','team_memberships','INSERT,UPDATE'),
      ('agentcapsule_worker','team_memberships','UPDATE'),
      ('agentcapsule_api','teams','INSERT,UPDATE'),
      ('agentcapsule_worker','teams','UPDATE'),
      ('agentcapsule_api','tenant_agent_audit','INSERT'),
      ('agentcapsule_worker','tenant_agent_audit','INSERT,DELETE'),
      ('agentcapsule_api','tenant_http_receipts','INSERT,DELETE'),
      ('agentcapsule_worker','tenant_http_receipts','INSERT,UPDATE,DELETE'),
      ('agentcapsule_api','tenant_member_audit','INSERT'),
      ('agentcapsule_worker','tenant_member_audit','DELETE'),
      ('agentcapsule_api','tenant_refusal_audit','INSERT'),
      ('agentcapsule_worker','tenant_refusal_audit','DELETE'),
      ('agentcapsule_api','tenant_service_audit','INSERT'),
      ('agentcapsule_worker','tenant_service_audit','DELETE'),
      ('agentcapsule_api','tenant_team_audit','INSERT'),
      ('agentcapsule_worker','tenant_team_audit','DELETE'),
      ('agentcapsule_api','trace_pseudonym_key',''),
      ('agentcapsule_worker','trace_pseudonym_key',''),
      ('agentcapsule_api','transit_configuration','UPDATE'),
      ('agentcapsule_worker','transit_configuration','UPDATE'),
      ('agentcapsule_api','transit_keys','UPDATE'),
      ('agentcapsule_worker','transit_keys','UPDATE'),
      ('agentcapsule_api','transit_parties','INSERT,DELETE'),
      ('agentcapsule_worker','transit_parties','INSERT,UPDATE,DELETE'),
      ('agentcapsule_api','transit_payloads','INSERT,UPDATE,DELETE'),
      ('agentcapsule_worker','transit_payloads','INSERT,UPDATE,DELETE'),
      ('agentcapsule_api','users','INSERT,UPDATE'),
      ('agentcapsule_worker','users','UPDATE'),
      ('agentcapsule_api','volume_archives',''),
      ('agentcapsule_worker','volume_archives','INSERT,UPDATE,DELETE'),
      ('agentcapsule_api','volume_relocations',''),
      ('agentcapsule_worker','volume_relocations','INSERT,UPDATE'),
      ('agentcapsule_api','volume_restore_losses','UPDATE'),
      ('agentcapsule_worker','volume_restore_losses','INSERT,UPDATE'),
      ('agentcapsule_api','volume_restores',''),
      ('agentcapsule_worker','volume_restores','INSERT,UPDATE'),
      ('agentcapsule_api','worker_hosts','INSERT,UPDATE'),
      ('agentcapsule_worker','worker_hosts','INSERT,UPDATE'),
      ('agentcapsule_api','worker_jobs',''),
      ('agentcapsule_worker','worker_jobs','INSERT,UPDATE,DELETE')
  ) AS g(role, tbl, privileges)
$$;

REVOKE EXECUTE ON FUNCTION agentcapsule_service_grants() FROM PUBLIC;
SELECT agentcapsule_service_grants();
