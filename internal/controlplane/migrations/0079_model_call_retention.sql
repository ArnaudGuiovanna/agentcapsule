-- The retention of finished model calls (v0.1.0 audit, P-04 and P-05;
-- docs/worker.md, model_call_retention). The worker deletes, past the
-- retention, the settled and released calls that nothing needs any more
-- (model_call_retention.go): these indexes find them oldest first, and the
-- audit events that still name one. Each CREATE INDEX takes its table's
-- SHARE lock while it builds; the migration runs with the API and the
-- workers stopped, offline (docs/cli-host.md).
CREATE INDEX llm_usage_finished ON llm_usage(created_at) WHERE state IN ('settled','released');
CREATE INDEX llm_audit_usage ON llm_audit(usage_id) WHERE usage_id IS NOT NULL;
