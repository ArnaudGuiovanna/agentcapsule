-- The retention of finished records (P-04, docs/worker.md). The worker
-- deletes, past terminal_retention, the finished invocations, wakes, sleeps
-- and requests between agents of its host that nothing needs any more, with
-- what hangs on them: their mailbox entries, idempotency keys, inbox items,
-- closures, mandates and content tombstones. These indexes find them oldest
-- first, and serve the checks of the foreign keys that point at the rows it
-- deletes, so that no deletion scans a table. Each CREATE INDEX takes its
-- table's SHARE lock while it builds; the migration runs with the API and the
-- workers stopped (docs/install.md).
CREATE INDEX platform_operations_finished ON platform_operations(completed_at)
  WHERE status IN ('SUCCEEDED','FAILED','CANCELED');
CREATE INDEX agent_requests_finished ON agent_requests(expires_at)
  WHERE state IN ('REPLIED','DECLINED','EXPIRED','CANCELED','FAILED');
CREATE INDEX agent_requests_mandate ON agent_requests(mandate_id);
CREATE INDEX agent_mailboxes_reference ON agent_mailboxes(ref_id) WHERE ref_id IS NOT NULL;
CREATE INDEX idempotency_keys_response ON idempotency_keys(response_ref);
CREATE INDEX inbox_items_reference ON inbox_items(ref_id) WHERE ref_id IS NOT NULL;
CREATE INDEX owner_messages_request ON owner_messages(request_id) WHERE request_id IS NOT NULL;
CREATE INDEX peer_wakes_request ON peer_wakes(request_id);
CREATE INDEX tenant_agent_audit_request ON tenant_agent_audit(request_id) WHERE request_id IS NOT NULL;
CREATE INDEX corpus_builds_invocation ON corpus_builds(invocation_id) WHERE invocation_id IS NOT NULL;
CREATE INDEX corpus_extensions_invocation ON corpus_extensions(invocation_id) WHERE invocation_id IS NOT NULL;
