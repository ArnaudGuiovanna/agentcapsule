-- Expired idempotency receipts are purged in bounded batches by the worker.
-- These indexes keep that scan proportional to the number of expired rows.
CREATE INDEX IF NOT EXISTS http_receipts_expiry ON http_receipts(expires_at);
CREATE INDEX IF NOT EXISTS tenant_http_receipts_expiry ON tenant_http_receipts(expires_at);
