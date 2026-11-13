-- Correlation (OPS-02): an operation records the X-Request-ID of the API
-- request that created it. The API sets agentcapsule.request_id for its
-- transaction (Store.begin), so every place that creates an operation records
-- it without passing it along; work without an API request records nothing.
-- The worker's job events then carry the same ID, also for the requests an
-- agent sends under the mandate that operation granted.
ALTER TABLE platform_operations ADD COLUMN request_id text
  DEFAULT nullif(current_setting('agentcapsule.request_id', true), '')
  CHECK (request_id ~ '^[0-9a-f]{32}$');
