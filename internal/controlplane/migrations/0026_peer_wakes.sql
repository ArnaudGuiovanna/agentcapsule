-- Wake budget (INT-04, A2A-009): an organization's agents may wake one another
-- through requests only so many times per rolling hour. Each VM boot caused by
-- a request between agents of an organization is recorded; replies, statuses,
-- owner instructions and explicit wakes are not. The limit belongs with the
-- organization's other limits (PUT /v1/queue/limits).
ALTER TABLE queue_limits ADD COLUMN max_peer_wakes_per_hour integer NOT NULL DEFAULT 60
  CHECK (max_peer_wakes_per_hour BETWEEN 1 AND 100000);
CREATE TABLE peer_wakes (
  id text PRIMARY KEY CHECK (id <> ''),
  tenant_id text NOT NULL REFERENCES organizations(id),
  agent_id text NOT NULL REFERENCES agents(id),
  request_id text NOT NULL REFERENCES agent_requests(id),
  woken_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX peer_wakes_window ON peer_wakes(tenant_id, woken_at);
