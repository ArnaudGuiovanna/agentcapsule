-- The worker's polling queries (P-04) read open work only: the open
-- operations, requests and closures of a host's agents, the content due for
-- purge (the model calls in flight have llm_usage_unresolved, and the
-- requests' scopes the indexes of 0065). These partial indexes hold those rows
-- alone, so that the queries no longer scan the whole history of the tables
-- under the worker_hosts row lock. Each CREATE INDEX takes its table's SHARE
-- lock, which blocks writes to it (not reads) while it builds; the migration
-- runs offline, the API and the workers stopped (docs/cli-host.md).
CREATE INDEX agent_placements_host ON agent_placements(host_id, state);
CREATE INDEX platform_operations_open ON platform_operations(agent_id, seq)
  WHERE status IN ('PENDING','RUNNING');
CREATE INDEX platform_operations_open_host ON platform_operations(host_id, kind)
  WHERE status IN ('PENDING','RUNNING');
CREATE INDEX platform_operations_sleeps ON platform_operations(agent_id, created_at)
  WHERE kind = 'sleep';
CREATE INDEX agent_requests_open_sender ON agent_requests(sender_agent_id, expires_at)
  WHERE state IN ('PENDING_APPROVAL','DELIVERING','PROCESSING');
CREATE INDEX agent_requests_open_recipient ON agent_requests(recipient_agent_id, expires_at)
  WHERE state IN ('PENDING_APPROVAL','DELIVERING','PROCESSING');
CREATE INDEX request_closures_fencing ON request_closures(request_id) WHERE phase = 'FENCING';
CREATE INDEX transit_payloads_purge_due ON transit_payloads(purge_after, id) WHERE purged_at IS NULL;

-- The latest activity of each agent (P-04): what the idle policy and the
-- eviction order compare, kept in the transaction of the activity itself
-- instead of a max() over every operation, request and model call the agent
-- ever had. at counts every platform operation, request sent or received and
-- model call; idle_at the same, of the operations only wakes and
-- invocations, as the idle policy always counted. Rows only grow later: a
-- purge of old rows leaves them as they are.
CREATE TABLE agent_activity (
  agent_id text PRIMARY KEY REFERENCES agents(id),
  at timestamptz NOT NULL,
  idle_at timestamptz
);
INSERT INTO agent_activity(agent_id, at, idle_at)
SELECT agent_id, max(t), max(t) FILTER (WHERE idle) FROM (
  SELECT agent_id, greatest(created_at, coalesce(completed_at, created_at)) AS t, kind IN ('wake','instruction') AS idle
    FROM platform_operations
  UNION ALL SELECT sender_agent_id, greatest(created_at, coalesce(decided_at, created_at)), true FROM agent_requests
  UNION ALL SELECT recipient_agent_id, greatest(created_at, coalesce(decided_at, created_at)), true FROM agent_requests
  UNION ALL SELECT agent_id, coalesce(settled_at, created_at), true FROM llm_usage
) activity GROUP BY agent_id;

-- One statement's rows make one upsert, in agent order: two transactions
-- never take two agents' rows in opposite orders within a statement. An
-- update counts only where a time it reads changed.
CREATE FUNCTION agent_activity_upsert(agents text[], ats timestamptz[], idle_ats timestamptz[]) RETURNS void
LANGUAGE sql SET search_path FROM CURRENT AS $$
  INSERT INTO agent_activity AS v(agent_id, at, idle_at)
  SELECT agent_id, max(at), max(idle_at) FROM unnest(agents, ats, idle_ats) AS c(agent_id, at, idle_at)
   GROUP BY agent_id ORDER BY agent_id
  ON CONFLICT (agent_id) DO UPDATE SET at = greatest(v.at, EXCLUDED.at), idle_at = greatest(v.idle_at, EXCLUDED.idle_at)
$$;
CREATE FUNCTION agent_activity_from_operations() RETURNS trigger LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
DECLARE agents text[]; ats timestamptz[]; idle_ats timestamptz[];
BEGIN
  IF TG_OP = 'INSERT' THEN
    SELECT array_agg(n.agent_id), array_agg(greatest(n.created_at, n.completed_at)),
           array_agg(CASE WHEN n.kind IN ('wake','instruction') THEN greatest(n.created_at, n.completed_at) END)
      INTO agents, ats, idle_ats FROM changed_rows n;
  ELSE
    SELECT array_agg(n.agent_id), array_agg(greatest(n.created_at, n.completed_at)),
           array_agg(CASE WHEN n.kind IN ('wake','instruction') THEN greatest(n.created_at, n.completed_at) END)
      INTO agents, ats, idle_ats FROM changed_rows n JOIN previous_rows o ON o.id = n.id
     WHERE (o.created_at, o.completed_at) IS DISTINCT FROM (n.created_at, n.completed_at);
  END IF;
  IF agents IS NOT NULL THEN
    PERFORM agent_activity_upsert(agents, ats, idle_ats);
  END IF;
  RETURN NULL;
END $$;
CREATE FUNCTION agent_activity_from_requests() RETURNS trigger LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
DECLARE agents text[]; ats timestamptz[];
BEGIN
  IF TG_OP = 'INSERT' THEN
    SELECT array_agg(p.agent_id), array_agg(greatest(n.created_at, n.decided_at))
      INTO agents, ats FROM changed_rows n CROSS JOIN LATERAL (VALUES (n.sender_agent_id), (n.recipient_agent_id)) AS p(agent_id);
  ELSE
    SELECT array_agg(p.agent_id), array_agg(greatest(n.created_at, n.decided_at))
      INTO agents, ats FROM changed_rows n JOIN previous_rows o ON o.id = n.id
      CROSS JOIN LATERAL (VALUES (n.sender_agent_id), (n.recipient_agent_id)) AS p(agent_id)
     WHERE (o.created_at, o.decided_at) IS DISTINCT FROM (n.created_at, n.decided_at);
  END IF;
  IF agents IS NOT NULL THEN
    PERFORM agent_activity_upsert(agents, ats, ats);
  END IF;
  RETURN NULL;
END $$;
CREATE FUNCTION agent_activity_from_model_calls() RETURNS trigger LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
DECLARE agents text[]; ats timestamptz[];
BEGIN
  IF TG_OP = 'INSERT' THEN
    SELECT array_agg(n.agent_id), array_agg(coalesce(n.settled_at, n.created_at)) INTO agents, ats FROM changed_rows n;
  ELSE
    SELECT array_agg(n.agent_id), array_agg(coalesce(n.settled_at, n.created_at))
      INTO agents, ats FROM changed_rows n JOIN previous_rows o ON o.id = n.id
     WHERE (o.created_at, o.settled_at) IS DISTINCT FROM (n.created_at, n.settled_at);
  END IF;
  IF agents IS NOT NULL THEN
    PERFORM agent_activity_upsert(agents, ats, ats);
  END IF;
  RETURN NULL;
END $$;
CREATE TRIGGER agent_activity_operations_added AFTER INSERT ON platform_operations
  REFERENCING NEW TABLE AS changed_rows FOR EACH STATEMENT EXECUTE FUNCTION agent_activity_from_operations();
CREATE TRIGGER agent_activity_operations_changed AFTER UPDATE ON platform_operations
  REFERENCING OLD TABLE AS previous_rows NEW TABLE AS changed_rows FOR EACH STATEMENT EXECUTE FUNCTION agent_activity_from_operations();
CREATE TRIGGER agent_activity_requests_added AFTER INSERT ON agent_requests
  REFERENCING NEW TABLE AS changed_rows FOR EACH STATEMENT EXECUTE FUNCTION agent_activity_from_requests();
CREATE TRIGGER agent_activity_requests_changed AFTER UPDATE ON agent_requests
  REFERENCING OLD TABLE AS previous_rows NEW TABLE AS changed_rows FOR EACH STATEMENT EXECUTE FUNCTION agent_activity_from_requests();
CREATE TRIGGER agent_activity_model_calls_added AFTER INSERT ON llm_usage
  REFERENCING NEW TABLE AS changed_rows FOR EACH STATEMENT EXECUTE FUNCTION agent_activity_from_model_calls();
CREATE TRIGGER agent_activity_model_calls_changed AFTER UPDATE ON llm_usage
  REFERENCING OLD TABLE AS previous_rows NEW TABLE AS changed_rows FOR EACH STATEMENT EXECUTE FUNCTION agent_activity_from_model_calls();
