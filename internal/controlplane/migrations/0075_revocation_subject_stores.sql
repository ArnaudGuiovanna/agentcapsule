-- The stores of a revocation subject's scope that never change, recorded
-- with the subject (FIX-1; docs/adr/006-authority-service.md, "Changes after
-- the v0.1.0 audit"): an event/<id> subject's destination, a request/<id>
-- subject's sender and recipient. The scope was read from the mailbox entry
-- and the request, which the retention of finished records (migration
-- finished-record-retention) deletes; a subject the authority begins after
-- that, as a reconciliation does after a failover, fell into every store's
-- scope, and its ID reached the guests of other organizations. An agent/<id>
-- subject's scope follows the agent's kept requests: it records none.
--
-- The guard of revocation_catalogue refuses every UPDATE: this migration
-- turns it off for its own backfill only, in its transaction, and the
-- column is written once, at the subject's insertion. A constant NULL default
-- rewrites no row; the check holds for every NULL.
ALTER TABLE revocation_catalogue ADD COLUMN stores text[]
  CHECK (stores IS NULL OR cardinality(stores) BETWEEN 1 AND 2);
ALTER TABLE revocation_catalogue DISABLE TRIGGER revocation_catalogue_guard;
UPDATE revocation_catalogue c SET stores=ARRAY[m.dest_agent_id]
  FROM agent_mailboxes m WHERE c.subject='event/'||m.id;
UPDATE revocation_catalogue c SET stores=ARRAY(SELECT DISTINCT x FROM unnest(ARRAY[r.sender_agent_id,r.recipient_agent_id]) x ORDER BY x)
  FROM agent_requests r WHERE c.subject='request/'||r.id;
ALTER TABLE revocation_catalogue ENABLE TRIGGER revocation_catalogue_guard;
