-- Waking the worker (P-01, docs/worker.md). The worker passes over its work
-- queue every poll_interval; these triggers notify it at once, on channel
-- agentcapsule_work, when work that DiscoverWork finds may have arrived for a
-- host: a delivery queued, a mailbox head that leaves the queue (its
-- successor becomes the head), a platform operation recorded or a wake or
-- sleep that ends (the agent's next command becomes due), a request closure
-- or an agent deletion recorded, and a VM that stopped (a slot frees, an
-- interrupted agent may resume). The payload is the host's ID, never
-- content; PostgreSQL folds identical notifications of one transaction. A
-- lost notification only delays the work until the next pass.
CREATE FUNCTION work_notify_host(host text) RETURNS void LANGUAGE plpgsql AS $$
BEGIN
  IF host IS NOT NULL AND host <> '' THEN
    PERFORM pg_notify('agentcapsule_work', host);
  END IF;
END $$;
CREATE FUNCTION work_notify_agent(agent text) RETURNS void LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
  PERFORM work_notify_host(p.host_id) FROM agent_placements p WHERE p.agent_id = agent;
END $$;

CREATE FUNCTION work_notify_outbox() RETURNS trigger LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
  PERFORM work_notify_agent(m.dest_agent_id) FROM agent_mailboxes m WHERE m.id = NEW.mailbox_id;
  RETURN NULL;
END $$;
CREATE TRIGGER work_delivery_queued AFTER INSERT ON outbox
  FOR EACH ROW EXECUTE FUNCTION work_notify_outbox();

CREATE FUNCTION work_notify_mailbox() RETURNS trigger LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
  PERFORM work_notify_agent(NEW.dest_agent_id);
  RETURN NULL;
END $$;
CREATE TRIGGER work_mailbox_moved AFTER UPDATE OF delivery_state ON agent_mailboxes
  FOR EACH ROW WHEN (OLD.delivery_state IS DISTINCT FROM NEW.delivery_state)
  EXECUTE FUNCTION work_notify_mailbox();

CREATE FUNCTION work_notify_operation() RETURNS trigger LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
  PERFORM work_notify_host(NEW.host_id);
  RETURN NULL;
END $$;
CREATE TRIGGER work_operation_recorded AFTER INSERT ON platform_operations
  FOR EACH ROW EXECUTE FUNCTION work_notify_operation();
CREATE TRIGGER work_lifecycle_ended AFTER UPDATE OF status ON platform_operations
  FOR EACH ROW WHEN (NEW.kind IN ('wake','sleep') AND OLD.status IS DISTINCT FROM NEW.status
    AND NEW.status IN ('SUCCEEDED','FAILED','CANCELED'))
  EXECUTE FUNCTION work_notify_operation();

CREATE FUNCTION work_notify_closure() RETURNS trigger LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
  PERFORM work_notify_agent(r.sender_agent_id) FROM agent_requests r WHERE r.id = NEW.request_id;
  RETURN NULL;
END $$;
CREATE TRIGGER work_closure_recorded AFTER INSERT ON request_closures
  FOR EACH ROW EXECUTE FUNCTION work_notify_closure();

CREATE FUNCTION work_notify_deletion() RETURNS trigger LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
  PERFORM work_notify_agent(NEW.agent_id);
  RETURN NULL;
END $$;
CREATE TRIGGER work_deletion_recorded AFTER INSERT ON deletion_operations
  FOR EACH ROW EXECUTE FUNCTION work_notify_deletion();

CREATE FUNCTION work_notify_placement() RETURNS trigger LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
  PERFORM work_notify_host(NEW.host_id);
  RETURN NULL;
END $$;
CREATE TRIGGER work_vm_stopped AFTER UPDATE OF state ON agent_placements
  FOR EACH ROW WHEN (NEW.state = 'STOPPED' AND OLD.state IS DISTINCT FROM NEW.state)
  EXECUTE FUNCTION work_notify_placement();
