-- The scope of a revocation subject: the stores that can act on it
-- (docs/adr/006-authority-service.md, "Changes after the v0.1.0 audit"). A
-- deleted agent's scope is its own store and every agent it shares a request
-- with; a request's is its two parties; an event's is its destination. These
-- indexes find them by agent, without scanning every request or mailbox.
CREATE INDEX IF NOT EXISTS agent_requests_by_sender ON agent_requests(sender_agent_id);
CREATE INDEX IF NOT EXISTS agent_requests_by_recipient ON agent_requests(recipient_agent_id);
CREATE INDEX IF NOT EXISTS agent_mailboxes_closing ON agent_mailboxes(dest_agent_id) WHERE closing;
