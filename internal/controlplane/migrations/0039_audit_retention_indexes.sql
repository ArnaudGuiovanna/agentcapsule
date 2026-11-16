-- The audit retention (ADR 014) also covers the capability policy changes
-- (0036) and the replays of dead letters (0035). Its purge selects by age
-- alone.
CREATE INDEX capability_audit_created ON capability_audit(created_at);
CREATE INDEX instruction_replays_replayed ON instruction_replays(replayed_at);
