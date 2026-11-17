-- The operator's garbage collection on demand (OPR-5, ADR 014 §7):
-- agentcapsule-worker -collect-garbage removes, on its host, the archives
-- past retention, the archives of deleted agents and the unused cached
-- harness images, as the maintenance worker does on its own. A run that is
-- not a dry run is audited, with its host as the target.
ALTER TABLE operator_audit DROP CONSTRAINT operator_audit_action_check,
  ADD CONSTRAINT operator_audit_action_check
  CHECK (action IN ('credential.revoked','provisioning.abandoned','audit.retention_set','audit.purged','host.taken_over','garbage.collected'));
