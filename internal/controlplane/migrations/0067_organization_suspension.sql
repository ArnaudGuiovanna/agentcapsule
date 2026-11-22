-- A disabled organization's work stops (docs/api/organizations.md,
-- "Disabling"). The worker puts its running agents to sleep with the
-- ordinary sleep command, whose cause says why; the same code closes its
-- scheduled invocations that come due and its wakes.
ALTER TABLE platform_operations DROP CONSTRAINT platform_operations_cause_check;
ALTER TABLE platform_operations ADD CONSTRAINT platform_operations_cause_check
  CHECK (cause IN ('request','idle_policy','organization_disabled'));
