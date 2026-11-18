-- Unresponsive guests (ADR 012, question 7). A guest whose harness never
-- answers the fence of a delivery past its attempts holds its store, and the
-- agent's other work waits behind it. The worker stops its VM and records a
-- third kind of guest failure, which counts against the agent's restart
-- budget like a failed boot or a crash, and names the reason of an agent it
-- makes FAILED.
ALTER TABLE guest_failures
  DROP CONSTRAINT guest_failures_kind_check,
  ADD CONSTRAINT guest_failures_kind_check CHECK (kind IN ('boot','crash','unresponsive'));
ALTER TABLE failed_agents
  DROP CONSTRAINT failed_agents_reason_check,
  ADD CONSTRAINT failed_agents_reason_check CHECK (reason IN ('boot_failed','crashed','unresponsive'));
