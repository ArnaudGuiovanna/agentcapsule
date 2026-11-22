-- Refused attempts coalesced (v0.1.0 audit, L-04; ADR 014 §10, question 7).
-- In each window of a minute, the API records in full the first refused
-- attempt of an actor at each target of an action, for one reason, up to ten
-- targets; it counts the others, and records their number at the window's end
-- as one event that names the organization. attempts is how many refused
-- attempts a row stands for: 1 for an attempt recorded in full.
-- A constant default rewrites no row. The check is not validated against the
-- existing rows, which all hold the default, so the table is not scanned
-- under its lock; every new row is checked.
ALTER TABLE tenant_refusal_audit ADD COLUMN attempts integer NOT NULL DEFAULT 1;
ALTER TABLE tenant_refusal_audit ADD CONSTRAINT tenant_refusal_audit_attempts_check
  CHECK (attempts BETWEEN 1 AND 1000000000) NOT VALID;
