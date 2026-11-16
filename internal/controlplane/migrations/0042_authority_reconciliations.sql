-- The reconciliation of PostgreSQL with the authorities after a failover
-- (ADR 006 wave 7; ADR 005, "What the code must do", items 14 and 15). A
-- promotion of the authorities takes a new epoch, and PostgreSQL, promoted
-- from its older copy, may lack what the authorities hold:
-- agentcapsule-admin reconcile brings it up to them, then records the epoch
-- here. The API starts, and its readiness says ready, only once the epoch of
-- its authority service is here. Epoch 1 was never promoted: no failover set
-- this database behind the authorities, and it counts as reconciled.
-- degraded and the window: the promotion assumed that a degraded period ran,
-- announced the window from the standby's last contact with the old primary
-- to the failover, and revoked every bearer token issued before the failover
-- (blanket_revocation_id). report holds what the last run found: the stores
-- whose registration or incarnation differs, the deletions it resumed.
CREATE TABLE authority_reconciliations (
  epoch bigint PRIMARY KEY CHECK (epoch > 0),
  restore_authority_id text CHECK (restore_authority_id ~ '^restoreauth_[0-9a-f]{32}$'),
  degraded boolean NOT NULL DEFAULT false,
  window_from timestamptz,
  window_to timestamptz,
  blanket_revocation_id text REFERENCES access_revocations(id),
  report jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(report) = 'object'),
  first_reconciled_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  reconciled_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CHECK (degraded = (window_from IS NOT NULL AND window_to IS NOT NULL AND blanket_revocation_id IS NOT NULL)),
  CHECK (window_from IS NULL OR window_from <= window_to)
);
INSERT INTO authority_reconciliations(epoch) VALUES (1);

-- The blanket revocation of every bearer token issued before a failover that
-- may have ended a degraded period: an access revocation record of its own
-- kind, written by the promotion, replayed by the reconciliation.
ALTER TABLE access_revocations DROP CONSTRAINT access_revocations_kind_check;
ALTER TABLE access_revocations ADD CONSTRAINT access_revocations_kind_check
  CHECK (kind IN ('api_token','service_token','platform_credential','delegated_token','blanket',
    'member','principal','organization','team','team_membership','assignment','mandate','delegation_trust','llm_provider'));
