-- D-01 (ADR 001): the operator bootstrap and the tenant transition.
--
-- The public keys of each delegation trust are held here, so that an operator
-- adds, rotates and retires them without restarting the API. The verifier of a
-- token is built from these rows in the transaction that consumes it.
ALTER TABLE delegation_trusts
  ADD COLUMN allowed_scopes text[],
  ADD COLUMN max_ttl_nanoseconds bigint CHECK (max_ttl_nanoseconds > 0);
-- One organization per issuer and audience, as the verifier requires.
CREATE UNIQUE INDEX delegation_trusts_issuer_audience ON delegation_trusts(issuer,audience);
-- A key ID is bound to one public key for good, and a retired key never
-- returns. expires_at ends the overlap of a scheduled retirement: tokens signed
-- with the key are refused from that instant. retired_at removes the key from
-- the trust's key set. fingerprint is the trust restricted to this key.
CREATE TABLE delegation_keys (
  tenant_id text NOT NULL,
  issuer text NOT NULL,
  audience text NOT NULL,
  key_id text NOT NULL CHECK (octet_length(key_id) BETWEEN 1 AND 1024),
  public_key bytea NOT NULL CHECK (octet_length(public_key)=32),
  fingerprint bytea NOT NULL CHECK (octet_length(fingerprint)=32),
  added_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  expires_at timestamptz,
  retired_at timestamptz,
  PRIMARY KEY (tenant_id,issuer,audience,key_id),
  FOREIGN KEY (tenant_id,issuer,audience) REFERENCES delegation_trusts(tenant_id,issuer,audience),
  CHECK (retired_at IS NULL OR (expires_at IS NOT NULL AND expires_at<=retired_at))
);
ALTER TABLE delegation_audit DROP CONSTRAINT delegation_audit_action_check;
ALTER TABLE delegation_audit ADD CONSTRAINT delegation_audit_action_check
  CHECK (action IN ('install','rotate','revoke-trust','revoke-token','add-key','retire-key'));
ALTER TABLE delegation_audit ADD COLUMN key_id text NOT NULL DEFAULT '';

-- Operator actions outside any organization. Metadata only, never a secret.
CREATE TABLE platform_audit (
  id text PRIMARY KEY CHECK (id <> ''),
  action text NOT NULL CHECK (action IN ('platform_credential.created','platform_credential.revoked')),
  actor text NOT NULL CHECK (length(btrim(actor)) BETWEEN 1 AND 100),
  credential_id text NOT NULL REFERENCES platform_credentials(id),
  changed boolean NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX platform_audit_created ON platform_audit(created_at,id);

-- A second organization of the same name is refused while the first is
-- active, so that running the bootstrap twice cannot create a duplicate.
CREATE UNIQUE INDEX organizations_active_name ON organizations(lower(name)) WHERE status='active';
